import { Service, type Context } from '@deepseek-ai/cordis';
import { isAbsolute, join, resolve } from 'node:path';
import { mkdir, open, readFile, rename, rm } from 'node:fs/promises';
import type { Binding, HttpTransport, IdentityRef } from './types.js';
import type { CallbackHandoff, HostSecretStore } from './host.js';
import { PapClient } from './client.js';
import { ProtocolIdentityHost, type ProtocolIdentityClient } from './protocol-adapter.js';
import { SafeHttpsTransport } from './network.js';
import { PapError, requirePap, type PapAuthHint } from './errors.js';
import { KeyringSecretStore } from './keyring.js';
import { DeviceCallbackHandoff } from './callback-handoff.js';
import { PAP_CONSUMER, PAP_MANAGER, PAP_TOOLS, identityReferenceSchema, managementRequestSchema, operationRequestSchema, type PapHostConsumer, type PapManagementRequest, type ProductResult } from './product-api.js';
import { assertApproval, findOperation, prepareOperation, privateValues, publicOperations, publicResponse, sanitizePublicValue } from './product-operations.js';
import { httpsUrl, id, sha256 } from './util.js';
import { strictJson } from './strict-json.js';
import { CredentialHistory } from './credential-history.js';

export interface PapPluginConfig {
  /** Explicit opt-in; loading an unconfigured bundle performs no discovery or signing. */
  enabled?: boolean;
  stateRoot?: string;
  keyringService?: string;
  /** Approved C policy chosen by Host configuration, never by a Remote or model. */
  policyRef?: string;
  identityRef?: IdentityRef;
}
/** Optional OS-specific Host provider. It never supplies Agent keys or device credentials. */
export interface PapHostServices { secrets: HostSecretStore; transport?: HttpTransport }
declare module '@deepseek-ai/cordis' { interface Context { pap: PapService; papHost: PapHostServices } }
export const name = PAP_CONSUMER;
export const inject = ['anpIdentity'];
interface InstalledEntry { options: { name: string }; disabled?: boolean; fiber?: { state: number; ctx?: Context } }
const fiberOf = (fiber: object | undefined) => (fiber as { ctx?: Context } | undefined)?.ctx?.fiber ?? fiber;

/** Arbitrary provider/network descriptions never cross a public boundary. */
export async function publicResult(operation: () => Promise<unknown>): Promise<ProductResult> {
  try { return { ok: true, value: await operation() }; }
  catch (error) {
    if (error instanceof PapError) return { ok: false, error: { code: error.code, ...(error.retryAfterSeconds === undefined ? {} : { retryAfterSeconds: error.retryAfterSeconds }) } };
    const code = (error as { code?: unknown } | null)?.code;
    if (typeof code === 'string' && ['callback_not_ready','callback_claimed','callback_expired','callback_conflict','callback_unavailable','callback_limit','management_auth_required','not_published','client_id_conflict','idempotency_conflict','provider_unavailable','provider_disposed','consumer_forbidden'].includes(code)) return { ok: false, error: { code } };
    return { ok: false, error: { code: 'permission_denied' } };
  }
}

/** Actual installed F Host. Engine, C targets and callback capabilities remain in this process. */
export class PapService extends Service {
  private readonly installedContext: Context;
  private client?: PapClient;
  private hostConsumer?: PapHostConsumer;
  private selected?: IdentityRef;
  private binding?: Binding;
  private stopped = false;
  private lastError?: string;
  private readonly ready: Promise<void>;
  private readonly authHints = new Map<string, PapAuthHint>();
  private readonly credentialHistory = new CredentialHistory();
  private changing = false;
  constructor(ctx: Context, private readonly config: PapPluginConfig = {}) {
    super(ctx, 'pap');
    // Cordis service access can associate this.ctx with a caller. C must always
    // receive the original installed F Context, never the manager/tool caller.
    this.installedContext = ctx;
    ctx.effect(() => () => this.stop());
    this.ready = Promise.resolve().then(() => this.restore());
  }
  private assertInstalled(context: Context, expected: string): void {
    requirePap(!this.stopped, 'disconnected');
    const loader = this.installedContext.get('loader') as { entries?: () => Iterable<InstalledEntry> } | undefined;
    const entry = loader?.entries && [...loader.entries()].find(value => fiberOf(value.fiber) === fiberOf(context.fiber));
    requirePap(entry && !entry.disabled && entry.options.name === expected && entry.fiber && [1,2].includes(entry.fiber.state), 'permission_denied');
  }
  private async consumer(): Promise<PapHostConsumer> {
    requirePap(!this.stopped, 'disconnected');
    requirePap(this.config.enabled === true && typeof this.config.stateRoot === 'string' && isAbsolute(this.config.stateRoot) && Boolean(this.config.policyRef), 'not_configured');
    if (!this.hostConsumer) {
      const identity = this.installedContext.get('anpIdentity') as { bindPapHostConsumer?: (context: Context) => PapHostConsumer } | undefined;
      requirePap(typeof identity?.bindPapHostConsumer === 'function', 'permission_denied');
      this.hostConsumer = identity.bindPapHostConsumer(this.installedContext);
    }
    await this.hostConsumer.assertActive(); return this.hostConsumer;
  }
  private async restore(): Promise<void> {
    if (this.config.enabled !== true) return;
    if (typeof this.config.stateRoot !== 'string' || !isAbsolute(this.config.stateRoot) || !this.config.policyRef) { this.lastError = 'not_configured'; return; }
    try {
      let reference = this.config.identityRef;
      try { reference = identityReferenceSchema.parse(strictJson(await readFile(join(this.config.stateRoot!, 'selected-identity.json')), 4096)); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw new PapError('state_corrupt'); }
      if (reference) await this.select(reference, false);
    } catch (error) { this.lastError = error instanceof PapError ? error.code : 'permission_denied'; }
  }
  private async persistSelection(reference: IdentityRef): Promise<void> {
    const root = this.config.stateRoot!; await mkdir(root, { recursive: true, mode: 0o700 });
    const temporary = join(root, `.${id('selection')}.tmp`);
    try {
      const file = await open(temporary, 'wx', 0o600);
      try { await file.writeFile(JSON.stringify(reference)); await file.sync(); } finally { await file.close(); }
      await rename(temporary, join(root, 'selected-identity.json'));
      const directory = await open(root, 'r'); try { await directory.sync(); } finally { await directory.close(); }
    } finally { await rm(temporary, { force: true }); }
  }
  private async select(reference: IdentityRef, persist: boolean): Promise<void> {
    requirePap(!this.changing && !this.stopped, 'state_conflict'); this.changing = true;
    let next: PapClient | undefined;
    try {
      // A disposed C facade never revives. Only an explicit user selection (or
      // plugin reload) reacquires current authority from the installed Context.
      if (persist) { this.hostConsumer?.dispose(); this.hostConsumer = undefined; }
      const consumer = await this.consumer();
      const resolved = await consumer.resolveBinding(reference, this.config.policyRef!, 'pap_session');
      const identityRef = resolved.binding.identityRef;
      requirePap(identityRef.storeId === reference.storeId && identityRef.identityId === reference.identityId && identityRef.did === reference.did && typeof resolved.binding.ownerRef === 'string' && resolved.binding.ownerRef.length > 0, 'permission_denied');
      const binding: Binding = { identityRef: { storeId: identityRef.storeId, identityId: identityRef.identityId, did: identityRef.did }, ownerRef: resolved.binding.ownerRef, clientId: resolved.binding.clientId };
      httpsUrl(binding.clientId);
      const identity = this.installedContext.get('anpIdentity') as { bindProtocolConsumer(context: Context): ProtocolIdentityClient };
      requirePap(typeof identity.bindProtocolConsumer === 'function', 'permission_denied');
      const protocolHost = new ProtocolIdentityHost(identity.bindProtocolConsumer(this.installedContext), this.config.policyRef!);
      const host = this.installedContext.get('papHost') as PapHostServices | undefined;
      const protectedSecrets = host?.secrets ?? new KeyringSecretStore(this.config.keyringService ?? 'org.agentconnect.dsh-pap', join(this.config.stateRoot!, 'keyring-locks'));
      const profileNamespace = `dsh-pap/profile/${sha256(resolve(this.config.stateRoot!))}/`;
      const secrets: HostSecretStore = {
        getEncryptionKey: namespace => protectedSecrets.getEncryptionKey(profileNamespace + namespace),
        getOrCreateEncryptionKey: namespace => protectedSecrets.getOrCreateEncryptionKey(profileNamespace + namespace),
      };
      const management = async (transactionId?: string, callbackRef?: string) => {
        await consumer.assertActive(); let state = await next!.store.read();
        let tx = transactionId ? state.transactions[transactionId] : Object.values(state.transactions).find(value => value.callbackRef === callbackRef);
        requirePap(tx && tx.status === 'pending' && tx.expiresAt > Date.now(), 'invalid_authorization_response');
        let subject = state.subjects[tx.subjectRef]; let company = subject && state.companies[subject.companyRef];
        requirePap(company && company.issuer === tx.issuer && tx.clientId === binding.clientId, 'permission_denied');
        if(company.expiresAt<=Date.now()) {
          await next!.resolvePapCompany(company.domain);await consumer.assertActive();state=await next!.store.read();
          tx=transactionId?state.transactions[transactionId]:Object.values(state.transactions).find(value=>value.callbackRef===callbackRef);
          requirePap(tx&&tx.status==='pending'&&tx.expiresAt>Date.now(),'invalid_authorization_response');subject=state.subjects[tx.subjectRef];company=subject&&state.companies[subject.companyRef];
          requirePap(company&&company.issuer===tx.issuer&&tx.clientId===binding.clientId,'permission_denied');
        }
        const latest=Object.values(state.companies).filter(value=>value.domain===company.domain).sort((left,right)=>right.generation-left.generation)[0];
        requirePap(latest?.companyId===company.companyId&&latest.issuer===tx.issuer,'namespace_changed');
        const target = await protocolHost.acquire(binding, company, 'pap_account', tx.resource, undefined, tx.scope);
        requirePap(target.targetRef, 'permission_denied');
        return consumer.callbackManagementFor({ identityRef: reference, policyRef: this.config.policyRef!, targetRef: target.targetRef });
      };
      const handoff: CallbackHandoff = {
        register: async input => { const driver = await management(input.transactionId); try { return await new DeviceCallbackHandoff(driver).register(input); } finally { driver.dispose(); } },
        collect: async callbackRef => { const driver = await management(undefined, callbackRef); try { return await new DeviceCallbackHandoff(driver).collect(callbackRef); } finally { driver.dispose(); } },
      };
      next = new PapClient({ stateRoot: join(this.config.stateRoot!, `identity-${sha256(JSON.stringify(binding))}`), binding, identityHost: protocolHost, secretStore: secrets, callbackHandoff: handoff, observeCredentials: credentials => this.credentialHistory.observe(credentials) }, host?.transport ?? new SafeHttpsTransport());
      await next.recover(); await consumer.assertActive(); requirePap(!this.stopped, 'disconnected');
      if (persist) await this.persistSelection(reference);
      await consumer.assertActive(); requirePap(!this.stopped, 'disconnected');
      this.client?.close(); this.authHints.clear(); this.client = next; this.binding = binding; this.selected = structuredClone(reference); this.lastError = undefined;
    } catch (error) { next?.close(); this.lastError = error instanceof PapError ? error.code : 'permission_denied'; throw error; }
    finally { this.changing = false; }
  }
  private async engine(): Promise<PapClient> {
    await this.ready; requirePap(!this.stopped, 'disconnected'); requirePap(this.client, 'not_configured'); await (await this.consumer()).assertActive(); return this.client;
  }
  private async runPublic(operation: () => Promise<unknown>): Promise<ProductResult> {
    const result = await publicResult(operation);
    if (this.stopped) return {ok:false,error:{code:'disconnected'}};
    try { return sanitizePublicValue(result,this.credentialHistory.values()) as ProductResult; }
    catch { return {ok:false,error:{code:'credential_unavailable'}}; }
  }
  private publicValue(state: Parameters<typeof privateValues>[0], value: unknown, userAuthorizationUrl = false): unknown {
    requirePap(state.credentialVault?.completeness === 'complete','credential_history_incomplete');
    this.credentialHistory.restore(state);
    const tokens=this.credentialHistory.values();
    const sanitized=sanitizePublicValue(value,[...tokens,...privateValues(state)]);
    if(userAuthorizationUrl&&value&&typeof value==='object'&&!Array.isArray(value)&&typeof (value as {authorizationUrl?:unknown}).authorizationUrl==='string') {
      // Only this explicit user result may carry the AS-bound state/challenge.
      (sanitized as Record<string,unknown>).authorizationUrl=sanitizePublicValue((value as {authorizationUrl:string}).authorizationUrl,[...tokens,...privateValues(state,false)]);
    }
    return sanitized;
  }
  private assertCurrentEngine(engine: PapClient): void { requirePap(!this.stopped, 'disconnected'); requirePap(!this.changing && this.client === engine, 'state_conflict'); }
  private async catalog(enabledOnly: boolean, check: () => void): Promise<object[]> {
    check(); const engine = await this.engine(); const state = await engine.store.read();
    check(); this.assertCurrentEngine(engine); await (await this.consumer()).assertActive(); check(); this.assertCurrentEngine(engine);
    return this.publicValue(state,publicOperations(state, enabledOnly)) as object[];
  }
  async start(): Promise<void> { await this.ready; }
  stop(): void { if (this.stopped) return; this.stopped = true; this.client?.close(); this.hostConsumer?.dispose(); this.credentialHistory.dispose(); }
  async getStatus(includeManagementHints = false): Promise<object> {
    await this.ready;
    requirePap(!this.stopped, 'disconnected');
    if (this.config.enabled !== true) return { state: 'disabled' };
    if (!this.client) return { state: this.lastError === 'credential_unavailable' ? 'credential_unavailable' : 'unconfigured', ...(this.lastError ? { error: this.lastError } : {}) };
    const engine = this.client; await (await this.consumer()).assertActive();
    const state = await engine.store.read();
    this.assertCurrentEngine(engine); await (await this.consumer()).assertActive(); this.assertCurrentEngine(engine);
    if (state.credentialVault?.completeness !== 'complete' || state.credentialVault.blocked) {
      if (!includeManagementHints) throw new PapError(state.credentialVault?.completeness !== 'complete'?'credential_history_incomplete':'credential_unavailable');
      return {state:state.credentialVault?.completeness !== 'complete'?'migration_required':'credential_unavailable',error:state.credentialVault?.completeness !== 'complete'?'credential_history_incomplete':'credential_unavailable',
        accounts:[...new Map<string,{accountSlot:string;status:string;scopes:readonly string[]}>([...Object.values(state.grants).map(value=>[value.accountSlot,{accountSlot:value.accountSlot,status:value.status,scopes:[]}] as const),...Object.values(state.transactions).map(value=>[value.accountSlot,{accountSlot:value.accountSlot,status:'pending_login',scopes:[]}] as const)]).values()]};
    }
    return this.publicValue(state,{ state: 'ready', identity: this.selected, supportedSignIn: ['direct'],
      ...(includeManagementHints ? { authenticationHints: [...this.authHints].map(([operationRef, hint]) => ({ operationRef, ...hint })),
        pendingSignIns: Object.values(state.transactions).filter(value => value.status === 'pending' && value.expiresAt > Date.now()).map(value => ({ transactionRef:value.ref, accountSlot:value.accountSlot, ...(state.subjects[value.subjectRef]?{companyRef:state.subjects[value.subjectRef]!.companyRef}:{}), expiresAt:value.expiresAt })) } : {}),
      companies: Object.values(state.companies).map(value => ({ companyRef: value.ref, name: value.name, authMode: value.authMode, scopes: value.scopes })),
      sessions: Object.values(state.sessions).map(value => ({ sessionRef: value.ref, ...(state.subjects[value.subjectRef] ? { companyRef: state.subjects[value.subjectRef]!.companyRef } : {}), connected: value.connected, account: Boolean(value.accountSlot), ...(value.accountSlot ? { accountSlot: value.accountSlot } : {}) })),
      accounts: Object.values(state.grants).map(value => ({ accountSlot: value.accountSlot, ...(state.subjects[value.subjectRef] ? { companyRef:state.subjects[value.subjectRef]!.companyRef } : {}), status: value.status, scopes: value.scope,canRefresh:value.status==='active'&&Boolean(value.refreshToken) })),
    }) as object;
  }
  /** The installed user-only Typert manager receives the management facade. */
  acquireManagement(context: Context): { status(): Promise<ProductResult>; operations(): Promise<ProductResult>; execute(input: unknown): Promise<ProductResult> } {
    this.assertInstalled(context, PAP_MANAGER); const check = () => this.assertInstalled(context, PAP_MANAGER);
    return Object.freeze({
      status: () => this.runPublic(async () => { check(); const result = await this.getStatus(true); check(); return result; }),
      operations: () => this.runPublic(() => this.catalog(false, check)),
      execute: input => this.runPublic(async () => {
        check(); const parsed = managementRequestSchema.safeParse(input); requirePap(parsed.success, 'permission_denied'); const previous = this.client;
        const result = await this.manage(parsed.data, check); check();
        if (parsed.data.action !== 'identity/select' && previous) { this.assertCurrentEngine(previous); await (await this.consumer()).assertActive(); check(); this.assertCurrentEngine(previous); }
        const current = this.client;
        if (!current) return result;
        const state = await current.store.read(); check(); this.assertCurrentEngine(current); await (await this.consumer()).assertActive(); check(); this.assertCurrentEngine(current);
        if (parsed.data.action==='account/sign-out' && state.credentialVault?.completeness!=='complete') return result;
        if (parsed.data.action==='identity/select' && state.credentialVault?.completeness!=='complete') return result;
        return this.publicValue(state,result,parsed.data.action==='account/sign-in');
      }),
    });
  }
  /** Agent capability contains only approved local operation references. */
  acquireTools(context: Context): { status(): Promise<ProductResult>; operations(): Promise<ProductResult>; request(input: unknown, signal?: AbortSignal): Promise<ProductResult> } {
    this.assertInstalled(context, PAP_TOOLS); const check = () => this.assertInstalled(context, PAP_TOOLS);
    return Object.freeze({
      status: () => this.runPublic(async () => { check(); const result = await this.getStatus(); check(); return result; }),
      operations: () => this.runPublic(() => this.catalog(true, check)),
      request: (input, signal) => this.runPublic(async () => {
        check(); const parsed = operationRequestSchema.safeParse(input); requirePap(parsed.success, 'permission_denied');
        const engine = await this.engine(); const pin = this.credentialHistory.begin();
        try {
        const snapshot = await engine.store.read(); requirePap(snapshot.credentialVault?.completeness==='complete','credential_history_incomplete'); const prepared = prepareOperation(snapshot, parsed.data);
        this.credentialHistory.restore(snapshot);
        for (const grant of Object.values(snapshot.grants)) { this.credentialHistory.rememberIfAbsent(grant.accessToken); if (grant.refreshToken) this.credentialHistory.rememberIfAbsent(grant.refreshToken); }
        const checkRequest = () => { check(); this.assertCurrentEngine(engine); };
        checkRequest(); this.credentialHistory.assertUsable();
        const sentSecrets = new Set(privateValues(snapshot));
        try {
          const response = await engine.dispatchPap(prepared.approval.sessionRef, prepared.operation, { signal,
            assertAllowed: state => { checkRequest(); this.credentialHistory.assertUsable(); assertApproval(state, parsed.data.operationRef, prepared.approval); },
            captureSecrets: (values, credentials) => { for (const value of values) sentSecrets.add(value); if (credentials) this.credentialHistory.observe(credentials); this.credentialHistory.assertUsable(); },
          });
          checkRequest(); await (await this.consumer()).assertActive(); checkRequest();
          const current = await engine.store.read(); assertApproval(current, parsed.data.operationRef, prepared.approval);
          this.credentialHistory.restore(current);
          const secrets = [...sentSecrets, ...privateValues(current), ...this.credentialHistory.values()];
          checkRequest(); await (await this.consumer()).assertActive(); checkRequest();
          this.authHints.delete(parsed.data.operationRef); return publicResponse(response, secrets);
        } catch (error) {
          if (this.client === engine && !this.changing && error instanceof PapError && error.authHint) {
            if (this.authHints.size >= 32) this.authHints.delete(this.authHints.keys().next().value!);
            this.authHints.set(parsed.data.operationRef, error.authHint);
          }
          throw error;
        }
        } finally { this.credentialHistory.end(pin); }
      }),
    });
  }
  private async manage(input: PapManagementRequest, check: () => void): Promise<unknown> {
    await this.ready; check();
    if (input.action === 'identity/select') { await this.select(input.reference, true); check(); return this.getStatus(true); }
    const engine = await this.engine(); check();
    if (input.action!=='account/sign-out') requirePap((await engine.store.read()).credentialVault?.completeness==='complete','credential_history_incomplete');
    if (input.action === 'company/discover') return engine.resolvePapCompany(input.domain);
    if (input.action === 'session/connect') {
      const subject = await engine.getOrCreatePapUser(input.companyRef, input.mode ?? 'regular', true); check();
      return { ...subject, ...(await engine.openPapSession(subject.subjectRef, input.accountSlot)) };
    }
    if (input.action === 'session/disconnect') { await engine.disconnectPap(input.sessionRef); return null; }
    if (input.action === 'operation/disable') { await engine.store.transaction(state => { check(); if (state.product) delete state.product.operations[input.operationRef]; }); return null; }
    if (input.action === 'operation/enable') return engine.store.transaction(state => {
      check(); const { company, route } = findOperation(state, input.operationRef); const session = state.sessions[input.sessionRef];
      requirePap(session?.connected && state.subjects[session.subjectRef]?.companyRef === company.ref, 'permission_denied');
      const scopes = [...new Set(input.scopes ?? [])].sort();
      requirePap(scopes.every(scope => company.scopes.includes(scope)) && (session.accountSlot || scopes.length === 0), 'insufficient_scope');
      state.product ??= { operations: {} }; state.product.operations[input.operationRef] = { companyRef: company.ref, method: route.method, template: route.template, resource: route.resource, sessionRef: input.sessionRef, scopes, generation: state.generation + 1 };
      return { operationRef: input.operationRef, enabled: true };
    });
    if (input.action === 'account/sign-in') {
      const state = await engine.store.read(); const { company, route } = findOperation(state, input.operationRef); const session = state.sessions[input.sessionRef];
      requirePap(session?.connected && state.subjects[session.subjectRef]?.companyRef === company.ref, 'permission_denied');
      const resolved = await (await this.consumer()).resolveBinding(this.selected!, this.config.policyRef!, 'pap_account');
      const current = this.binding!; const candidate = resolved.binding;
      requirePap(candidate.clientId === current.clientId && candidate.ownerRef === current.ownerRef && candidate.identityRef.storeId === current.identityRef.storeId && candidate.identityRef.identityId === current.identityRef.identityId && candidate.identityRef.did === current.identityRef.did && resolved.redirectUri, 'unsupported_sign_in');
      httpsUrl(resolved.redirectUri); check();
      return engine.startSignIn(session.subjectRef, { scopes: input.scopes, resource: route.resource, redirectUri: resolved.redirectUri, callbackMode: 'handoff', method: 'direct' });
    }
    if (input.action === 'account/collect') return engine.collectSignIn(input.transactionRef);
    const state = await engine.store.read(); const account = Object.values(state.grants).find(value => value.accountSlot === input.accountSlot) ?? Object.values(state.transactions).find(value => value.accountSlot === input.accountSlot);
    requirePap(account, 'reauthorization_required');
    if(input.action==='account/refresh') {
      const grant=state.grants[account.ref];requirePap(grant?.status==='active'&&grant.refreshToken,'reauthorization_required');
      const subject=state.subjects[grant.subjectRef];const company=subject&&state.companies[subject.companyRef];const slot=state.accountSlots[input.accountSlot];
      requirePap(subject&&company&&company.companyId===subject.companyId&&grant.issuer===company.issuer&&grant.clientId===this.binding?.clientId&&JSON.stringify(subject.binding)===JSON.stringify(this.binding)&&company.routes.some(route=>route.resource===grant.resource),'permission_denied');
      requirePap(slot&&!slot.signedOut&&slot.epoch===grant.accountEpoch,'reauthorization_required');
      const sessions=Object.values(state.sessions).filter(session=>session.connected&&session.accountSlot===input.accountSlot).map(session=>({ref:session.ref,generation:session.generation}));
      check();this.assertCurrentEngine(engine);await (await this.consumer()).assertActive();check();
      await engine.refreshAccountGrant(grant.ref);
      const current=await engine.store.read();check();this.assertCurrentEngine(engine);await (await this.consumer()).assertActive();check();this.assertCurrentEngine(engine);
      requirePap(current.accountSlots[input.accountSlot]?.epoch===slot.epoch&&!current.accountSlots[input.accountSlot]?.signedOut&&current.grants[grant.ref]?.status==='active','reauthorization_required');
      requirePap(current.companies[subject.companyRef]?.companyId===company.companyId&&current.companies[subject.companyRef]?.issuer===company.issuer&&sessions.every(session=>current.sessions[session.ref]?.connected&&current.sessions[session.ref]?.generation===session.generation&&current.sessions[session.ref]?.accountSlot===input.accountSlot),'state_conflict');
      return {status:'active'};
    }
    return engine.signOutAccount(account.subjectRef, input.accountSlot);
  }
}
export function apply(ctx: Context, config: PapPluginConfig = {}): PapService { return new PapService(ctx, config); }
