import { Service, type Context } from '@deepseek-ai/cordis';
import { isAbsolute, join, resolve } from 'node:path';
import { mkdir, open, readFile, rename, rm } from 'node:fs/promises';
import type { Binding, HttpTransport, IdentityRef, PapState, ProductOperationApproval, Operation } from './types.js';
import type { CallbackHandoff, HostSecretStore } from './host.js';
import { PapClient } from './client.js';
import { ProtocolIdentityHost, type ProtocolIdentityClient } from './protocol-adapter.js';
import { SafeHttpsTransport } from './network.js';
import { PapError, requirePap, type PapAuthHint } from './errors.js';
import { KeyringSecretStore } from './keyring.js';
import { FileSecretStore, syncDirectory } from './file-secrets.js';
import { DeviceCallbackHandoff } from './callback-handoff.js';
import { PAP_CONSUMER, PAP_MANAGER, PAP_TOOLS, identityReferenceSchema, managementRequestSchema, operationRequestSchema, type PapHostConsumer, type PapManagementRequest, type ProductResult, type PapRequestTrace } from './product-api.js';
import { assertApproval, findOperation, prepareOperation, prepareDiscoveredOperation, privateValues, publicOperations, publicResponse, sanitizePublicValue } from './product-operations.js';
import { httpsUrl, id, sha256 } from './util.js';
import { strictJson } from './strict-json.js';
import { CredentialHistory } from './credential-history.js';
import { PapConsentPending, waitForConsent, type DomainOperationConsumer, type ConsentDecision } from './domain-consent.js';
import { PapPolicyTargets, classifyRoute, type PolicyHost, type PolicyAdmission } from './protocol-policy.js';

export interface PapPluginConfig {
  /** Exact installed package names approved by the Host for business UI integration. */
  businessConsumers?: readonly string[];
  /** Explicit opt-in; loading an unconfigured bundle performs no discovery or signing. */
  enabled?: boolean;
  /** Host-approved domain mode; connects signed-out read operations without per-domain settings. */
  autoConnect?: boolean;
  approvalWaitMs?: number;
  approvalPollMs?: number;
  stateRoot?: string;
  keyringService?: string;
  /** Explicit local storage selection; no automatic fallback between backends. */
  secretStore?: 'keyring' | 'local-file';
  /** Absolute key directory, separate from stateRoot. Required for local-file. */
  secretsRoot?: string;
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
    if (error instanceof PapError) return { ok: false, error: { code: error.code, ...(error.retryAfterSeconds === undefined ? {} : { retryAfterSeconds: error.retryAfterSeconds }), ...(error instanceof PapConsentPending ? {approval:{requestId:error.requestId,presentation:'dialog' as const,status:'pending' as const}} : {}) } };
    const code = (error as { code?: unknown } | null)?.code;
    if(typeof code==='string' && ['protocol_policy_unavailable','protocol_policy_changed','protocol_policy_target_revoked','protocol_policy_invalid_target','protocol_policy_invalid_operation'].includes(code))return {ok:false,error:{code}};
    if (typeof code === 'string' && ['domain_access_disabled','domain_access_expired','published_identity_required','default_identity_required','default_identity_changed','scope_authorization_required','request_previously_denied','once_authorization_required','grant_inactive','grant_conflict','operation_mismatch','operation_result_unknown','callback_not_ready','callback_claimed','callback_expired','callback_conflict','callback_unavailable','callback_limit','management_auth_required','not_published','client_id_conflict','idempotency_conflict','provider_unavailable','provider_disposed','consumer_forbidden'].includes(code)) return { ok: false, error: { code } };
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
  private domainFlight: Promise<unknown> = Promise.resolve();
  private readonly consentController = new AbortController();
  private readonly pendingConsents = new Map<string, ConsentDecision>();
  /** Bound once to this installed plugin; pending requests retain their owning facade across retries. */
  private operationConsumer?: DomainOperationConsumer;
  private policyTargets?: PapPolicyTargets;
  private readonly approvalWaitMs: number;
  private readonly approvalPollMs: number;
  constructor(ctx: Context, private config: PapPluginConfig = {}) {
    super(ctx, 'pap');
    this.approvalWaitMs = config.approvalWaitMs ?? 120000;
    this.approvalPollMs = config.approvalPollMs ?? 1000;
    requirePap(Number.isSafeInteger(this.approvalWaitMs) && this.approvalWaitMs >= 0 && this.approvalWaitMs <= 600000
      && Number.isSafeInteger(this.approvalPollMs) && this.approvalPollMs >= 10 && this.approvalPollMs <= 10000, 'not_configured');
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
    if (this.config.autoConnect) return;
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
      await syncDirectory(root);
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
      requirePap(this.config.secretStore === undefined || ['keyring', 'local-file'].includes(this.config.secretStore), 'not_configured');
      let protectedSecrets: HostSecretStore;
      if (this.config.secretStore === 'local-file') {
        requirePap(typeof this.config.secretsRoot === 'string' && isAbsolute(this.config.secretsRoot), 'not_configured');
        protectedSecrets = new FileSecretStore(this.config.secretsRoot);
      } else if (this.config.secretStore === 'keyring') {
        protectedSecrets = new KeyringSecretStore(this.config.keyringService ?? 'org.agentconnect.dsh-pap', join(this.config.stateRoot!, 'keyring-locks'));
      } else {
        protectedSecrets = host?.secrets ?? new KeyringSecretStore(this.config.keyringService ?? 'org.agentconnect.dsh-pap', join(this.config.stateRoot!, 'keyring-locks'));
      }
      if (protectedSecrets instanceof FileSecretStore) protectedSecrets.assertSeparateFrom(this.config.stateRoot!);
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
      next = new PapClient({ stateRoot: join(this.config.stateRoot!, `identity-${sha256(JSON.stringify(binding))}`), binding, identityHost: protocolHost, secretStore: secrets, callbackHandoff: handoff, observeCredentials: credentials => this.credentialHistory.observe(credentials) }, host?.transport ?? new SafeHttpsTransport({maxBytes:this.config.businessConsumers?.length ? 8*1024*1024 : 1024*1024}));
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
    if (this.stopped) return {ok:false,error:{code:!result.ok && ['request_uncertain','operation_result_unknown'].includes(result.error.code) ? result.error.code : 'disconnected'}};
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
  private protocolPolicy(): PapPolicyTargets {
    if (!this.policyTargets) {
      const host=this.installedContext.get('anpIdentity') as Partial<PolicyHost>;
      requirePap(typeof host.bindProtocolPolicy==='function','protocol_policy_required');
      this.policyTargets=new PapPolicyTargets(host.bindProtocolPolicy(this.installedContext,'pap'));
    }
    return this.policyTargets;
  }
  private async policyAdmission(state:PapState,reference:string,url?:string):Promise<PolicyAdmission> {
    const {company,route}=findOperation(state,reference), targets=this.protocolPolicy();
    const classification=classifyRoute(targets.policy,route);
    if(state.product?.operations[reference]?.scopes.length)classification.extraPermissions=true;
    return targets.policy.evaluate(targets.target(company),{url:url??route.template,...classification});
  }
  private async catalog(enabledOnly: boolean, check: () => void): Promise<object[]> {
    check(); const engine = await this.engine(); const state = await engine.store.read();
    check(); this.assertCurrentEngine(engine); await (await this.consumer()).assertActive(); check(); this.assertCurrentEngine(engine);
    if(!this.config.autoConnect)return this.publicValue(state,publicOperations(state, enabledOnly)) as object[];
    const operations=[];
    for(const raw of publicOperations(state)) {
      const entry=raw as {operationRef:string;blocked:boolean};
      const {company}=findOperation(state,entry.operationRef);
      if(!company.discoveryOrigin){
        // An unrelated legacy cache cannot make a newly discovered domain's connection fail.
        if(!enabledOnly)operations.push({...entry,enabled:false,requiresApproval:false,permission:'rediscovery-required',unavailableReason:'protocol_rediscovery_required'});
        continue;
      }
      const admission=await this.policyAdmission(state,entry.operationRef);
      const {route}=findOperation(state,entry.operationRef);
      const effect=classifyRoute(this.protocolPolicy().policy,route).effect;
      const blocked=entry.blocked||admission.decision==='deny';
      if(!enabledOnly||!blocked&&admission.decision==='allow')operations.push({...entry,effect,blocked,enabled:!blocked&&admission.decision==='allow',requiresApproval:admission.decision==='ask',permission:admission.decision});
      check();this.assertCurrentEngine(engine);
    }
    return this.publicValue(state,operations) as object[];
  }
  async start(): Promise<void> { await this.ready; }
  stop(): void { if (this.stopped) return; this.stopped = true; this.consentController.abort(); this.policyTargets?.dispose(); this.client?.close(); this.hostConsumer?.dispose(); this.credentialHistory.dispose(); }
  async getStatus(includeManagementHints = false, businessMetadata = false): Promise<object> {
    await this.ready;
    requirePap(!this.stopped, 'disconnected');
    if (this.config.enabled !== true) return { state: 'disabled' };
    if ((includeManagementHints || businessMetadata) && this.config.autoConnect && !this.client) {
      // Serialize local recovery with domain connects and other status readers.
      const restore = this.domainFlight.then(async () => {
        if (this.client) return;
        requirePap(!this.stopped,'disconnected');
        // Restore lifecycle state without discovering, reconnecting or enabling a Company.
        const host=this.installedContext.get('anpIdentity') as {
          resolveDomainAccess(context:Context,profile:'pap_session'):Promise<{identityRef:IdentityRef;policyRef:string;stateRoot:string;secretsRoot:string;secretStore:'keyring'|'local-file'}>;
        };
        const binding=await host.resolveDomainAccess(this.installedContext,'pap_session');
        requirePap(!this.stopped,'disconnected');
        this.config={...this.config,identityRef:binding.identityRef,policyRef:binding.policyRef,
          stateRoot:binding.stateRoot,secretStore:binding.secretStore,secretsRoot:binding.secretsRoot};
        await this.select(binding.identityRef,false);
      });
      this.domainFlight = restore.catch(() => undefined);
      await restore;
    }
    if (this.config.autoConnect && this.selected) {
      const host=this.installedContext.get('anpIdentity') as {resolveDomainAccess(context:Context,profile:'pap_session'):Promise<{identityRef:IdentityRef;policyRef:string}>};
      const current=await host.resolveDomainAccess(this.installedContext,'pap_session');
      requirePap(JSON.stringify(current.identityRef)===JSON.stringify(this.selected)&&current.policyRef===this.config.policyRef,'permission_denied');
    }
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
      companies: Object.values(state.companies).map(value => ({ companyRef: value.ref, ...(businessMetadata?{domain:value.domain,companyId:value.companyId}:{}), name: value.name, authMode: value.authMode, scopes: value.scopes })),
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
  acquireTools(context: Context): import('./product-api.js').PapOperationsClient {
    return this.operationsFor(context, PAP_TOOLS, false);
  }
  /** Business cards share the same identity, policy and once-approval dispatch as tools. */
  acquireBusiness(context: Context): import('./product-api.js').PapOperationsClient {
    for (const name of this.config.businessConsumers ?? []) {
      if ([PAP_CONSUMER,PAP_MANAGER,PAP_TOOLS].includes(name)) continue;
      try { this.assertInstalled(context,name); } catch { continue; }
      return this.operationsFor(context,name,true);
    }
    throw new PapError('permission_denied');
  }
  private operationsFor(context: Context, consumer: string, business: boolean): import('./product-api.js').PapOperationsClient {
    const check = () => {
      this.assertInstalled(context, consumer);
      if (business) requirePap(this.config.businessConsumers?.includes(consumer), 'permission_denied');
    };
    check();
    return Object.freeze<import('./product-api.js').PapOperationsClient>({
      requestTimeoutMs: this.approvalWaitMs + 30000,
      connect: domain => this.runPublic(() => {
        const run = this.domainFlight.then(() => this.connectDomain(domain, check));
        this.domainFlight = run.catch(() => undefined);
        return run;
      }),
      status: () => this.runPublic(async () => { check(); const result = await this.getStatus(false,business); check(); return result; }),
      operations: () => this.runPublic(() => this.catalog(!this.config.autoConnect, check)),
      request: async (input, signal) => {
        const trace: PapRequestTrace = {phase:'prepare',businessRequest:'not_sent'};
        const result = await this.runPublic(async () => {
        check(); const parsed = operationRequestSchema.safeParse(input); requirePap(parsed.success, 'permission_denied');
        const engine = await this.engine(); const pin = this.credentialHistory.begin();
        try {
        const snapshot = await engine.store.read(); requirePap(snapshot.credentialVault?.completeness==='complete','credential_history_incomplete');
        const { route } = findOperation(snapshot, parsed.data.operationRef);
        const domain=this.config.autoConnect===true;
        const prepared = domain ? this.prepareDomainOperation(snapshot, parsed.data) : prepareOperation(snapshot, parsed.data);
        const admission=domain?await this.policyAdmission(snapshot,parsed.data.operationRef,prepared.operation.url):undefined;
        const effect=domain?classifyRoute(this.protocolPolicy().policy,route).effect:undefined;
        requirePap(admission?.decision!=='deny','protocol_permission_denied');
        const needsConsent=admission?.decision==='ask';
        const assertOperation = domain ? this.domainOperationFence(snapshot, parsed.data.operationRef, prepared.approval) : (state: PapState) => assertApproval(state, parsed.data.operationRef, prepared.approval);
        this.credentialHistory.restore(snapshot);
        for (const grant of Object.values(snapshot.grants)) { this.credentialHistory.rememberIfAbsent(grant.accessToken); if (grant.refreshToken) this.credentialHistory.rememberIfAbsent(grant.refreshToken); }
        const checkRequest = () => { check(); this.assertCurrentEngine(engine); };
        const assertPolicy=async()=>{
          if(!admission)return;
          checkRequest();await admission.assertActive();
          const host=this.installedContext.get('anpIdentity') as {resolveDomainAccess(context:Context,profile:'pap_session'):Promise<{identityRef:IdentityRef;policyRef:string}>};
          const binding=await host.resolveDomainAccess(this.installedContext,'pap_session');
          requirePap(JSON.stringify(binding.identityRef)===JSON.stringify(this.selected)&&binding.policyRef===this.config.policyRef,'permission_denied');
          await this.protocolPolicy().policy.assertNoDenial(new Request(prepared.operation.url,{method:prepared.operation.method,headers:prepared.operation.headers,body:prepared.operation.body,redirect:'manual',credentials:'omit'}));
          await admission.assertActive();checkRequest();
        };
        await assertPolicy();
        checkRequest(); this.credentialHistory.assertUsable();
        const sentSecrets = new Set(privateValues(snapshot));
        try {
          const dispatch = (assertConsent?: () => Promise<void>) => {
            trace.phase='identity';
            return engine.dispatchPap(prepared.approval.sessionRef, prepared.operation, { signal,
            observeBusiness: (event,status) => {
              trace.phase=event==='attempted'?'request':'response';
              trace.businessRequest=event==='attempted'?'unknown':'response_received';
              if(event==='attempted')delete trace.httpStatus;
              else if(status!==undefined)trace.httpStatus=status;
            },
            assertAllowed: state => { checkRequest(); this.credentialHistory.assertUsable(); assertOperation(state); },
            ...((admission||assertConsent)?{assertConsent:async()=>{await assertPolicy();await assertConsent?.();},singleOperation:needsConsent||!['GET','HEAD'].includes(route.method)||effect!=='read'}:{}),
            captureSecrets: (values, credentials) => { for (const value of values) sentSecrets.add(value); if (credentials) this.credentialHistory.observe(credentials); this.credentialHistory.assertUsable(); },
          });
          };
          if(needsConsent)trace.phase='approval';
          const response = needsConsent ? await this.withDomainConsent(prepared.operation, signal, checkRequest, dispatch,admission!.version) : await dispatch();
          await assertPolicy();
          checkRequest(); await (await this.consumer()).assertActive(); checkRequest();
          const current = await engine.store.read(); assertOperation(current);
          this.credentialHistory.restore(current);
          const secrets = [...sentSecrets, ...privateValues(current), ...this.credentialHistory.values()];
          checkRequest(); await (await this.consumer()).assertActive(); checkRequest();
          this.authHints.delete(parsed.data.operationRef); return publicResponse(response, secrets, business ? 8*1024*1024 : 65536);
        } catch (error) {
          if (this.client === engine && !this.changing && error instanceof PapError && error.authHint) {
            if (this.authHints.size >= 32) this.authHints.delete(this.authHints.keys().next().value!);
            this.authHints.set(parsed.data.operationRef, error.authHint);
          }
          throw error;
        }
        } finally { this.credentialHistory.end(pin); }
        });
        return result.ok ? result : {...result,error:{...result.error,...trace}};
      },
    });
  }
  private prepareDomainOperation(state: PapState, input: import('./product-api.js').PapOperationRequest) {
    requirePap(!state.product?.disabled?.includes(input.operationRef), 'permission_denied');
    const { company, route } = findOperation(state, input.operationRef);
    const existing = state.product?.operations[input.operationRef];
    if (existing) assertApproval(state, input.operationRef, existing);
    const session = existing ? state.sessions[existing.sessionRef] : Object.values(state.sessions).find(value => value.connected && !value.accountSlot
      && state.subjects[value.subjectRef]?.companyRef === company.ref);
    requirePap(session?.connected, 'disconnected');
    const approval: ProductOperationApproval = existing ?? {companyRef:company.ref, method:route.method, template:route.template,
      resource:route.resource, sessionRef:session.ref, scopes:[], generation:state.generation};
    return prepareDiscoveredOperation(state, input, approval);
  }
  private domainOperationFence(snapshot: PapState, reference: string, approval: ProductOperationApproval): (state: PapState) => void {
    const original = findOperation(snapshot, reference);
    const permission = JSON.stringify(snapshot.product?.operations[reference] ?? null);
    const generation = snapshot.sessions[approval.sessionRef]!.generation;
    return state => {
      requirePap(!state.product?.disabled?.includes(reference), 'permission_denied');
      requirePap(JSON.stringify(state.product?.operations[reference] ?? null) === permission, 'state_conflict');
      const { company, route } = findOperation(state, reference);
      requirePap(company.metadataDigest === original.company.metadataDigest && route.method === approval.method && route.template === approval.template && route.resource === approval.resource, 'state_conflict');
      const session = state.sessions[approval.sessionRef];
      requirePap(session?.connected && session.generation === generation && state.subjects[session.subjectRef]?.companyRef === company.ref, 'disconnected');
    };
  }
  private async withDomainConsent<T>(operation: Operation, inputSignal: AbortSignal | undefined, check: () => void, effect: (assertActive: () => Promise<void>) => Promise<T>,policyVersion:number): Promise<T> {
    const identity = this.installedContext.get('anpIdentity') as {
      bindDomainOperationConsumer(context: Context): DomainOperationConsumer;
      resolveDomainAccess(context: Context, profile: 'pap_session'): Promise<{identityRef:IdentityRef;policyRef:string}>;
    };
    requirePap(typeof identity.bindDomainOperationConsumer === 'function', 'not_configured');
    const signal = AbortSignal.any([this.consentController.signal, ...(inputSignal ? [inputSignal] : [])]);
    const assertBinding = async () => {
      check(); requirePap(!signal.aborted, 'disconnected');
      const current = await identity.resolveDomainAccess(this.installedContext, 'pap_session');
      check(); requirePap(!signal.aborted && JSON.stringify(current.identityRef) === JSON.stringify(this.selected) && current.policyRef === this.config.policyRef, 'permission_denied');
    };
    await assertBinding();
    const consumer = this.operationConsumer ??= identity.bindDomainOperationConsumer(this.installedContext);
    const request = new Request(operation.url, {method:operation.method, headers:operation.headers, body:operation.body, signal, redirect:'manual', credentials:'omit'});
    const key = sha256(JSON.stringify([this.selected,this.config.policyRef,policyVersion,request.method,request.url,[...request.headers],operation.body ?? null]));
    const old = this.pendingConsents.get(key);
    let decision = old ? await consumer.status(old.id) : await consumer.request({requestId:id('pap-consent'),purpose:`PAP exact operation ${request.method} ${new URL(request.url).origin}; policy ${policyVersion}`,request:request.clone()});
    if (decision.status === 'pending') {
      this.pendingConsents.set(key, decision);
      try { decision = await waitForConsent(consumer,decision,signal,this.approvalWaitMs,this.approvalPollMs); }
      catch (error) {
        this.pendingConsents.delete(key);
        await consumer.cancel(decision.id,decision.version).catch(() => undefined);
        throw error;
      }
    }
    check(); requirePap(!signal.aborted, 'disconnected');
    if (decision.status !== 'pending') this.pendingConsents.delete(key);
    if (['denied','cancelled'].includes(decision.status)) throw new PapError('identity_authorization_denied');
    if (decision.status === 'expired') throw new PapError('identity_authorization_expired');
    if (decision.status === 'pending') throw new PapConsentPending(decision.id);
    requirePap(decision.status === 'approved' && decision.grantId, 'permission_denied');
    requirePap(decision.mode === 'once', 'permission_denied');
    return consumer.execute(decision.grantId,request,async assertActive => {
      const active = async () => { await assertBinding(); await assertActive(); check(); requirePap(!signal.aborted,'disconnected'); };
      await active(); const result = await effect(active); await active(); return result;
    });
  }
  private async connectDomain(domain: string, check: () => void): Promise<unknown> {
    await this.ready; check();
    requirePap(this.config.enabled === true && this.config.autoConnect === true, 'not_configured');
    requirePap(typeof domain === 'string' && domain.length > 0 && domain.length <= 253 && !/[/?#@\\\s]/.test(domain), 'unsafe_destination');
    const identity = this.installedContext.get('anpIdentity') as {
      resolveDomainAccess(context: Context, profile: 'pap_session'): Promise<{ identityRef: IdentityRef; policyRef: string; stateRoot: string; secretsRoot: string; secretStore: 'keyring' | 'local-file' }>;
    };
    requirePap(typeof identity.resolveDomainAccess === 'function', 'not_configured');
    const binding = await identity.resolveDomainAccess(this.installedContext, 'pap_session'); check();
    if (this.selected && (JSON.stringify(this.selected) !== JSON.stringify(binding.identityRef) || this.config.policyRef !== binding.policyRef)) {
      // A fresh explicit domain connect adopts the Host default. Old requests keep
      // their engine fence; no stored identities, sessions or credentials are erased.
      this.client?.close(); this.client = undefined;
      this.hostConsumer?.dispose(); this.hostConsumer = undefined;
      this.policyTargets?.dispose(); this.policyTargets = undefined;
      this.authHints.clear();
      for (const consent of this.pendingConsents.values()) {
        try { await this.operationConsumer?.cancel(consent.id, consent.version); }
        catch { /* A concurrent owner decision is authoritative; do not reuse it. */ }
      }
      this.pendingConsents.clear(); check();
    }
    if (!this.client) {
      // Local paths and policy references come exclusively from the identity Host.
      this.config = { ...this.config, identityRef: binding.identityRef, policyRef: binding.policyRef,
        stateRoot: binding.stateRoot, secretStore: binding.secretStore, secretsRoot: binding.secretsRoot };
      await this.select(binding.identityRef, false); check();
    }
    const engine = await this.engine();
    const company = await engine.resolvePapCompany(domain); check(); this.assertCurrentEngine(engine);
    const subject = await engine.getOrCreatePapUser(company.companyRef, 'regular', true); check();
    const snapshot = await engine.store.read(); check();
    this.protocolPolicy().target(snapshot.companies[company.companyRef]!);
    const previous = Object.values(snapshot.sessions).filter(session => session.subjectRef === subject.subjectRef && !session.accountSlot);
    // A disconnected session is an owner fence, not a connection failure to repair automatically.
    requirePap(!previous.length || previous.some(session => session.connected), 'disconnected');
    const session = previous.find(value => value.connected) ?? await engine.openPapSession(subject.subjectRef);
    check(); this.assertCurrentEngine(engine); await (await this.consumer()).assertActive(); check();
    const sessionRef = 'sessionRef' in session ? session.sessionRef : session.ref;
    await engine.store.transaction(state => {
      check(); this.assertCurrentEngine(engine);
      const storedSession = state.sessions[sessionRef]; requirePap(storedSession?.connected, 'disconnected');
      if (storedSession.autoReadConfigured) return; // Preserve explicit operation disables on repeated discovery.
      storedSession.autoReadConfigured = true;
      const current = state.companies[company.companyRef]; requirePap(current, 'discovery_failed');
      for (const raw of publicOperations(state)) {
        const operation = raw as { companyRef: string; operationRef: string; method: string };
        if (operation.companyRef !== company.companyRef || !['GET', 'HEAD'].includes(operation.method)) continue;
        const { route } = findOperation(state, operation.operationRef);
        if (route.requiresConsent) continue;
        state.product ??= { operations: {} };
        state.product.operations[operation.operationRef] = { companyRef: current.ref, method: route.method, template: route.template,
          resource: route.resource, sessionRef, scopes: [], generation: state.generation + 1 };
      }
    });
    check(); this.assertCurrentEngine(engine);
    return this.publicValue(await engine.store.read(), { company, operations: (await this.catalog(true, check) as { companyRef: string; effect: string }[]).filter(operation => operation.companyRef === company.companyRef && operation.effect==='read') });
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
    if (input.action === 'operation/disable') { await engine.store.transaction(state => { check(); state.product ??= {operations:{}}; delete state.product.operations[input.operationRef]; state.product.disabled = [...new Set([...(state.product.disabled ?? []), input.operationRef])]; }); return null; }
    if (input.action === 'operation/enable') return engine.store.transaction(state => {
      check(); const { company, route } = findOperation(state, input.operationRef); const session = state.sessions[input.sessionRef];
      requirePap(session?.connected && state.subjects[session.subjectRef]?.companyRef === company.ref, 'permission_denied');
      const scopes = [...new Set(input.scopes ?? [])].sort();
      requirePap(scopes.every(scope => company.scopes.includes(scope)) && (session.accountSlot || scopes.length === 0), 'insufficient_scope');
      state.product ??= { operations: {} }; state.product.disabled = state.product.disabled?.filter(reference => reference !== input.operationRef); state.product.operations[input.operationRef] = { companyRef: company.ref, method: route.method, template: route.template, resource: route.resource, sessionRef: input.sessionRef, scopes, generation: state.generation + 1 };
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
