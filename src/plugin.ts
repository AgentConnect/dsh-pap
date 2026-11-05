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
import { assertApproval, findOperation, prepareOperation, publicOperations, publicResponse } from './product-operations.js';
import { httpsUrl, id, sha256 } from './util.js';
import { strictJson } from './strict-json.js';

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
  private changing = false;
  constructor(ctx: Context, private readonly config: PapPluginConfig = {}) {
    super(ctx, 'pap');
    // Cordis service access can associate this.ctx with a caller. C must always
    // receive the original installed F Context, never the manager/tool caller.
    this.installedContext = ctx;
    this.ready = Promise.resolve().then(() => this.restore());
  }
  private assertInstalled(context: Context, expected: string): void {
    requirePap(!this.stopped, 'disconnected');
    const loader = this.installedContext.get('loader') as { entries?: () => Iterable<InstalledEntry> } | undefined;
    const entry = loader?.entries && [...loader.entries()].find(value => fiberOf(value.fiber) === fiberOf(context.fiber));
    requirePap(entry && !entry.disabled && entry.options.name === expected && entry.fiber && [1,2].includes(entry.fiber.state), 'permission_denied');
  }
  private async consumer(): Promise<PapHostConsumer> {
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
        await consumer.assertActive(); const state = await next!.store.read();
        const tx = transactionId ? state.transactions[transactionId] : Object.values(state.transactions).find(value => value.callbackRef === callbackRef);
        requirePap(tx && tx.status === 'pending' && tx.expiresAt > Date.now(), 'invalid_authorization_response');
        const subject = state.subjects[tx.subjectRef]; const company = subject && state.companies[subject.companyRef];
        requirePap(company && company.issuer === tx.issuer && tx.clientId === binding.clientId, 'permission_denied');
        const target = await protocolHost.acquire(binding, company, 'pap_account', tx.resource, undefined, tx.scope);
        requirePap(target.targetRef, 'permission_denied');
        return consumer.callbackManagementFor({ identityRef: reference, policyRef: this.config.policyRef!, targetRef: target.targetRef });
      };
      const handoff: CallbackHandoff = {
        register: async input => { const driver = await management(input.transactionId); try { return await new DeviceCallbackHandoff(driver).register(input); } finally { driver.dispose(); } },
        collect: async callbackRef => { const driver = await management(undefined, callbackRef); try { return await new DeviceCallbackHandoff(driver).collect(callbackRef); } finally { driver.dispose(); } },
      };
      next = new PapClient({ stateRoot: join(this.config.stateRoot!, `identity-${sha256(JSON.stringify(binding))}`), binding, identityHost: protocolHost, secretStore: secrets, callbackHandoff: handoff }, host?.transport ?? new SafeHttpsTransport());
      await next.recover(); await consumer.assertActive(); requirePap(!this.stopped, 'disconnected');
      if (persist) await this.persistSelection(reference);
      this.client?.close(); this.authHints.clear(); this.client = next; this.binding = binding; this.selected = structuredClone(reference); this.lastError = undefined;
    } catch (error) { next?.close(); this.lastError = error instanceof PapError ? error.code : 'permission_denied'; throw error; }
    finally { this.changing = false; }
  }
  private async engine(): Promise<PapClient> {
    await this.ready; requirePap(!this.stopped, 'disconnected'); requirePap(this.client, 'not_configured'); await (await this.consumer()).assertActive(); return this.client;
  }
  async start(): Promise<void> { await this.ready; }
  stop(): void { this.stopped = true; this.client?.close(); this.hostConsumer?.dispose(); }
  async getStatus(includeManagementHints = false): Promise<object> {
    await this.ready;
    if (this.config.enabled !== true) return { state: 'disabled' };
    if (!this.client) return { state: this.lastError === 'credential_unavailable' ? 'credential_unavailable' : 'unconfigured', ...(this.lastError ? { error: this.lastError } : {}) };
    await (await this.consumer()).assertActive();
    const state = await this.client.store.read();
    return { state: 'ready', identity: this.selected, supportedSignIn: ['direct'],
      ...(includeManagementHints ? { authenticationHints: [...this.authHints].map(([operationRef, hint]) => ({ operationRef, ...hint })) } : {}),
      companies: Object.values(state.companies).map(value => ({ companyRef: value.ref, name: value.name, authMode: value.authMode, scopes: value.scopes })),
      sessions: Object.values(state.sessions).map(value => ({ sessionRef: value.ref, ...(state.subjects[value.subjectRef] ? { companyRef: state.subjects[value.subjectRef]!.companyRef } : {}), connected: value.connected, account: Boolean(value.accountSlot), ...(value.accountSlot ? { accountSlot: value.accountSlot } : {}) })),
      accounts: Object.values(state.grants).map(value => ({ accountSlot: value.accountSlot, status: value.status, scopes: value.scope })),
    };
  }
  /** The installed user-only Typert manager receives the management facade. */
  acquireManagement(context: Context): { status(): Promise<ProductResult>; operations(): Promise<ProductResult>; execute(input: unknown): Promise<ProductResult> } {
    this.assertInstalled(context, PAP_MANAGER); const check = () => this.assertInstalled(context, PAP_MANAGER);
    return Object.freeze({
      status: () => publicResult(async () => { check(); return this.getStatus(true); }),
      operations: () => publicResult(async () => { check(); return publicOperations(await (await this.engine()).store.read()); }),
      execute: input => publicResult(async () => { check(); const parsed = managementRequestSchema.safeParse(input); requirePap(parsed.success, 'permission_denied'); return this.manage(parsed.data, check); }),
    });
  }
  /** Agent capability contains only approved local operation references. */
  acquireTools(context: Context): { status(): Promise<ProductResult>; operations(): Promise<ProductResult>; request(input: unknown, signal?: AbortSignal): Promise<ProductResult> } {
    this.assertInstalled(context, PAP_TOOLS); const check = () => this.assertInstalled(context, PAP_TOOLS);
    return Object.freeze({
      status: () => publicResult(async () => { check(); return this.getStatus(); }),
      operations: () => publicResult(async () => { check(); return publicOperations(await (await this.engine()).store.read(), true); }),
      request: (input, signal) => publicResult(async () => {
        check(); const parsed = operationRequestSchema.safeParse(input); requirePap(parsed.success, 'permission_denied');
        const engine = await this.engine(); const prepared = prepareOperation(await engine.store.read(), parsed.data);
        try {
          const response = await engine.dispatchPap(prepared.approval.sessionRef, prepared.operation, { signal, assertAllowed: state => { check(); assertApproval(state, parsed.data.operationRef, prepared.approval); } });
          this.authHints.delete(parsed.data.operationRef); return publicResponse(response);
        } catch (error) {
          if (error instanceof PapError && error.authHint) {
            if (this.authHints.size >= 32) this.authHints.delete(this.authHints.keys().next().value!);
            this.authHints.set(parsed.data.operationRef, error.authHint);
          }
          throw error;
        }
      }),
    });
  }
  private async manage(input: PapManagementRequest, check: () => void): Promise<unknown> {
    await this.ready; check();
    if (input.action === 'identity/select') { await this.select(input.reference, true); check(); return this.getStatus(); }
    const engine = await this.engine(); check();
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
    requirePap(account, 'reauthorization_required'); return engine.signOutAccount(account.subjectRef, input.accountSlot);
  }
}
export function apply(ctx: Context, config: PapPluginConfig = {}): PapService { return new PapService(ctx, config); }
