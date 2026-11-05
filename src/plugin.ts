import { Service, type Context } from '@deepseek-ai/cordis';
import { isAbsolute } from 'node:path';
import type { Binding, HttpTransport } from './types.js';
import type { CallbackHandoff, HostSecretStore } from './host.js';
import { PapClient } from './client.js';
import { ProtocolIdentityHost, type ProtocolIdentityClient } from './protocol-adapter.js';
import { SafeHttpsTransport } from './network.js';
import { PapError, requirePap } from './errors.js';

export interface PapPluginConfig {
  stateRoot: string;
  binding: Binding;
  /** Explicit approved C management policy, never accepted from Remote/LLM input. */
  policyRef: string;
}
/** Installed by the host secrets/handoff provider, not browser code or consumer JSON. */
export interface PapHostServices { secrets: HostSecretStore; callbackHandoff?: CallbackHandoff; transport?: HttpTransport }
declare module '@deepseek-ai/cordis' {
  interface Context { pap: PapService; papHost: PapHostServices }
}
export const name = '@agentconnect/dsh-pap';
export const inject = ['anpIdentity', 'papHost'];

/** DSH Host service. The engine and all callbacks remain in the same-process boundary. */
export class PapService extends Service {
  readonly engine: PapClient;
  constructor(ctx: Context, config: PapPluginConfig) {
    super(ctx, 'pap');
    requirePap(isAbsolute(config.stateRoot) && typeof config.policyRef === 'string' && config.policyRef.length > 0, 'permission_denied');
    const identity = ctx.get('anpIdentity') as { bindProtocolConsumer?: (context: Context) => ProtocolIdentityClient } | undefined;
    const host = ctx.get('papHost') as PapHostServices | undefined;
    requirePap(typeof identity?.bindProtocolConsumer === 'function' && host?.secrets, 'permission_denied');
    const protocol = identity.bindProtocolConsumer(ctx);
    this.engine = new PapClient({ stateRoot: config.stateRoot, binding: config.binding, identityHost: new ProtocolIdentityHost(protocol, config.policyRef), secretStore: host.secrets, callbackHandoff: host.callbackHandoff }, host.transport ?? new SafeHttpsTransport());
  }
  stop(): void { this.engine.close(); }
  async start(): Promise<void> { await this.engine.recover(); }
  /** Safe status can cross a user-authenticated management channel. No dispatch or signer endpoint is registered. */
  async getStatus(): ReturnType<PapClient['getPapStatus']> { return this.engine.getPapStatus(); }
}
export function apply(ctx: Context, config: PapPluginConfig): PapService { return new PapService(ctx, config); }

export interface UserManagementContext { assertAuthorizedUserAction(): void }
/** Explicit user UI boundary. Authorization URLs must go to user UI, never model tool output. */
export class PapUserManagement {
  constructor(private readonly engine: PapClient, private readonly context: UserManagementContext) {}
  private check(): void { requirePap(typeof this.context.assertAuthorizedUserAction === 'function', 'permission_denied'); this.context.assertAuthorizedUserAction(); }
  status(): ReturnType<PapClient['getPapStatus']> { this.check(); return this.engine.getPapStatus(); }
  discover(domain: string): ReturnType<PapClient['resolvePapCompany']> { this.check(); return this.engine.resolvePapCompany(domain); }
  createUser(companyRef: string, mode?: 'regular' | 'anonymous'): ReturnType<PapClient['getOrCreatePapUser']> { this.check(); return this.engine.getOrCreatePapUser(companyRef, mode); }
  openSession(subjectRef: string, accountSlot?: string): ReturnType<PapClient['openPapSession']> { this.check(); return this.engine.openPapSession(subjectRef, accountSlot); }
  signIn(subjectRef: string, input: Parameters<PapClient['startSignIn']>[1]): ReturnType<PapClient['startSignIn']> { this.check(); return this.engine.startSignIn(subjectRef, input); }
  collectSignIn(transactionRef: string): ReturnType<PapClient['collectSignIn']> { this.check(); return this.engine.collectSignIn(transactionRef); }
  signOut(subjectRef: string, accountSlot: string): ReturnType<PapClient['signOutAccount']> { this.check(); return this.engine.signOutAccount(subjectRef, accountSlot); }
  disconnect(sessionRef: string): Promise<void> { this.check(); return this.engine.disconnectPap(sessionRef); }
}
