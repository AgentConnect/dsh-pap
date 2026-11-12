export { PapClient } from './client.js';
export { PapError } from './errors.js';
export type { PapErrorCode, PapAuthHint } from './errors.js';
export { PapDiscovery } from './discovery.js';
export { SafeHttpsTransport } from './network.js';
export type { SafeHttpsOptions } from './network.js';
export { ProtocolIdentityHost } from './protocol-adapter.js';
export type { ProtocolIdentityClient } from './protocol-adapter.js';
export type { Binding, Company, Operation, HttpTransport, HttpResponse } from './types.js';
export type { HostSecretStore, CallbackHandoff, PapIdentityHost, PapSigningLease, PapHostOptions } from './host.js';

export { DeviceCallbackHandoff } from './callback-handoff.js';
export type { DeviceManagementOperations, CallbackManagementOperation, CallbackRegistration, CallbackClaim, CallbackRegistrationResult, CallbackClaimResult, RegisterCallbackOperation, ClaimCallbackOperation } from './callback-handoff.js';
export { PapService } from './plugin.js';
export type { PapPluginConfig, PapHostServices } from './plugin.js';
export type { PapHostConsumer, PapManagementRequest, PapOperationRequest, PapOperationsClient, ProductResult } from './product-api.js';
export { FileSecretStore } from './file-secrets.js';
export { KeyringSecretStore } from './keyring.js';
/** Root Loader row declares the browser client; the capability-owning service is ./plugin. */
export const name = '@awiki/dsh-pap';
export const inject: string[] = [];
export function apply(_context: import('@deepseek-ai/cordis').Context): void {}
