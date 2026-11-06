import type { AsMetadata, Binding, Company, IdentityRef, KeyRef, KeyScope, PublicJwk } from './types.js';
import type { CredentialObservation } from './credential-history.js';

/** Same-process Host capability. Never expose through Remote or tools. */
export interface PapSigningLease {
  /** Actual C target object, Host-only; never serialized or accepted from user input. */
  readonly targetRef?: object;
  getOAuthClientIdentity(): Promise<{ clientId: string; alg: string; kid: string; publicJwk?: PublicJwk; redirectUris?: string[] }>;
  createDelegatedKey(scope: KeyScope, operationId: string): Promise<KeyRef>;
  issuePapDelegation(key: KeyRef, scope: KeyScope, ttlSeconds: number): Promise<string>;
  signPapSessionRequest(input: { key: KeyRef; scope: KeyScope; delegation: string; clientId: string; sid: string; sub: string; agentId?: string; httpMethod: string; httpUri: string; accessToken?: string }): Promise<string>;
  createDpopKey(scope: KeyScope, operationId: string): Promise<KeyRef>;
  signDpopProof(input: { key: KeyRef; scope: KeyScope; httpMethod: string; httpUri: string; accessToken?: string; nonce?: string }): Promise<string>;
  signOAuthClientAssertion(): Promise<string>;
  retireTemporaryKey(key: KeyRef, scope: KeyScope): Promise<void>;
  assertActive(): Promise<void>;
}
export interface PapIdentityHost {
  dispose?(): void;
  /** Host must independently verify sources and enforce preapproved target policy. */
  acquire(binding: Binding, company: Company, purpose: 'pap_session' | 'pap_account', resource: string, destination?: string, requestedScopes?: readonly string[]): Promise<PapSigningLease>;
}
export interface HostSecretStore {
  getEncryptionKey(namespace: string): Promise<Uint8Array | undefined>;
  /** Atomic across Host processes; key is 32 random bytes and never persisted in the PAP directory. */
  getOrCreateEncryptionKey(namespace: string): Promise<Uint8Array>;
}
export interface CallbackHandoff {
  /** Authenticated device-bound registration; the service receives no PKCE verifier or PAP IDs. */
  register(input: { transactionId: string; issuer: string; clientId: string; redirectUri: string; state: string; expiresAt: number }): Promise<{ callbackRef: string }>;
  collect(callbackRef: string): Promise<{ state?: string; iss?: string; code?: string; error?: string }>;
  cancel?(callbackRef: string): Promise<void>;
}
export interface PapHostOptions {
  binding: Binding; identityHost: PapIdentityHost; secretStore: HostSecretStore; stateRoot: string;
  callbackHandoff?: CallbackHandoff; clock?: () => number;
  /** Maximum local inline cooldown wait, 0..5000ms; this never shortens the persisted server fence. */
  inlineCooldownWaitMs?: number;
  /** Host-only observer, must not throw or log; used for private response-redaction history. */
  observeCredentials?: (credentials: CredentialObservation) => void;
}
export type { AsMetadata, IdentityRef };
