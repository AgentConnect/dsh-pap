export type JsonObject = Record<string, unknown>;
export interface IdentityRef { readonly storeId: string; readonly identityId: string; readonly did: string }
export interface Binding { readonly identityRef: IdentityRef; readonly ownerRef: string; readonly clientId: string }
export interface PublicJwk { kty: 'EC'; crv: 'P-256'; x: string; y: string }
export interface KeyScope { owner: string; company_id: string; user_id: string; account_slot?: string }
export interface KeyRef { handle: string; purpose: 'pap_session' | 'pap_dpop'; generation: number; public_jwk: PublicJwk; thumbprint: string }
export interface Route { method: string; template: string; resource: string }
export interface AsMetadata {
  issuer: string; authorization_endpoint?: string; token_endpoint: string; revocation_endpoint?: string;
  grant_types_supported: string[]; token_endpoint_auth_methods_supported?: string[];
  dpop_signing_alg_values_supported?: string[]; protected_resources: string[];
  code_challenge_methods_supported?: string[];
}
export interface Company {
  ref: string; domain: string; name: string; companyId: string; issuer?: string; authDisabled: boolean;
  authMode: 'no_as' | 'account' | 'disabled'; metadata?: AsMetadata;
  routes: Route[]; scopes: string[]; metadataDigest: string; expiresAt: number; generation: number;
  sources: { url: string; digest: string }[];
}
export interface Subject { ref: string; companyRef: string; companyId: string; binding: Binding; mode: 'regular' | 'anonymous'; userId: string; agentId?: string }
export interface Session { ref: string; subjectRef: string; sid: string; accountSlot?: string; generation: number; connected: boolean }
export interface Delegation { subjectRef: string; key: KeyRef; compact: string; expiresAt: number; generation: number }
export interface Grant {
  ref: string; subjectRef: string; accountSlot: string; issuer: string; clientId: string; resource: string; scope: string[];
  accessToken: string; refreshToken?: string; tokenType: 'Bearer' | 'DPoP'; dpopKey?: KeyRef;
  expiresAt?: number; usableUntil: number; generation: number; accountEpoch: number;
  status: 'active' | 'refreshing' | 'uncertain' | 'reauthorization_required' | 'revocation_pending' | 'signed_out';
}
export interface AuthTransaction {
  ref: string; subjectRef: string; accountSlot: string; issuer: string; clientId: string;
  redirectUri: string; state: string; verifier: string; resource: string; scope: string[];
  expiresAt: number; accountEpoch: number; exchangeInFlight?: boolean; status: 'pending' | 'exchanging' | 'consumed' | 'failed' | 'cancelled'; dpopKey?: KeyRef;
  callbackRef?: string;
}
export interface PapState {
  schemaVersion: 1; generation: number;
  companies: Record<string, Company>; subjects: Record<string, Subject>; sessions: Record<string, Session>;
  delegations: Record<string, Delegation>; grants: Record<string, Grant>; transactions: Record<string, AuthTransaction>;
  nonces: Record<string, string>;
  cooldowns: Record<string, { notBeforeMs: string; generation: number }>;
  accountSlots: Record<string, { subjectRef: string; epoch: number; signedOut: boolean }>;
  delegationAttempts: Record<string, { sequence: number; status: 'reserved' | 'issued' | 'failed' }>;
  retirements: Record<string, { subjectRef: string; key: KeyRef }>;
}
export interface Operation { url: string; method?: string; headers?: Record<string, string>; body?: string; resource?: string; scopes?: string[]; idempotencyKey?: string }
export interface HttpResponse { status: number; headers: Record<string, string>; body: Uint8Array; url: string }
export interface HttpTransport { request(url: string, options?: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal }): Promise<HttpResponse> }
