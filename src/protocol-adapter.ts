import type { PapIdentityHost, PapSigningLease } from './host.js';
import type { Binding, Company, KeyRef, KeyScope, PublicJwk } from './types.js';
import { requirePap } from './errors.js';
import { htu } from './util.js';

/** Structural subset of C's real ./protocol-client API. No native or generic signer fallback. */
export interface ProtocolKeyReference { keyRef: object; handle: string; purpose: 'pap_session' | 'pap_dpop'; generation: number; publicJwk: PublicJwk; thumbprint: string }
export interface ProtocolSignerLease {
  readonly targetRef: object;
  getOAuthClientIdentity(): Promise<{ clientId: string; keyId: string; algorithm: 'ES256'; publicJwk: PublicJwk; redirectUris?: string[] }>;
  assertActive(): Promise<void>;
  signOAuthClientAssertion(targetRef: object): Promise<string>;
  bindPapScope(input: { userId: string; accountSlot?: string }): object;
  createDelegatedKey(scopeRef: object, operationId: string): Promise<ProtocolKeyReference>;
  createDpopKey(scopeRef: object, operationId: string): Promise<ProtocolKeyReference>;
  restorePapKey(scopeRef: object, input: { handle: string; generation: number; purpose: 'pap_session' | 'pap_dpop' }): Promise<ProtocolKeyReference>;
  issuePapDelegation(scopeRef: object, input: { keyRef: object; ttlSeconds: number }): Promise<string>;
  signPapSessionRequest(scopeRef: object, input: { keyRef: object; delegation: string; clientId: string; sid: string; sub: string; agentId?: string; httpMethod: string; httpUri: string; accessToken?: string }): Promise<string>;
  signDpopProof(scopeRef: object, input: { keyRef: object; httpMethod: string; httpUri: string; accessToken?: string; nonce?: string }): Promise<string>;
  retireTemporaryKey(scopeRef: object, keyRef: object): Promise<void>;
  dispose(): void;
}
export interface ProtocolIdentityClient {
  registerValidatedTarget(input: { identityRef: Binding['identityRef']; policyRef: string; discovery: {
    profile: 'pap_session' | 'pap_account'; issuer: string; resource: string; tokenEndpoint?: string; revocationEndpoint?: string;
    companyId: string; metadataDigest: string; expiresAt: number; allowedEndpoints?: string[];
    sources: { resource: string; authorizationServer: string };
  }; requestedScopes: string[] }): Promise<ProtocolSignerLease>;
}
const serializable = (key: ProtocolKeyReference): KeyRef => ({ handle: key.handle, purpose: key.purpose, generation: key.generation, public_jwk: key.publicJwk, thumbprint: key.thumbprint });

/** Bind to C from the installed Host Context; persist only the native handle and public descriptor. */
export class ProtocolIdentityHost implements PapIdentityHost {
  private readonly rawLeases = new Set<ProtocolSignerLease>();
  private readonly leases = new Map<string, PapSigningLease>();
  constructor(private readonly client: ProtocolIdentityClient, private readonly policyRef: string) {}
  dispose(): void { for (const lease of this.rawLeases) lease.dispose(); this.rawLeases.clear(); this.leases.clear(); }
  async acquire(binding: Binding, company: Company, purpose: 'pap_session' | 'pap_account', resource: string, destination?: string, requestedScopes: readonly string[] = []): Promise<PapSigningLease> {
    const key = JSON.stringify([binding.identityRef, company.ref, company.generation, purpose, resource, destination, [...requestedScopes].sort()]);
    const existing = this.leases.get(key); if (existing) { await existing.assertActive(); return existing; }
    const discoveryUrl = company.sources[0]!.url;
    const raw = await this.client.registerValidatedTarget({ identityRef: binding.identityRef, policyRef: this.policyRef, discovery: {
      profile: purpose, issuer: company.issuer ?? company.companyId, companyId: company.companyId, resource,
      tokenEndpoint: company.metadata?.token_endpoint, revocationEndpoint: company.metadata?.revocation_endpoint,
      metadataDigest: company.metadataDigest, expiresAt: company.expiresAt,
      // Dynamic path parameters are authorized by registering the exact operation URL below.
      allowedEndpoints: [...company.routes.filter(x => !x.template.includes('{')).map(x => htu(x.template)), ...(destination ? [htu(destination)] : [])],
      sources: { resource: discoveryUrl, authorizationServer: company.sources.find(x => x.url.includes('/.well-known/oauth-authorization-server'))?.url ?? discoveryUrl },
    }, requestedScopes: [...requestedScopes] });
    this.rawLeases.add(raw);
    const scopes = new Map<string, object>(); const keys = new Map<string, ProtocolKeyReference>();
    const scopeRef = (scope: KeyScope): object => {
      requirePap(scope.company_id === company.companyId && scope.owner === binding.ownerRef, 'permission_denied');
      const cacheKey = JSON.stringify(scope); let ref = scopes.get(cacheKey);
      if (!ref) { ref = raw.bindPapScope({ userId: scope.user_id, accountSlot: scope.account_slot }); scopes.set(cacheKey, ref); } return ref;
    };
    const restored = async (scope: KeyScope, key: KeyRef): Promise<ProtocolKeyReference> => {
      const cacheKey = JSON.stringify([scope, key.handle, key.generation]);
      let ref = keys.get(cacheKey);
      if (!ref) { ref = await raw.restorePapKey(scopeRef(scope), { handle: key.handle, generation: key.generation, purpose: key.purpose }); keys.set(cacheKey, ref); }
      requirePap(ref.thumbprint === key.thumbprint && ref.purpose === key.purpose && ref.generation === key.generation, 'credential_unavailable'); return ref;
    };
    const create = async (scope: KeyScope, operationId: string, purpose: 'pap_session' | 'pap_dpop'): Promise<KeyRef> => {
      const key = await (purpose === 'pap_session' ? raw.createDelegatedKey(scopeRef(scope), operationId) : raw.createDpopKey(scopeRef(scope), operationId));
      keys.set(JSON.stringify([scope, key.handle, key.generation]), key); return serializable(key);
    };
    const lease: PapSigningLease = {
      targetRef: raw.targetRef,
      getOAuthClientIdentity: async () => { const identity = await raw.getOAuthClientIdentity(); return { clientId: identity.clientId, alg: identity.algorithm, kid: identity.keyId, publicJwk: identity.publicJwk, redirectUris: identity.redirectUris }; },
      assertActive: () => raw.assertActive(),
      createDelegatedKey: (scope, operationId) => create(scope, operationId, 'pap_session'),
      createDpopKey: (scope, operationId) => create(scope, operationId, 'pap_dpop'),
      issuePapDelegation: async (key, scope, ttlSeconds) => raw.issuePapDelegation(scopeRef(scope), { keyRef: (await restored(scope, key)).keyRef, ttlSeconds }),
      signPapSessionRequest: async input => { const { key, scope, ...request } = input; return raw.signPapSessionRequest(scopeRef(scope), { ...request, keyRef: (await restored(scope, key)).keyRef }); },
      signDpopProof: async input => { const { key, scope, ...request } = input; return raw.signDpopProof(scopeRef(scope), { ...request, keyRef: (await restored(scope, key)).keyRef }); },
      signOAuthClientAssertion: () => raw.signOAuthClientAssertion(raw.targetRef),
      retireTemporaryKey: async (key, scope) => raw.retireTemporaryKey(scopeRef(scope), (await restored(scope, key)).keyRef),
    };
    this.leases.set(key, lease); return lease;
  }
}
