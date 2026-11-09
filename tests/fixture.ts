import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import type { PapIdentityHost, PapSigningLease } from '../src/host.js';
import type { Binding, Company, HttpResponse, HttpTransport, KeyRef, KeyScope, PublicJwk } from '../src/types.js';
import { htu, id, sha256 } from '../src/util.js';
import { thumbprint } from '../src/delegation.js';
import { requirePap } from '../src/errors.js';

export const binding: Binding = { identityRef: { storeId: 'fixture-store', identityId: 'fixture-agent', did: 'did:wba:fixture.example' }, ownerRef: 'fixture-owner', clientId: 'https://agent.example/client.json' };
export const secretKey = randomBytes(32);
export const secrets = { getEncryptionKey: async () => secretKey, getOrCreateEncryptionKey: async () => secretKey };
export const makeKey = () => {
  const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const exported = pair.publicKey.export({ format: 'jwk' });
  return { ...pair, jwk: { kty: 'EC', crv: 'P-256', x: exported.x!, y: exported.y! } as PublicJwk };
};
export function signed(header: object, payload: object, key: ReturnType<typeof makeKey>['privateKey']): string {
  const input = `${Buffer.from(JSON.stringify(header)).toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}`;
  return `${input}.${sign('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
}
/** Real cryptography fixture only. Production never imports this in-memory key custodian. */
export class FixtureHost implements PapIdentityHost {
  constructor(readonly clientBinding: Binding = binding, private readonly clock: () => number = () => Date.now()) {}
  identityKid = 'identity-fixture';
  identity = makeKey(); keys = new Map<string, { key: ReturnType<typeof makeKey>; scope: string; descriptor: KeyRef }>();
  operations = new Map<string, KeyRef>(); active = true; createCount = 0; sessionCount = 0; assertionCount = 0; dpopCount = 0; delegationCount = 0;
  async acquire(_binding: Binding, company: Company): Promise<PapSigningLease> {
    const check = () => requirePap(this.active, 'permission_denied');
    const create = async (scope: KeyScope, operationId: string, purpose: KeyRef['purpose']) => {
      check(); const cached = this.operations.get(operationId); if (cached) return cached;
      const key = makeKey(); const descriptor: KeyRef = { handle: id('key'), purpose, generation: 1, public_jwk: key.jwk, thumbprint: thumbprint(key.jwk) };
      this.keys.set(descriptor.handle, { key, descriptor, scope: JSON.stringify(scope) }); this.operations.set(operationId, descriptor); this.createCount++; return descriptor;
    };
    const get = (ref: KeyRef, scope: KeyScope) => { check(); const value = this.keys.get(ref.handle); requirePap(value && value.scope === JSON.stringify(scope) && value.descriptor.generation === ref.generation, 'credential_unavailable'); return value.key; };
    return {
      getOAuthClientIdentity: async () => ({ clientId: this.clientBinding.clientId, alg: 'ES256', kid: this.identityKid, publicJwk: this.identity.jwk, redirectUris: ['https://agent.example/pap-callback','http://127.0.0.1:57293/callback'] }),
      assertActive: async () => check(),
      createDelegatedKey: (scope, operationId) => create(scope, operationId, 'pap_session'),
      createDpopKey: (scope, operationId) => create(scope, operationId, 'pap_dpop'),
      issuePapDelegation: async (ref, scope, ttl) => { const key = get(ref, scope); this.delegationCount++; const now = Math.floor(this.clock()/1000); return signed({ alg: 'ES256', typ: 'poppy-delegation+jwt', kid: this.identityKid }, { iss: this.clientBinding.clientId, cnf: { jwk: key.jwk }, iat: now, exp: now + ttl, jti: id('dlg') }, this.identity.privateKey); },
      signPapSessionRequest: async input => { const key = get(input.key, input.scope); this.sessionCount++; return signed({ alg: 'ES256', typ: 'poppy-session+jwt', kid: input.key.thumbprint, poppy_dlg: input.delegation }, { iss: input.clientId, aud: company.companyId, sid: input.sid, sub: input.sub, ...(input.agentId ? { agent_id: input.agentId } : {}), htm: input.httpMethod, htu: htu(input.httpUri), iat: Math.floor(this.clock()/1000), jti: id('req'), ...(input.accessToken ? { ath: sha256(input.accessToken) } : {}) }, key.privateKey); },
      signDpopProof: async input => { const key = get(input.key, input.scope); this.dpopCount++; return signed({ alg: 'ES256', typ: 'dpop+jwt', jwk: key.jwk }, { htm: input.httpMethod, htu: htu(input.httpUri), iat: Math.floor(this.clock()/1000), jti: id('dpop'), ...(input.accessToken ? { ath: sha256(input.accessToken) } : {}), ...(input.nonce ? { nonce: input.nonce } : {}) }, key.privateKey); },
      signOAuthClientAssertion: async () => { check(); this.assertionCount++; const now = Math.floor(this.clock()/1000); return signed({ alg: 'ES256', typ: 'JWT', kid: this.identityKid }, { iss: this.clientBinding.clientId, sub: this.clientBinding.clientId, aud: company.issuer, iat: now, exp: now+60, jti: id('ca') }, this.identity.privateKey); },
      retireTemporaryKey: async (ref, scope) => { get(ref, scope); this.keys.delete(ref.handle); },
    };
  }
}
export const jsonResponse = (url: string, body: unknown, status = 200, headers: Record<string,string> = {}): HttpResponse => ({ url, status, headers: { 'content-type': 'application/json', ...headers }, body: Buffer.from(JSON.stringify(body)) });
export class FixtureTransport implements HttpTransport {
  calls: { url: string; options: Parameters<HttpTransport['request']>[1] }[] = [];
  mode: 'none' | 'account' | 'disabled' = 'none'; prmStatus = 200; issuer = 'https://auth.shop.example'; scopes = ['orders:read'];
  override?: (url: string, options: Parameters<HttpTransport['request']>[1]) => HttpResponse | Promise<HttpResponse> | undefined;
  async request(url: string, options: Parameters<HttpTransport['request']>[1] = {}): Promise<HttpResponse> {
    this.calls.push({ url, options }); const override = this.override?.(url, options); if (override) return override;
    const target = new URL(url);
    if (target.pathname === '/.well-known/poppy.json') return jsonResponse(url, { protocol_version: '0.3', organization: { name: 'Fixture Shop', domain: target.host }, apis: [{ type: 'openapi', url: `${target.origin}/openapi.json` }], ...(this.mode !== 'none' ? { auth: { issuer: this.issuer, disabled: this.mode === 'disabled', scopes: { 'orders:read': 'Orders' } } } : {}) });
    if (target.pathname === '/.well-known/oauth-protected-resource') return jsonResponse(url, { resource: target.origin, ...(this.mode !== 'none' ? { authorization_servers: [this.issuer] } : {}) }, this.prmStatus);
    if (target.pathname.startsWith('/.well-known/oauth-authorization-server')) return jsonResponse(url, { issuer: this.issuer, protected_resources: ['https://shop.example'], token_endpoint: `${this.issuer}/token`, authorization_endpoint: `${this.issuer}/authorize`, revocation_endpoint: `${this.issuer}/revoke`, grant_types_supported: ['authorization_code','refresh_token'], token_endpoint_auth_methods_supported: ['private_key_jwt'], code_challenge_methods_supported: ['S256'], dpop_signing_alg_values_supported: ['ES256'] });
    if (target.pathname === '/openapi.json') return jsonResponse(url, { openapi: '3.1.0', servers: [{ url: target.origin }], paths: { '/api/cart': { get: {}, post: {} }, '/api/objects/{id}': { get: {} } } });
    if (target.pathname.startsWith('/api/')) return jsonResponse(url, { ok: true });
    if (target.pathname === '/token') return jsonResponse(url, { access_token: 'access-fixture', refresh_token: 'refresh-fixture', token_type: 'DPoP', expires_in: 3600 });
    if (target.pathname === '/revoke') return jsonResponse(url, {});
    return jsonResponse(url, {}, 404);
  }
}
