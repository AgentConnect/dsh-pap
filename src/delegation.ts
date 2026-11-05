import { createPublicKey, verify } from 'node:crypto';
import type { PapSigningLease } from './host.js';
import type { Delegation, KeyRef, PublicJwk, Subject } from './types.js';
import { requirePap } from './errors.js';
import { jwtParts, scopeFor, sha256 } from './util.js';
export function thumbprint(jwk: PublicJwk): string { return sha256(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })); }
export function verifyCompact(jwt: string, jwk: PublicJwk): boolean {
  try {
    const [head, payload, signature] = jwt.split('.');
    return verify('sha256', Buffer.from(`${head}.${payload}`), { key: createPublicKey({ key: jwk as never, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, Buffer.from(signature!, 'base64url'));
  } catch { return false; }
}
export function checkDelegation(jwt: string, key: KeyRef, clientId: string, identity: { alg: string; kid: string; publicJwk?: PublicJwk }, now: number): number {
  const { header, payload } = jwtParts(jwt);
  requirePap(identity.alg === 'ES256' && identity.publicJwk && header.alg === 'ES256' && header.typ === 'poppy-delegation+jwt' && header.kid === identity.kid && verifyCompact(jwt, identity.publicJwk), 'delegation_blocked');
  requirePap(Object.keys(payload).sort().join(',') === 'cnf,exp,iat,iss,jti', 'delegation_blocked');
  const cnf = payload.cnf as { jwk?: PublicJwk } | undefined;
  requirePap(cnf?.jwk && Object.keys(cnf.jwk).sort().join(',') === 'crv,kty,x,y' && cnf.jwk.kty === 'EC' && cnf.jwk.crv === 'P-256', 'delegation_blocked');
  requirePap(thumbprint(cnf.jwk) === key.thumbprint && key.thumbprint === thumbprint(key.public_jwk), 'delegation_blocked');
  requirePap(payload.iss === clientId && Number.isSafeInteger(payload.iat) && Number.isSafeInteger(payload.exp) && typeof payload.jti === 'string' && payload.jti.length > 0, 'delegation_blocked');
  const iat = Number(payload.iat); const exp = Number(payload.exp);
  requirePap(iat <= Math.floor(now / 1000) + 5 && exp * 1000 > now && exp > iat && exp - iat <= 86400, 'delegation_blocked');
  return exp * 1000;
}
export async function newDelegation(subject: Subject, lease: PapSigningLease, generation: number, now: number): Promise<Delegation> {
  const scope = scopeFor(subject);
  const identity = await lease.getOAuthClientIdentity();
  requirePap(identity.clientId === subject.binding.clientId, 'permission_denied');
  const key = await lease.createDelegatedKey(scope, `pap-delegation/${subject.ref}/${generation}`);
  requirePap(key.purpose === 'pap_session', 'delegation_blocked');
  try {
    const compact = await lease.issuePapDelegation(key, scope, 3600);
    const expiresAt = checkDelegation(compact, key, subject.binding.clientId, identity, now);
    await lease.assertActive();
    return { subjectRef: subject.ref, key, compact, expiresAt, generation };
  } catch (error) { await lease.retireTemporaryKey(key, scope).catch(() => {}); throw error; }
}
