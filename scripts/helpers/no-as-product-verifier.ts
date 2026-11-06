/** Independent NoAS verifier extracted from the original product component, not a production server. */
import assert from 'node:assert/strict';
import { createPublicKey, verify } from 'node:crypto';
import type { JsonWebKey } from 'node:crypto';
import type { RequestListener } from 'node:http';
import { strictJson } from '../../src/strict-json.js';

/** Public publisher material plus the exact HTTPS Company namespace. */
export interface NoAsProductVerifierOptions {
  clientId: string;
  jwks: { keys: Array<JsonWebKey & { kid?: string }> };
  companyOrigin: string;
}

/** Reuse the original Node-crypto handler with an explicit Company origin. */
export function createNoAsProductVerifier(options: NoAsProductVerifierOptions) {
  const origin = new URL(options.companyOrigin);
  assert(origin.protocol === 'https:' && origin.origin === options.companyOrigin);
  const observations = { requests: 0, publicRequests: 0, publicUnauthenticated: true };
  const jtis = new Set<string>();
  let priorSid = '';
  const parse = (compact: unknown) => {
    assert(typeof compact === 'string');
    const parts = compact.split('.'); assert(parts.length === 3);
    return { parts, header: strictJson(Buffer.from(parts[0]!, 'base64url')) as Record<string, unknown>,
      payload: strictJson(Buffer.from(parts[1]!, 'base64url')) as Record<string, unknown> };
  };
  const signed = (compact: unknown, jwk: JsonWebKey) => {
    const p = parse(compact);
    return verify('sha256', Buffer.from(p.parts[0] + '.' + p.parts[1]),
      { key: createPublicKey({ key: jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, Buffer.from(p.parts[2]!, 'base64url'));
  };
  const handler: RequestListener = (request, response) => {
    response.setHeader('content-type', 'application/json');
    if (request.url !== '/api/ping') {
      observations.publicRequests++;
      observations.publicUnauthenticated &&= !request.headers.authorization && !request.headers['poppy-session'] && !request.headers.dpop;
      if (request.url === '/.well-known/poppy.json') { response.end(JSON.stringify({ protocol_version: '0.3',
        organization: { name: 'Independent product verifier', domain: origin.host }, apis: [{ type: 'openapi', url: options.companyOrigin + '/openapi.json' }] })); return; }
      if (request.url === '/openapi.json') { response.end(JSON.stringify({ openapi: '3.1.0', servers: [{ url: options.companyOrigin + '/api' }], paths: { '/ping': { get: {} } } })); return; }
      response.statusCode = 404; response.end('{}'); return;
    }
    try {
      const compact = request.headers['poppy-session']; assert(typeof compact === 'string');
      assert(!request.headers.authorization && !request.headers.dpop);
      const session = parse(compact);
      assert(session.header.alg === 'ES256' && session.header.typ === 'poppy-session+jwt');
      const delegation = parse(session.header.poppy_dlg);
      const identityKey = options.jwks.keys.find(key => key.kid === delegation.header.kid);
      assert(identityKey); assert(signed(session.header.poppy_dlg, identityKey));
      assert(delegation.header.typ === 'poppy-delegation+jwt');
      assert(Object.keys(delegation.payload).every(key => ['iss', 'cnf', 'iat', 'exp', 'jti'].includes(key)));
      assert(delegation.payload.iss === options.clientId); assert(Number(delegation.payload.exp) * 1000 > Date.now());
      const cnf = delegation.payload.cnf as { jwk: JsonWebKey };
      assert(signed(compact, cnf.jwk));
      assert(session.payload.iss === options.clientId && session.payload.aud === options.companyOrigin);
      assert(session.payload.htm === 'GET' && session.payload.htu === options.companyOrigin + '/api/ping');
      assert(!Object.hasOwn(session.payload, 'ath'));
      assert(typeof session.payload.jti === 'string' && !jtis.has(session.payload.jti));
      jtis.add(session.payload.jti);
      if (priorSid) assert(priorSid === session.payload.sid); else { assert(typeof session.payload.sid === 'string'); priorSid = session.payload.sid; }
      observations.requests++; response.end(JSON.stringify({ visits: observations.requests }));
    } catch { response.statusCode = 400; response.end(JSON.stringify({ error: 'invalid_session' })); }
  };
  return { handler, observations, uniqueRequestProofs: () => jtis.size };
}
