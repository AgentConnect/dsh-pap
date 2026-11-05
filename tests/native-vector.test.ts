import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { verifyCompact, thumbprint } from '../src/delegation.js';
import { jwtParts, htu, sha256 } from '../src/util.js';
import type { PublicJwk } from '../src/types.js';
test('F-T03 independently verifies A native local-signer-v2 public compatibility vector', async()=>{
  const vector=JSON.parse(await readFile(new URL('./vectors/local-signer-v2.json',import.meta.url),'utf8'));
  const delegation=jwtParts(vector.delegation);const session=jwtParts(vector.session);const assertion=jwtParts(vector.assertion);const dpop=jwtParts(vector.dpop);
  const identity=vector.jwks.keys.find((key:{kid:string})=>key.kid===delegation.header.kid);
  assert(verifyCompact(vector.delegation,identity));assert(verifyCompact(vector.assertion,identity));assert(verifyCompact(vector.session,vector.delegated_jwk));assert(verifyCompact(vector.dpop,vector.dpop_jwk));
  assert.equal(delegation.header.typ,'poppy-delegation+jwt');assert.deepEqual(Object.keys(delegation.payload).sort(),['cnf','exp','iat','iss','jti']);assert.equal((delegation.payload.cnf as {jwk:PublicJwk}).jwk.x,vector.delegated_jwk.x);
  assert.equal(session.header.typ,'poppy-session+jwt');assert.equal(session.header.alg,'ES256');assert.equal(session.header.kid,thumbprint(vector.delegated_jwk));assert.equal(session.header.poppy_dlg,vector.delegation);
  assert.equal(session.payload.aud,vector.request.company_id);assert.equal(session.payload.htm,vector.request.method);assert.equal(session.payload.htu,htu(vector.request.target));if(vector.request.access_token)assert.equal(session.payload.ath,sha256(vector.request.access_token));else assert(!Object.hasOwn(session.payload,'ath'));
  assert.equal(assertion.payload.aud,vector.assertion_request.audience);assert.equal(dpop.header.typ,'dpop+jwt');assert.equal(dpop.payload.nonce,vector.dpop_request.nonce);
});
