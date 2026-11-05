import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PapClient } from '../src/client.js';
import { PapError } from '../src/errors.js';
import { verifyCompact } from '../src/delegation.js';
import { jwtParts, sha256 } from '../src/util.js';
import { binding, FixtureHost, FixtureTransport, jsonResponse, secrets } from './fixture.js';
async function setup(t: test.TestContext, mode: FixtureTransport['mode'] = 'none') {
  const root = await mkdtemp(join(tmpdir(), 'dsh-pap-unit-')); t.after(() => rm(root, { recursive:true, force:true }));
  const host = new FixtureHost(); const transport = new FixtureTransport(); transport.mode = mode;
  const handoff = { register: async () => ({ callbackRef: 'protected-claim-reference' }), collect: async () => ({}) };
  const options = { stateRoot: root, binding, secretStore: secrets, identityHost: host, callbackHandoff: handoff };
  const client = new PapClient(options, transport); const company = await client.resolvePapCompany('shop.example'); const subject = await client.getOrCreatePapUser(company.companyRef); const session = await client.openPapSession(subject.subjectRef);
  return { root, host, transport, client, options, ...company, ...subject, ...session };
}
const fails = (code: string) => (error: unknown) => error instanceof PapError && error.code === code;

test('F-T01 no AS: 404 and valid empty metadata; errors never erase known issuer', async t => {
  const f = await setup(t,'account'); const before = await f.client.store.read();
  f.transport.prmStatus = 503; await assert.rejects(f.client.resolvePapCompany('shop.example'), fails('discovery_failed'));
  assert.equal((await f.client.store.read()).companies[f.companyRef]!.companyId, before.companies[f.companyRef]!.companyId);
  f.transport.mode = 'none'; f.transport.prmStatus = 404; const no = await f.client.resolvePapCompany('shop.example'); assert.equal(no.authMode,'no_as');
  await assert.rejects(f.client.dispatchPap(f.sessionRef,{url:'https://shop.example/api/cart'}),fails('namespace_changed'));
});
test('F-T01 rejects mismatched issuer, organization, old protocol and metadata redirect', async t => {
  const f = await setup(t);
  for (const response of [
    jsonResponse('https://shop.example/.well-known/poppy.json',{protocol_version:'0.2',organization:{name:'Bad',domain:'shop.example'}}),
    jsonResponse('https://shop.example/.well-known/poppy.json',{protocol_version:'0.3',organization:{name:'Bad',domain:'evil.example'}}),
  ]) { f.transport.override = url => url.endsWith('poppy.json') ? response : undefined; await assert.rejects(f.client.resolvePapCompany('shop.example')); }
  f.transport.override = url => url.endsWith('oauth-protected-resource') ? jsonResponse(url,{},302,{location:'https://evil.example/metadata'}) : undefined;
  await assert.rejects(f.client.resolvePapCompany('shop.example'), fails('discovery_failed'));
});
test('F-T01 disabled preserves issuer and refuses all new sign-in', async t => {
  const f = await setup(t,'disabled'); assert.equal(f.companyId,'https://auth.shop.example'); assert.equal(f.authMode,'disabled');
  await assert.rejects(f.client.startSignIn(f.subjectRef,{resource:'https://shop.example',scopes:['orders:read'],redirectUri:'https://agent.example/pap-callback',callbackMode:'handoff'}), fails('unsupported_sign_in'));
  await f.client.dispatchPap(f.sessionRef,{url:'https://shop.example/api/cart'});
});
test('F-T02 private IDs stable across restart, Company/mode isolated; encrypted state excludes credentials', async t => {
  const f = await setup(t); const initial = await f.client.store.read();
  const restarted = new PapClient(f.options,f.transport); const again = await restarted.getOrCreatePapUser(f.companyRef); assert.equal(again.subjectRef,f.subjectRef);
  const anonymous = await restarted.getOrCreatePapUser(f.companyRef,'anonymous'); const anonymous2 = await restarted.getOrCreatePapUser(f.companyRef,'anonymous'); assert.notEqual(anonymous.subjectRef,anonymous2.subjectRef);
  await f.client.dispatchPap(f.sessionRef,{url:'https://shop.example/api/cart'});
  const bytes = await readFile(join(f.root,'pap-state.enc')); assert.equal(bytes.includes(Buffer.from(initial.subjects[f.subjectRef]!.userId)),false); assert.equal(bytes.includes(Buffer.from('poppy-delegation')),false);
  assert(!JSON.stringify(await restarted.getPapStatus()).includes('handle'));
});
test('F-T03/04 per-request real signature chain, actual URL/method and no token acquisition signed out', async t => {
  const f = await setup(t);
  await f.client.dispatchPap(f.sessionRef,{url:'https://shop.example/api/cart?secret=query'}); await f.client.dispatchPap(f.sessionRef,{url:'https://shop.example/api/cart',method:'POST',body:'{}',idempotencyKey:'operation-one'});
  const calls = f.transport.calls.filter(x => x.url.includes('/api/cart'));
  const first = calls[0]!.options!.headers!['poppy-session']!; const second = calls[1]!.options!.headers!['poppy-session']!;
  const one = jwtParts(first); const two = jwtParts(second); const delegation = jwtParts(one.header.poppy_dlg as string);
  assert(verifyCompact(one.header.poppy_dlg as string,f.host.identity.jwk)); assert(verifyCompact(first,(delegation.payload.cnf as {jwk: typeof f.host.identity.jwk}).jwk));
  assert.equal(one.payload.sid,two.payload.sid); assert.notEqual(one.payload.jti,two.payload.jti); assert.equal(one.payload.htu,'https://shop.example/api/cart'); assert.equal(two.payload.htm,'POST'); assert(!Object.hasOwn(one.payload,'ath'));
  assert(!f.transport.calls.some(x => x.url.endsWith('/token'))); assert(!f.transport.calls.some(x => x.options?.headers?.authorization));
  await assert.rejects(f.client.dispatchPap(f.sessionRef,{url:'https://shop.example/unknown'}),fails('unsafe_destination'));
  await assert.rejects(f.client.dispatchPap(f.sessionRef,{url:'https://shop.example/api/cart',headers:{Authorization:'forbidden'}}),fails('permission_denied'));
});
test('F-T05 concurrent delegation, rotation and restart preserve sid/User IDs', async t => {
  const f = await setup(t); await Promise.all(Array.from({length:8},() => f.client.dispatchPap(f.sessionRef,{url:'https://shop.example/api/cart'}))); assert.equal(f.host.createCount,1);
  const before = await f.client.store.read(); await f.client.rotateDelegation(f.subjectRef); const after = await f.client.store.read();
  assert.equal(before.sessions[f.sessionRef]!.sid,after.sessions[f.sessionRef]!.sid); assert.equal(before.subjects[f.subjectRef]!.userId,after.subjects[f.subjectRef]!.userId); assert.notEqual(before.delegations[f.subjectRef]!.key.handle,after.delegations[f.subjectRef]!.key.handle);
  await new PapClient(f.options,f.transport).dispatchPap(f.sessionRef,{url:'https://shop.example/api/cart'});
});
test('F-T06 Direct validates error iss/state and PKCE; only standard OAuth fields go to AS', async t => {
  const f = await setup(t,'account'); const login = await f.client.startSignIn(f.subjectRef,{scopes:['orders:read'],resource:'https://shop.example',redirectUri:'https://agent.example/pap-callback',callbackMode:'handoff'});
  const url = new URL(login.authorizationUrl); const tx = (await f.client.store.read()).transactions[login.transactionRef]!; assert.equal(url.searchParams.get('code_challenge'),sha256(tx.verifier)); assert(tx.verifier.length>=43&&tx.verifier.length<=128);
  await assert.rejects(f.client.completeSignIn(login.transactionRef,{state:tx.state,iss:'https://evil.example',error:'access_denied'}), fails('invalid_authorization_response'));
  const grant = await f.client.completeSignIn(login.transactionRef,{state:tx.state,iss:tx.issuer,code:'one-use-code'});
  const call = f.transport.calls.find(x => x.url.endsWith('/token'))!; const form = new URLSearchParams(call.options!.body); assert.equal(form.get('code_verifier'),tx.verifier); assert.equal(form.get('redirect_uri'),tx.redirectUri); assert.equal(jwtParts(form.get('client_assertion')!).payload.aud,tx.issuer);
  assert(!call.options!.headers!['poppy-session']); assert(!form.has('session_id')); assert(!form.has('sub')); assert(!form.has('sid')); assert.equal(jwtParts(call.options!.headers!.dpop!).payload.ath,undefined);
  await assert.rejects(f.client.completeSignIn(login.transactionRef,{state:tx.state,iss:tx.issuer,code:'one-use-code'}), fails('invalid_authorization_response'));
  const session = await f.client.openPapSession(f.subjectRef,grant.accountSlot); await f.client.dispatchPap(session.sessionRef,{url:'https://shop.example/api/cart',scopes:['orders:read']});
  const actual = f.transport.calls.at(-1)!; assert.equal(actual.options!.headers!.authorization,'DPoP access-fixture'); assert.equal(jwtParts(actual.options!.headers!['poppy-session']!).payload.ath,sha256('access-fixture')); assert.equal(jwtParts(actual.options!.headers!.dpop!).payload.ath,sha256('access-fixture'));
});
async function signedIn(f: Awaited<ReturnType<typeof setup>>) {
  const login = await f.client.startSignIn(f.subjectRef,{scopes:['orders:read'],resource:'https://shop.example',redirectUri:'https://agent.example/pap-callback',callbackMode:'handoff'}); const tx=(await f.client.store.read()).transactions[login.transactionRef]!;
  return f.client.completeSignIn(login.transactionRef,{state:tx.state,iss:tx.issuer,code:'fixture-code'});
}
test('F-T07 refresh single-flight retains absent refresh, unknown TTL, signout all grants and signed-out continuity', async t => {
  const f = await setup(t,'account'); const grant = await signedIn(f); const session=await f.client.openPapSession(f.subjectRef,grant.accountSlot);
  f.transport.override = url => url.endsWith('/token') ? jsonResponse(url,{access_token:'refreshed-access',token_type:'DPoP'}) : undefined;
  await Promise.all(Array.from({length:8},() => f.client.refreshAccountGrant(grant.grantRef)));
  const current = (await f.client.store.read()).grants[grant.grantRef]!; assert.equal(current.refreshToken,'refresh-fixture'); assert.equal(current.expiresAt,undefined);
  const refreshCalls = f.transport.calls.filter(x => x.url.endsWith('/token') && new URLSearchParams(x.options!.body).get('grant_type') === 'refresh_token'); assert.equal(refreshCalls.length,1);
  assert.equal((await f.client.signOutAccount(f.subjectRef,grant.accountSlot)).status,'signed_out');
  await f.client.dispatchPap(session.sessionRef,{url:'https://shop.example/api/cart'}); assert(!f.transport.calls.at(-1)!.options!.headers!.authorization); assert(!Object.hasOwn(jwtParts(f.transport.calls.at(-1)!.options!.headers!['poppy-session']!).payload,'ath'));
});
test('F-T07 refresh lost response marks uncertain and prevents old refresh replay', async t => {
  const f=await setup(t,'account'); const grant=await signedIn(f);
  f.transport.override = url => { if(url.endsWith('/token')) throw new Error('fixture lost response'); };
  await assert.rejects(f.client.refreshAccountGrant(grant.grantRef),fails('request_uncertain')); assert.equal((await f.client.store.read()).grants[grant.grantRef]!.status,'uncertain'); await assert.rejects(f.client.refreshAccountGrant(grant.grantRef),fails('reauthorization_required'));
});
test('F-T08 session_ended retries once with new sid/proof; invalid_session and uncertain POST never retry', async t => {
  const f=await setup(t); let count=0;
  f.transport.override = url => url.includes('/api/cart') && count++ === 0 ? jsonResponse(url,{error:'session_ended'},409) : undefined;
  await f.client.dispatchPap(f.sessionRef,{url:'https://shop.example/api/cart',method:'POST',body:'{}',idempotencyKey:'same-operation'});
  const calls=f.transport.calls.filter(x=>x.url.includes('/api/cart')); assert.equal(calls.length,2); assert.notEqual(jwtParts(calls[0]!.options!.headers!['poppy-session']!).payload.sid,jwtParts(calls[1]!.options!.headers!['poppy-session']!).payload.sid);
  f.transport.override = url => url.includes('/api/cart') ? jsonResponse(url,{error:'invalid_session'},401) : undefined;
  await assert.rejects(f.client.dispatchPap(f.sessionRef,{url:'https://shop.example/api/cart'}),fails('invalid_session'));
  const before=f.host.sessionCount; f.transport.override = url => { if(url.includes('/api/cart')) throw new Error('lost'); };
  await assert.rejects(f.client.dispatchPap(f.sessionRef,{url:'https://shop.example/api/cart',method:'POST',body:'{}'}),fails('request_uncertain')); assert.equal(f.host.sessionCount,before+1);
});
test('F-T08 redirect, 429, revoked permission and disconnect do not change protocol or identity', async t => {
  const f=await setup(t);
  f.transport.override = url => url.includes('/api/cart') ? jsonResponse(url,{},302,{location:'https://evil.example'}) : undefined;
  await assert.rejects(f.client.dispatchPap(f.sessionRef,{url:'https://shop.example/api/cart'}),fails('redirect_blocked'));
  f.transport.override = url => url.includes('/api/cart') ? jsonResponse(url,{},429,{'retry-after':'25'}) : undefined;
  await assert.rejects(f.client.dispatchPap(f.sessionRef,{url:'https://shop.example/api/cart'}),error=>error instanceof PapError&&error.code==='rate_limited'&&error.retryAfterSeconds===25);
  f.host.active=false; await assert.rejects(f.client.dispatchPap(f.sessionRef,{url:'https://shop.example/api/cart'}),fails('permission_denied'));
  await f.client.disconnectPap(f.sessionRef); await assert.rejects(f.client.dispatchPap(f.sessionRef,{url:'https://shop.example/api/cart'}),fails('disconnected'));
});
test('F-T10 Device remains a separately unimplemented lane and is never advertised',async t=>{const f=await setup(t,'account'); assert.deepEqual((await f.client.getPapStatus()).supportedSignIn,['direct']);await assert.rejects(f.client.startSignIn(f.subjectRef,{method:'device',resource:'https://shop.example',scopes:['orders:read'],redirectUri:'https://agent.example/pap-callback',callbackMode:'handoff'}),fails('unsupported_sign_in'));});
test('F-T07 independent clients merge a concurrent refresh and resource/AS nonce stay separate',async t=>{
  const f=await setup(t,'account');const grant=await signedIn(f);const restarted=new PapClient(f.options,f.transport);let refreshes=0;
  f.transport.override=(url,options)=>{
    if(url.endsWith('/token')&&new URLSearchParams(options!.body).get('grant_type')==='refresh_token'){
      refreshes++;return new Promise(resolve=>setTimeout(()=>resolve(jsonResponse(url,{access_token:'updated',refresh_token:'rotated',token_type:'DPoP'})),40));
    }
  };
  await Promise.all([f.client.refreshAccountGrant(grant.grantRef),restarted.refreshAccountGrant(grant.grantRef)]);assert.equal(refreshes,1);assert.equal((await f.client.store.read()).grants[grant.grantRef]!.refreshToken,'rotated');
});
test('F-T07 refresh/signout race retains new refresh for revocation without resurrecting account',async t=>{
  const f=await setup(t,'account');const grant=await signedIn(f);let release:()=>void=()=>{};let entered:()=>void=()=>{};const start=new Promise<void>(resolve=>entered=resolve);
  f.transport.override=(url,options)=>{
    if(url.endsWith('/token')&&new URLSearchParams(options!.body).get('grant_type')==='refresh_token')return new Promise(resolve=>{release=()=>resolve(jsonResponse(url,{access_token:'new-access',refresh_token:'new-refresh',token_type:'DPoP'}));entered();});
  };
  const flight=f.client.refreshAccountGrant(grant.grantRef);await start;assert.equal((await f.client.signOutAccount(f.subjectRef,grant.accountSlot)).status,'revocation_pending');release();await assert.rejects(flight,fails('revocation_pending'));
  const state=await f.client.store.read();assert(!Object.values(state.grants).some(x=>x.status==='active'));assert(Object.values(state.grants).some(x=>x.status==='revocation_pending'&&x.refreshToken==='new-refresh'));
  assert.equal((await f.client.signOutAccount(f.subjectRef,grant.accountSlot)).status,'signed_out');
});
test('F-T04 OAuth/description endpoint never receives Session even when an API also declares it',async t=>{
  const f=await setup(t,'account');
  f.transport.override=url=>url.includes('oauth-authorization-server')?jsonResponse(url,{issuer:f.transport.issuer,protected_resources:['https://shop.example'],token_endpoint:'https://shop.example/api/cart',authorization_endpoint:f.transport.issuer+'/authorize',revocation_endpoint:f.transport.issuer+'/revoke',grant_types_supported:['authorization_code','refresh_token']}):undefined;
  await f.client.resolvePapCompany('shop.example');const before=f.host.sessionCount;
  await assert.rejects(f.client.dispatchPap(f.sessionRef,{url:'https://shop.example/api/cart'}),fails('unsafe_destination'));assert.equal(f.host.sessionCount,before);
});
test('F-T07 DPoP key loss blocks grant without Bearer downgrade',async t=>{
  const f=await setup(t,'account');const result=await signedIn(f);const session=await f.client.openPapSession(f.subjectRef,result.accountSlot);const grant=(await f.client.store.read()).grants[result.grantRef]!;f.host.keys.delete(grant.dpopKey!.handle);
  await assert.rejects(f.client.dispatchPap(session.sessionRef,{url:'https://shop.example/api/cart'}),fails('credential_unavailable'));assert.equal((await f.client.store.read()).grants[result.grantRef]!.status,'reauthorization_required');assert(!f.transport.calls.some(x=>x.url.includes('/api/cart')&&x.options!.headers?.authorization?.startsWith('Bearer ')));
});
test('F-T02 optional agent shares Company User identity/account slot; anonymous identity discarded on disconnect',async t=>{
  const f=await setup(t,'account');const grant=await signedIn(f);const agent=await f.client.getOrCreatePapUser(f.companyRef,'regular',true);const state=await f.client.store.read();assert.equal(state.subjects[agent.subjectRef]!.userId,state.subjects[f.subjectRef]!.userId);assert(state.subjects[agent.subjectRef]!.agentId);
  const agentSession=await f.client.openPapSession(agent.subjectRef,grant.accountSlot);await f.client.dispatchPap(agentSession.sessionRef,{url:'https://shop.example/api/cart'});
  const anon=await f.client.getOrCreatePapUser(f.companyRef,'anonymous');const anonSession=await f.client.openPapSession(anon.subjectRef);await f.client.dispatchPap(anonSession.sessionRef,{url:'https://shop.example/api/cart'});const key=(await f.client.store.read()).delegations[anon.subjectRef]!.key.handle;await f.client.disconnectPap(anonSession.sessionRef);assert(!(await f.client.store.read()).subjects[anon.subjectRef]);assert(!f.host.keys.has(key));
});
