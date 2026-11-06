/** Focused account contracts. Virtual HTTP/storage fixtures; not C/native, Commerce or product E2E evidence. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PapClient } from '../src/client.js';
import { PapError } from '../src/errors.js';
import { id,jwtParts,sha256 } from '../src/util.js';
import { binding,FixtureHost,FixtureTransport,jsonResponse,secrets } from './fixture.js';

const origin='https://shop.example';
const fails=(code:string)=>(error:unknown)=>error instanceof PapError&&error.code===code;
async function setup(t:test.TestContext,scopeNames=['orders:read']) {
  const root=await mkdtemp(join(tmpdir(),'pap-account-contract-'));t.after(()=>rm(root,{recursive:true,force:true}));
  const host=new FixtureHost();const transport=new FixtureTransport();transport.mode='account';
  transport.override=url=>url.endsWith('/.well-known/poppy.json')?jsonResponse(url,{protocol_version:'0.3',organization:{name:'Account contract fixture',domain:'shop.example'},auth:{issuer:transport.issuer,scopes:Object.fromEntries(scopeNames.map(scope=>[scope,scope]))},apis:[{type:'openapi',url:origin+'/openapi.json'}]}):undefined;
  const client=new PapClient({stateRoot:root,binding,secretStore:secrets,identityHost:host,callbackHandoff:{register:async()=>({callbackRef:'fixture-only-pickup-reference'}),collect:async()=>({})}},transport);
  t.after(()=>client.close());const company=await client.resolvePapCompany('shop.example');const subject=await client.getOrCreatePapUser(company.companyRef,'regular',true);const signedOut=await client.openPapSession(subject.subjectRef);
  return {client,host,transport,...company,...subject,signedOut,scopeNames};
}
async function signIn(f:Awaited<ReturnType<typeof setup>>,scopes=f.scopeNames) {
  const pending=await f.client.startSignIn(f.subjectRef,{scopes,resource:origin,redirectUri:'https://agent.example/pap-callback',callbackMode:'handoff'});
  const tx=(await f.client.store.read()).transactions[pending.transactionRef]!;
  return {pending,complete:()=>f.client.completeSignIn(pending.transactionRef,{state:tx.state,iss:tx.issuer,code:id('fixture_code')})};
}
const resources=(f:Awaited<ReturnType<typeof setup>>)=>f.transport.calls.filter(call=>new URL(call.url).pathname.startsWith('/api/'));
const tokens=(f:Awaited<ReturnType<typeof setup>>)=>f.transport.calls.filter(call=>new URL(call.url).pathname==='/token');

test('P19 one grant serves two independent sid values before and after one rotating refresh',async t=>{
  const f=await setup(t);const grant=await(await signIn(f)).complete();const first=await f.client.openPapSession(f.subjectRef,grant.accountSlot);const second=await f.client.openPapSession(f.subjectRef,grant.accountSlot);
  const before=await f.client.store.read();const sid1=before.sessions[first.sessionRef]!.sid;const sid2=before.sessions[second.sessionRef]!.sid;assert(sid1!==sid2);
  const old=before.grants[grant.grantRef]!;
  for(const session of [first,second])await f.client.dispatchPap(session.sessionRef,{url:origin+'/api/cart',scopes:['orders:read']});
  const seenBefore=resources(f).slice(-2).map(call=>jwtParts(call.options!.headers!['poppy-session']!).payload);
  assert(seenBefore[0]!.sid===sid1&&seenBefore[1]!.sid===sid2);assert(seenBefore.every(payload=>payload.ath===sha256(old.accessToken)));
  let rotations=0;const prior=f.transport.override;
  f.transport.override=(url,options)=>{
    if(url.endsWith('/token')&&new URLSearchParams(options!.body).get('grant_type')==='refresh_token'){
      assert(new URLSearchParams(options!.body).get('refresh_token')===old.refreshToken);rotations++;
      return jsonResponse(url,{access_token:'unit-rotated-access',refresh_token:'unit-rotated-refresh',token_type:'DPoP',expires_in:3600});
    }return prior?.(url,options);
  };
  await f.client.refreshAccountGrant(grant.grantRef,first.sessionRef);const after=await f.client.store.read();const current=after.grants[grant.grantRef]!;
  assert(current.accessToken!==old.accessToken&&current.refreshToken!==old.refreshToken);assert.equal(current.status,'active');assert.equal(rotations,1);assert.equal(Object.keys(after.grants).length,1);
  assert(after.sessions[first.sessionRef]!.sid===sid1&&after.sessions[second.sessionRef]!.sid===sid2);
  assert(after.sessions[first.sessionRef]!.accountSlot===grant.accountSlot&&after.sessions[second.sessionRef]!.accountSlot===grant.accountSlot);
  for(const session of [first,second])assert.equal((await f.client.dispatchPap(session.sessionRef,{url:origin+'/api/cart',scopes:['orders:read']})).status,200);
  const seenAfter=resources(f).slice(-2).map(call=>jwtParts(call.options!.headers!['poppy-session']!).payload);
  assert(seenAfter[0]!.sid===sid1&&seenAfter[1]!.sid===sid2);assert(seenAfter.every(payload=>payload.ath===sha256(current.accessToken)));assert.equal(tokens(f).length,2);
});

test('P20 fewer granted scopes allow only the returned subset without another authorization',async t=>{
  const f=await setup(t,['orders:read','cart:write']);const prior=f.transport.override;
  f.transport.override=(url,options)=>url.endsWith('/token')?jsonResponse(url,{access_token:'unit-subset-access',refresh_token:'unit-subset-refresh',token_type:'DPoP',scope:'orders:read',expires_in:3600}):prior?.(url,options);
  const grant=await(await signIn(f)).complete();const session=await f.client.openPapSession(f.subjectRef,grant.accountSlot);
  const current=(await f.client.store.read()).grants[grant.grantRef]!;assert.deepEqual(current.scope,['orders:read']);
  assert.equal((await f.client.dispatchPap(session.sessionRef,{url:origin+'/api/cart',scopes:['orders:read']})).status,200);
  const signatures=f.host.sessionCount;const calls=resources(f).length;
  await assert.rejects(f.client.dispatchPap(session.sessionRef,{url:origin+'/api/cart',scopes:['cart:write']}),fails('insufficient_scope'));
  assert.equal(f.host.sessionCount,signatures);assert.equal(resources(f).length,calls);assert.equal(tokens(f).length,1);assert.equal(Object.keys((await f.client.store.read()).transactions).length,0);
});
for(const returned of ['','orders:read admin:write'])test(`P20 ${returned?'extra':'empty'} scope response cannot create a usable account grant`,async t=>{
  const f=await setup(t,['orders:read','cart:write']);const prior=f.transport.override;
  f.transport.override=(url,options)=>url.endsWith('/token')?jsonResponse(url,{access_token:'unit-rejected-access',refresh_token:'unit-rejected-refresh',token_type:'DPoP',scope:returned,expires_in:3600}):prior?.(url,options);
  const login=await signIn(f);await assert.rejects(login.complete(),fails('insufficient_scope'));
  const state=await f.client.store.read();assert.equal(Object.keys(state.grants).length,0);assert.equal(state.transactions[login.pending.transactionRef]!.status,'failed');assert.equal(tokens(f).length,1);
  assert.equal((await f.client.dispatchPap(f.signedOut.sessionRef,{url:origin+'/api/cart'})).status,200);
  assert(!resources(f).at(-1)!.options!.headers!.authorization);assert(!Object.hasOwn(jwtParts(resources(f).at(-1)!.options!.headers!['poppy-session']!).payload,'ath'));assert.equal(tokens(f).length,1);
});

test('P20 unauthorized_client at AS and resource preserves permitted signed-out access without retry or scope expansion',async t=>{
  const f=await setup(t);const good=await(await signIn(f)).complete();const account=await f.client.openPapSession(f.subjectRef,good.accountSlot);const original=(await f.client.store.read()).grants[good.grantRef]!;const prior=f.transport.override;
  f.transport.override=(url,options)=>url.endsWith('/token')?jsonResponse(url,{error:'unauthorized_client'},400):prior?.(url,options);
  const denied=await signIn(f);await assert.rejects(denied.complete(),fails('unauthorized_client'));assert.equal(tokens(f).length,2);
  const retained=(await f.client.store.read()).grants[good.grantRef]!;assert(retained.status==='active'&&retained.generation===original.generation&&retained.accessToken===original.accessToken);assert.deepEqual(retained.scope,original.scope);
  f.transport.override=(url,options)=>url.endsWith('/api/cart')&&options?.headers?.authorization?jsonResponse(url,{error:'unauthorized_client'},403):prior?.(url,options);
  const before=resources(f).length;await assert.rejects(f.client.dispatchPap(account.sessionRef,{url:origin+'/api/cart',scopes:['orders:read']}),fails('unauthorized_client'));assert.equal(resources(f).length,before+1);assert.equal(tokens(f).length,2);
  assert.equal((await f.client.dispatchPap(f.signedOut.sessionRef,{url:origin+'/api/cart'})).status,200);assert(!resources(f).at(-1)!.options!.headers!.authorization);assert.equal(tokens(f).length,2);
  const after=await f.client.store.read();assert.equal(Object.keys(after.transactions).length,1);assert.equal(after.transactions[denied.pending.transactionRef]!.status,'failed');assert.equal(Object.keys(after.grants).length,1);
});

test('P21 a second session_ended stops after exactly one sid replacement without refreshing a valid grant',async t=>{
  const f=await setup(t);const grant=await(await signIn(f)).complete();const session=await f.client.openPapSession(f.subjectRef,grant.accountSlot);const before=await f.client.store.read();const initial=before.sessions[session.sessionRef]!;const prior=f.transport.override;
  f.transport.override=(url,options)=>url.endsWith('/api/cart')?jsonResponse(url,{error:'session_ended'},400):prior?.(url,options);
  await assert.rejects(f.client.dispatchPap(session.sessionRef,{url:origin+'/api/cart',scopes:['orders:read']}),fails('session_ended'));
  const calls=resources(f);assert.equal(calls.length,2);const proofs=calls.map(call=>jwtParts(call.options!.headers!['poppy-session']!).payload);
  assert(proofs[0]!.sid===initial.sid&&proofs[1]!.sid!==initial.sid);assert(proofs[0]!.jti!==proofs[1]!.jti);
  const after=await f.client.store.read();assert.equal(after.sessions[session.sessionRef]!.generation,initial.generation+1);assert(after.sessions[session.sessionRef]!.sid===proofs[1]!.sid);assert.equal(tokens(f).length,1);
  assert(after.grants[grant.grantRef]!.status==='active'&&after.grants[grant.grantRef]!.generation===before.grants[grant.grantRef]!.generation);
});
test('P21 invalid_session retains a valid account grant and the next explicit request can use it',async t=>{
  const f=await setup(t);const grant=await(await signIn(f)).complete();const session=await f.client.openPapSession(f.subjectRef,grant.accountSlot);const before=await f.client.store.read();const prior=f.transport.override;
  f.transport.override=(url,options)=>url.endsWith('/api/cart')?jsonResponse(url,{error:'invalid_session'},400):prior?.(url,options);
  await assert.rejects(f.client.dispatchPap(session.sessionRef,{url:origin+'/api/cart',scopes:['orders:read']}),fails('invalid_session'));assert.equal(resources(f).length,1);assert.equal(tokens(f).length,1);
  const after=await f.client.store.read();const a=after.grants[grant.grantRef]!;const b=before.grants[grant.grantRef]!;
  assert(a.status==='active'&&a.generation===b.generation&&a.accessToken===b.accessToken&&a.refreshToken===b.refreshToken);assert(after.sessions[session.sessionRef]!.sid===before.sessions[session.sessionRef]!.sid);
  f.transport.override=prior;assert.equal((await f.client.dispatchPap(session.sessionRef,{url:origin+'/api/cart',scopes:['orders:read']})).status,200);assert.equal(resources(f).length,2);assert.equal(tokens(f).length,1);
});

test('P23 selecting one account revokes all its stored resource refresh credentials and leaves another account usable',async t=>{
  const f=await setup(t);let issued=0;const prior=f.transport.override;const revoked:string[]=[];
  f.transport.override=(url,options)=>{
    if(url.endsWith('/token')){issued++;return jsonResponse(url,{access_token:'unit-access-'+issued,refresh_token:'unit-refresh-'+issued,token_type:'DPoP',expires_in:3600});}
    if(url.endsWith('/revoke')){const fields=new URLSearchParams(options!.body);assert.equal(fields.get('token_type_hint'),'refresh_token');revoked.push(fields.get('token')!);return jsonResponse(url,{});}
    return prior?.(url,options);
  };
  const selected=await(await signIn(f)).complete();const other=await(await signIn(f)).complete();const first=await f.client.openPapSession(f.subjectRef,selected.accountSlot);const second=await f.client.openPapSession(f.subjectRef,selected.accountSlot);const otherSession=await f.client.openPapSession(f.subjectRef,other.accountSlot);
  const extraRef=id('grant');
  // Controlled encrypted-storage fixture: no public API currently issues another resource grant into an existing slot.
  await f.client.store.transaction(state=>{
    state.companies[f.companyRef]!.routes.push({method:'GET',template:origin+'/other/cart',resource:origin+'/other'});
    state.companies[f.companyRef]!.metadata!.protected_resources.push(origin+'/other');
    state.grants[extraRef]={...structuredClone(state.grants[selected.grantRef]!),ref:extraRef,resource:origin+'/other',accessToken:'unit-selected-extra-access',refreshToken:'unit-selected-extra-refresh'};
  });
  const before=await f.client.store.read();const selectedA=before.grants[selected.grantRef]!;const selectedB=before.grants[extraRef]!;const kept=before.grants[other.grantRef]!;
  assert.equal((await f.client.signOutAccount(f.subjectRef,selected.accountSlot)).status,'signed_out');assert.equal(revoked.length,2);assert(revoked.includes(selectedA.refreshToken!)&&revoked.includes(selectedB.refreshToken!));assert(!revoked.includes(kept.refreshToken!));
  const after=await f.client.store.read();for(const ref of [selected.grantRef,extraRef]){assert.equal(after.grants[ref]!.status,'signed_out');assert(after.grants[ref]!.accessToken==='');assert(after.grants[ref]!.refreshToken===undefined);}
  assert(after.grants[other.grantRef]!.status==='active'&&after.grants[other.grantRef]!.generation===kept.generation&&after.grants[other.grantRef]!.refreshToken===kept.refreshToken);
  assert(after.accountSlots[other.accountSlot]!.epoch===before.accountSlots[other.accountSlot]!.epoch&&!after.accountSlots[other.accountSlot]!.signedOut);assert(after.accountSlots[selected.accountSlot]!.signedOut);
  assert(!after.sessions[first.sessionRef]!.accountSlot&&!after.sessions[second.sessionRef]!.accountSlot);assert(after.sessions[otherSession.sessionRef]!.accountSlot===other.accountSlot);
  assert.equal((await f.client.dispatchPap(otherSession.sessionRef,{url:origin+'/api/cart',scopes:['orders:read']})).status,200);assert(resources(f).at(-1)!.options!.headers!.authorization==='DPoP '+kept.accessToken);
});

test('P24 Company identifier change creates new User Agent and sid and cannot attach or send the old account token',async t=>{
  const f=await setup(t);const grant=await(await signIn(f)).complete();const oldSession=await f.client.openPapSession(f.subjectRef,grant.accountSlot);const before=await f.client.store.read();const oldSubject=before.subjects[f.subjectRef]!;const old=before.sessions[oldSession.sessionRef]!;
  f.transport.issuer='https://other-auth.shop.example';const company=await f.client.resolvePapCompany('shop.example');assert(company.companyId!==f.companyId&&company.companyRef!==f.companyRef);
  const subject=await f.client.getOrCreatePapUser(company.companyRef,'regular',true);const session=await f.client.openPapSession(subject.subjectRef);const after=await f.client.store.read();const next=after.subjects[subject.subjectRef]!;
  assert(next.userId!==oldSubject.userId&&next.agentId!==oldSubject.agentId&&after.sessions[session.sessionRef]!.sid!==old.sid);assert(next.companyId===company.companyId);assert(!Object.values(after.grants).some(value=>value.subjectRef===subject.subjectRef));
  const signatures=f.host.sessionCount;const calls=resources(f).length;
  await assert.rejects(f.client.dispatchPap(oldSession.sessionRef,{url:origin+'/api/cart',scopes:['orders:read']}),fails('namespace_changed'));assert.equal(f.host.sessionCount,signatures);assert.equal(resources(f).length,calls);
  await assert.rejects(f.client.openPapSession(subject.subjectRef,grant.accountSlot),fails('reauthorization_required'));
  assert.equal((await f.client.dispatchPap(session.sessionRef,{url:origin+'/api/cart'})).status,200);const sent=resources(f).at(-1)!;const payload=jwtParts(sent.options!.headers!['poppy-session']!).payload;
  assert(payload.aud===company.companyId&&payload.sub===next.userId&&payload.agent_id===next.agentId&&payload.sid===after.sessions[session.sessionRef]!.sid);assert(!Object.hasOwn(payload,'ath'));assert(!sent.options!.headers!.authorization&&!sent.options!.headers!.dpop);assert.equal(tokens(f).length,1);
  const final=await f.client.store.read();assert(final.grants[grant.grantRef]!.subjectRef===f.subjectRef&&final.grants[grant.grantRef]!.issuer===f.companyId);assert.equal(Object.keys(final.grants).length,1);
});
