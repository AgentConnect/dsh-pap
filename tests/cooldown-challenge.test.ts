import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { execFileSync, spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PapClient } from '../src/client.js';
import { PapError } from '../src/errors.js';
import { asCooldownKey, resourceCooldownKey, retryAfterUntil } from '../src/cooldown.js';
import { parseAuthenticate } from '../src/auth-challenge.js';
import { SafeHttpsTransport } from '../src/network.js';
import { binding, FixtureHost, FixtureTransport, jsonResponse, secretKey, secrets } from './fixture.js';
const fails=(code:string)=>(error:unknown)=>error instanceof PapError&&error.code===code;
const sleep=(ms:number)=>new Promise(resolve=>setTimeout(resolve,ms));
async function setup(t:test.TestContext, account=false, sameOrigin=false, clock?:()=>number){
  const root=await mkdtemp(join(tmpdir(),'pap-cooldown-'));t.after(()=>rm(root,{recursive:true,force:true}));const host=new FixtureHost();const transport=new FixtureTransport();transport.mode=account?'account':'none';if(sameOrigin)transport.issuer='https://shop.example';
  const options={binding,stateRoot:root,identityHost:host,secretStore:secrets,...(clock?{clock}:{}),callbackHandoff:{register:async()=>({callbackRef:'fixture-claim'}),collect:async()=>({})}};
  const client=new PapClient(options,transport);const company=await client.resolvePapCompany('shop.example');const subject=await client.getOrCreatePapUser(company.companyRef);const session=await client.openPapSession(subject.subjectRef);return {root,host,transport,options,client,...company,...subject,...session};
}
async function account(f:Awaited<ReturnType<typeof setup>>, bearer=false){
  if(bearer)f.transport.override=url=>url.endsWith('/token')?jsonResponse(url,{access_token:'fixture-bearer',refresh_token:'fixture-refresh',token_type:'Bearer'}):undefined;
  const auth=await f.client.startSignIn(f.subjectRef,{scopes:['orders:read'],resource:'https://shop.example',redirectUri:'https://agent.example/pap-callback',callbackMode:'handoff'});const tx=(await f.client.store.read()).transactions[auth.transactionRef]!;const grant=await f.client.completeSignIn(auth.transactionRef,{state:tx.state,iss:tx.issuer,code:'fixture-code'});const session=await f.client.openPapSession(f.subjectRef,grant.accountSlot);return {...grant,...session};
}

test('P22 Retry-After preserves long integer fences and parses HTTP-date formats',()=>{
  const now=Date.UTC(2026,10,6,0,0,0);assert.equal(BigInt(retryAfterUntil('3601',now)),BigInt(now)+3601000n);
  assert.equal(retryAfterUntil('Fri, 06 Nov 2026 00:00:01 GMT',now),String(now+1000));assert.equal(retryAfterUntil('Friday, 06-Nov-26 00:00:01 GMT',now),String(now+1000));assert.equal(retryAfterUntil('Fri Nov  6 00:00:01 2026',now),String(now+1000));
  const enormous='9'.repeat(80);assert(BigInt(retryAfterUntil(enormous,now))>BigInt(Number.MAX_SAFE_INTEGER));assert.equal(retryAfterUntil('invalid',now),String(now+1000));
});

test('P22 actual HTTPS short cooldown blocks cross-instance signatures and sends; original 429 is not retried',async t=>{
  const root=await mkdtemp(join(tmpdir(),'pap-cooldown-https-'));t.after(()=>rm(root,{recursive:true,force:true}));execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(root,'key'),'-out',join(root,'crt'),'-days','1','-subj','/CN=company.test','-addext','subjectAltName=DNS:company.test'],{stdio:'ignore'});const ca=await readFile(join(root,'crt'));const calls:{at:number;method:string}[]=[];
  const server=https.createServer({key:await readFile(join(root,'key')),cert:ca},(req,res)=>{
    res.setHeader('content-type','application/json');if(req.url==='/.well-known/poppy.json')return res.end(JSON.stringify({protocol_version:'0.3',organization:{name:'Cooldown',domain:'company.test'},apis:[{type:'openapi',url:'https://company.test/openapi.json'}]}));
    if(req.url==='/.well-known/oauth-protected-resource'){res.statusCode=404;return res.end('{}');}if(req.url==='/openapi.json')return res.end(JSON.stringify({openapi:'3.1.0',servers:[{url:'https://company.test'}],paths:{'/api/cart':{get:{},post:{}}}}));
    assert.equal(req.url,'/api/cart');assert(req.headers['poppy-session']);calls.push({at:Date.now(),method:req.method!});if(calls.length===1){res.statusCode=429;res.setHeader('retry-after','1');}res.end('{}');
  });await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise<void>((resolve,reject)=>server.close(error=>error?reject(error):resolve())));
  const host=new FixtureHost();const transport=new SafeHttpsTransport({ca,privateOrigins:['https://company.test'],portOverrides:{'https://company.test':(server.address()as{port:number}).port},lookup:async()=>[{address:'127.0.0.1',family:4}]});const options={binding,stateRoot:join(root,'state'),identityHost:host,secretStore:secrets};const first=new PapClient(options,transport);const c=await first.resolvePapCompany('company.test');const subject=await first.getOrCreatePapUser(c.companyRef);const session=await first.openPapSession(subject.subjectRef);
  await assert.rejects(first.dispatchPap(session.sessionRef,{url:'https://company.test/api/cart',method:'POST',body:'{}'}),fails('rate_limited'));assert.equal(calls.length,1);const signatures=host.sessionCount;const delegations=host.delegationCount;
  const second=new PapClient(options,transport);const third=new PapClient(options,transport);const pending=[second.dispatchPap(session.sessionRef,{url:'https://company.test/api/cart'}),third.dispatchPap(session.sessionRef,{url:'https://company.test/api/cart'})];await sleep(100);assert.equal(host.sessionCount,signatures);assert.equal(host.delegationCount,delegations);assert.equal(calls.length,1);await Promise.all(pending);assert.equal(calls.length,3);assert(calls.slice(1).every(call=>call.at-calls[0]!.at>=990));
});

test('P22 HTTP-date fence survives a new Node process before any signer or network',async t=>{
  const f=await setup(t);const until=Date.now()+60000;f.transport.override=url=>url.includes('/api/cart')?jsonResponse(url,{},429,{'retry-after':new Date(until).toUTCString()}):undefined;await assert.rejects(f.client.dispatchPap(f.sessionRef,{url:'https://shop.example/api/cart'}),fails('rate_limited'));
  const child=spawn(process.execPath,['--import',fileURLToPath(new URL('../node_modules/tsx/dist/loader.mjs',import.meta.url)),fileURLToPath(new URL('./helpers/cooldown-child.ts',import.meta.url))],{stdio:['pipe','pipe','pipe']});let output='';child.stdout.on('data',value=>output+=String(value));child.stderr.resume();child.stdin.end(JSON.stringify({stateRoot:f.root,binding,master:secretKey.toString('base64url'),sessionRef:f.sessionRef,operation:{url:'https://shop.example/api/cart'}}));const code=await new Promise<number|null>(resolve=>child.once('close',resolve));assert.equal(code,0);const result=JSON.parse(output);assert.equal(result.code,'rate_limited');assert(Number(result.retryAfterSeconds)>50);assert.equal(result.signerCalls,0);assert.equal(result.networkCalls,0);
});

test('P22 long cooldown is not capped to 300 and is shared by sessions/instances',async t=>{
  const f=await setup(t);f.transport.override=url=>url.includes('/api/cart')?jsonResponse(url,{},429,{'retry-after':'3601'}):undefined;const started=Date.now();await assert.rejects(f.client.dispatchPap(f.sessionRef,{url:'https://shop.example/api/cart'}),error=>error instanceof PapError&&Number(error.retryAfterSeconds)>3600);const state=await f.client.store.read();assert(BigInt(state.cooldowns[resourceCooldownKey(f.companyId,'https://shop.example')]!.notBeforeMs)>=BigInt(started)+3601000n);const count=f.host.sessionCount;const other=new PapClient(f.options,f.transport);const session=await other.openPapSession(f.subjectRef);await assert.rejects(other.dispatchPap(session.sessionRef,{url:'https://shop.example/api/cart'}),fails('rate_limited'));assert.equal(f.host.sessionCount,count);assert.equal(f.transport.calls.filter(call=>call.url.includes('/api/cart')).length,1);
});

for(const action of ['disconnect','close','signout']as const)test(`P22 ${action} cancels an inline wait while the persisted fence remains`,{timeout:15000},async t=>{
  const now=Date.now();const f=await setup(t,action==='signout',false,()=>now);
  const current=action==='signout'?await account(f):{sessionRef:f.sessionRef,accountSlot:undefined};
  f.transport.override=url=>url.includes('/api/cart')?jsonResponse(url,{},429,{'retry-after':'1'}):undefined;
  await assert.rejects(f.client.dispatchPap(current.sessionRef,{url:'https://shop.example/api/cart'}),fails('rate_limited'));const count=f.host.sessionCount;
  let observed:()=>void=()=>{};const waiting=new Promise<void>(resolve=>observed=resolve);const read=f.client.store.read.bind(f.client.store);let reads=0;
  f.client.store.read=async()=>{const state=await read();if(++reads>=2)observed();return state;};
  const pending=f.client.dispatchPap(current.sessionRef,{url:'https://shop.example/api/cart'}).then(()=>'',error=>(error as PapError).code);
  await waiting;
  const stopped=action==='disconnect'?new PapClient(f.options,f.transport).disconnectPap(current.sessionRef):action==='close'?Promise.resolve(f.client.close()):f.client.signOutAccount(f.subjectRef,current.accountSlot!);
  const code=await pending;assert.equal(code,action==='signout'?'reauthorization_required':'disconnected');await stopped;
  assert.equal(f.host.sessionCount,count);assert.equal(f.transport.calls.filter(call=>call.url.includes('/api/cart')).length,1);
  assert(Object.keys((await f.client.store.read()).cooldowns).length>0);
});

test('P22 scope and lease are rechecked after cooldown without signing or sending',async t=>{
  const f=await setup(t,true);const current=await account(f);f.transport.override=url=>url.includes('/api/cart')?jsonResponse(url,{},429,{'retry-after':'1'}):undefined;await assert.rejects(f.client.dispatchPap(current.sessionRef,{url:'https://shop.example/api/cart'}),fails('rate_limited'));const count=f.host.sessionCount;const pending=f.client.dispatchPap(current.sessionRef,{url:'https://shop.example/api/cart',scopes:['orders:read']});await sleep(80);await f.client.store.transaction(state=>{state.grants[current.grantRef]!.scope=[];});await assert.rejects(pending,fails('insufficient_scope'));assert.equal(f.host.sessionCount,count);
  const g=await setup(t);g.transport.override=url=>url.includes('/api/cart')?jsonResponse(url,{},429,{'retry-after':'1'}):undefined;await assert.rejects(g.client.dispatchPap(g.sessionRef,{url:'https://shop.example/api/cart'}),fails('rate_limited'));const before=g.host.sessionCount;const revoked=g.client.dispatchPap(g.sessionRef,{url:'https://shop.example/api/cart'});await sleep(80);g.host.active=false;await assert.rejects(revoked,fails('permission_denied'));assert.equal(g.host.sessionCount,before);
});

test('P22 AS cooldown blocks assertions across clients but not a valid resource call on the same origin',async t=>{
  const f=await setup(t,true,true);const current=await account(f);let first=true;f.transport.override=(url,options)=>{if(url.endsWith('/token')&&new URLSearchParams(options!.body).get('grant_type')==='refresh_token'){if(first){first=false;return jsonResponse(url,{},429,{'retry-after':'1'});}return jsonResponse(url,{access_token:'after-as-window',token_type:'DPoP',expires_in:3600});}};
  await assert.rejects(f.client.refreshAccountGrant(current.grantRef),fails('rate_limited'));assert.equal((await f.client.store.read()).grants[current.grantRef]!.status,'active');const assertions=f.host.assertionCount;const tokenCalls=f.transport.calls.filter(call=>call.url.endsWith('/token')).length;const other=new PapClient(f.options,f.transport);const pending=other.refreshAccountGrant(current.grantRef);await sleep(80);assert.equal(f.host.assertionCount,assertions);assert.equal(f.transport.calls.filter(call=>call.url.endsWith('/token')).length,tokenCalls);assert.equal((await f.client.dispatchPap(current.sessionRef,{url:'https://shop.example/api/cart'})).status,200);await pending;assert.equal(f.host.assertionCount,assertions+1);
  f.transport.override=url=>url.includes('/api/cart')?jsonResponse(url,{},429,{'retry-after':'3601'}):undefined;await assert.rejects(f.client.dispatchPap(current.sessionRef,{url:'https://shop.example/api/cart'}),fails('rate_limited'));const prior=f.host.assertionCount;await f.client.refreshAccountGrant(current.grantRef);assert.equal(f.host.assertionCount,prior+1);const state=await f.client.store.read();assert(state.cooldowns[asCooldownKey(f.companyId,f.transport.issuer)]);assert(state.cooldowns[resourceCooldownKey(f.companyId,'https://shop.example')]);
});

test('P22 disconnect cancels a dispatch waiting for AS refresh before a client assertion',{timeout:15000},async t=>{
  const now=Date.now();const f=await setup(t,true,false,()=>now);const current=await account(f);
  f.transport.override=(url,options)=>url.endsWith('/token')&&new URLSearchParams(options!.body).get('grant_type')==='refresh_token'?jsonResponse(url,{},429,{'retry-after':'1'}):undefined;
  await assert.rejects(f.client.refreshAccountGrant(current.grantRef),fails('rate_limited'));
  await f.client.store.transaction(state=>{state.grants[current.grantRef]!.expiresAt=now-1;});const before=f.host.assertionCount;
  let observed:()=>void=()=>{};const refreshing=new Promise<void>(resolve=>observed=resolve);const read=f.client.store.read.bind(f.client.store);
  f.client.store.read=async()=>{const state=await read();if(state.grants[current.grantRef]?.status==='refreshing')observed();return state;};
  const pending=f.client.dispatchPap(current.sessionRef,{url:'https://shop.example/api/cart'}).then(()=>'',error=>(error as PapError).code);
  await refreshing;await f.client.disconnectPap(current.sessionRef);assert.equal(await pending,'disconnected');
  assert.equal(f.host.assertionCount,before);assert.equal(f.transport.calls.filter(call=>call.url.includes('/api/cart')).length,0);
});

test('P22 challenge-only Bearer takes precedence and exposes only safe management hints',async t=>{
  const f=await setup(t,true);const current=await account(f,true);const before=f.transport.calls.length;const assertions=f.host.assertionCount;const secret='REMOTE-DESCRIPTION-MUST-NOT-ESCAPE';f.transport.override=url=>url.includes('/api/cart')?jsonResponse(url,{error:'invalid_token',error_description:secret},403,{'www-authenticate':`Basic realm="other, realm", Bearer realm="ignored", error="insufficient_scope", scope="orders:read", resource_metadata="https://shop.example/.well-known/oauth-protected-resource", error_description="${secret}"`}):undefined;
  let caught:PapError|undefined;try{await f.client.dispatchPap(current.sessionRef,{url:'https://shop.example/api/cart'});}catch(error){caught=error as PapError;}assert.equal(caught?.code,'insufficient_scope');assert.deepEqual(caught?.authHint,{scheme:'Bearer',scope:['orders:read'],resourceMetadataUrl:'https://shop.example/.well-known/oauth-protected-resource'});assert(!JSON.stringify(caught).includes(secret));assert(!caught!.message.includes(secret));assert.equal(f.host.assertionCount,assertions);assert.equal(f.transport.calls.length,before+1);assert.deepEqual((await f.client.store.read()).grants[current.grantRef]!.scope,['orders:read']);
});

test('P22 DPoP empty-JSON challenge rejects unsafe replay; untrusted hint URLs/scopes are dropped',async t=>{
  const f=await setup(t,true);const current=await account(f);const assertions=f.host.assertionCount;f.transport.override=url=>url.includes('/api/cart')?jsonResponse(url,{},401,{'www-authenticate':'dPoP realm="ignored, escaped\\\"realm", error="invalid_token", scope="unknown-admin", resource_metadata="https://127.0.0.1/.well-known/oauth-protected-resource?secret=hidden"'}):undefined;
  let caught:PapError|undefined;try{await f.client.dispatchPap(current.sessionRef,{url:'https://shop.example/api/cart',method:'POST',body:'{}',idempotencyKey:'explicit-business-id'});}catch(error){caught=error as PapError;}assert.equal(caught?.code,'invalid_token');assert.deepEqual(caught?.authHint,{scheme:'DPoP'});assert.equal(f.host.assertionCount,assertions);assert.equal(f.transport.calls.filter(call=>call.url.includes('/api/cart')).length,1);assert(!JSON.stringify(caught).includes('hidden'));
  const parsed=parseAuthenticate('Negotiate opaque==, Bearer error="invalid_token", DPoP error="insufficient_scope", scope="orders:read"');assert.equal(parsed.challenges.length,2);
});

test('P22 duplicate challenge parameters fail closed without refresh or metadata access',async t=>{
  const f=await setup(t,true);const current=await account(f);const count=f.transport.calls.length;const before=f.host.assertionCount;f.transport.override=url=>url.includes('/api/cart')?jsonResponse(url,{},401,{'www-authenticate':'DPoP error="invalid_token", ERROR="insufficient_scope", resource_metadata="https://evil.example/token"'}):undefined;await assert.rejects(f.client.dispatchPap(current.sessionRef,{url:'https://shop.example/api/cart'}),fails('oauth_error'));assert.equal(f.host.assertionCount,before);assert.equal(f.transport.calls.length,count+1);
});

test('P22 final actual lease is rechecked after a suspended state-key resolver before any HTTP start',async t=>{
  const f=await setup(t);let arm=false;let entered:()=>void=()=>{};let resume:()=>void=()=>{};const blocked=new Promise<void>(resolve=>entered=resolve);const gate=new Promise<void>(resolve=>resume=resolve);const acquire=f.host.acquire.bind(f.host);f.host.acquire=async(...args)=>{const lease=await acquire(...args);return {...lease,signPapSessionRequest:async input=>{const jwt=await lease.signPapSessionRequest(input);arm=true;return jwt;}};};let once=true;
  const secretStore={...secrets,getEncryptionKey:async()=>{if(arm&&once){once=false;entered();await gate;}return secretKey;}};const client=new PapClient({...f.options,secretStore},f.transport);const pending=client.dispatchPap(f.sessionRef,{url:'https://shop.example/api/cart'});await blocked;f.host.active=false;resume();await assert.rejects(pending,fails('permission_denied'));assert.equal(f.host.sessionCount,1);assert.equal(f.transport.calls.filter(call=>call.url.includes('/api/cart')).length,0);
});

test('P22 a concurrent refresh waiter receives the persisted AS rate limit instead of false reauthorization',async t=>{
  const f=await setup(t,true);const current=await account(f);let release:()=>void=()=>{};let entered:()=>void=()=>{};const started=new Promise<void>(resolve=>entered=resolve);
  f.transport.override=(url,options)=>url.endsWith('/token')&&new URLSearchParams(options!.body).get('grant_type')==='refresh_token'?new Promise(resolve=>{release=()=>resolve(jsonResponse(url,{},429,{'retry-after':'60'}));entered();}):undefined;
  const capture=(promise:Promise<unknown>)=>promise.then(()=>'',error=>(error as PapError).code);const first=capture(f.client.refreshAccountGrant(current.grantRef));await started;const other=new PapClient(f.options,f.transport);const second=capture(other.refreshAccountGrant(current.grantRef));await sleep(80);release();assert.equal(await first,'rate_limited');assert.equal(await second,'rate_limited');assert.equal((await f.client.store.read()).grants[current.grantRef]!.status,'active');assert.equal(f.transport.calls.filter(call=>call.url.endsWith('/token')).length,2);
});

test('P22 matching DPoP challenge wins over another scheme and unsafe metadata never becomes a request',async t=>{
  const f=await setup(t,true);const current=await account(f);const before=f.host.assertionCount;const count=f.transport.calls.length;
  f.transport.override=url=>url.includes('/api/cart')?jsonResponse(url,{},403,{'www-authenticate':'Bearer error="invalid_token", DPoP error="insufficient_scope", scope="orders:read", resource_metadata="https://shop.example/token"'}):undefined;
  let caught:PapError|undefined;try{await f.client.dispatchPap(current.sessionRef,{url:'https://shop.example/api/cart'});}catch(error){caught=error as PapError;}assert.equal(caught?.code,'insufficient_scope');assert.deepEqual(caught?.authHint,{scheme:'DPoP',scope:['orders:read']});assert.equal(f.host.assertionCount,before);assert.equal(f.transport.calls.length,count+1);
});

test('P06 fixture client retains issuer while disabled sign-in allows valid refresh then rejects invalid_grant',async t=>{
  const f=await setup(t,true);const current=await account(f);f.transport.mode='disabled';f.transport.override=url=>url.endsWith('/.well-known/poppy.json')?jsonResponse(url,{protocol_version:'0.3',organization:{name:'Disabled Company',domain:'shop.example'},auth:{issuer:f.transport.issuer,disabled:true},apis:[{type:'openapi',url:'https://shop.example/openapi.json'}]}):undefined;const discovered=await f.client.resolvePapCompany('shop.example');assert.equal(discovered.authMode,'disabled');assert.equal(discovered.companyId,f.transport.issuer);
  await assert.rejects(f.client.startSignIn(f.subjectRef,{scopes:['orders:read'],resource:'https://shop.example',redirectUri:'https://agent.example/pap-callback',callbackMode:'handoff'}),fails('unsupported_sign_in'));
  f.transport.override=(url,options)=>url.endsWith('/token')&&new URLSearchParams(options!.body).get('grant_type')==='refresh_token'?jsonResponse(url,{access_token:'valid-disabled-refresh',token_type:'DPoP',expires_in:3600}):undefined;
  await f.client.refreshAccountGrant(current.grantRef);assert.equal((await f.client.dispatchPap(current.sessionRef,{url:'https://shop.example/api/cart'})).status,200);assert.equal((await f.client.store.read()).grants[current.grantRef]!.status,'active');
  f.transport.override=(url,options)=>url.endsWith('/token')&&new URLSearchParams(options!.body).get('grant_type')==='refresh_token'?jsonResponse(url,{error:'invalid_grant'},400):undefined;
  await assert.rejects(f.client.refreshAccountGrant(current.grantRef),fails('reauthorization_required'));const state=await f.client.store.read();assert.equal(state.grants[current.grantRef]!.status,'reauthorization_required');assert.equal(state.companies[f.companyRef]!.companyId,f.transport.issuer);assert.equal(state.companies[f.companyRef]!.authMode,'disabled');assert.equal((await f.client.dispatchPap(f.sessionRef,{url:'https://shop.example/api/cart'})).status,200);
  const grants=f.transport.calls.filter(call=>call.url.endsWith('/token')).map(call=>new URLSearchParams(call.options!.body).get('grant_type'));assert.deepEqual(grants,['authorization_code','refresh_token','refresh_token']);
});

test('P22 nonstandard Session or legacy errors in OAuth challenges cannot restart sid or replay POST',async t=>{
  const f=await setup(t,true);const current=await account(f);const sid=(await f.client.store.read()).sessions[current.sessionRef]!.sid;const before=f.host.assertionCount;
  for(const error of ['session_ended','invalid_session','sign_in_required']){const calls=f.transport.calls.length;f.transport.override=url=>url.includes('/api/cart')?jsonResponse(url,{},401,{'www-authenticate':`DPoP error="${error}"`}):undefined;await assert.rejects(f.client.dispatchPap(current.sessionRef,{url:'https://shop.example/api/cart',method:'POST',body:'{}'}),fails('oauth_error'));assert.equal(f.transport.calls.length,calls+1);assert.equal((await f.client.store.read()).sessions[current.sessionRef]!.sid,sid);}
  assert.equal(f.host.assertionCount,before);
});

test('P22 an expiring code transaction stops during AS cooldown before signing or HTTP',async t=>{
  const f=await setup(t,true);const current=await account(f);f.transport.override=(url,options)=>url.endsWith('/token')&&new URLSearchParams(options!.body).get('grant_type')==='refresh_token'?jsonResponse(url,{},429,{'retry-after':'1'}):undefined;await assert.rejects(f.client.refreshAccountGrant(current.grantRef),fails('rate_limited'));
  const auth=await f.client.startSignIn(f.subjectRef,{scopes:['orders:read'],resource:'https://shop.example',redirectUri:'https://agent.example/pap-callback',callbackMode:'handoff'});const tx=await f.client.store.transaction(state=>{state.transactions[auth.transactionRef]!.expiresAt=Date.now()+300;return state.transactions[auth.transactionRef]!;});const assertions=f.host.assertionCount;const calls=f.transport.calls.length;const started=Date.now();await assert.rejects(f.client.completeSignIn(auth.transactionRef,{state:tx.state,iss:tx.issuer,code:'expired-local-code'}),fails('reauthorization_required'));assert(Date.now()-started<800);assert.equal(f.host.assertionCount,assertions);assert.equal(f.transport.calls.length,calls);
});
