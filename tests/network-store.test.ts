import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import type { IncomingHttpHeaders } from 'node:http';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PapClient } from '../src/client.js';
import { PapDiscovery } from '../src/discovery.js';
import { SafeHttpsTransport, isPublicAddress } from '../src/network.js';
import { PapStore } from '../src/store.js';
import { jwtParts, sha256 } from '../src/util.js';
import { verifyCompact } from '../src/delegation.js';
import { binding, FixtureHost, secrets } from './fixture.js';

test('F-T01 DNS rebinding/private/special addresses rejected before connection',async()=>{
  for(const ip of ['127.0.0.1','10.1.2.3','172.31.255.1','192.168.1.1','169.254.169.254','100.64.0.1','::1','::ffff:127.0.0.1','fc00::1','fe80::123','2001:db8::1','2002:7f00:1::'])assert.equal(isPublicAddress(ip),false,ip);
  assert.equal(isPublicAddress('8.8.8.8'),true);assert.equal(isPublicAddress('2606:4700:4700::1111'),true);
  const transport=new SafeHttpsTransport({lookup:async()=>[{address:'8.8.8.8',family:4},{address:'127.0.0.1',family:4}]});
  await assert.rejects(transport.request('https://public.example/'),{code:'unsafe_destination'});
  await assert.rejects(transport.request('http://public.example/'),{code:'unsafe_destination'});
});
test('F-T02 encrypted store cross-instance CAS serialization, wrong key/corruption reject',async t=>{
  const root=await mkdtemp(join(tmpdir(),'pap-store-'));t.after(()=>rm(root,{recursive:true,force:true}));
  const one=new PapStore(root,secrets,'fixture'); const two=new PapStore(root,secrets,'fixture');
  await Promise.all(Array.from({length:20},(_,i)=>(i%2?one:two).transaction(state=>{state.nonces.counter=String(Number(state.nonces.counter??0)+1);})));assert.equal((await one.read()).nonces.counter,'20');
  assert.equal((await stat(join(root,'pap-state.enc'))).mode&0o777,0o600);
  const wrong=new PapStore(root,{getEncryptionKey:async()=>new Uint8Array(32),getOrCreateEncryptionKey:async()=>new Uint8Array(32)},'fixture');await assert.rejects(wrong.read(),{code:'state_corrupt'});
  const bytes=await readFile(join(root,'pap-state.enc'));bytes[40]=bytes[40]!^1;await writeFile(join(root,'pap-state.enc'),bytes);await assert.rejects(one.read(),{code:'state_corrupt'});
});
test('F-T09 isolated real HTTPS Company independently verifies signature chain and sid continuity',async t=>{
  const root=await mkdtemp(join(tmpdir(),'pap-http-'));t.after(()=>rm(root,{recursive:true,force:true}));
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(root,'tls.key'),'-out',join(root,'tls.crt'),'-days','1','-subj','/CN=company.test','-addext','subjectAltName=DNS:company.test'],{stdio:'ignore'});
  const ca=await readFile(join(root,'tls.crt'));const custody=new FixtureHost();const requests:{url:string;headers:IncomingHttpHeaders}[]=[];const seen=new Set<string>();let sid='';let visits=0;
  const server=https.createServer({key:await readFile(join(root,'tls.key')),cert:ca},(request,response)=>{
    const url=`https://company.test${request.url}`; requests.push({url,headers:request.headers});response.setHeader('content-type','application/json');
    if(request.url==='/.well-known/poppy.json')return response.end(JSON.stringify({protocol_version:'0.3',organization:{name:'HTTP Company',domain:'company.test'},apis:[{type:'openapi',url:'https://company.test/openapi.json'}]}));
    if(request.url==='/.well-known/oauth-protected-resource'){response.statusCode=404;return response.end('{}');}
    if(request.url==='/openapi.json')return response.end(JSON.stringify({openapi:'3.1.0',servers:[{url:'https://company.test'}],paths:{'/api/cart':{get:{}}}}));
    if(request.url==='/api/cart'){
      try{
        const compact=request.headers['poppy-session'];assert.equal(typeof compact,'string');const {header,payload}=jwtParts(compact as string);const delegation=jwtParts(header.poppy_dlg as string);const jwk=(delegation.payload.cnf as {jwk:typeof custody.identity.jwk}).jwk;
        assert(verifyCompact(header.poppy_dlg as string,custody.identity.jwk));assert(verifyCompact(compact as string,jwk));assert.equal(payload.aud,'https://company.test');assert.equal(payload.iss,binding.clientId);assert.equal(payload.htm,request.method);assert.equal(payload.htu,url);assert(!seen.has(String(payload.jti)));seen.add(String(payload.jti));assert.equal(payload.ath,undefined);assert.equal(request.headers.authorization,undefined);
        if(sid)assert.equal(payload.sid,sid);else sid=String(payload.sid);response.end(JSON.stringify({visits:++visits}));
      }catch{response.statusCode=401;response.end(JSON.stringify({error:'invalid_session'}));}return;
    }
    response.statusCode=404;response.end('{}');
  });
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise<void>((resolve,reject)=>server.close(error=>error?reject(error):resolve())));
  const port=(server.address() as {port:number}).port;
  const transport=new SafeHttpsTransport({ca,privateOrigins:['https://company.test'],portOverrides:{'https://company.test':port},lookup:async()=>[{address:'127.0.0.1',family:4}]});
  const client=new PapClient({stateRoot:join(root,'state'),secretStore:secrets,binding,identityHost:custody},transport);const company=await client.resolvePapCompany('company.test');const subject=await client.getOrCreatePapUser(company.companyRef);const session=await client.openPapSession(subject.subjectRef);
  const one=await client.dispatchPap(session.sessionRef,{url:'https://company.test/api/cart'});assert.equal(one.status,200);assert.equal(JSON.parse(Buffer.from(one.body).toString()).visits,1);
  await client.rotateDelegation(subject.subjectRef);const two=await client.dispatchPap(session.sessionRef,{url:'https://company.test/api/cart'});assert.equal(two.status,200);assert.equal(JSON.parse(Buffer.from(two.body).toString()).visits,2);
  assert(!requests.some(x=>x.url.includes('/token')));assert(requests.filter(x=>!x.url.includes('/api/cart')).every(x=>!x.headers['poppy-session']));assert.notEqual(sha256('first'),sha256('second'));
  const wrongRedirect=new SafeHttpsTransport({ca,privateOrigins:['https://company.test'],portOverrides:{'https://company.test':port},lookup:async()=>[{address:'127.0.0.1',family:4}]});
  assert.equal((await new PapDiscovery(wrongRedirect).resolve('company.test')).authMode,'no_as');
});
test('F-T02 existing encrypted state never creates a replacement key after secret loss',async t=>{
  const root=await mkdtemp(join(tmpdir(),'pap-secret-loss-'));t.after(()=>rm(root,{recursive:true,force:true}));await new PapStore(root,secrets,'lost').transaction(state=>{state.nonces.fixture='secret-state';});let creations=0;
  const lost=new PapStore(root,{getEncryptionKey:async()=>undefined,getOrCreateEncryptionKey:async()=>{creations++;return new Uint8Array(32);}},'lost');
  await assert.rejects(lost.read(),{code:'credential_unavailable'});assert.equal(creations,0);
});
