/** Explicit local source integration: C Context authorization -> real A native custody -> F -> HTTPS. */
import assert from 'node:assert/strict';
import https from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { PapClient } from '../src/client.js';
import { SafeHttpsTransport } from '../src/network.js';
import { ProtocolIdentityHost } from '../src/protocol-adapter.js';
import { jwtParts } from '../src/util.js';
import { verifyCompact } from '../src/delegation.js';
import type { PublicJwk } from '../src/types.js';
import { secrets } from '../tests/fixture.js';
const fixturePath=resolve(process.argv[2]!);
const {createNativeProtocolFixture}=await import(pathToFileURL(fixturePath).href);
const fixture=await createNativeProtocolFixture({consumer:'@awiki/dsh-pap',profiles:['pap_session','pap_account'],issuers:['https://company.test'],resources:['https://company.test','https://company.test/api'],scopes:['orders:read']});
const root=await mkdtemp(join(tmpdir(),'pap-native-component-'));
let server:https.Server|undefined;
try {
  const binaryPath=resolve(dirname(fixturePath),'../../../../bindings/node/anp-identity.linux-x64-gnu.node');
  const nativeSha256=createHash('sha256').update(await readFile(binaryPath)).digest('hex');
  assert.equal(nativeSha256,'e2c4b86a0b3622aaefa70b44d3dc31cdab579b1237a4418d349bd294c52663ef');
  const discovery={profile:'pap_session' as const,issuer:'https://company.test',companyId:'https://company.test',resource:'https://company.test',allowedEndpoints:['https://company.test/api/cart'],metadataDigest:'a'.repeat(64),expiresAt:Date.now()+300000,sources:{resource:'https://company.test/.well-known/poppy.json',authorizationServer:'https://company.test/.well-known/poppy.json'}};
  const initial=await fixture.client.registerValidatedTarget({identityRef:fixture.reference,policyRef:fixture.policyRef,discovery,requestedScopes:[]});const identity=await initial.getOAuthClientIdentity();initial.dispose();
  const binding={identityRef:fixture.reference,ownerRef:'native-component-owner',clientId:identity.clientId};
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(root,'tls.key'),'-out',join(root,'tls.crt'),'-days','1','-subj','/CN=company.test','-addext','subjectAltName=DNS:company.test'],{stdio:'ignore'});
  const ca=await readFile(join(root,'tls.crt'));let priorSid='';let requests=0;
  server=https.createServer({key:await readFile(join(root,'tls.key')),cert:ca},(request,response)=>{
    response.setHeader('content-type','application/json');
    if(request.url==='/.well-known/poppy.json')return response.end(JSON.stringify({protocol_version:'0.3',organization:{name:'Native component',domain:'company.test'},apis:[{type:'openapi',url:'https://company.test/openapi.json'}]}));
    if(request.url==='/.well-known/oauth-protected-resource'){response.statusCode=404;return response.end('{}');}
    if(request.url==='/openapi.json')return response.end(JSON.stringify({openapi:'3.1.0',servers:[{url:'https://company.test'}],paths:{'/api/cart':{get:{}}}}));
    try{
      assert.equal(request.url,'/api/cart');const compact=request.headers['poppy-session'];assert.equal(typeof compact,'string');const {header,payload}=jwtParts(compact as string);const delegation=jwtParts(header.poppy_dlg as string);
      assert(verifyCompact(header.poppy_dlg as string,identity.publicJwk));assert(verifyCompact(compact as string,(delegation.payload.cnf as {jwk:PublicJwk}).jwk));assert.equal(payload.iss,identity.clientId);assert.equal(payload.aud,'https://company.test');assert.equal(payload.htm,'GET');assert.equal(payload.htu,'https://company.test/api/cart');assert.equal(payload.ath,undefined);
      if(priorSid)assert.equal(priorSid,payload.sid);else priorSid=String(payload.sid);requests++;response.end(JSON.stringify({visits:requests}));
    }catch{response.statusCode=401;response.end(JSON.stringify({error:'invalid_session'}));}
  });
  await new Promise<void>(resolve=>server!.listen(0,'127.0.0.1',resolve));const port=(server.address() as {port:number}).port;
  const transport=new SafeHttpsTransport({ca,privateOrigins:['https://company.test'],portOverrides:{'https://company.test':port},lookup:async()=>[{address:'127.0.0.1',family:4}]});
  const host=new ProtocolIdentityHost(fixture.client,fixture.policyRef);
  const options={stateRoot:join(root,'state'),binding,secretStore:secrets,identityHost:host};
  const client=new PapClient(options,transport);const company=await client.resolvePapCompany('company.test');const subject=await client.getOrCreatePapUser(company.companyRef);const session=await client.openPapSession(subject.subjectRef);
  assert.equal((await client.dispatchPap(session.sessionRef,{url:'https://company.test/api/cart'})).status,200);await client.rotateDelegation(subject.subjectRef);assert.equal((await client.dispatchPap(session.sessionRef,{url:'https://company.test/api/cart'})).status,200);
  client.close();
  const restoredHost=new ProtocolIdentityHost(fixture.client,fixture.policyRef);const restarted=new PapClient({...options,identityHost:restoredHost},transport);await restarted.recover();assert.equal((await restarted.dispatchPap(session.sessionRef,{url:'https://company.test/api/cart'})).status,200);restarted.close();
  assert.equal(requests,3);console.log(JSON.stringify({passed:true,lane:'real-C-context-A-native-F-HTTPS',nativeSha256,sessionRequests:requests,delegationRotated:true,keyRestoredAfterRestart:true,publication:'explicit-fixture-acceptance',accountOAuth:'not-run',secretStore:'isolated-test-master'}));
}finally{
  if(server)await new Promise<void>((resolve,reject)=>server!.close(error=>error?reject(error):resolve()));await fixture.dispose();await rm(root,{recursive:true,force:true});
}
