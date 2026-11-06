/** Controlled P18 HTTPS wire differences, not a third-party AS, System Test or GUI lane. */
import assert from 'node:assert/strict';
import https from 'node:https';
import http from 'node:http';
import { execFileSync } from 'node:child_process';
import { createHash,createPublicKey,randomBytes,verify } from 'node:crypto';
import { mkdtemp,readFile,readdir,rm,stat } from 'node:fs/promises';
import { dirname,join,resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { PapClient } from '../src/client.js';
import { ProtocolIdentityHost,type ProtocolIdentityClient } from '../src/protocol-adapter.js';
import type { PapIdentityHost } from '../src/host.js';
import { KeyringSecretStore } from '../src/keyring.js';
import { SafeHttpsTransport } from '../src/network.js';
import { strictJson } from '../src/strict-json.js';
import { sha256 } from '../src/util.js';
import { createSecretServiceSidecar } from './helpers/secret-service-sidecar.js';

const [helperInput,bSource,python,expectedNative]=process.argv.slice(2);
assert(helperInput&&bSource&&python&&expectedNative,'Explicit fresh C helper, B source, Python and frozen native SHA are required');
const helperPath=resolve(helperInput);const cRoot=resolve(dirname(helperPath),'../..');const root=await mkdtemp(join(tmpdir(),'pap-p18-wire-'));
const digest=(bytes:string|Uint8Array)=>createHash('sha256').update(bytes).digest('hex');
const sourceHashes=async(directory:string)=>Object.fromEntries(await Promise.all((await readdir(directory,{recursive:true})).filter(path=>/\.tsx?$/.test(path)).sort().map(async path=>[path,digest(await readFile(join(directory,path)))])));
const beforeF=await sourceHashes(resolve('src'));const beforeC=await sourceHashes(join(cRoot,'src'));const helperHash=digest(await readFile(helperPath));
const consumer='@fixture/pap-p18-wire';const bearerOrigin='https://bearer.p18.test';const dpopOrigin='https://dpop.p18.test';
const oldPath=process.env.PATH;const oldHome=process.env.HOME;
let fixture:any;let sidecar:Awaited<ReturnType<typeof createSecretServiceSidecar>>|undefined;let server:https.Server|undefined;let stage='setup';let passed=false;let result:any;
const clients:PapClient[]=[];
const audit=new Map<string,{createDpop:number;signDpop:number}>();
type Callback={state:string;iss:string;code:string};
let expectedCallback:{state:string;issuer:string;accept(value:Callback):void}|undefined;
const loopback=http.createServer((request,response)=>{
  response.setHeader('content-type','application/json');response.setHeader('cache-control','no-store');
  try{
    const url=new URL(request.url??'/','http://127.0.0.1');assert(request.method==='GET'&&url.pathname==='/callback'&&expectedCallback);
    assert([...url.searchParams.keys()].length===3&&['code','state','iss'].every(key=>url.searchParams.getAll(key).length===1));
    assert(url.searchParams.get('state')===expectedCallback.state&&url.searchParams.get('iss')===expectedCallback.issuer);
    const current=expectedCallback;expectedCallback=undefined;current.accept({state:url.searchParams.get('state')!,iss:url.searchParams.get('iss')!,code:url.searchParams.get('code')!});
    response.end('{"received":true}');
  }catch{response.statusCode=400;response.end('{"error":"invalid_callback"}');}
});
interface Lane {
  origin:string;dpop:boolean;asNonce?:string;resourceNonce?:string;keyThumb?:string;
  code?:{value:string;challenge:string;redirect:string;used:boolean};access?:string;refresh?:string;
  authorizationRequests:number;codePosts:number;refreshPosts:number;resourceGets:number;asChallenges:number;resourceChallenges:number;
  assertionJtis:Set<string>;dpopJtis:Set<string>;sessionJtis:Set<string>;
}
const lane=(origin:string,dpop:boolean):Lane=>({origin,dpop,authorizationRequests:0,codePosts:0,refreshPosts:0,resourceGets:0,asChallenges:0,resourceChallenges:0,assertionJtis:new Set(),dpopJtis:new Set(),sessionJtis:new Set()});
const lanes=new Map([[new URL(bearerOrigin).host,lane(bearerOrigin,false)],[new URL(dpopOrigin).host,lane(dpopOrigin,true)]]);
const thumb=(jwk:any)=>sha256(JSON.stringify({crv:jwk.crv,kty:jwk.kty,x:jwk.x,y:jwk.y}));
const jwt=(compact:string)=>{const parts=compact.split('.');assert(parts.length===3);return{parts,header:strictJson(Buffer.from(parts[0]!,'base64url')) as any,payload:strictJson(Buffer.from(parts[1]!,'base64url')) as any};};
const signature=(compact:string,key:any)=>{const parsed=jwt(compact);return verify('sha256',Buffer.from(parsed.parts[0]+'.'+parsed.parts[1]),{key:createPublicKey({key,format:'jwk'}),dsaEncoding:'ieee-p1363'},Buffer.from(parsed.parts[2]!,'base64url'));};
let clientId='';let publicKeys:any[]=[];
const validateAssertion=(compact:string,current:Lane)=>{
  const p=jwt(compact);assert(p.header.alg==='ES256'&&p.header.typ==='JWT');const key=publicKeys.find(value=>value.kid===p.header.kid);assert(key&&signature(compact,key));
  assert(p.payload.iss===clientId&&p.payload.sub===clientId&&p.payload.aud===current.origin);assert(p.payload.exp*1000>Date.now()&&p.payload.iat*1000<=Date.now()+5000);
  assert(typeof p.payload.jti==='string'&&!current.assertionJtis.has(p.payload.jti));current.assertionJtis.add(p.payload.jti);
};
const validateDpop=(compact:string,current:Lane,method:string,uri:string,access?:string)=>{
  const p=jwt(compact);assert(p.header.typ==='dpop+jwt'&&p.header.alg==='ES256'&&p.header.jwk&&!p.header.jwk.d);assert(signature(compact,p.header.jwk));
  assert(p.payload.htm===method&&p.payload.htu===uri&&Number.isSafeInteger(p.payload.iat));assert(p.payload.iat*1000>=Date.now()-60000&&p.payload.iat*1000<=Date.now()+5000);
  assert(typeof p.payload.jti==='string'&&!current.dpopJtis.has(p.payload.jti));current.dpopJtis.add(p.payload.jti);
  if(access)assert(p.payload.ath===sha256(access));else assert(!Object.hasOwn(p.payload,'ath'));
  const keyThumb=thumb(p.header.jwk);if(current.keyThumb)assert(current.keyThumb===keyThumb);else current.keyThumb=keyThumb;
  return p.payload;
};
const validateSession=(compact:string,current:Lane,access:string)=>{
  const p=jwt(compact);assert(p.header.alg==='ES256'&&p.header.typ==='poppy-session+jwt');const delegation=jwt(p.header.poppy_dlg);const key=publicKeys.find(value=>value.kid===delegation.header.kid);
  assert(key&&signature(p.header.poppy_dlg,key));assert(delegation.header.typ==='poppy-delegation+jwt'&&delegation.payload.iss===clientId&&delegation.payload.exp*1000>Date.now());
  assert(signature(compact,delegation.payload.cnf.jwk)&&p.header.kid===thumb(delegation.payload.cnf.jwk));assert(p.payload.iss===clientId&&p.payload.aud===current.origin&&p.payload.htm==='GET'&&p.payload.htu===current.origin+'/api/value'&&p.payload.ath===sha256(access));
  assert(!current.sessionJtis.has(p.payload.jti));current.sessionJtis.add(p.payload.jti);
};
const readBody=(request:http.IncomingMessage)=>new Promise<string>((resolve,reject)=>{let value='';request.on('data',chunk=>{value+=String(chunk);if(Buffer.byteLength(value)>131072){request.destroy();reject(new Error('Request limit'));}});request.on('end',()=>resolve(value));request.on('error',reject);});
try{
  sidecar=await createSecretServiceSidecar();process.env.PATH=sidecar.binDirectory+':'+oldPath;
  await new Promise<void>(resolve=>loopback.listen(0,'127.0.0.1',resolve));const redirectUri=`http://127.0.0.1:${(loopback.address() as any).port}/callback`;
  stage='actual_fresh_C';const {createProductHostFixture}=await import(pathToFileURL(helperPath).href);
  fixture=await createProductHostFixture({source:resolve(bSource),python:resolve(python),publicationCapabilities:{mcpMachine:false,papSession:true,papAccount:true},redirectUris:[redirectUri]});
  const metadata=strictJson(Buffer.from(fixture.publicMaterials.metadata)) as any;clientId=metadata.client_id;publicKeys=(strictJson(Buffer.from(fixture.publicMaterials.jwks)) as any).keys;assert(metadata.redirect_uris.includes(redirectUri)&&publicKeys.every(key=>!key.d));
  let actualProtocol:ProtocolIdentityClient|undefined;
  const module={apply(context:any){actualProtocol=context.get('anpIdentity').bindProtocolConsumer(context);}};
  await fixture.reopen({protocolPolicies:[{id:'p18-policy',version:1,consumer,owner:'@agent-network-protocol/dsh-anp-identity',identity:fixture.publicRef,profiles:['pap_session','pap_account'],issuers:[bearerOrigin,dpopOrigin],resources:[bearerOrigin,bearerOrigin+'/api',dpopOrigin,dpopOrigin+'/api'],publicTargets:false,scopes:['profile:read'],expiresAt:Date.now()+3600000}],modules:{[consumer]:module},entries:[{name:consumer}]});assert(actualProtocol);
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(root,'tls.key'),'-out',join(root,'tls.crt'),'-days','1','-subj','/CN=p18.test','-addext','subjectAltName=DNS:bearer.p18.test,DNS:dpop.p18.test'],{stdio:'ignore'});const ca=await readFile(join(root,'tls.crt'));
  server=https.createServer({key:await readFile(join(root,'tls.key')),cert:ca},async(request,response)=>{
    response.setHeader('content-type','application/json');response.setHeader('cache-control','no-store');
    try{
      const current=lanes.get(request.headers.host??'');assert(current);const url=new URL(request.url??'/',current.origin);const resource=current.origin+'/api';
      if(url.pathname==='/api/value'){
        current.resourceGets++;assert(request.method==='GET'&&current.access);const expected=(current.dpop?'DPoP ':'Bearer ')+current.access;assert(request.headers.authorization===expected&&typeof request.headers['poppy-session']==='string');validateSession(request.headers['poppy-session'],current,current.access);
        if(current.dpop){assert(typeof request.headers.dpop==='string');const proof=validateDpop(request.headers.dpop,current,'GET',current.origin+'/api/value',current.access);
          if(!current.resourceNonce){assert(proof.nonce===undefined);current.resourceNonce=randomBytes(24).toString('base64url');current.resourceChallenges++;response.statusCode=401;response.setHeader('www-authenticate','DPoP error="use_dpop_nonce"');response.setHeader('dpop-nonce',current.resourceNonce);return response.end('{"error":"use_dpop_nonce"}');}
          assert(proof.nonce===current.resourceNonce&&proof.nonce!==current.asNonce);
        }else assert(request.headers.dpop===undefined);
        return response.end('{"ok":true}');
      }
      assert(request.headers['poppy-session']===undefined&&request.headers.authorization===undefined);
      if(url.pathname==='/.well-known/poppy.json')return response.end(JSON.stringify({protocol_version:'0.3',organization:{name:'Controlled P18 fixture',domain:url.host},auth:{issuer:current.origin,scopes:{'profile:read':'Read profile'}},apis:[{type:'openapi',url:current.origin+'/openapi.json'}]}));
      if(url.pathname==='/.well-known/oauth-protected-resource'||url.pathname==='/.well-known/oauth-protected-resource/api')return response.end(JSON.stringify({resource:url.pathname.endsWith('/api')?resource:current.origin,authorization_servers:[current.origin]}));
      if(url.pathname==='/.well-known/oauth-authorization-server')return response.end(JSON.stringify({issuer:current.origin,authorization_endpoint:current.origin+'/authorize',token_endpoint:current.origin+'/token',revocation_endpoint:current.origin+'/revoke',protected_resources:[current.origin,resource],grant_types_supported:['authorization_code','refresh_token'],token_endpoint_auth_methods_supported:['private_key_jwt'],code_challenge_methods_supported:['S256'],...(current.dpop?{dpop_signing_alg_values_supported:['ES256']}:{})}));
      if(url.pathname==='/openapi.json')return response.end(JSON.stringify({openapi:'3.1.0',servers:[{url:resource}],paths:{'/value':{get:{}}}}));
      if(url.pathname==='/authorize'){
        assert(request.method==='GET'&&url.searchParams.get('client_id')===clientId&&url.searchParams.get('redirect_uri')===redirectUri&&url.searchParams.get('response_type')==='code'&&url.searchParams.get('resource')===resource&&url.searchParams.get('scope')==='profile:read'&&url.searchParams.get('code_challenge_method')==='S256');
        current.authorizationRequests++;current.code={value:randomBytes(32).toString('base64url'),challenge:url.searchParams.get('code_challenge')!,redirect:redirectUri,used:false};const target=new URL(redirectUri);target.searchParams.set('code',current.code.value);target.searchParams.set('state',url.searchParams.get('state')!);target.searchParams.set('iss',current.origin);response.statusCode=302;response.setHeader('location',target.href);return response.end('{}');
      }
      if(url.pathname==='/token'){
        assert(request.method==='POST');const fields=new URLSearchParams(await readBody(request));assert(fields.get('client_id')===clientId&&fields.get('resource')===resource&&fields.get('client_assertion_type')==='urn:ietf:params:oauth:client-assertion-type:jwt-bearer');for(const key of ['sid','session_id','sub','agent_id'])assert(!fields.has(key));validateAssertion(fields.get('client_assertion')!,current);
        const refresh=fields.get('grant_type')==='refresh_token';if(refresh){current.refreshPosts++;assert(fields.get('refresh_token')===current.refresh);}else{current.codePosts++;assert(fields.get('grant_type')==='authorization_code'&&current.code&&!current.code.used&&fields.get('code')===current.code.value&&fields.get('redirect_uri')===current.code.redirect&&sha256(fields.get('code_verifier')!)===current.code.challenge);}
        if(current.dpop){assert(typeof request.headers.dpop==='string');const proof=validateDpop(request.headers.dpop,current,'POST',current.origin+'/token');
          if((!refresh&&current.codePosts===1)||(refresh&&current.refreshPosts===1)){
            assert(refresh?proof.nonce===current.asNonce&&proof.nonce!==current.resourceNonce:proof.nonce===undefined);current.asNonce=randomBytes(24).toString('base64url');current.asChallenges++;response.statusCode=401;response.setHeader('www-authenticate','DPoP error="use_dpop_nonce"');response.setHeader('dpop-nonce',current.asNonce);return response.end('{"error":"use_dpop_nonce"}');
          }
          assert(proof.nonce===current.asNonce&&proof.nonce!==current.resourceNonce);
        }else assert(request.headers.dpop===undefined);
        if(!refresh)current.code!.used=true;current.access=randomBytes(32).toString('base64url');current.refresh=randomBytes(32).toString('base64url');return response.end(JSON.stringify({access_token:current.access,refresh_token:current.refresh,token_type:current.dpop?'DPoP':'Bearer',scope:'profile:read',expires_in:3600}));
      }
      response.statusCode=404;response.end('{}');
    }catch{response.statusCode=400;response.end('{"error":"controlled_verifier_rejected"}');}
  });
  await new Promise<void>(resolve=>server!.listen(0,'127.0.0.1',resolve));const port=(server.address() as any).port;
  const transport=new SafeHttpsTransport({ca,privateOrigins:[bearerOrigin,dpopOrigin],portOverrides:{[bearerOrigin]:port,[dpopOrigin]:port},lookup:async()=>[{address:'127.0.0.1',family:4}]});
  const realHost=new ProtocolIdentityHost(actualProtocol!,'p18-policy');
  const auditedHost:PapIdentityHost={dispose:()=>realHost.dispose(),acquire:async(...args)=>{
    const actual=await realHost.acquire(...args);const origin=args[1].issuer!;const counts=audit.get(origin)??{createDpop:0,signDpop:0};audit.set(origin,counts);
    // Pass through every real result and opaque reference; no C method is replaced or mocked.
    return {...actual,createDpopKey:async(...input)=>{counts.createDpop++;return actual.createDpopKey(...input);},signDpopProof:async input=>{counts.signDpop++;return actual.signDpopProof(input);}};
  }};
  const secrets=new KeyringSecretStore('pap-p18-wire-'+randomBytes(8).toString('hex'),join(root,'locks'));
  for(const current of lanes.values()){
    stage=current.dpop?'DPoP_nonce_wire':'Bearer_no_advertisement_wire';
    const client=new PapClient({stateRoot:join(root,current.dpop?'dpop':'bearer'),binding:{identityRef:fixture.publicRef,ownerRef:'@agent-network-protocol/dsh-anp-identity',clientId},identityHost:auditedHost,secretStore:secrets},transport);clients.push(client);
    const company=await client.resolvePapCompany(new URL(current.origin).host);const subject=await client.getOrCreatePapUser(company.companyRef);const login=await client.startSignIn(subject.subjectRef,{scopes:['profile:read'],resource:current.origin+'/api',redirectUri,callbackMode:'loopback'});
    const callback=new Promise<Callback>(accept=>{expectedCallback={state:new URL(login.authorizationUrl).searchParams.get('state')!,issuer:current.origin,accept};});
    const authorize=await transport.request(login.authorizationUrl);assert(authorize.status===302&&authorize.headers.location);const redirect=new URL(authorize.headers.location);assert(redirect.origin+redirect.pathname===redirectUri);
    await new Promise<void>((resolve,reject)=>{http.get(redirect,response=>{response.resume();response.once('end',()=>response.statusCode===200?resolve():reject(new Error('Callback rejected')));}).once('error',reject);});
    const grant=await client.completeSignIn(login.transactionRef,await callback);const firstState=await client.store.read();const saved=firstState.grants[grant.grantRef]!;
    assert(saved.tokenType===(current.dpop?'DPoP':'Bearer'));assert(current.dpop?Boolean(saved.dpopKey):saved.dpopKey===undefined);
    const session=await client.openPapSession(subject.subjectRef,grant.accountSlot);assert((await client.dispatchPap(session.sessionRef,{url:current.origin+'/api/value',scopes:['profile:read']})).status===200);
    await client.refreshAccountGrant(grant.grantRef);assert((await client.dispatchPap(session.sessionRef,{url:current.origin+'/api/value',scopes:['profile:read']})).status===200);
    const counters=audit.get(current.origin)!;
    if(current.dpop){assert(current.codePosts===2&&current.refreshPosts===2&&current.resourceGets===3&&current.asChallenges===2&&current.resourceChallenges===1);assert(counters.createDpop===1&&counters.signDpop===7&&current.dpopJtis.size===7&&current.assertionJtis.size===4&&current.sessionJtis.size===3);assert(current.asNonce!==current.resourceNonce);}
    else assert(counters.createDpop===0&&counters.signDpop===0&&current.codePosts===1&&current.refreshPosts===1&&current.resourceGets===2&&current.assertionJtis.size===2&&current.dpopJtis.size===0&&current.sessionJtis.size===2);
  }
  assert.deepEqual(await sourceHashes(resolve('src')),beforeF);assert.deepEqual(await sourceHashes(join(cRoot,'src')),beforeC);assert.equal(digest(await readFile(helperPath)),helperHash);
  const paths=(process.report.getReport() as any).sharedObjects.filter((path:string)=>path.endsWith('.node')&&path.includes('anp-identity')) as string[];const natives=await Promise.all(paths.map(async path=>({path,sha256:digest(await readFile(path))})));assert(natives.some(value=>value.sha256===expectedNative));
  passed=true;result={status:'passed',lane:'controlled_P18_HTTPS_scripted_AS_RS_actual_C_A_signer',nativeHashes:natives,helperSha256:helperHash,sourceGuardsUnchanged:true,
    bearer:{noDpopAdvertisement:true,createDpopCalls:0,signDpopCalls:0,wireDpopHeaders:0,ASPosts:2,resourceGets:2,sessionAthVerified:true},
    dpop:{ASChallenges:2,resourceChallenges:1,codePosts:2,refreshPosts:2,resourceGets:3,uniqueDpopProofs:7,uniqueAssertions:4,uniqueSessions:3,ASResourceNoncesIndependent:true,htmHtuIatJtiAthIndependentlyVerified:true},
    boundaries:{scriptedAS:true,independentThirdPartyAS:false,SystemTest:false,GUI:false,LLM:false,AgentPrivateKeyExported:false,productionModified:false,defaultBackend:'existing_Keyring_via_private_real_SecretService',callback:'explicit_published_loopback_HTTP',CProvider:'existing_actual_fresh_fixture_local_file'}};
}catch{result={status:'failed',stage,credentialsLogged:false};process.exitCode=1;}
finally{
  for(const client of clients)client.close();const fixtureRoot=fixture?.root;const cleanup:any={};try{await fixture?.dispose();cleanup.CFixtureDisposed=true;}catch{cleanup.CFixtureDisposed=false;passed=false;process.exitCode=1;}
  if(server)await new Promise<void>(resolve=>server!.close(()=>resolve()));await new Promise<void>(resolve=>loopback.close(()=>resolve()));cleanup.listenersClosed=true;cleanup.secretService=await sidecar?.stop();process.env.PATH=oldPath;cleanup.homePreserved=process.env.HOME===oldHome;await rm(root,{recursive:true,force:true});cleanup.FStateRemoved=true;cleanup.CStateRemoved=fixtureRoot?await stat(fixtureRoot).then(()=>false,()=>true):true;
  result.cleanup=cleanup;if(!passed)result.status='failed';console.log(JSON.stringify(result));
}
