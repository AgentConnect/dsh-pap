/** Actual installed F user manager + C target-bound callback factory + default Secret Service + G OAuth. */
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { createInterface } from 'node:readline';
import { readFile,writeFile,mkdir,mkdtemp,rm,stat,readdir } from 'node:fs/promises';
import { dirname,join,resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL,fileURLToPath } from 'node:url';
import * as rootMarker from '../src/index.js';
import * as plugin from '../src/plugin.js';
import Manager from '../src/management-remote.js';
import * as tools from '../src/tools.js';
import { PAP_CONSUMER,PAP_MANAGER,PAP_TOOLS } from '../src/product-api.js';
import { SafeHttpsTransport } from '../src/network.js';
import { parseJson } from '../src/util.js';
import { strictJson } from '../src/strict-json.js';
import { PapError } from '../src/errors.js';
import type { HttpTransport } from '../src/types.js';
import { createSecretServiceSidecar } from './helpers/secret-service-sidecar.js';

const [fixtureArg,bSource,python,materialsArg,toolsArg,expectedNative='e2c4b86a0b3622aaefa70b44d3dc31cdab579b1237a4418d349bd294c52663ef']=process.argv.slice(2);
assert(fixtureArg&&bSource&&python&&materialsArg&&toolsArg,'Explicit fixture, B source, Python, public materials and ToolRuntime inputs required');
const fixturePath=resolve(fixtureArg);const materialsPath=resolve(materialsArg);const toolsPath=resolve(toolsArg);const cRoot=resolve(dirname(fixturePath),'../..');
const digest=(value:string|Uint8Array)=>createHash('sha256').update(value).digest('hex');
const fixtureHash=digest(await readFile(fixturePath));assert.equal(fixtureHash,'e5645e1c815e4f223448426c0cb4bbf3323c72a8cc1091760aad1c0d6f6225a6');
const sources=async(root:string)=>Object.fromEntries(await Promise.all((await readdir(root,{recursive:true})).filter(path=>/\.tsx?$/.test(path)).sort().map(async path=>[path,digest(await readFile(join(root,path)))])));
const beforeF=await sources(resolve('src'));const beforeC=await sources(join(cRoot,'src'));const driverHash=digest(await readFile(fileURLToPath(import.meta.url)));
const originalPath=process.env.PATH;const originalHome=process.env.HOME;const root=await mkdtemp(join(tmpdir(),'pap-product-account-'));const papRoot=join(root,'pap');
const publicationOrigin='https://agent.test:29443';const companyOrigin='https://company-a.test';const callbackPath='/user-service/v1/pap-callback';const redirectUri=publicationOrigin+callbackPath;
let fixture:any;let sidecar:Awaited<ReturnType<typeof createSecretServiceSidecar>>|undefined;let transport:SafeHttpsTransport|undefined;let completion:string|undefined;let materialsCreated=false;
let stage='private_secret_service';let passed=false;let forwarded=0;let received=0;let tokenRequests=0;let revocations=0;const grantTypes:string[]=[];let result:any;
const allowedErrors:Record<number,Set<string>>={400:new Set(['invalid_callback','callback_expired','callback_issuer_mismatch']),409:new Set(['callback_conflict']),503:new Set(['callback_unavailable'])};
const relay=http.createServer(async(request,response)=>{
  response.setHeader('content-type','application/json');response.setHeader('cache-control','no-store');response.setHeader('referrer-policy','no-referrer');
  const raw=request.url??'';
  if(!fixture||request.method!=='GET'||raw.split('?',1)[0]!==callbackPath||raw.length>8192||raw.includes('#')||['authorization','cookie','dpop','poppy-session','proxy-authorization'].some(name=>request.headers[name]!==undefined)){response.statusCode=400;response.end('{"error":"invalid_callback"}');return;}
  try{
    // Forward the unchanged query only in memory; no code/state parse, storage, log or pickup here.
    const reply=await fixture.requestForTest(new Request(publicationOrigin+raw,{method:'GET',redirect:'manual'}));
    const bytes=new Uint8Array(await reply.arrayBuffer());assert(bytes.length<=4096);const body=strictJson(bytes) as any;forwarded++;
    if(reply.status===200&&Object.keys(body).join(',')==='state'&&body.state==='received'){received++;response.end('{"state":"received"}');}
    else if(Object.keys(body).join(',')==='error'&&allowedErrors[reply.status]?.has(body.error)){response.statusCode=reply.status;response.end(JSON.stringify({error:body.error}));}
    else{response.statusCode=502;response.end('{"error":"callback_unavailable"}');}
  }catch{response.statusCode=502;response.end('{"error":"callback_unavailable"}');}
});
try{
  sidecar=await createSecretServiceSidecar();process.env.PATH=sidecar.binDirectory+':'+originalPath;
  stage='actual_fresh_C_B_publication';const {createProductHostFixture}=await import(pathToFileURL(fixturePath).href);
  fixture=await createProductHostFixture({source:resolve(bSource),python:resolve(python),publicationOrigin,publicationCapabilities:{mcpMachine:true,papSession:true,papAccount:true},redirectUris:[redirectUri]});
  const metadata=strictJson(Buffer.from(fixture.publicMaterials.metadata)) as any;const jwks=strictJson(Buffer.from(fixture.publicMaterials.jwks)) as any;
  assert(new URL(metadata.client_id).origin===publicationOrigin);assert(metadata.redirect_uris.includes(redirectUri));assert(jwks.keys.every((key:any)=>!Object.hasOwn(key,'d')));
  const Runtime=await import(pathToFileURL(toolsPath).href);const NETWORK='@fixture/pap-network-only';const PROMPT='@fixture/pap-prompt-registration';
  const observed:HttpTransport={request:async(url,options)=>{
    assert(transport,'Company transport is not ready');
    if(url.endsWith('/api/pap03/oauth/token')){tokenRequests++;assert(!options?.headers?.['poppy-session']);const form=new URLSearchParams(options?.body);grantTypes.push(form.get('grant_type')??'');for(const name of ['sid','session_id','sub','agent_id'])assert(!form.has(name));}
    if(url.endsWith('/api/pap03/oauth/revoke')){revocations++;assert(!options?.headers?.['poppy-session']);}
    return transport.request(url,options);
  }};
  const policy={id:'pap-product-account',version:1,consumer:PAP_CONSUMER,owner:'@agent-network-protocol/dsh-anp-identity',identity:fixture.publicRef,profiles:['pap_session','pap_account'],issuers:[companyOrigin],resources:[companyOrigin,companyOrigin+'/api/pap03'],publicTargets:false,scopes:['profile:read'],expiresAt:Date.now()+3600000};
  stage='actual_F_entries';let ctx=await fixture.reopen({protocolPolicies:[policy],modules:{'@agentconnect/dsh-pap':rootMarker,[PAP_CONSUMER]:plugin,[PAP_MANAGER]:Manager,[PAP_TOOLS]:tools,'@deepseek-ai/dsh-tools':Runtime,[NETWORK]:{apply(context:any){context.provide('papHost',{transport:observed});}},[PROMPT]:{apply(context:any){context.provide('systemPrompt',{tools(){return()=>{};}});}}},
    entries:[{name:NETWORK},{name:PROMPT},{name:'@deepseek-ai/dsh-tools',config:{mode:'native'}},{name:'@agentconnect/dsh-pap'},{name:PAP_CONSUMER,config:{enabled:true,stateRoot:papRoot,policyRef:policy.id}},{name:PAP_MANAGER},{name:PAP_TOOLS}]});
  await new Promise<void>(resolve=>relay.listen(0,'127.0.0.1',resolve));const callbackForward=`http://127.0.0.1:${(relay.address() as any).port}${callbackPath}`;
  await mkdir(dirname(materialsPath),{recursive:true,mode:0o700});await writeFile(materialsPath,JSON.stringify({client_id:metadata.client_id,metadata:fixture.publicMaterials.metadata,jwks:fixture.publicMaterials.jwks}),{flag:'wx',mode:0o600});materialsCreated=true;
  console.log(JSON.stringify({stage:'public_materials_ready',publicMaterials:materialsPath,callbackForward,callbackUri:redirectUri,fixtureSha256:fixtureHash,expectedNative,defaultSecretBackend:'private_real_SecretService'}));
  stage='await_G_window';const input=createInterface({input:process.stdin});const manifestPath=await new Promise<string>((resolve,reject)=>{const timer=setTimeout(()=>{input.close();reject(new Error('Peer timeout'));},300000);input.once('line',line=>{clearTimeout(timer);resolve(line.trim());input.close();});input.once('close',()=>{clearTimeout(timer);reject(new Error('Peer input closed'));});});
  const manifest=strictJson(await readFile(resolve(manifestPath))) as any;assert(manifest.origin===companyOrigin&&manifest.client_id===metadata.client_id&&manifest.callback_uri===redirectUri&&manifest.callback_forward===callbackForward);assert(manifest.identity_key===undefined);
  if(typeof manifest.completion_file==='string'){completion=resolve(manifest.completion_file);assert(dirname(completion)===dirname(resolve(manifestPath)));}
  assert(manifest.binary_sha256==='35f6265876ef98daa69e8780f055ed2e6f164468494f1241b711dd2e7be09444');
  transport=new SafeHttpsTransport({ca:await readFile(manifest.ca),privateOrigins:[companyOrigin,publicationOrigin],portOverrides:{[companyOrigin]:Number(manifest.tls_port)},lookup:async()=>[{address:'127.0.0.1',family:4}]});
  const servedMetadata=await transport.request(metadata.client_id);const servedJwks=await transport.request(metadata.jwks_uri);assert(Buffer.from(servedMetadata.body).equals(Buffer.from(fixture.publicMaterials.metadata)));assert(Buffer.from(servedJwks.body).equals(Buffer.from(fixture.publicMaterials.jwks)));
  const unwrap=(reply:any)=>{if(reply?.ok!==true)throw new PapError(reply?.error?.code??'permission_denied');return reply.value;};
  let manager=ctx.get('papManager');const manage=async(input:any)=>unwrap(await manager.manage(input));let calls=0;
  const execute=async(operationRef:string)=>{const reply=await ctx.get('tools').execute({callId:'pap-account-'+(++calls),name:'pap_request',arguments:{operationRef},agent:{},signal:new AbortController().signal});assert(reply.isError===false);return unwrap(reply.value);};
  stage='discovery_signed_out';await manage({action:'identity/select',reference:fixture.publicRef});const company=await manage({action:'company/discover',domain:new URL(companyOrigin).host});const session=await manage({action:'session/connect',companyRef:company.companyRef});
  const operations=unwrap(await manager.operations());const statusOp=operations.find((entry:any)=>entry.method==='GET'&&entry.path==='/api/pap03/session');const accountOp=operations.find((entry:any)=>entry.method==='GET'&&entry.path==='/api/pap03/account');assert(statusOp&&accountOp);
  await manage({action:'operation/enable',operationRef:statusOp.operationRef,sessionRef:session.sessionRef});assert((await execute(statusOp.operationRef)).status===200);assert.equal(tokenRequests,0);
  stage='user_Remote_sign_in';const login=await manage({action:'account/sign-in',sessionRef:session.sessionRef,operationRef:accountOp.operationRef,scopes:['profile:read']});
  const userPost=async(path:string,body:object,headers:Record<string,string>={})=>{const response=await transport!.request(companyOrigin+path,{method:'POST',headers:{'content-type':'application/json',origin:companyOrigin,...headers},body:JSON.stringify(body)});assert(response.status===200,'Company user actor request failed');return parseJson(response);};
  const challenge=await userPost('/v1/personal/otp/request',{channel:'email',target:'mvp1@example.test',purpose:'signin'});const person=await userPost('/v1/personal/otp/verify',{challenge_id:challenge.challenge_id,code:'246810'});
  const consent=await transport.request(login.authorizationUrl);assert(consent.status===200);const pageMatch=new TextDecoder('utf-8',{fatal:true}).decode(consent.body).match(/const page=(.*?);let challenge/);assert(pageMatch);const page=strictJson(Buffer.from(pageMatch[1]!)) as any;
  const approved=await userPost('/api/pap03/oauth/approve/'+page.id,{csrf:page.csrf,approve:true},{authorization:'Bearer '+person.access_token,...(consent.headers['set-cookie']?{cookie:consent.headers['set-cookie'].split(';')[0]!}:{})});const redirect=new URL(String(approved.redirect));assert(redirect.origin+redirect.pathname===redirectUri);
  stage='actual_HTTPS_relay';const delivered=await transport.request(redirect.href);assert(delivered.status===200&&parseJson(delivered).state==='received');assert.equal(received,1);
  stage='C_factory_original_device_collect_PKCE';const account=await manage({action:'account/collect',transactionRef:login.transactionRef});assert.equal(tokenRequests,1);
  const accountSession=await manage({action:'session/connect',companyRef:company.companyRef,accountSlot:account.accountSlot});await manage({action:'operation/enable',operationRef:accountOp.operationRef,sessionRef:accountSession.sessionRef,scopes:['profile:read']});
  const checkAccount=async()=>{const reply=await execute(accountOp.operationRef);assert(reply.status===200&&reply.body.account_id===person.user_id);};await checkAccount();
  stage='actual_F_restart_DPoP_restore';const entry=[...ctx.loader.entries()].find((value:any)=>value.options.name===PAP_CONSUMER);assert(entry);await ctx.loader.update(entry.id,{disabled:true});await ctx.loader.update(entry.id,{disabled:false});await ctx.loader.await();manager=ctx.get('papManager');
  const restoredStatus=unwrap(await manager.status());let userReselected=false;if(restoredStatus.state!=='ready'){await new Promise(resolve=>setTimeout(resolve,150));await manage({action:'identity/select',reference:fixture.publicRef});userReselected=true;}await checkAccount();assert.equal(tokenRequests,1);
  stage='user_Remote_refresh_revoke';await manage({action:'account/refresh',accountSlot:account.accountSlot});assert.equal(tokenRequests,2);await checkAccount();await manage({action:'account/sign-out',accountSlot:account.accountSlot});assert.equal(revocations,1);
  await manage({action:'operation/enable',operationRef:statusOp.operationRef,sessionRef:session.sessionRef});assert((await execute(statusOp.operationRef)).status===200);
  assert.deepEqual(grantTypes,['authorization_code','refresh_token']);assert.equal(digest(await readFile(fixturePath)),fixtureHash);assert.deepEqual(await sources(resolve('src')),beforeF);assert.deepEqual(await sources(join(cRoot,'src')),beforeC);
  const nativePaths=(process.report.getReport() as any).sharedObjects.filter((path:string)=>path.endsWith('.node')&&path.includes('anp-identity')) as string[];const nativeHashes=await Promise.all(nativePaths.map(async path=>({path,sha256:digest(await readFile(path))})));assert(nativeHashes.some(item=>item.sha256===expectedNative));
  passed=true;result={status:'passed',lane:'actual_product_F_user_Remote_C_factory_A_custody_B_HTTPS_relay_G_account_default_Keyring',
    assertions:{actualFreshApprovalRegistrationPublication:true,actualInstalledFContext:true,actualCAccountFactory:true,defaultFKeyring:true,actualHttpsRelay:true,callbackForwarded:forwarded,callbackReceived:received,originalDeviceCollect:true,PKCE:true,DPoPAccount:true,realFRestart:true,userReselectedAfterRestart:userReselected,DPoPRestored:true,tokenRequests,grantTypes,revocationRequests:revocations,signedOutContinued:true},
    source:{FSourceSha256:beforeF,CSourceSha256:beforeC,fixtureSha256:fixtureHash,driverSha256:driverHash,nativeHashes,companyBinarySha256:manifest.binary_sha256,metadataSha256:digest(servedMetadata.body),jwksSha256:digest(servedJwks.body),unchanged:true},
    boundaries:{GUIProductE2E:false,SystemTest:false,LLM:false,actorCompanyOTP:'isolated_reserved_fixture',BMiddleware:'real_production_ASGI_logical_HTTPS',Company:'actual_TLS_Rust_PG',HostSecretTool:'private_shim_to_container_real_SecretService',hostKeyringConfigured:false,AgentPrivateKeyExported:false},sidecar:{imageId:sidecar.imageId,socket:sidecar.socket,packages:sidecar.facts.packages}};
}catch(error){result={status:'failed',stage,errorCode:error instanceof PapError?error.code:'component_failed',credentialsLogged:false};process.exitCode=1;}
finally{
  if(completion)await writeFile(completion,passed?'done\n':'failed\n',{mode:0o600}).catch(()=>{});
  const fixtureRoot=fixture?.root;const cleanup:any={};try{await fixture?.dispose();cleanup.CFixtureDisposed=true;}catch{cleanup.CFixtureDisposed=false;passed=false;process.exitCode=1;}
  await new Promise<void>(resolve=>relay.close(()=>resolve()));cleanup.relayClosed=true;cleanup.secretService=await sidecar?.stop();process.env.PATH=originalPath;cleanup.homePreserved=process.env.HOME===originalHome;
  await rm(root,{recursive:true,force:true});if(materialsCreated)await rm(materialsPath,{force:true});cleanup.FStateAndPublicMaterialsRemoved=true;cleanup.CStateRemoved=fixtureRoot?await stat(fixtureRoot).then(()=>false,()=>true):true;
  result.cleanup=cleanup;if(!passed)result.status='failed';console.log(JSON.stringify(result));
}
