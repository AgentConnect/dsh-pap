/** Actual fresh C/B/A Host -> installed F manager/tools -> independent NoAS HTTPS verifier. */
import assert from 'node:assert/strict';
import https from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, stat, readdir } from 'node:fs/promises';
import { join, resolve, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import * as plugin from '../src/plugin.js';
import Manager from '../src/management-remote.js';
import * as tools from '../src/tools.js';
import { PAP_CONSUMER,PAP_MANAGER,PAP_TOOLS } from '../src/product-api.js';
import { SafeHttpsTransport } from '../src/network.js';
import { sha256 } from '../src/util.js';
import { KeyringSecretStore } from '../src/keyring.js';
import { createSecretServiceSidecar } from './helpers/secret-service-sidecar.js';
import { createNoAsProductVerifier } from './helpers/no-as-product-verifier.js';

const [fixtureInput,source,python,toolsInput,expectedNative='e2c4b86a0b3622aaefa70b44d3dc31cdab579b1237a4418d349bd294c52663ef',expectedFixture='e5645e1c815e4f223448426c0cb4bbf3323c72a8cc1091760aad1c0d6f6225a6']=process.argv.slice(2);assert(fixtureInput&&source&&python&&toolsInput,'Four explicit component inputs are required');
const fixturePath=resolve(fixtureInput);const toolsEntry=resolve(toolsInput);
const cRoot=resolve(dirname(fixturePath),'../..');
const cSources=async()=>Object.fromEntries(await Promise.all((await readdir(join(cRoot,'src'),{recursive:true})).filter(path=>/\.tsx?$/.test(path)).sort().map(async path=>[path,createHash('sha256').update(await readFile(join(cRoot,'src',path))).digest('hex')])));
assert.equal(createHash('sha256').update(await readFile(fixturePath)).digest('hex'),expectedFixture);
const hostSources=async()=>{
  const root=resolve('src');const paths=(await readdir(root,{recursive:true})).filter(path=>path.endsWith('.ts')&&!path.startsWith('client/')).sort();
  return Object.fromEntries(await Promise.all(paths.map(async path=>[path,createHash('sha256').update(await readFile(join(root,path))).digest('hex')])));
};
const before=await hostSources();const cBefore=await cSources();const originalPath=process.env.PATH;const originalHome=process.env.HOME;
const root=await mkdtemp(join(tmpdir(),'pap-product-native-'));const papRoot=join(root,'pap-profile');
let fixture:any;let sidecar:Awaited<ReturnType<typeof createSecretServiceSidecar>>|undefined;let server:https.Server|undefined;
let stage='secret_service';let passed=false;let verifier:ReturnType<typeof createNoAsProductVerifier>|undefined;let secretItemVerified=false;let cleanup:any={};let result:any;
try{
  sidecar=await createSecretServiceSidecar();process.env.PATH=sidecar.binDirectory+':'+originalPath;
  stage='fresh_C_B_publication';const {createProductHostFixture}=await import(pathToFileURL(fixturePath).href);
  fixture=await createProductHostFixture({source,python,publicationCapabilities:{mcpMachine:false,papSession:true,papAccount:false},redirectUris:[]});
  const metadata=JSON.parse(fixture.publicMaterials.metadata);const jwks=JSON.parse(fixture.publicMaterials.jwks);
  assert(metadata.client_id&&Array.isArray(jwks.keys));
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(root,'tls.key'),'-out',join(root,'tls.crt'),'-days','1','-subj','/CN=company.test','-addext','subjectAltName=DNS:company.test'],{stdio:'ignore'});
  const ca=await readFile(join(root,'tls.crt'));
  verifier=createNoAsProductVerifier({clientId:metadata.client_id,jwks,companyOrigin:'https://company.test'});
  server=https.createServer({key:await readFile(join(root,'tls.key')),cert:ca},verifier.handler);
  await new Promise<void>(resolve=>server!.listen(0,'127.0.0.1',resolve));const port=(server.address() as any).port;
  const transport=new SafeHttpsTransport({ca,privateOrigins:['https://company.test'],portOverrides:{'https://company.test':port},lookup:async()=>[{address:'127.0.0.1',family:4}]});
  const runtime=await import(pathToFileURL(toolsEntry).href);
  const NETWORK='@fixture/pap-network-only';const PROMPT='@fixture/pap-prompt-registration';
  const policy={id:'pap-product-policy',version:1,consumer:PAP_CONSUMER,owner:'@agent-network-protocol/dsh-anp-identity',identity:fixture.publicRef,profiles:['pap_session'],issuers:['https://company.test'],resources:['https://company.test','https://company.test/api'],publicTargets:false,scopes:['pap.read'],expiresAt:Date.now()+3600000};
  stage='actual_F_Loader';const ctx=await fixture.reopen({protocolPolicies:[policy],modules:{[PAP_CONSUMER]:plugin,[PAP_MANAGER]:Manager,[PAP_TOOLS]:tools,'@deepseek-ai/dsh-tools':runtime,[NETWORK]:{apply(context:any){context.provide('papHost',{transport});}},[PROMPT]:{apply(context:any){context.provide('systemPrompt',{tools(){return()=>{};}});}}},
    entries:[{name:NETWORK},{name:PROMPT},{name:'@deepseek-ai/dsh-tools',config:{mode:'native'}},{name:PAP_CONSUMER,config:{enabled:true,stateRoot:papRoot,policyRef:policy.id}},{name:PAP_MANAGER},{name:PAP_TOOLS}]});
  const manager=ctx.get('papManager');const unwrap=(result:any)=>{assert(result.ok===true,'PAP manager operation failed');return result.value;};
  assert(unwrap(await manager.status()).state==='unconfigured');unwrap(await manager.manage({action:'identity/select',reference:fixture.publicRef}));
  const company=unwrap(await manager.manage({action:'company/discover',domain:'company.test'}));const session=unwrap(await manager.manage({action:'session/connect',companyRef:company.companyRef}));
  const operations=unwrap(await manager.operations());assert(operations.length===1);const operationRef=operations[0].operationRef;
  const registry=ctx.get('tools');let call=0;const execute=()=>registry.execute({callId:'pap-native-'+(++call),name:'pap_request',arguments:{operationRef},agent:{},signal:new AbortController().signal});
  const denied=await execute();assert(denied.value?.ok===false);assert(verifier.observations.requests===0);
  unwrap(await manager.manage({action:'operation/enable',operationRef,sessionRef:session.sessionRef}));
  stage='actual_C_A_NoAS_signatures';for(let i=0;i<2;i++){const response=await execute();assert(response.isError===false&&response.value?.ok===true&&response.value.value.status===200);}
  const binding={identityRef:{storeId:fixture.publicRef.storeId,identityId:fixture.publicRef.identityId,did:fixture.publicRef.did},ownerRef:policy.owner,clientId:metadata.client_id};
  const namespace='dsh-pap/profile/'+sha256(resolve(papRoot))+'/pap/'+sha256(JSON.stringify(binding));
  const protectedKey=await new KeyringSecretStore('org.agentconnect.dsh-pap',join(root,'lookup-locks')).getEncryptionKey(namespace);assert(protectedKey?.length===32);protectedKey.fill(0);secretItemVerified=true;
  stage='actual_F_unload';const entry=[...ctx.loader.entries()].find((value:any)=>value.options.name===PAP_CONSUMER);assert(entry);await ctx.loader.update(entry.id,{disabled:true});
  const prior=verifier.observations.requests;const after=await execute();assert(after.isError===true||after.value?.ok===false);assert(verifier.observations.requests===prior);assert(verifier.observations.publicUnauthenticated);assert.equal(verifier.observations.requests,2);assert.equal(verifier.uniqueRequestProofs(),2);
  const afterSources=await hostSources();assert.deepEqual(afterSources,before);assert.deepEqual(await cSources(),cBefore);
  const nativeFiles=(process.report.getReport() as any).sharedObjects.filter((path:string)=>path.includes('anp-identity')&&path.endsWith('.node')) as string[];
  const nativeHashes=await Promise.all(nativeFiles.map(async path=>({path,sha256:createHash('sha256').update(await readFile(path)).digest('hex')})));
  assert(nativeHashes.some(item=>item.sha256===expectedNative));
  passed=true;result={status:'passed',stage:'complete',lane:'actual_fresh_C_B_A_factory_installed_F_tools_default_KeyringSecretStore_HTTPS_NoAS',
    assertions:{actualCFactory:true,actualInstalledFContext:true,defaultFSecretStore:true,realSecretServiceItem:secretItemVerified,unapprovedPhysicalRequests:0,verifiedDelegationAndSessionRequests:verifier.observations.requests,uniqueRequestProofs:verifier.uniqueRequestProofs(),accountTokenRequests:0,publicDiscoveryUnauthenticated:verifier.observations.publicUnauthenticated,unloadFurtherPhysicalRequests:0},
    boundaries:{modelRun:false,productE2E:false,systemTest:false,fixtureModuleResolution:true,strictBActorOutsidePlugin:true,ASGIOrigin:'logical_HTTPS',companyVerifier:'independent_Node_crypto_over_actual_TLS',CNativeRoot:'task_local_A_local_file_fixture',HostSecretTool:'task_private_shim_to_real_container_backend',hostKeyringConfigured:false},
    source:{fixtureSha256:createHash('sha256').update(await readFile(fixturePath)).digest('hex'),toolsEntrySha256:createHash('sha256').update(await readFile(toolsEntry)).digest('hex'),FHostSha256:before,CSourceSha256:cBefore,nativeHashes,unchanged:true,dependencyMode:'explicit_local_A_runtime_aliases_C_registry_Harness_peers'},sidecar:{imageId:sidecar.imageId,socket:sidecar.socket,packages:sidecar.facts.packages},publicMetadataRequests:verifier.observations.publicRequests};
}catch{result={status:'failed',stage,credentialsLogged:false};process.exitCode=1;}
finally{
  const fixtureRoot=fixture?.root;
  try{await fixture?.dispose();cleanup.CFixtureDisposed=true;}catch{cleanup.CFixtureDisposed=false;passed=false;process.exitCode=1;}
  if(server)await new Promise<void>(resolve=>server!.close(()=>resolve()));cleanup.httpsServerClosed=true;
  cleanup.secretService=await sidecar?.stop();process.env.PATH=originalPath;cleanup.hostHomePreserved=process.env.HOME===originalHome;
  await rm(root,{recursive:true,force:true});cleanup.FStateRemoved=true;
  cleanup.CStateRemoved=fixtureRoot?await stat(fixtureRoot).then(()=>false,()=>true):true;
  result.cleanup=cleanup;if(!passed)result.status='failed';console.log(JSON.stringify(result));
}
