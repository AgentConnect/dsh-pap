/** Explicit isolated component driver. Test custody only; never runtime Host key storage. */
import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PapClient } from '../src/client.js';
import { SafeHttpsTransport } from '../src/network.js';
import type { PublicJwk } from '../src/types.js';
import { FixtureHost, secrets } from '../tests/fixture.js';
const manifest = JSON.parse(await readFile(process.argv[2]!, 'utf8'));
const root = await mkdtemp(join(tmpdir(), 'pap-frontvia-component-'));
try {
  const key = createPrivateKey(await readFile(manifest.identity_key));
  const publicKey = createPublicKey(key); const jwk = publicKey.export({format:'jwk'});
  const binding = {identityRef:{storeId:'component',identityId:'frontvia',did:'did:wba:agent.test'},ownerRef:'component',clientId:manifest.client_id};
  const custody = new FixtureHost(binding);custody.identityKid='c1';custody.identity={privateKey:key,publicKey,jwk:{kty:'EC',crv:'P-256',x:jwk.x!,y:jwk.y!} as PublicJwk};
  const transport = new SafeHttpsTransport({ca:await readFile(manifest.ca),privateOrigins:[manifest.origin,manifest.fixture_origin],portOverrides:{[manifest.origin]:manifest.tls_port},lookup:async()=>[{address:'127.0.0.1',family:4}]});
  const client = new PapClient({stateRoot:root,binding,secretStore:secrets,identityHost:custody},transport);
  const company=await client.resolvePapCompany(new URL(manifest.origin).host);
  const subject=await client.getOrCreatePapUser(company.companyRef);const session=await client.openPapSession(subject.subjectRef);
  const invoke=async(path:string,method='GET',body?:string)=>{
    const response=await client.dispatchPap(session.sessionRef,{url:`${manifest.origin}/api/pap03${path}`,method,body,headers:body?{'content-type':'application/json'}:undefined});
    assert(response.status>=200&&response.status<300,`Component response status ${response.status}`);return JSON.parse(Buffer.from(response.body).toString());
  };
  const first=await invoke('/session');await client.rotateDelegation(subject.subjectRef);const second=await invoke('/session');
  assert.equal(first.sid,second.sid);
  const object=await invoke('/objects','POST',JSON.stringify({component:'F-dispatcher'}));
  const objectId=object.id??object.object_id;
  assert.equal(typeof objectId,'string');await invoke(`/objects/${objectId}`);
  let accountOAuth='not-run';
  if(process.argv.includes('--account')) {
    const userRequest=async(path:string,body:object,headers:Record<string,string>={})=>{
      const response=await transport.request(manifest.origin+path,{method:'POST',headers:{'content-type':'application/json',origin:manifest.origin,...headers},body:JSON.stringify(body)});
      assert.equal(response.status,200,`Browser fixture response ${response.status}`);return JSON.parse(Buffer.from(response.body).toString());
    };
    const challenge=await userRequest('/v1/personal/otp/request',{channel:'email',target:'mvp1@example.test',purpose:'signin'});
    const person=await userRequest('/v1/personal/otp/verify',{challenge_id:challenge.challenge_id,code:'246810'});
    const login=await client.startSignIn(subject.subjectRef,{scopes:['profile:read'],resource:manifest.origin+'/api/pap03',redirectUri:'http://127.0.0.1:57293/callback',callbackMode:'loopback'});
    const consent=await transport.request(login.authorizationUrl);assert.equal(consent.status,200);
    const html=Buffer.from(consent.body).toString();const match=html.match(/const page=(.*?);let challenge/);assert(match);
    const page=JSON.parse(match[1]!);
    const approved=await userRequest('/api/pap03/oauth/approve/'+page.id,{csrf:page.csrf,approve:true},{authorization:'Bearer '+person.access_token,...(consent.headers['set-cookie']?{cookie:consent.headers['set-cookie'].split(';')[0]!}:{})});
    const callback=new URL(approved.redirect);
    const grant=await client.completeSignIn(login.transactionRef,{state:callback.searchParams.get('state')??undefined,iss:callback.searchParams.get('iss')??undefined,code:callback.searchParams.get('code')??undefined});
    const accountSession=await client.openPapSession(subject.subjectRef,grant.accountSlot);
    const account=await client.dispatchPap(accountSession.sessionRef,{url:manifest.origin+'/api/pap03/account',scopes:['profile:read']});assert.equal(account.status,200);
    assert.equal(JSON.parse(Buffer.from(account.body).toString()).account_id,person.user_id);
    await client.refreshAccountGrant(grant.grantRef);
    const refreshed=await client.dispatchPap(accountSession.sessionRef,{url:manifest.origin+'/api/pap03/account',scopes:['profile:read']});assert.equal(refreshed.status,200);
    assert.equal((await client.signOutAccount(subject.subjectRef,grant.accountSlot)).status,'signed_out');
    const out=await client.dispatchPap(accountSession.sessionRef,{url:manifest.origin+'/api/pap03/session'});assert.equal(out.status,200);
    accountOAuth='Direct-PKCE-issuer-state-DPoP-refresh-revoke-signedout-passed';
  }
  console.log(JSON.stringify({passed:true,lane:'F-to-G-real-HTTPS-Rust-Session',authMode:company.authMode,sessionRequests:2,delegationRotated:true,custody:'explicit-test-fixture',accountOAuth,objects:2,...(manifest.binary_sha256?{companyBinarySha256:manifest.binary_sha256}:{})}));
} finally {await rm(root,{recursive:true,force:true});}
