import test from 'node:test';
import assert from 'node:assert/strict';
import {PapDiscovery} from '../src/discovery.js';
import {operationRef,publicOperations} from '../src/product-operations.js';
import {FixtureTransport,jsonResponse} from './fixture.js';
import {PapPolicyTargets,type PolicyClient} from '../src/protocol-policy.js';
import type {PapState} from '../src/types.js';

test('PAP discovery never treats malformed security, extra scopes or GET bodies as global read permission',async()=>{
  const transport=new FixtureTransport();
  transport.override=url=>new URL(url).pathname==='/openapi.json'?jsonResponse(url,{openapi:'3.1.0',paths:{
    '/public':{get:{security:[]}},'/scoped':{get:{security:[{oauth:['account.read']}]}},
    '/invalid':{get:{security:null}},'/body':{get:{requestBody:{}}},
  }}):undefined;
  const company=await new PapDiscovery(transport).resolve('shop.example');
  const route=(path:string)=>company.routes.find(route=>route.template.endsWith(path))!;
  assert.equal(Boolean(route('/public').requiresConsent),false);
  for(const path of ['/scoped','/invalid','/body'])assert.equal(route(path).requiresConsent,true);
  const old=route('/public');
  assert.equal(operationRef(company,old),operationRef(company,{...old,requiresConsent:false}));
  assert.notEqual(operationRef(company,old),operationRef(company,{...old,requiresConsent:true}));
});
test('PAP exposes bounded discovered body schemas so domain-only callers do not have to guess business inputs',async()=>{
  const transport=new FixtureTransport();
  const schema={type:'object',properties:{text:{type:'string'},idempotency_key:{type:'string',minLength:8},structured:{$ref:'#/$defs/value'}},required:['text','idempotency_key'],$defs:{value:{type:'string'}}};
  transport.override=url=>new URL(url).pathname==='/openapi.json'?jsonResponse(url,{openapi:'3.1.0',paths:{
    '/api/create':{post:{operationId:'match_request_create',requestBody:{content:{'application/json':{schema}}}}},
    '/api/external':{post:{requestBody:{content:{'application/json':{schema:{$ref:'https://untrusted.example/schema'}}}}}},
  }}):undefined;
  const company=await new PapDiscovery(transport).resolve('shop.example');
  const state={companies:{[company.ref]:company},sessions:{}} as PapState;
  const operations=publicOperations(state) as {path:string;operationId?:string;bodySchema?:unknown;bodySchemaUnavailable?:boolean}[];
  assert.deepEqual(JSON.parse(JSON.stringify(operations.find(operation=>operation.path==='/api/create')?.bodySchema)),schema);
  assert.equal(operations.find(operation=>operation.path==='/api/create')?.operationId,'match_request_create');
  assert.equal(operations.find(operation=>operation.path==='/api/external')?.bodySchemaUnavailable,true);
  assert(!transport.calls.some(call=>call.url.includes('untrusted.example')));
});

test('PAP policy binds the original discovery origin across redirects, not a hostname suffix or an unverified alias',async()=>{
  const transport=new FixtureTransport();
  transport.override=url=>new URL(url).hostname==='entry.example'?{url,status:302,headers:{location:'https://shop.example/.well-known/poppy.json'},body:new Uint8Array()}:undefined;
  const company=await new PapDiscovery(transport).resolve('entry.example');
  assert.equal(company.discoveryOrigin,'https://entry.example');assert.equal(company.domain,'shop.example');
  const registrations:unknown[]=[],forgotten:unknown[]=[];
  const policy:PolicyClient={async assertNoDenial(){},classifyHttp(){return{effect:'unknown',extraPermissions:false};},
    register(input){registrations.push(input);return{protocolTarget:true};},forget(target){forgotten.push(target);},async evaluate(){throw new Error('Not used');}};
  const targets=new PapPolicyTargets(policy),first=targets.target(company);assert.equal(targets.target(company),first);
  assert.deepEqual(registrations,[{discoveryOrigin:'https://entry.example',destinations:['https://shop.example']}]);
  const changed={...company,discoveryOrigin:'https://different.example'};assert.notEqual(targets.target(changed),first);assert.deepEqual(forgotten,[first]);
  targets.dispose();assert.equal(forgotten.length,2);
});
