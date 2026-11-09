import test from 'node:test';
import assert from 'node:assert/strict';
import {PapDiscovery} from '../src/discovery.js';
import {operationRef} from '../src/product-operations.js';
import {FixtureTransport,jsonResponse} from './fixture.js';

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
