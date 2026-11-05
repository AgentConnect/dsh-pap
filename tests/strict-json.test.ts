import test from 'node:test';
import assert from 'node:assert/strict';
import { strictJson } from '../src/strict-json.js';
import { jwtParts, parseJson } from '../src/util.js';
import { isPublicAddress } from '../src/network.js';

test('F-T01 duplicate JSON members, invalid UTF-8, excessive depth and size fail closed',()=>{
  for(const value of ['{"issuer":"a","issuer":"b"}','{"a":{"x":1,"\\u0078":2}}','[1,]','{"x":1,}','[01]','1e999','null false','['.repeat(34)+'0'+']'.repeat(34)])assert.throws(()=>strictJson(Buffer.from(value)));
  assert.throws(()=>strictJson(Buffer.from([0xef,0xbb,0xbf,0x7b,0x7d])));
  assert.throws(()=>strictJson(Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xc0,0xaf,0x22,0x7d])));
  assert.throws(()=>strictJson(Buffer.from('{"a":1}'),3));
  assert.equal((strictJson(Buffer.from('{"x":"escaped \\" quote","y":[true,null,1.5]}')) as Record<string,unknown>).x,'escaped " quote');
  assert.throws(()=>parseJson({status:200,headers:{'content-type':'text/html'},url:'https://company.example',body:Buffer.from('{}')}),{code:'discovery_failed'});
  assert.throws(()=>parseJson({status:200,headers:{},url:'https://company.example',body:Buffer.from('{"access_token":"a","access_token":"b"}')}),{code:'discovery_failed'});
});
test('F-T03 JWT canonical base64url, strict UTF-8 and member uniqueness enforced',()=>{
  const compact=(header:Uint8Array,payload=Buffer.from('{"iss":"https://agent.example"}'))=>`${Buffer.from(header).toString('base64url')}.${payload.toString('base64url')}.AA`;
  assert.throws(()=>jwtParts(compact(Buffer.from('{"alg":"ES256","alg":"none"}'))),{code:'delegation_blocked'});
  assert.throws(()=>jwtParts(compact(Buffer.from([0xff,0xfe]))),{code:'delegation_blocked'});
  assert.throws(()=>jwtParts(compact(Buffer.from('{"alg":"ES256"}'),Buffer.from('{"sub":"a","sub":"b"}'))),{code:'delegation_blocked'});
  assert.throws(()=>jwtParts('e30=.e30.AA'),{code:'delegation_blocked'});
});
test('F-T01 IPv6 special-use 2001::/23 and documentation are rejected',()=>{
  for(const address of ['2001:20::1','2001:10::1','2001:2::1','2001:100::1','2001:1::1','3fff::1'])assert.equal(isPublicAddress(address),false,address);
  assert.equal(isPublicAddress('2001:4860:4860::8888'),true);
});
