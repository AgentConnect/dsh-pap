import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { DeviceCallbackHandoff } from '../src/callback-handoff.js';

test('F-T06 B fixed callback relay keeps state and independent one-shot pickup authorization separate',async()=>{
  const requests:Parameters<ConstructorParameters<typeof DeviceCallbackHandoff>[0]['execute']>[0][]=[];
  const handoff=new DeviceCallbackHandoff({execute:async input=>{
    requests.push(input);
    if(input.action==='pap-callback-register')return {transaction_id:input.callback.transaction_id,callback_uri:input.callback.redirect_uri};
    return {state:'synthetic-state',iss:'https://company.example',code:'synthetic-code'};
  }});
  const result=await handoff.register({transactionId:'transaction-synthetic',clientId:'https://agent.example/client.json',issuer:'https://company.example',redirectUri:'https://agent.example/user-service/v1/pap-callback',state:'synthetic-state',expiresAt:Date.now()+600000});
  const request=requests[0]!.callback;assert.equal(request.state_sha256,createHash('sha256').update('synthetic-state').digest('hex'));assert.notEqual(request.state_sha256,request.claim_sha256);assert(!Object.hasOwn(request,'state'));assert(!Object.hasOwn(request,'code_verifier'));assert(!Object.hasOwn(request,'claim_secret'));
  const response=await handoff.collect(result.callbackRef);assert.equal(response.code,'synthetic-code');
  assert.equal(createHash('sha256').update(requests[1]!.callback.claim_secret!).digest('hex'),request.claim_sha256);assert(!JSON.stringify(requests).includes('poppy-session'));
});
