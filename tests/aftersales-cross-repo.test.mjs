import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { operationChallenge, approvalHeader } from '../src/operations-approval.ts';

const core = process.env.FRONTVIA_CORE_DIR;
const host = process.env.ANP_IDENTITY_DIR;
test('Core cancellation terms survive PAP review and exactly one Identity admission', {skip: !core || !host}, async t => {
  const {prepareAfterSalesTerms} = await import(pathToFileURL(join(core,'ecommerce/modules/commerce/src/buyer/aftersales-terms.ts')));
  const {AuthorizationEngine,freezeOperation} = await import(pathToFileURL(join(host,'packages/dsh-anp-identity/lib/authorization.js')));
  const origin='https://shop.example';
  const identity={storeId:'identity-store',identityId:'buyer',did:'did:wba:example.test:buyer'};
  const caller={consumer:'pap',displayName:'PAP'};
  const policy={version:'domain-operation/1',capabilities:['identity:read','identity:http-auth'],signingPurposes:[],httpOrigins:[origin]};
  const dir=await mkdtemp(join(tmpdir(),'aftersales-consent-'));
  t.after(()=>rm(dir,{recursive:true,force:true}));
  const engine=new AuthorizationEngine(dir,{validateCaller:async()=>{},resolveSnapshot:async()=>policy});
  await engine.initialize();
  const order={id:randomUUID(),provider_customer_id:'native-buyer'};
  const input={action:'submit',kind:'cancel_order',reason:'Duplicate purchase',intent_id:randomUUID()};
  const request={method:'POST',url:origin+'/poppy/v1/aftersales/orders/'+order.id+'/cases',body:JSON.stringify(input)};
  const lines=Array.from({length:55},(_,i)=>({id:'line-'+i,title:'Order product '+i,quantity:i+1}));
  const reviews=[];
  for(const title of ['Original item','Replacement item']){
    const items=lines.map((row,i)=>i===54 ? {...row,title}:row);
    const prepared=await prepareAfterSalesTerms({locale:'zh-CN',store_id:'store',origin},order,input,{
      allowed:['cancel_order'],lines:items,shipping_minor:'100',payment:{id:'payment',currency:'CNY',captured_minor:'900',refundable_minor:'900'},
    },async id=>id);
    const revision=createHash('sha256').update(JSON.stringify(prepared.terms)).digest('hex');
    const approval=operationChallenge({status:403,headers:{'content-type':'application/json'},body:Buffer.from(JSON.stringify({
      error:'approval_required',operation:{operation_id:input.intent_id,revision,terms:prepared.terms,expires_at:new Date(Date.now()+60000).toISOString()}
    }))},request);
    assert(approval);
    const operation=freezeOperation({capability:'identity:http-auth',summary:'Submit request',httpOrigin:origin},
      {...request,approval:approvalHeader(approval)});
    const admitted=await engine.requestAccess(caller,{requestId:randomUUID(),identity,operation,approvalProfile:'exact-operation/1',
      purpose:approval.purpose,details:approval.details});
    assert.equal(admitted.details.revision,revision);
    for(const line of items) assert(admitted.details.rows.some(row=>row.label===line.title && row.value===line.id+' × '+line.quantity));
    reviews.push({admitted,operation});
  }
  assert.notEqual(reviews[0].admitted.fingerprint,reviews[1].admitted.fingerprint);
  const {admitted,operation}=reviews[1];
  const grant=await engine.decide({requestId:admitted.id,expectedVersion:admitted.version,decision:'approve',mode:'once',reviewedSnapshot:policy});
  const lease=await engine.open(caller,grant.grantId);
  let writes=0;
  const deliver=async()=>{await engine.admit(caller,lease,operation,randomUUID());writes++;};
  await assert.rejects(engine.admit(caller,lease,reviews[0].operation,randomUUID()));
  const attempts=await Promise.allSettled([deliver(),deliver()]);
  assert.equal(attempts.filter(a=>a.status==='fulfilled').length,1);
  assert.equal(writes,1);
});
