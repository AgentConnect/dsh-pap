import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {PapDiscovery} from '../src/discovery.js';
import {PapClient} from '../src/client.js';
import {isUcpRead,negotiateUcp,UCP_VERSION} from '../src/ucp.js';
import {operationRef,prepareOperation} from '../src/product-operations.js';
import {binding,FixtureHost,FixtureTransport,jsonResponse,secrets} from './fixture.js';
import {jwtParts} from '../src/util.js';
const origin='https://shop.example';
const platformUrl='https://agent.example/ucp-platform';
const profile=(endpoint?:string)=>({ucp:{version:UCP_VERSION,payment_handlers:{},services:endpoint?{'dev.ucp.shopping':[{transport:'rest',version:UCP_VERSION,endpoint}]}:{},capabilities:Object.fromEntries(['catalog.search','catalog.lookup','cart','checkout','order'].map(name=>[`dev.ucp.shopping.${name}`,[{version:UCP_VERSION}]]))}});
function fixture(protocolVersion='1.0'){
  const transport=new FixtureTransport();
  transport.override=url=>{
    if(url.endsWith('/poppy.json'))return jsonResponse(url,{protocol_version:protocolVersion,organization:{name:'Shop',domain:'shop.example'},extensions:{ucp:[{version:'1'}]},apis:[{type:'openapi',url:`${origin}/openapi.json`}]});
    if(url===`${origin}/.well-known/ucp`)return jsonResponse(url,profile(`${origin}/ucp/v1`));
    if(url===platformUrl)return jsonResponse(url,profile());
    if(url.includes('/.well-known/oauth-protected-resource/'))return jsonResponse(url,{},404);
    if(url.includes('/ucp/v1'))return jsonResponse(url,{ucp:{version:UCP_VERSION},id:'cart_one'});
  };
  return transport;
}
async function setup(t:test.TestContext,transport=fixture()){
  const root=await mkdtemp(join(tmpdir(),'pap10-unit-'));t.after(()=>rm(root,{recursive:true,force:true}));
  const client=new PapClient({stateRoot:root,binding,identityHost:new FixtureHost(),secretStore:secrets,ucpPlatformProfileUrl:platformUrl,callbackHandoff:{register:async()=>({callbackRef:'fixture'}),collect:async()=>({})}},transport);
  const company=await client.resolvePapCompany('shop.example');const subject=await client.getOrCreatePapUser(company.companyRef);const session=await client.openPapSession(subject.subjectRef);
  return {client,transport,...company,...subject,...session};
}
test('PAP 1.0 discovery negotiates the configured product profile',async()=>{
  const transport=fixture();const company=await new PapDiscovery(transport,()=>Date.now(),platformUrl).resolve('shop.example');
  assert.equal(company.protocolVersion,'1.0');assert.deepEqual(company.extensions,{ucp:'1'});assert.equal(company.ucp?.platformProfileUrl,platformUrl);
  assert.equal(company.routes.filter(r=>r.channel==='ucp').length,13);
  assert(company.routes.filter(r=>r.operationId==='search_catalog').every(isUcpRead));
  assert(!isUcpRead({...company.routes.find(r=>r.operationId==='create_cart')!,policyEvidence:{hasRequestBody:true,declaredEffect:'read'}}));
  const plain=await new PapDiscovery(transport).resolve('shop.example');assert.equal(plain.protocolVersion,'1.0');assert(!plain.ucp);assert(!plain.routes.some(r=>r.channel==='ucp'));
});
test('UCP Ask negotiates Common REST independently and signs only the discovered public route',async t=>{
  const endpoint=`${origin}/common/v1`,path=endpoint+'/ask',ask='dev.ucp.common.ask',common='dev.ucp.common';
  const platform=profile();
  Object.assign(platform.ucp.services,{[common]:[{version:UCP_VERSION,transport:'rest'}]});
  Object.assign(platform.ucp.capabilities,{[ask]:[{version:UCP_VERSION}]});
  const business=profile(`${origin}/ucp/v1`);
  Object.assign(business.ucp.services,{[common]:[{version:UCP_VERSION,transport:'rest',endpoint}]});
  Object.assign(business.ucp.capabilities,{[ask]:[{version:UCP_VERSION}]});
  const transport=fixture(),previous=transport.override!;
  transport.override=(url,options)=>{
    if(url===platformUrl)return jsonResponse(url,platform);
    if(url===`${origin}/.well-known/ucp`)return jsonResponse(url,business);
    if(url===`${origin}/.well-known/oauth-protected-resource/common/v1`)return jsonResponse(url,{resource:endpoint});
    if(url===path)return jsonResponse(url,{answer:{plain:'Size up once.'}});
    return previous(url,options);
  };
  const f=await setup(t,transport);
  const company=(await f.client.store.read()).companies[f.companyRef]!;
  const route=company.routes.find(value=>value.operationId==='ask_business')!;
  assert(isUcpRead(route));
  assert.equal(route.template,path);
  assert.equal(route.resource,endpoint);
  assert.equal(company.routes.find(value=>value.operationId==='search_catalog')?.template,`${origin}/ucp/v1/catalog/search`);
  const idempotencyKey='54fdf38e-2454-4db9-bade-f569caa338a9';
  const body=JSON.stringify({query:'Does it fit?',ids:['product-1']});
  const operation={url:path,method:'POST',body,idempotencyKey};
  await f.client.dispatchPap(f.sessionRef,operation,{operationRef:operationRef(company,route)});
  const request=transport.calls.at(-1)!;
  assert.equal(request.url,path);
  assert.equal(request.options?.body,body);
  const headers=request.options?.headers;
  assert(headers?.['poppy-session']);
  assert.equal(jwtParts(headers['poppy-session']).payload.htu,path);
  assert.equal(headers['ucp-agent'],`profile="${platformUrl}"`);
  assert.equal(headers['idempotency-key'],idempotencyKey);
  assert.equal(headers.authorization,undefined);
  assert.equal(headers.dpop,undefined);
  const count=transport.calls.length;
  await assert.rejects(f.client.dispatchPap(f.sessionRef,{...operation,scopes:['dev.ucp.common.ask:read']}),{code:'permission_denied'});
  await assert.rejects(f.client.dispatchPap(f.sessionRef,{...operation,url:path+'?target=another'}),{code:'unsafe_destination'});
  assert.equal(transport.calls.length,count);

  const select=(merchant:Parameters<typeof negotiateUcp>[0],agent:Parameters<typeof negotiateUcp>[1])=>
    negotiateUcp(merchant,agent,origin+'/.well-known/ucp',platformUrl,origin);
  const platformWithoutCommon={ucp:{...platform.ucp,services:{}}};
  assert(!select(business,platformWithoutCommon).routes.some(value=>value.operationId==='ask_business'));
  const foreign={ucp:{...business.ucp,services:{...business.ucp.services,[common]:[{version:UCP_VERSION,transport:'rest',endpoint:'https://other.example/v1'}]}}};
  assert(!select(foreign,platform).routes.some(value=>value.operationId==='ask_business'));
  const ambiguous={ucp:{...business.ucp,services:{...business.ucp.services,[common]:[endpoint,origin].map(endpoint=>({version:UCP_VERSION,transport:'rest',endpoint}))}}};
  const shoppingRoutes=select(ambiguous,platform).routes;
  assert(shoppingRoutes.some(value=>value.operationId==='search_catalog'));
  assert(!shoppingRoutes.some(value=>value.operationId==='ask_business'));
  for (const malformed of [[null], ['not-an-entry'], [null, {version:UCP_VERSION}]]) {
    const badBusiness={ucp:{...business.ucp,capabilities:{...business.ucp.capabilities,[ask]:malformed}}};
    const badPlatform={ucp:{...platform.ucp,capabilities:{...platform.ucp.capabilities,[ask]:malformed}}};
    for (const result of [select(badBusiness,platform),select(business,badPlatform)]) {
      assert(result.routes.some(value=>value.operationId==='search_catalog'));
      assert(!result.routes.some(value=>value.operationId==='ask_business'));
    }
  }
  const askOnly={ucp:{...business.ucp,services:{[common]:[{version:UCP_VERSION,transport:'rest',endpoint}]}}};
  assert.deepEqual(select(askOnly,platform).routes.map(value=>value.operationId),['ask_business']);
});
test('An invalid optional Common resource binding leaves verified Shopping routes usable',async()=>{
  const ask='dev.ucp.common.ask',common='dev.ucp.common';
  const platform=profile(),business=profile(`${origin}/ucp/v1`);
  Object.assign(platform.ucp.services,{[common]:[{version:UCP_VERSION,transport:'rest'}]});
  Object.assign(business.ucp.services,{[common]:[{version:UCP_VERSION,transport:'rest',endpoint:`${origin}/common/v1`}]});
  for (const declaration of [platform,business]) Object.assign(declaration.ucp.capabilities,{[ask]:[{version:UCP_VERSION}]});
  const transport=fixture(),previous=transport.override!;
  const metadataUrl=`${origin}/.well-known/oauth-protected-resource/common/v1`;
  let resourceStatus=503;
  transport.override=(url,options)=>{
    if(url===platformUrl)return jsonResponse(url,platform);
    if(url===`${origin}/.well-known/ucp`)return jsonResponse(url,business);
    if(url===metadataUrl)return jsonResponse(url,{resource:`${origin}/other`,scopes_supported:['unverified:scope']},resourceStatus);
    return previous(url,options);
  };
  for (const status of [503,200]) {
    resourceStatus=status;
    const resolved=await new PapDiscovery(transport,()=>Date.now(),platformUrl).resolve('shop.example');
    assert(resolved.routes.some(value=>value.operationId==='search_catalog'));
    assert(!resolved.routes.some(value=>value.operationId==='ask_business'));
    assert(!resolved.ucp?.capabilities.includes(ask));
    assert.equal(resolved.ucp?.commonEndpoint,undefined);
    assert(!resolved.scopes.includes('unverified:scope'));
    assert(!resolved.sources.some(value=>value.url===metadataUrl));
  }
});
test('Frontvia reads require matching extension versions and parents on both profiles',()=>{
  const store='com.frontvia.shopping.store_context', history='com.frontvia.shopping.order_history';
  const withExtensions=(endpoint?:string)=>{
    const result=profile(endpoint);
    Object.assign(result.ucp.capabilities,{
      [store]:[{version:UCP_VERSION,extends:'dev.ucp.shopping.catalog.search'}],
      [history]:[{version:UCP_VERSION,extends:'dev.ucp.shopping.order'}],
    });
    return result;
  };
  const business=withExtensions(`${origin}/ucp/v1`), platform=withExtensions();
  const negotiate=(b=business,p=platform)=>negotiateUcp(b,p,`${origin}/.well-known/ucp`,platformUrl,origin);
  const {routes}=negotiate();
  const route=(id:string)=>routes.find(route=>route.operationId===id)!;
  assert.deepEqual([route('get_store_context').template,route('list_orders').template],
    [`${origin}/ucp/v1/store-context`,`${origin}/ucp/v1/orders`]);
  assert(isUcpRead(route('get_store_context'))&&isUcpRead(route('list_orders')));
  assert.deepEqual(route('get_store_context').parameters,[]);
  assert.deepEqual(route('list_orders').parameters,
    ['limit','cursor'].map(name=>({name,in:'query',required:false})));
  for(const [name,parent] of [[store,'dev.ucp.shopping.catalog.search'],[history,'dev.ucp.shopping.order']] as const){
    const id=name===store?'get_store_context':'list_orders';
    for(const side of ['business','platform']){
      for(const invalid of ['version','extends','parent']){
        const b=structuredClone(business),p=structuredClone(platform);
        const capabilities=(side==='business'?b:p).ucp.capabilities;
        if(invalid==='parent')delete capabilities[parent];
        else Object.assign(capabilities[name]![0]!,{[invalid]:'invalid'});
        assert(!negotiate(b,p).routes.some(route=>route.operationId===id));
      }
    }
  }
});
test('PAP binds a cross-origin UCP endpoint without enabling Frontvia merchant reads',async t=>{
  const apiOrigin='https://api.shop.example', endpoint=apiOrigin+'/ucp/v1';
  const store='com.frontvia.shopping.store_context', history='com.frontvia.shopping.order_history';
  const confirmation='com.frontvia.shopping.checkout_confirmation';
  const transport=fixture(),previous=transport.override!;
  transport.override=(url,options)=>{
    if(url===apiOrigin+'/.well-known/oauth-protected-resource/ucp/v1')
      return jsonResponse(url,{resource:endpoint});
    if(url!==platformUrl && url!==origin+'/.well-known/ucp')return previous(url,options);
    const data=profile(url===platformUrl?undefined:endpoint);
    Object.assign(data.ucp.capabilities,{
      [store]:[{version:UCP_VERSION,extends:'dev.ucp.shopping.catalog.search'}],
      [history]:[{version:UCP_VERSION,extends:'dev.ucp.shopping.order'}],
      [confirmation]:[{version:UCP_VERSION,extends:'dev.ucp.shopping.checkout'}],
    });
    return jsonResponse(url,data);
  };
  const f=await setup(t,transport);
  const state=await f.client.store.read(),company=state.companies[f.companyRef]!;
  assert.equal(company.ucp?.endpoint,endpoint);
  assert(!company.ucp?.capabilities.includes(store));
  assert(!company.ucp?.capabilities.includes(history));
  assert(company.routes.some(route=>route.operationId==='prepare_checkout'));
  const search=company.routes.find(route=>route.operationId==='search_catalog')!;
  assert.equal(search.resource,endpoint);
  assert.equal(search.template,endpoint+'/catalog/search');
  await f.client.dispatchPap(f.sessionRef,{url:search.template,method:'POST',body:'{}'});
  const sent=transport.calls.at(-1)!;
  assert.equal(sent.url,search.template);
  assert(sent.options?.headers?.['poppy-session']);
  const count=transport.calls.length;
  for(const path of ['/store-context','/orders'])
    await assert.rejects(f.client.dispatchPap(f.sessionRef,{url:endpoint+path}),{code:'unsafe_destination'});
  assert.equal(transport.calls.length,count);
});
test('Frontvia order history uses the negotiated PAP Session and only its allowed query names',async t=>{
  const transport=fixture(),previous=transport.override!;
  transport.override=(url,options)=>{
    if(url!==platformUrl && url!==`${origin}/.well-known/ucp`)return previous(url,options);
    const data=profile(url===platformUrl?undefined:`${origin}/ucp/v1`);
    Object.assign(data.ucp.capabilities,{
      'com.frontvia.shopping.order_history':[{version:UCP_VERSION,extends:'dev.ucp.shopping.order'}],
      'com.frontvia.shopping.store_context':[{version:UCP_VERSION,extends:'dev.ucp.shopping.catalog.search'}],
    });
    return jsonResponse(url,data);
  };
  const f=await setup(t,transport),url=`${origin}/ucp/v1/orders?limit=3&cursor=next`;
  const state=await f.client.store.read(),company=state.companies[f.companyRef]!;
  const history=company.routes.find(route=>route.operationId==='list_orders')!;
  const reference=operationRef(company,history);
  assert.throws(()=>prepareOperation(state,{operationRef:reference}),{code:'permission_denied'});
  state.product={operations:{[reference]:{companyRef:company.ref,sessionRef:f.sessionRef,
    method:history.method,template:history.template,resource:history.resource,scopes:[],generation:1}}};
  assert.equal(prepareOperation(state,{operationRef:reference,query:{limit:'3',cursor:'next'}}).operation.url,url);
  assert.throws(()=>prepareOperation(state,{operationRef:reference,query:{destination:'other'}}),{code:'unsafe_destination'});
  await f.client.dispatchPap(f.sessionRef,{url});
  const sent=transport.calls.at(-1)!;
  assert.equal(sent.url,url);
  assert(sent.options?.headers?.['poppy-session']);
  assert.equal(sent.options?.headers?.['ucp-agent'],`profile="${platformUrl}"`);
  const count=transport.calls.length;
  for(const path of ['/orders?tenant_id=other','/orders?limit=1&limit=3','/store-context?cursor=next'])
    await assert.rejects(f.client.dispatchPap(f.sessionRef,{url:`${origin}/ucp/v1${path}`}),{code:'unsafe_destination'});
  assert.equal(transport.calls.length,count);
});
test('PAP rejects retired or unknown versions without following an alternate',async()=>{
  for(const version of ['0.3','1.x','2.0']){
    const transport=fixture();
    transport.override=url=>jsonResponse(url,{protocol_version:version,supported_versions:{'1.0':`${origin}/poppy/1.0.json`},organization:{name:'Shop',domain:'shop.example'}});
    await assert.rejects(new PapDiscovery(transport,()=>Date.now(),platformUrl).resolve('shop.example'),{code:'unsupported_profile'});
    assert.equal(transport.calls.length,1);
  }
});
test('Session pins version and extension headers and protects caller overrides',async t=>{
  const f=await setup(t,fixture('1.1'));await f.client.dispatchPap(f.sessionRef,{url:`${origin}/ucp/v1/catalog/search`,method:'POST',body:'{}'});
  const sent=f.transport.calls.at(-1)!.options!.headers!;
  assert.equal(sent['poppy-version'],'1.0');assert.equal(sent['poppy-extensions'],'"ucp";v="1"');assert.equal(sent['ucp-agent'],`profile="${platformUrl}"`);
  for(const header of ['Poppy-Version','Poppy-Extensions','UCP-Agent','Signature','Signature-Input','Content-Digest'])await assert.rejects(f.client.dispatchPap(f.sessionRef,{url:`${origin}/api/cart`,headers:{[header]:'bad'}}));
  await f.client.store.transaction(state=>{delete (state.sessions[f.sessionRef] as Partial<typeof state.sessions[string]>).protocolVersion;});
  const count=f.transport.calls.length;
  await assert.rejects(f.client.dispatchPap(f.sessionRef,{url:`${origin}/api/cart`}),{code:'version_unsupported'});
  assert.equal(f.transport.calls.length,count);
});
test('PAR is preferred, carries consent, assertion and the same DPoP key as token exchange',async t=>{
  const transport=new FixtureTransport();transport.mode='account';
  transport.override=url=>url.includes('oauth-authorization-server')?jsonResponse(url,{issuer:transport.issuer,protected_resources:[origin],token_endpoint:`${transport.issuer}/token`,authorization_endpoint:`${transport.issuer}/authorize`,revocation_endpoint:`${transport.issuer}/revoke`,pushed_authorization_request_endpoint:`${transport.issuer}/par`,require_pushed_authorization_requests:true,grant_types_supported:['authorization_code','refresh_token'],token_endpoint_auth_methods_supported:['private_key_jwt'],code_challenge_methods_supported:['S256'],dpop_signing_alg_values_supported:['ES256']}):url.endsWith('/par')?jsonResponse(url,{request_uri:'urn:ietf:params:oauth:request_uri:test',expires_in:60},201):undefined;
  const f=await setup(t,transport);const login=await f.client.startSignIn(f.subjectRef,{scopes:['orders:read'],resource:origin,redirectUri:'https://agent.example/pap-callback',callbackMode:'handoff'});
  const url=new URL(login.authorizationUrl);assert.deepEqual([...url.searchParams.keys()].sort(),['client_id','request_uri']);
  const par=transport.calls.find(c=>c.url.endsWith('/par'))!;const fields=new URLSearchParams(par.options!.body);assert.equal(fields.get('prompt'),'consent');assert(fields.get('client_assertion'));assert(par.options!.headers!.dpop);assert(!par.options!.headers!['poppy-session']);
  const state=await f.client.store.read(),tx=state.transactions[login.transactionRef]!;
  const result=await f.client.completeSignIn(tx.ref,{state:tx.state,iss:tx.issuer,code:'fixture-code'});
  assert.equal((await f.client.store.read()).grants[result.grantRef]!.dpopKey!.handle,tx.dpopKey!.handle);
});
test('resource tokens rotate one shared refresh grant with its original DPoP key',async t=>{
  const transport=new FixtureTransport();transport.mode='account';const f=await setup(t,transport);
  const login=await f.client.startSignIn(f.subjectRef,{scopes:['orders:read'],resource:origin,redirectUri:'https://agent.example/pap-callback',callbackMode:'handoff'});
  const tx=(await f.client.store.read()).transactions[login.transactionRef]!;const result=await f.client.completeSignIn(tx.ref,{state:tx.state,iss:tx.issuer,code:'fixture-code'});
  const original=(await f.client.store.read()).grants[result.grantRef]!;
  await f.client.store.transaction(state=>state.companies[f.companyRef]!.routes.push({method:'GET',template:`${origin}/api/second`,resource:`${origin}/second`}));
  await f.client.refreshAccountGrant(result.grantRef,undefined,`${origin}/second`);
  const state=await f.client.store.read();assert.equal(Object.keys(state.grants).length,1);assert.equal(state.grants[result.grantRef]!.resource,`${origin}/second`);assert.equal(state.grants[result.grantRef]!.dpopKey!.handle,original.dpopKey!.handle);
});

test('UCP writes require UUID idempotency and always supply a UUID Request-Id',async t=>{
  const f=await setup(t);
  for(const idempotencyKey of [undefined,'legacy-command'])await assert.rejects(f.client.dispatchPap(f.sessionRef,{url:`${origin}/ucp/v1/carts`,method:'POST',body:'{}',idempotencyKey}));
  assert(!f.transport.calls.some(call=>call.url===`${origin}/ucp/v1/carts`));
  const idempotencyKey='7a66afff-4d4a-4d28-9dfb-247e7e72f7f1';await f.client.dispatchPap(f.sessionRef,{url:`${origin}/ucp/v1/carts`,method:'POST',body:'{}',idempotencyKey});
  const headers=f.transport.calls.at(-1)!.options!.headers!;assert.equal(headers['idempotency-key'],idempotencyKey);assert.match(headers['request-id']!,/^[a-f0-9-]{36}$/);
});
test('version_unsupported is surfaced without retrying or changing the Session',async t=>{
  const f=await setup(t), before=(await f.client.store.read()).sessions[f.sessionRef]!.sid;
  const previous=f.transport.override!;let sent=0;
  f.transport.override=(url,options)=>{
    if(url!==`${origin}/api/cart`)return previous(url,options);
    sent++;
    return jsonResponse(url,{error:'version_unsupported'},400);
  };
  await assert.rejects(f.client.dispatchPap(f.sessionRef,{url:`${origin}/api/cart`}),{code:'version_unsupported'});
  assert.equal(sent,1);
  assert.equal((await f.client.store.read()).sessions[f.sessionRef]!.sid,before);
});
test('UCP Session errors require the detected channel, error envelope and HTTP 400', async t => {
  const f = await setup(t);
  const before = (await f.client.store.read()).sessions[f.sessionRef]!.sid;
  const cart = `${origin}/ucp/v1/carts/cart_one`;
  const error = (code: string, version = UCP_VERSION) => ({
    ucp: { version, status: 'error' }, messages: [{ type: 'error', code, content: code }],
  });
  const previous = f.transport.override!;
  const cases = [
    { url: cart, status: 401, body: error('authentication_required') },
    { url: cart, status: 409, body: error('session_ended') },
    { url: cart, status: 400, body: error('session_ended', '2026-01-01') },
    { url: cart, status: 400, body: { ...error('session_ended'), ucp: { version: UCP_VERSION } } },
    { url: cart, status: 400, body: { ...error('session_ended'), messages: [{ type: 'warning', code: 'session_ended' }] } },
    { url: cart, status: 400, body: { error: 'session_ended' } },
    { url: `${origin}/api/cart`, status: 400, body: error('session_ended') },
  ];
  for (const {url, status, body} of cases) {
    f.transport.override = (target, options) => target === url ? jsonResponse(url, body, status) : previous(target, options);
    assert.equal((await f.client.dispatchPap(f.sessionRef, {url})).status, status);
  }
  for (const code of ['invalid_session', 'version_unsupported']) {
    f.transport.override = (target, options) => target === cart ? jsonResponse(cart, error(code), 400) : previous(target, options);
    await assert.rejects(f.client.dispatchPap(f.sessionRef, {url:cart}), {code});
  }
  assert.equal((await f.client.store.read()).sessions[f.sessionRef]!.sid, before);
});
test('UCP session_ended rotates once and retries only within the existing consent policy', async t => {
  const f = await setup(t);
  const cart = `${origin}/ucp/v1/carts`;
  const previous = f.transport.override!;
  f.transport.override = (url, options) => url === cart ? jsonResponse(url, {
    ucp: { version: UCP_VERSION, status: 'error' },
    messages: [{ type: 'error', code: 'session_ended', content: 'Session ended' }],
  }, 400) : previous(url, options);

  const operation = { url: cart, method: 'POST', body: '{"line_items":[]}', idempotencyKey: '7a66afff-4d4a-4d28-9dfb-247e7e72f7f1' };
  await assert.rejects(f.client.dispatchPap(f.sessionRef, operation), { code: 'session_ended' });
  const calls = f.transport.calls.filter(call => call.url === cart);
  assert.equal(calls.length, 2);
  const [first, second] = calls.map(call => call.options!.headers!['poppy-session']!);
  assert.notEqual(jwtParts(first!).payload.sid, jwtParts(second!).payload.sid);
  for (const call of calls) {
    assert.equal(call.options!.headers!['idempotency-key'], operation.idempotencyKey);
    assert.equal(call.options!.body, operation.body);
  }

  await assert.rejects(f.client.dispatchPap(f.sessionRef, operation, {singleOperation: true}), { code: 'session_ended' });
  assert.equal(f.transport.calls.filter(call => call.url === cart).length, 3);
});
test('service PRM must match its exact resource rather than broad origin metadata',async()=>{
  const transport=fixture(),prior=transport.override!;transport.override=(url,options)=>url===`${origin}/.well-known/oauth-protected-resource/ucp/v1`?jsonResponse(url,{resource:origin}):prior(url,options);
  await assert.rejects(new PapDiscovery(transport,()=>Date.now(),platformUrl).resolve('shop.example'));
});

test('legacy Company aliases retain the buyer ID while opening a current-version Session',async t=>{
  const f=await setup(t);
  const before=await f.client.store.read();
  const original=before.subjects[f.subjectRef]!;
  const current=original.companyRef;
  await f.client.store.transaction(state=>{
    const legacy={...state.companies[current]!,ref:'legacy-company-alias',generation:0};
    delete (legacy as Partial<typeof legacy>).protocolVersion;
    delete legacy.ucp;
    state.companies[legacy.ref]=legacy;
    state.subjects[f.subjectRef]!.companyRef=legacy.ref;
    delete (state.sessions[f.sessionRef] as Partial<typeof state.sessions[string]>).protocolVersion;
  });
  const next=await f.client.getOrCreatePapUser(current);
  assert.notEqual(next.subjectRef,f.subjectRef);
  const session=await f.client.openPapSession(next.subjectRef);
  const state=await f.client.store.read();
  assert.equal(state.subjects[next.subjectRef]!.userId,original.userId);
  assert.equal(state.subjects[f.subjectRef]!.companyRef,'legacy-company-alias');
  assert.equal(state.sessions[session.sessionRef]!.protocolVersion,'1.0');
  assert.equal(state.sessions[f.sessionRef]!.protocolVersion,undefined);
});

test('catalog and checkout require a common Fulfillment parent at the negotiated version', () => {
  const fulfillment = 'dev.ucp.shopping.fulfillment', checkout = 'dev.ucp.shopping.checkout', catalog = 'dev.ucp.shopping.catalog.search';
  const make = (parents: string[], endpoint?: string) => {
    const doc = profile(endpoint);
    Object.assign(doc.ucp.capabilities, { [fulfillment]: [{ version: UCP_VERSION, extends: parents }] });
    return doc;
  };
  const select = (business: string[], platform: string[]) => negotiateUcp(make(business,origin + '/ucp/v1'),make(platform),
    origin + '/.well-known/ucp',platformUrl,origin).ucp;
  assert.deepEqual(select([checkout,catalog],[catalog]).fulfillmentParents, [catalog]);
  for (const parents of [[checkout,catalog],[catalog,checkout]]) {
    const business = make([],origin + '/ucp/v1');
    const platform = make([catalog]);
    delete platform.ucp.capabilities[checkout];
    Object.assign(business.ucp.capabilities, {
      [fulfillment]: parents.map(parent => ({version: UCP_VERSION, extends: parent})),
    });
    const {ucp} = negotiateUcp(business,platform,origin + '/.well-known/ucp',platformUrl,origin);
    assert(ucp.capabilities.includes(fulfillment));
    assert.deepEqual(ucp.fulfillmentParents, [catalog]);
  }
  const disjoint = select([catalog],[checkout]);
  assert.deepEqual(disjoint.fulfillmentParents, []);
  assert(!disjoint.capabilities.includes(fulfillment));
});
