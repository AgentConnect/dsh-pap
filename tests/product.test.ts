import test from 'node:test';
import { fixture } from './helpers/product-fixture.js';
import assert from 'node:assert/strict';
import https from 'node:https';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { PAP_CONSUMER, PAP_MANAGER, PAP_TOOLS, operationRequestSchema, type ProductResult } from '../src/product-api.js';
import type { Company, HttpTransport, PapState, ProductOperationApproval } from '../src/types.js';
import { PapError } from '../src/errors.js';
import { binding, jsonResponse } from './fixture.js';
import { operationRef, prepareDiscoveredOperation, publicResponse } from '../src/product-operations.js';
import { negotiateUcp } from '../src/ucp.js';
import { FRONTVIA_CHECKOUT_CONFIRMATION } from '../src/frontvia-checkout.js';
import { publicResult } from '../src/plugin.js';
import { PapClient } from '../src/client.js';
import { SafeHttpsTransport } from '../src/network.js';

type Value = Record<string, any>;
function value(result: ProductResult): Value { assert.equal(result.ok, true, result.ok ? undefined : result.error.code); return (result as { value: Value }).value; }
function error(result: ProductResult, code: string) { assert.equal(result.ok,false); if(result.ok)throw new Error('Expected refusal'); assert.equal(result.error.code,code); assert(Object.keys(result.error).every(key=>['code','phase','businessRequest','httpStatus','retryAfterSeconds','approval'].includes(key))); }

async function connected(f: Awaited<ReturnType<typeof fixture>>) {
  value(await f.select()); const company = value(await f.manager.manage({ action: 'company/discover', domain: 'shop.example' }));
  const session = value(await f.manager.manage({ action: 'session/connect', companyRef: company.companyRef }));
  const operations = value(await f.manager.operations()) as unknown as Value[];
  const operation = operations.find(item => item.method === 'GET' && item.path === '/api/cart')!;
  return { company, session, operation };
}
async function accountConnection(f:Awaited<ReturnType<typeof fixture>>) {
  const connectedState=await connected(f);const {operation,session,company}=connectedState;
  const pending=value(await f.manager.manage({action:'account/sign-in',sessionRef:session.sessionRef,operationRef:operation.operationRef,scopes:['orders:read']}));
  const authorize=new URL(pending.authorizationUrl);f.setResponse({state:authorize.searchParams.get('state')!,iss:f.transport.issuer,code:'unit-only-code'});
  value(await f.manager.manage({action:'account/collect',transactionRef:pending.transactionRef}));
  const account=value(await f.manager.manage({action:'session/connect',companyRef:company.companyRef,accountSlot:pending.accountSlot}));
  value(await f.manager.manage({action:'operation/enable',operationRef:operation.operationRef,sessionRef:account.sessionRef,scopes:['orders:read']}));
  return {...connectedState,pending,account,engine:(f.service as unknown as {client:PapClient}).client};
}

test('Frontvia checkout extension binds business proof to negotiated Complete only', () => {
  const origin = 'https://merchant.test', endpoint = origin + '/ucp/v1';
  const service = {version:'2026-08-25', transport:'rest', endpoint};
  const checkout = 'dev.ucp.shopping.checkout';
  const capability = {version:service.version};
  const profile = (extension: boolean) => ({
    ucp: {version:service.version, services:{'dev.ucp.shopping':[service]}, payment_handlers:{}, capabilities:{
      [checkout]: [capability],
      ...(extension ? {[FRONTVIA_CHECKOUT_CONFIRMATION]: [{...capability, extends:checkout}]} : {}),
    }},
  });
  const negotiate = (platform: boolean) => negotiateUcp(profile(true), profile(platform), origin + '/.well-known/ucp',
    'https://platform.test/.well-known/ucp', origin + '/commerce/rpc');
  const negotiated = negotiate(true);
  assert.deepEqual(negotiated.routes.filter(route => route.requiresConsent).map(route => route.operationId),
    ['prepare_checkout', 'approve_checkout_handoff']);
  assert(!negotiate(false).routes.some(route => route.requiresConsent));

  const prepare = (platform: boolean, operationId: string) => {
    const { ucp, routes } = negotiate(platform);
    const company = {ref:'company', sources:[], ucp, routes} as unknown as Company;
    const route = routes.find(route => route.operationId === operationId)!;
    const approval = {scopes:[]} as unknown as ProductOperationApproval;
    const input = {operationRef:operationRef(company, route), path:{id:'checkout'}, checkoutConfirmation:'e30'};
    return prepareDiscoveredOperation({companies:{company}} as unknown as PapState, input, approval);
  };
  assert.equal(prepare(true, 'complete_checkout').operation.headers?.['frontvia-checkout-confirmation'], 'e30');
  assert.throws(() => prepare(true, 'approve_checkout_handoff'), /permission_denied/);
  assert.throws(() => prepare(false, 'complete_checkout'), /permission_denied/);
  assert(!operationRequestSchema.safeParse({operationRef:'operation', checkoutConfirmation:'invalid=\r\n'}).success);
});

test('negotiated Frontvia prepare uses exact owner consent under allow-all writes', async t => {
  const platformUrl = 'https://platform.test/.well-known/ucp';
  const f = await fixture(t, {
    autoConnect:true, businessConsumers:['example/shop'], ucpPlatformProfileUrl:platformUrl,
  });
  f.policy.set('write','allow');
  const version = '2026-08-25';
  const checkout = 'dev.ucp.shopping.checkout';
  const capabilities = {
    [checkout]: [{version}],
    [FRONTVIA_CHECKOUT_CONFIRMATION]: [{version, extends:checkout}],
  };
  f.transport.override = (url, options) => {
    const target = new URL(url);
    if (target.pathname === '/.well-known/poppy.json')
      return jsonResponse(url, {protocol_version:'1.0', organization:{name:'Shop', domain:target.hostname},
        extensions:{ucp:[{version:'1'}]}});
    if (target.pathname === '/.well-known/ucp') return jsonResponse(url, {
      ucp:{version, capabilities, payment_handlers:{},
        services:{'dev.ucp.shopping':[{version, transport:'rest', endpoint:'https://shop.example/ucp/v1'}]}},
    });
    if (target.pathname.endsWith('/prepare')) {
      assert.equal(options?.method,'POST');
      assert.equal(options?.body,'{}');
      return jsonResponse(url,{status:'prepared'});
    }
    return undefined;
  };
  const context = [...f.loader.entries()].find(entry => entry.options.name === 'example/shop')!.fiber!.ctx;
  const business = f.service.acquireBusiness(context);
  value(await business.connect('shop.example'));
  const routes = value(await business.operations()) as unknown as Value[];
  const prepare = routes.find(route => route.operationId === 'prepare_checkout')!;
  const approve = routes.find(route => route.operationId === 'approve_checkout_handoff')!;
  assert(prepare.requiresApproval && approve.requiresApproval);
  const pending = business.request({operationRef:prepare.operationRef, path:{id:'draft'}, body:{},
    idempotencyKey:'7a66afff-4d4a-4d28-9dfb-247e7e72f7f1'});
  await untilConsent(f);
  assert(f.consent.request?.url.endsWith('/checkout-sessions/draft/prepare'));
  assert(!f.transport.calls.some(call => call.url.endsWith('/prepare')));
  f.consent.approve();
  assert.equal(value(await pending).status,200);
  assert.equal(f.transport.calls.filter(call => call.url.endsWith('/prepare')).length,1);
});

test('PAP 1.0 business client interoperates with an independent HTTPS UCP Catalog and Cart peer', async t => {
  const root=await mkdtemp(join(tmpdir(),'pap-ucp-peer-'));
  const key=join(root,'tls.key'),cert=join(root,'tls.crt');
  t.after(()=>rm(root,{recursive:true,force:true}));
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','1',
    '-subj','/CN=merchant.test','-addext','subjectAltName=DNS:merchant.test,DNS:platform.test'],{stdio:'ignore'});
  const origin='https://merchant.test',platform='https://platform.test/.well-known/ucp',version='2026-08-25';
  const spec=`https://ucp.dev/${version}`;
  const capabilities={
    'dev.ucp.shopping.catalog.search':[{version,spec:spec+'/specification/shopping/catalog/',schema:spec+'/schemas/shopping/catalog_search.json'}],
    'dev.ucp.shopping.cart':[{version,spec:spec+'/specification/shopping/cart/',schema:spec+'/schemas/shopping/cart.json'}],
  };
  const shopping={version,transport:'rest',spec:spec+'/specification/overview/',schema:spec+'/services/shopping/rest.openapi.json'};
  const organization={name:'Independent UCP peer',domain:'merchant.test'};
  const ca=await readFile(cert);
  const create={line_items:[{item:{id:'variant_tea'},quantity:1}]};
  const replace={line_items:[{id:'line_tea',item:{id:'variant_tea'},quantity:2}]};
  const createKey='7a66afff-4d4a-4d28-9dfb-247e7e72f7f1';
  const replaceKey='7a66afff-4d4a-4d28-9dfb-247e7e72f7f2';
  const staleKey='7a66afff-4d4a-4d28-9dfb-247e7e72f7f3';
  const cart=(quantity:number)=>{
    const totals=[{type:'subtotal',display_text:'Subtotal',amount:800*quantity},{type:'total',display_text:'Total',amount:800*quantity}];
    return {ucp:{version,status:'success',capabilities},id:'cart_tea',currency:'USD',
      line_items:[{id:'line_tea',item:{id:'variant_tea',title:'Tea',price:800},quantity,totals}],totals};
  };
  const stale={ucp:{version,status:'error'},messages:[{type:'error',code:'stale_cart',content:'Cart has changed.'}]};
  const calls:string[]=[],discovery:string[]=[],requestIds=new Set<string>();
  let etag='"cart-v1"';
  let peerFailure:unknown;
  const server=https.createServer({key:await readFile(key),cert:ca},async(request,response)=>{
    const send=(status:number,body:unknown,etag?:string)=>{
      response.writeHead(status,{'content-type':'application/json',...(etag?{etag}:{})});
      response.end(JSON.stringify(body));
    };
    try{
      const path=request.url??'';
      if(!path.startsWith('/shopping/')){
        assert(!request.headers['poppy-session']&&!request.headers.authorization);
        discovery.push(request.headers.host+path);
        if(request.headers.host==='platform.test'&&path==='/.well-known/ucp')
          return send(200,{ucp:{version,capabilities,payment_handlers:{},
            services:{'dev.ucp.shopping':[shopping]}}});
        if(path==='/.well-known/poppy.json')
          return send(200,{protocol_version:'1.0',organization,extensions:{ucp:[{version:'1'}]}});
        if(path==='/.well-known/ucp')return send(200,{ucp:{version,capabilities,payment_handlers:{},
          services:{'dev.ucp.shopping':[{...shopping,endpoint:origin+'/shopping'}]}}});
        return send(404,{});
      }
      calls.push(request.method+' '+path);
      assert.equal(request.headers['poppy-version'],'1.0');
      assert.equal(request.headers['poppy-extensions'],'"ucp";v="1"');
      assert.equal(request.headers['ucp-agent'],`profile="${platform}"`);
      assert.equal(typeof request.headers['poppy-session'],'string');
      assert.equal(request.headers.authorization,undefined);
      assert.equal(request.headers['content-type'],'application/json');
      const requestId=request.headers['request-id'];
      assert(typeof requestId==='string'&&/^[0-9a-f-]{36}$/.test(requestId)&&!requestIds.has(requestId));
      requestIds.add(requestId);
      const chunks:Buffer[]=[];
      for await(const chunk of request)chunks.push(chunk);
      const body=JSON.parse(Buffer.concat(chunks).toString());
      if(path==='/shopping/catalog/search'){
        assert.equal(request.method,'POST');assert.deepEqual(body,{query:'tea',context:{country:'US'}});
        assert.equal(request.headers['idempotency-key'],undefined);
        const price={amount:800,currency:'USD'},description={plain:'Loose leaf tea'};
        return send(200,{ucp:{version,status:'success',capabilities},products:[{id:'product_tea',title:'Tea',description,
          price_range:{min:price,max:price},variants:[{id:'variant_tea',title:'Tea',description,price}]}]});
      }
      if(path==='/shopping/carts'){
        assert.equal(request.method,'POST');assert.deepEqual(body,create);
        assert.equal(request.headers['idempotency-key'],createKey);
        return send(201,cart(1),etag);
      }
      assert.equal(path,'/shopping/carts/cart_tea');assert.equal(request.method,'PUT');
      assert.deepEqual(body,replace);
      assert.equal(request.headers['if-match'],'"cart-v1"');
      if(request.headers['if-match']!==etag){
        assert.equal(request.headers['idempotency-key'],staleKey);
        return send(412,stale);
      }
      assert.equal(request.headers['idempotency-key'],replaceKey);
      etag='"cart-v2"';
      return send(200,cart(2),etag);
    }catch(error){peerFailure=error;send(400,{});}
  });
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>new Promise<void>(resolve=>server.close(()=>resolve())));
  const port=(server.address() as {port:number}).port;
  const transport=new SafeHttpsTransport({ca,privateOrigins:[origin,'https://platform.test'],
    portOverrides:{[origin]:port,'https://platform.test':port},lookup:async()=>[{address:'127.0.0.1',family:4}]});
  const f=await fixture(t,{autoConnect:true,businessConsumers:['example/shop'],transport,ucpPlatformProfileUrl:platform});
  f.policy.set('write','allow');
  const context=[...f.loader.entries()].find(entry=>entry.options.name==='example/shop')!.fiber!.ctx;
  const business=f.service.acquireBusiness(context);
  const company=value(await business.connect('merchant.test'));
  const operations=(value(await business.operations()) as unknown as Value[]).filter(op=>op.companyRef===company.company.companyRef);
  const ref=(id:string)=>operations.find(op=>op.channel==='ucp'&&op.operationId===id)!.operationRef;
  const catalog=value(await business.request({operationRef:ref('search_catalog'),body:{query:'tea',context:{country:'US'}}}));
  assert.equal(catalog.status,200);assert.equal(catalog.body.products[0].variants[0].id,'variant_tea');
  const added=value(await business.request({operationRef:ref('create_cart'),body:create,idempotencyKey:createKey}));
  assert.deepEqual(added,{status:201,etag:'"cart-v1"',body:cart(1)});
  const update={operationRef:ref('update_cart'),path:{id:added.body.id},body:replace,ifMatch:added.etag};
  assert.deepEqual(value(await business.request({...update,idempotencyKey:replaceKey})),{status:200,etag:'"cart-v2"',body:cart(2)});
  const failure=value(await business.request({...update,idempotencyKey:staleKey}));
  assert.deepEqual(failure,{status:412,body:stale});
  assert.equal(peerFailure,undefined);
  assert(discovery.includes('merchant.test/.well-known/poppy.json')&&discovery.includes('merchant.test/.well-known/ucp')
    &&discovery.includes('platform.test/.well-known/ucp'));
  assert.deepEqual(calls,['POST /shopping/catalog/search','POST /shopping/carts','PUT /shopping/carts/cart_tea','PUT /shopping/carts/cart_tea']);
});

test('only a business order file uses the larger PDF response limit', async t => {
  const origin = 'https://shop.example';
  const root = await mkdtemp(join(tmpdir(), 'pap-order-pdf-'));
  t.after(() => rm(root, { recursive:true, force:true }));
  const key = join(root,'key.pem'), cert = join(root,'cert.pem');
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,
    '-days','1','-subj','/CN=shop.example','-addext','subjectAltName=DNS:shop.example'],{stdio:'ignore'});
  const ca = await readFile(cert);
  const size = 1024 * 1024;
  const pdf = Buffer.alloc(9 * size); pdf.write('%PDF-');
  const digest = createHash('sha256').update(pdf).digest('hex');
  const route = '/commerce/v1/stores/{store_id}/orders/{order_id}/lines/{line_id}/files/{sha256}';
  const other = '/unrelated';
  const path = {store_id:'shop',order_id:'order',line_id:'line',sha256:digest};
  const resolved = route.replace(/\{([a-z_0-9]+)\}/g, (_match,key:keyof typeof path)=>path[key]);
  const definition = {operationId:'commerce.orders.file',parameters:Object.keys(path).map(name=>({name,in:'path',required:true,schema:{type:'string'}}))};
  const largePdf = Buffer.alloc(11 * size); largePdf.write('%PDF-');
  let file = pdf;
  const server = https.createServer({key:await readFile(key),cert:ca}, (req,res) => {
    res.setHeader('content-type','application/json');
    if (req.url === '/.well-known/poppy.json') return res.end(JSON.stringify({
      protocol_version:'1.0',organization:{name:'Shop',domain:'shop.example'},
      apis:[{type:'openapi',url:origin+'/openapi.json'}],
    }));
    if (req.url === '/openapi.json') return res.end(JSON.stringify({
      openapi:'3.1.0',servers:[{url:origin}],paths:{[route]:{get:definition},[other]:{get:{operationId:'unrelated'}}},
    }));
    if (req.url === other) return res.writeHead(200,{'content-type':'application/pdf'}).end(largePdf);
    if (req.url === resolved && req.headers['poppy-session'])
      return res.writeHead(200,{'content-type':'application/pdf','x-frontvia-sha256':digest}).end(file);
    return res.writeHead(404).end();
  });
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>new Promise<void>(resolve=>server.close(()=>resolve())));
  const options = {ca,privateOrigins:[origin],portOverrides:{[origin]:(server.address() as {port:number}).port},
    lookup:async()=>[{address:'127.0.0.1',family:4}]};
  const transport = new SafeHttpsTransport({...options,maxBytes:8 * size});
  await assert.rejects(transport.request(origin+other),{code:'request_uncertain'});
  assert.equal((await new SafeHttpsTransport({...options,maxBytes:12 * size}).request(origin+other)).body.length,largePdf.length);

  const f = await fixture(t,{autoConnect:true,businessConsumers:['example/shop'],transport});
  const context = [...f.loader.entries()].find(entry=>entry.options.name==='example/shop')!.fiber!.ctx;
  const business = f.service.acquireBusiness(context);
  value(await business.connect('shop.example'));
  const operations = value(await business.operations()) as unknown as Value[];
  const operationRef = operations.find(entry=>entry.operationId==='commerce.orders.file')!.operationRef;
  const download = await business.request({operationRef,path});
  const body = value(download).body;
  assert.equal(body.sha256,digest);
  assert.deepEqual(Buffer.from(body.bytes_base64,'base64'),pdf);
  file = largePdf;
  error(await business.request({operationRef,path}),'request_uncertain');
});

test('a selected UCP order history operation keeps its protocol on a shared OpenAPI URL', async t => {
  const platformUrl = 'https://platform.test/.well-known/ucp';
  const origin = 'https://shop.example';
  const version = '2026-08-25';
  const order = 'dev.ucp.shopping.order';
  const history = 'com.frontvia.shopping.order_history';
  const f = await fixture(t, {autoConnect:true, businessConsumers:['example/shop'], ucpPlatformProfileUrl:platformUrl});
  f.transport.override = url => {
    const path = new URL(url).pathname;
    if (path === '/.well-known/poppy.json')
      return jsonResponse(url, {protocol_version:'1.0', organization:{name:'Shop',domain:'shop.example'},
        apis:[{type:'openapi',url:origin+'/openapi.json'}], extensions:{ucp:[{version:'1'}]}});
    if (path === '/openapi.json') return jsonResponse(url, {
      openapi:'3.1.0', servers:[{url:origin}], paths:{'/ucp/v1/orders':{get:{operationId:'orders'}}},
    });
    if (path === '/.well-known/ucp') return jsonResponse(url, {ucp:{
      version, capabilities:{[order]:[{version}], [history]:[{version,extends:order}]}, payment_handlers:{},
      services:{'dev.ucp.shopping':[{version,transport:'rest',endpoint:origin+'/ucp/v1'}]},
    }});
    if (path === '/ucp/v1/orders') return jsonResponse(url, {items:[]});
    return undefined;
  };
  const context = [...f.loader.entries()].find(entry => entry.options.name === 'example/shop')!.fiber!.ctx;
  const business = f.service.acquireBusiness(context);
  value(await business.connect('shop.example'));
  const routes = value(await business.operations()) as unknown as Value[];
  const ucp = routes.find(route => route.channel === 'ucp' && route.operationId === 'list_orders')!;
  const openapi = routes.find(route => route.channel === 'openapi' && route.path === '/ucp/v1/orders')!;
  assert(ucp && openapi);
  assert.equal(value(await business.request({operationRef:ucp.operationRef})).status, 200);
  assert.equal(value(await business.request({operationRef:openapi.operationRef})).status, 200);
  const calls = f.transport.calls.filter(call => call.url === origin+'/ucp/v1/orders');
  assert.equal(calls.length, 2);
  assert.equal(calls[0]!.options?.headers?.['ucp-agent'], `profile="${platformUrl}"`);
  assert.match(calls[0]!.options?.headers?.['request-id'] ?? '', /^[a-f0-9-]{36}$/);
  assert.equal(calls[1]!.options?.headers?.['ucp-agent'], undefined);
});

test('PAP product real Loader: disabled/unconfigured do not access secrets or network', async t => {
  const f = await fixture(t, { enabled: false }); assert.equal(value(await f.manager.status()).state, 'disabled');
  assert.equal(f.contexts.length, 0); assert.equal(f.transport.calls.length, 0); assert.deepEqual(await readdir(f.root), []);
  error(await f.select(), 'not_configured');
  const g = await fixture(t); assert.equal(value(await g.manager.status()).state, 'unconfigured'); assert.equal(g.contexts.length, 0);
  const h = await fixture(t, { missingConfig: true }); assert.equal(value(await h.manager.status()).state, 'unconfigured'); error(await h.select(), 'not_configured');
});
test('PAP product: installed manager and tools are distinct, raw contexts and wire capabilities denied', async t => {
  const f = await fixture(t);
  assert.throws(() => f.service.acquireManagement(f.ctx), PapError); assert.throws(() => f.service.acquireTools(f.ctx), PapError);
  const managerEntry = [...f.loader.entries()].find(entry => entry.options.name === PAP_MANAGER)!;
  assert.throws(() => f.service.acquireTools(managerEntry.fiber!.ctx), PapError);
  error(await f.manager.manage({ action: 'identity/select', reference: { ...binding.identityRef, verified: true } } as any), 'permission_denied');
  value(await f.select()); assert(f.contexts.length >= 2);
  const entry = [...f.loader.entries()].find(value => value.options.name === PAP_CONSUMER)!;
  assert(f.contexts.every(context => context.fiber === (entry.fiber as any).ctx.fiber));
  error(await f.execute('pap_request', { operationRef: 'made-up', url: 'https://evil.example', scopes: [] }), 'permission_denied');
  assert.deepEqual([...f.tools.keys()], ['pap_connect','pap_status','pap_operations','pap_request']);
  assert(f.tools.get('pap_status').description.includes('https://agent-network-protocol.com'));
  assert(f.tools.get('pap_status').description.includes('supports MCP, ANP and PAP'));
});
test('PAP product: explicit Company + Session + operation permission enables signed-out requests without Token', async t => {
  const f = await fixture(t); const { operation, session } = await connected(f);
  assert.deepEqual(value(await f.execute('pap_operations')), []);
  error(await f.execute('pap_request', { operationRef: operation.operationRef }), 'permission_denied');
  value(await f.manager.manage({ action: 'operation/enable', operationRef: operation.operationRef, sessionRef: session.sessionRef }));
  const response = value(await f.execute('pap_request', { operationRef: operation.operationRef })); assert.equal(response.status, 200); assert.deepEqual(response.body, { ok: true });
  const calls = f.transport.calls.filter(call => call.url.endsWith('/api/cart')); assert.equal(calls.length, 1); assert(calls[0]!.options?.headers?.['poppy-session']); assert(!calls[0]!.options?.headers?.authorization); assert(!f.transport.calls.some(call => call.url.endsWith('/token')));
  const safe = JSON.stringify(await f.execute('pap_status')); assert(!safe.includes('usr_')); assert(!safe.includes('key_')); assert(!safe.includes('https://')); assert(!safe.includes('eyJ'));
  await f.manager.manage({ action: 'operation/disable', operationRef: operation.operationRef }); error(await f.execute('pap_request', { operationRef: operation.operationRef }), 'permission_denied');
});
test('PAP product: path traversal, undeclared query/headers and arbitrary destination never dispatch', async t => {
  const f = await fixture(t); const { session } = await connected(f); const entries = value(await f.manager.operations()) as unknown as Value[];
  const operation = entries.find(item => item.path === '/api/objects/{id}')!;
  value(await f.manager.manage({ action: 'operation/enable', operationRef: operation.operationRef, sessionRef: session.sessionRef }));
  const before = f.host.sessionCount;
  for (const path of [{}, { id: '..' }, { id: 'a/b' }, { id: '%2f' }, { id: 'valid', other: 'bad' }]) error(await f.execute('pap_request', { operationRef: operation.operationRef, path }), 'unsafe_destination');
  error(await f.execute('pap_request', { operationRef: operation.operationRef, path: { id: 'one' }, query: { next: 'https://evil.example' } }), 'unsafe_destination');
  error(await f.execute('pap_request', { operationRef: operation.operationRef, path: { id: 'one' }, headers: { authorization: 'bad' } }), 'permission_denied');
  assert.equal(f.host.sessionCount, before); value(await f.execute('pap_request', { operationRef: operation.operationRef, path: { id: 'one' } }));
});
test('PAP product: user-only Direct handoff binds C target and keeps auth URL/code out of tools', async t => {
  const f = await fixture(t, { mode: 'account' }); const { session, operation, company } = await connected(f);
  const pending = value(await f.manager.manage({ action: 'account/sign-in', sessionRef: session.sessionRef, operationRef: operation.operationRef, scopes: ['orders:read'] }));
  assert(pending.authorizationUrl); assert.equal(f.counts.registerCount, 1); assert.equal(f.counts.disposedCallbacks, 1);
  const url = new URL(pending.authorizationUrl); f.setResponse({ state: url.searchParams.get('state')!, iss: f.transport.issuer, code: 'unit-authorization-code' });
  value(await f.manager.manage({ action: 'account/collect', transactionRef: pending.transactionRef })); assert.equal(f.counts.claimCount, 1); assert.equal(f.counts.disposedCallbacks, 2);
  const account = value(await f.manager.manage({ action: 'session/connect', companyRef: company.companyRef, accountSlot: pending.accountSlot }));
  value(await f.manager.manage({ action: 'operation/enable', operationRef: operation.operationRef, sessionRef: account.sessionRef, scopes: ['orders:read'] }));
  value(await f.execute('pap_request', { operationRef: operation.operationRef })); assert(f.transport.calls.at(-1)!.options?.headers?.authorization?.startsWith('DPoP '));
  const tools = JSON.stringify([await f.execute('pap_status'),await f.execute('pap_operations')]);
  for (const forbidden of [pending.authorizationUrl, 'unit-authorization-code', url.searchParams.get('state')!, 'access-fixture','refresh-fixture','claim_secret','callbackRef','key_']) assert(!tools.includes(forbidden));
  f.transport.override = target => target.endsWith('/api/cart') ? jsonResponse(target, { unknown: 'prefix access-fixture suffix', nested: ['refresh-fixture'], 'refresh-fixture': 'unknown-key', token: 'unrecognized-token' }) : undefined;
  const echo = JSON.stringify(await f.execute('pap_request', { operationRef: operation.operationRef }));
  for (const forbidden of ['access-fixture','refresh-fixture','unrecognized-token']) assert(!echo.includes(forbidden));
  value(await f.manager.manage({ action: 'account/sign-out', accountSlot: pending.accountSlot })); assert.equal(value(await f.manager.status()).accounts[0].status, 'signed_out');
});
test('PAP product: stop/disabled tool Context denies cached capability, errors are fixed and credential fields redacted', async t => {
  const f = await fixture(t); const { operation, session } = await connected(f);
  value(await f.manager.manage({ action: 'operation/enable', operationRef: operation.operationRef, sessionRef: session.sessionRef }));
  const output = publicResponse(jsonResponse('https://shop.example/api/cart', { ok: true, access_token: 'sensitive', nested: { refreshToken: 'sensitive' } }, 200, { 'set-cookie': 'sensitive' }));
  assert(!JSON.stringify(output).includes('sensitive'));
  f.host.active = false; error(await f.execute('pap_request', { operationRef: operation.operationRef }), 'permission_denied');
  f.service.stop(); error(await f.execute('pap_status'), 'disconnected');
});
test('PAP product: missing real C factory fails closed, selected identity reference file contains no credential', async t => {
  const f = await fixture(t, { missingFactory: true }); error(await f.select(), 'permission_denied'); assert.equal(f.transport.calls.length, 0);
  const g = await fixture(t); value(await g.select()); const selection = await readFile(join(g.root, 'selected-identity.json'), 'utf8'); assert.deepEqual(JSON.parse(selection), binding.identityRef); assert(!selection.includes('access_token'));
  const h = await fixture(t); value(await h.select()); assert(g.namespaces.every(namespace => namespace.startsWith('dsh-pap/profile/'))); assert.notEqual(g.namespaces[0], h.namespaces[0]);
});
test('PAP product: revoke and re-enable during signing fences the old permission generation before send', async t => {
  const f = await fixture(t); const { operation, session } = await connected(f);
  const enable = { action: 'operation/enable' as const, operationRef: operation.operationRef, sessionRef: session.sessionRef };
  value(await f.manager.manage(enable));
  let entered!: () => void; let release!: () => void; const start = new Promise<void>(resolve => entered = resolve); const gate = new Promise<void>(resolve => release = resolve);
  const acquire = f.host.acquire.bind(f.host);
  f.host.acquire = async (...args) => { const lease = await acquire(...args); const sign = lease.signPapSessionRequest; lease.signPapSessionRequest = async input => { const result = await sign(input); entered(); await gate; return result; }; return lease; };
  const request = f.execute('pap_request', { operationRef: operation.operationRef }); await start;
  value(await f.manager.manage({ action: 'operation/disable', operationRef: operation.operationRef })); value(await f.manager.manage(enable));
  const before = f.transport.calls.length; release(); error(await request, 'permission_denied'); assert.equal(f.transport.calls.length, before);
});
test('PAP product: encrypted operation permission and selected identity restore through actual Loader restart', async t => {
  const f = await fixture(t); const { operation, session } = await connected(f);
  value(await f.manager.manage({ action: 'operation/enable', operationRef: operation.operationRef, sessionRef: session.sessionRef })); value(await f.execute('pap_request', { operationRef: operation.operationRef }));
  const entry = [...f.loader.entries()].find(item => item.options.name === PAP_CONSUMER)!;
  await f.loader.update(entry.id, { disabled:true }); await f.loader.update(entry.id, { disabled:false }); await f.loader.await();
  assert.equal((f.service as any).stopped,true); assert.notEqual((f.ctx.pap as any).client,(f.service as any).client);
  value(await f.execute('pap_request', { operationRef: operation.operationRef }));
  const toolEntry = [...f.loader.entries()].find(item => item.options.name === PAP_TOOLS)!;
  const cached = f.tools.get('pap_request'); await f.loader.update(toolEntry.id, { disabled: true });
  error(await cached.execute({ operationRef: operation.operationRef }, { agent: {} }), 'permission_denied');
});
test('PAP product: blocked secret backend has no plaintext credential or encrypted-state replacement', async t => {
  const f = await fixture(t, { blockedSecrets: true }); error(await f.select(), 'credential_unavailable');
  assert.equal(value(await f.manager.status()).state, 'credential_unavailable'); assert.equal(f.transport.calls.length, 0);
  const files = await readdir(f.root, { recursive: true }); assert(!files.some(path => path.endsWith('.enc') || path.endsWith('.json') || path.endsWith('.yaml')));
});
test('PAP product: challenge metadata hints stay in user management and callback polling preserves fixed errors', async t => {
  const f = await fixture(t, { mode: 'account' }); const { operation, session } = await connected(f);
  value(await f.manager.manage({ action: 'operation/enable', operationRef: operation.operationRef, sessionRef: session.sessionRef }));
  f.transport.override = url => url.endsWith('/api/cart') ? jsonResponse(url, {}, 403, { 'www-authenticate': 'Bearer error="insufficient_scope", scope="orders:read", resource_metadata="https://shop.example/.well-known/oauth-protected-resource"' }) : undefined;
  error(await f.execute('pap_request', { operationRef: operation.operationRef }), 'insufficient_scope');
  const user = value(await f.manager.status()); assert.equal(user.authenticationHints[0].scope[0], 'orders:read'); assert.equal(user.authenticationHints[0].resourceMetadataUrl, 'https://shop.example/.well-known/oauth-protected-resource');
  assert(!JSON.stringify(await f.execute('pap_status')).includes('https://'));
  error(await publicResult(async () => { throw Object.assign(new Error('remote secret must not cross'), { code: 'callback_not_ready' }); }), 'callback_not_ready');
  error(await publicResult(async () => { throw Object.assign(new Error('remote secret must not cross'), { code: 'remote-description' }); }), 'permission_denied');
});
test('PAP product: declared query names are required and URI is built from the verified route only', async t => {
  const f = await fixture(t);
  f.transport.override = url => url.endsWith('/openapi.json') ? jsonResponse(url, { openapi: '3.1.0', servers: [{ url: 'https://shop.example' }], paths: { '/api/cart': { get: { parameters: [{ in: 'query', name: 'q', required: true }] } } } }) : undefined;
  const { operation, session } = await connected(f);
  value(await f.manager.manage({ action: 'operation/enable', operationRef: operation.operationRef, sessionRef: session.sessionRef }));
  error(await f.execute('pap_request', { operationRef: operation.operationRef }), 'unsafe_destination');
  error(await f.execute('pap_request', { operationRef: operation.operationRef, query: { q: '\u4e00'.repeat(1024) } }), 'unsafe_destination');
  value(await f.execute('pap_request', { operationRef: operation.operationRef, query: { q: 'one & two' } }));
  assert.equal(f.transport.calls.at(-1)!.url, 'https://shop.example/api/cart?q=one+%26+two');
});
test('PAP product: a disposed C generation never auto-revives; explicit user selection reacquires', async t => {
  const f = await fixture(t); const { operation, session } = await connected(f);
  value(await f.manager.manage({ action: 'operation/enable', operationRef: operation.operationRef, sessionRef: session.sessionRef }));
  const before = f.contexts.length; f.advanceProvider(); error(await f.execute('pap_status'), 'provider_disposed');
  error(await f.execute('pap_request', { operationRef: operation.operationRef }), 'provider_disposed'); assert.equal(f.contexts.length, before);
  value(await f.select()); assert(f.contexts.length > before); value(await f.execute('pap_request', { operationRef: operation.operationRef }));
});
for (const honorAbort of [true, false]) test(`PAP product: actual Loader unload aborts in-flight transport and rejects late result (honorAbort=${honorAbort})`, async t => {
  const f = await fixture(t); const { operation, session } = await connected(f);
  value(await f.manager.manage({ action: 'operation/enable', operationRef: operation.operationRef, sessionRef: session.sessionRef }));
  let entered!: () => void; let release!: () => void; let aborted = false; const start = new Promise<void>(resolve => entered = resolve);
  f.transport.override = (url, options) => url.endsWith('/api/cart') ? new Promise((resolve, reject) => {
    release = () => resolve(jsonResponse(url, { shouldNeverCross: 'late-business-result' }));
    options?.signal?.addEventListener('abort', () => { aborted = true; if (honorAbort) reject(new Error('Aborted transport')); }, { once: true }); entered();
  }) : undefined;
  const request = f.execute('pap_request', { operationRef: operation.operationRef }); await start;
  const entry = [...f.loader.entries()].find(item => item.options.name === PAP_CONSUMER)!;
  await f.loader.update(entry.id, { disabled: true }); assert.equal(aborted, true); if (!honorAbort) release();
  const result = await request; assert.equal(result.ok, false); assert(!JSON.stringify(result).includes('late-business-result'));
});
test('PAP product: unload during selection persistence closes the unpublished next engine', async t => {
  const f = await fixture(t); const service = f.service as any;
  let entered!: () => void; let release!: () => void; const start = new Promise<void>(resolve => entered = resolve); const gate = new Promise<void>(resolve => release = resolve);
  const persist = service.persistSelection.bind(service); service.persistSelection = async (reference: unknown) => { await persist(reference); entered(); await gate; };
  const close = PapClient.prototype.close; let closed = 0; PapClient.prototype.close = function () { closed++; return close.call(this); };
  t.after(() => { PapClient.prototype.close = close; });
  const selection = f.select(); await start; const entry = [...f.loader.entries()].find(item => item.options.name === PAP_CONSUMER)!;
  await f.loader.update(entry.id, { disabled: true }); release(); const result = await selection;
  assert.equal(result.ok, false); assert.equal(closed, 1); assert.equal(service.client, undefined);
});
test('PAP product: actual sent credentials stay redacted after refresh then signout clears the Store', async t => {
  const f = await fixture(t, { mode: 'account' }); const { operation, session, company } = await connected(f);
  const pending = value(await f.manager.manage({ action: 'account/sign-in', sessionRef: session.sessionRef, operationRef: operation.operationRef, scopes: ['orders:read'] }));
  const authorize = new URL(pending.authorizationUrl); f.setResponse({ state: authorize.searchParams.get('state')!, iss: f.transport.issuer, code: 'unit-one-time-code' });
  value(await f.manager.manage({ action: 'account/collect', transactionRef: pending.transactionRef }));
  const account = value(await f.manager.manage({ action: 'session/connect', companyRef: company.companyRef, accountSlot: pending.accountSlot }));
  value(await f.manager.manage({ action: 'operation/enable', operationRef: operation.operationRef, sessionRef: account.sessionRef, scopes: ['orders:read'] }));
  const engine = (f.service as unknown as { client: PapClient }).client;
  await engine.store.transaction(state => { for (const grant of Object.values(state.grants)) grant.expiresAt = 0; });
  let actualToken = ''; const nextRefresh = 'unit-new-refresh-secret';
  f.transport.override = (url, options) => {
    if (url.endsWith('/token')) return jsonResponse(url, { access_token: 'unit-new-access-secret', refresh_token: nextRefresh, token_type: 'DPoP', expires_in: 3600 });
    if (url.endsWith('/api/cart')) { actualToken = options!.headers!.authorization!.split(' ')[1]!; return jsonResponse(url, { ok: true, unexpected: `message ${actualToken} embedded`, [actualToken]: 'also-key', nested: [nextRefresh] }); }
  };
  let entered!: () => void; let release!: () => void; const start = new Promise<void>(resolve => entered = resolve); const gate = new Promise<void>(resolve => release = resolve);
  const dispatch = engine.dispatchPap.bind(engine); engine.dispatchPap = async (...args) => { const response = await dispatch(...args); entered(); await gate; return response; };
  const request = f.execute('pap_request', { operationRef: operation.operationRef }); await start;
  value(await f.manager.manage({ action: 'account/sign-out', accountSlot: pending.accountSlot }));
  const state = await engine.store.read(); assert(!Object.values(state.grants).some(grant => grant.accessToken === actualToken || grant.refreshToken === nextRefresh));
  release(); const result = await request; value(result); const visible = JSON.stringify(result);
  assert(!visible.includes(actualToken)); assert(!visible.includes(nextRefresh));
});
test('PAP product: explicit reselection fences an old engine response even for the same identity and approval', async t => {
  const f = await fixture(t); const { operation, session } = await connected(f);
  value(await f.manager.manage({ action: 'operation/enable', operationRef: operation.operationRef, sessionRef: session.sessionRef }));
  const engine = (f.service as unknown as { client: PapClient }).client;
  let entered!: () => void; let release!: () => void; const start = new Promise<void>(resolve => entered = resolve); const gate = new Promise<void>(resolve => release = resolve);
  const dispatch = engine.dispatchPap.bind(engine); engine.dispatchPap = async (...args) => { const response = await dispatch(...args); entered(); await gate; return response; };
  const request = f.execute('pap_request', { operationRef: operation.operationRef }); await start; value(await f.select()); release();
  error(await request, 'state_conflict'); value(await f.execute('pap_request', { operationRef: operation.operationRef }));
});
for (const surface of ['tool-status','tool-operations','user-status','user-operations'] as const) test(`PAP product: ${surface} rejects a Store read that resumes after actual Loader unload`, async t => {
  const f = await fixture(t); await connected(f); const pause = f.pauseNextKeyRead(); t.after(pause.release);
  const read = surface === 'tool-status' ? f.execute('pap_status') : surface === 'tool-operations' ? f.execute('pap_operations') : surface === 'user-status' ? f.manager.status() : f.manager.operations();
  await pause.start; const entry = [...f.loader.entries()].find(item => item.options.name === PAP_CONSUMER)!;
  await f.loader.update(entry.id, { disabled: true }); pause.release(); const result = await read;
  assert.equal(result.ok, false); assert(!JSON.stringify(result).includes('ready')); assert(!JSON.stringify(result).includes('op_'));
});
test('PAP product: status rechecks actual C authority after a suspended protected-key read', async t => {
  const f = await fixture(t); await connected(f); const pause = f.pauseNextKeyRead(); t.after(pause.release);
  const status = f.execute('pap_status'); await pause.start; f.advanceProvider(); pause.release(); error(await status, 'provider_disposed');
});
for (const restart of [false,true]) test(`PAP product S15: a later response cannot echo a still-valid credential replaced by an earlier refresh (restart=${restart})`, async t => {
  const f = await fixture(t, { mode: 'account' }); const { operation, session, company } = await connected(f);
  const pending = value(await f.manager.manage({ action: 'account/sign-in', sessionRef: session.sessionRef, operationRef: operation.operationRef, scopes: ['orders:read'] }));
  const authorize = new URL(pending.authorizationUrl); f.setResponse({ state: authorize.searchParams.get('state')!, iss: f.transport.issuer, code: 'unit-one-time-code' });
  value(await f.manager.manage({ action: 'account/collect', transactionRef: pending.transactionRef }));
  const account = value(await f.manager.manage({ action: 'session/connect', companyRef: company.companyRef, accountSlot: pending.accountSlot }));
  value(await f.manager.manage({ action: 'operation/enable', operationRef: operation.operationRef, sessionRef: account.sessionRef, scopes: ['orders:read'] }));
  let count = 0; const oldAccess = 'access-fixture'; const oldRefresh = 'refresh-fixture';
  f.transport.override = (url, options) => {
    if (url.endsWith('/token')) return jsonResponse(url, { access_token: 'unit-rotated-access', refresh_token: 'unit-rotated-refresh', token_type:'DPoP', expires_in:3600 });
    if (url.endsWith('/api/cart')) {
      count++; if (count === 1) return jsonResponse(url, { error:'invalid_token' }, 401);
      if (count === 2) return jsonResponse(url, { ok:true });
      assert(options?.headers?.authorization?.includes('unit-rotated-access'));
      return jsonResponse(url, { unexpected:`message ${oldAccess} embedded`, [oldRefresh]:'unexpected-key' });
    }
  };
  value(await f.execute('pap_request', { operationRef:operation.operationRef }));
  if (restart) { const entry = [...f.loader.entries()].find(item => item.options.name === PAP_CONSUMER)!; await f.loader.update(entry.id, { disabled:true }); await f.loader.update(entry.id, { disabled:false }); await f.loader.await(); assert.equal((f.service as any).stopped,true); assert.notEqual((f.ctx.pap as any).client,(f.service as any).client); }
  const visible = JSON.stringify(await f.execute('pap_request', { operationRef:operation.operationRef }));
  assert(!visible.includes(oldAccess)); assert(!visible.includes(oldRefresh));
});
test('PAP product S15: known credentials in discovered Company names and operation paths never reach public metadata', async t=>{
  const f=await fixture(t,{mode:'account'});const {session}=await accountConnection(f);const token='access-fixture';
  f.transport.override=url=>url.endsWith('/poppy.json')?jsonResponse(url,{protocol_version:'1.0',organization:{name:`Company ${token}`,domain:'shop.example'},auth:{issuer:f.transport.issuer,scopes:{'orders:read':'Orders'}},apis:[{type:'openapi',url:'https://shop.example/openapi.json'}]}):url.endsWith('/openapi.json')?jsonResponse(url,{openapi:'3.1.0',servers:[{url:'https://shop.example'}],paths:{['/api/'+token]:{get:{}}}}):undefined;
  const discovery=await f.manager.manage({action:'company/discover',domain:'shop.example'});assert(!JSON.stringify(discovery).includes(token));
  const operations=value(await f.manager.operations()) as unknown as Value[];assert.equal(operations.length,1);assert(!JSON.stringify(operations).includes(token));
  value(await f.manager.manage({action:'operation/enable',operationRef:operations[0]!.operationRef,sessionRef:session.sessionRef}));
  for(const result of [await f.manager.status(),await f.execute('pap_status'),await f.execute('pap_operations')])assert(!JSON.stringify(result).includes(token));
});
test('PAP product S15: legacy account history is gated after seeding, normal revoke cannot certify unknown old tokens', async t=>{
  const f=await fixture(t,{mode:'account'});const {engine,pending,operation}=await accountConnection(f);
  await engine.store.transaction(state=>{delete state.credentialVault;});
  const before=f.host.sessionCount;error(await f.execute('pap_request',{operationRef:operation.operationRef}),'credential_history_incomplete');assert.equal(f.host.sessionCount,before);
  const user=value(await f.manager.status());assert.equal(user.state,'migration_required');assert.deepEqual(Object.keys(user).sort(),['accounts','error','state']);assert.equal(user.accounts[0].accountSlot,pending.accountSlot);
  error(await f.execute('pap_status'),'credential_history_incomplete');error(await f.execute('pap_operations'),'credential_history_incomplete');
  value(await f.manager.manage({action:'account/sign-out',accountSlot:pending.accountSlot}));
  const state=await engine.store.read();assert.equal(state.credentialVault!.completeness,'legacy_incomplete');assert.equal(state.grants[Object.keys(state.grants)[0]!]!.status,'signed_out');
  assert(!(await readFile(join(engine.store.root,'pap-state.enc'))).includes(Buffer.from('access-fixture')));
});
test('PAP product S15: cancelled legacy account transaction is evidence, while an untouched NoAS state migrates complete', async t=>{
  const f=await fixture(t,{mode:'account'});const {session,operation}=await connected(f);
  const pending=value(await f.manager.manage({action:'account/sign-in',sessionRef:session.sessionRef,operationRef:operation.operationRef,scopes:['orders:read']}));
  const engine=(f.service as unknown as {client:PapClient}).client;
  await engine.store.transaction(state=>{for(const tx of Object.values(state.transactions)){tx.status='cancelled';tx.verifier='';}delete state.credentialVault;});
  assert.equal(value(await f.manager.status()).state,'migration_required');value(await f.manager.manage({action:'account/sign-out',accountSlot:pending.accountSlot}));
  const g=await fixture(t);const no=await connected(g);const core=(g.service as unknown as {client:PapClient}).client;
  await core.store.transaction(state=>{delete state.credentialVault;});assert.equal((await core.store.read()).credentialVault!.completeness,'complete');
  value(await g.manager.manage({action:'operation/enable',operationRef:no.operation.operationRef,sessionRef:no.session.sessionRef}));value(await g.execute('pap_request',{operationRef:no.operation.operationRef}));
});
test('PAP product: only the user authorization URL may contain the pending state; public metadata cannot echo it',async t=>{
  const f=await fixture(t,{mode:'account'});const {operation,session}=await connected(f);
  const pending=value(await f.manager.manage({action:'account/sign-in',sessionRef:session.sessionRef,operationRef:operation.operationRef,scopes:['orders:read']}));const state=new URL(pending.authorizationUrl).searchParams.get('state')!;assert(state);
  f.transport.override=url=>url.endsWith('/poppy.json')?jsonResponse(url,{protocol_version:'1.0',organization:{name:`Company ${state}`,domain:'shop.example'},auth:{issuer:f.transport.issuer,scopes:{'orders:read':'Orders'}},apis:[{type:'openapi',url:'https://shop.example/openapi.json'}]}):url.endsWith('/openapi.json')?jsonResponse(url,{openapi:'3.1.0',servers:[{url:'https://shop.example'}],paths:{['/api/'+state]:{get:{}}}}):undefined;
  const discovery=await f.manager.manage({action:'company/discover',domain:'shop.example'});assert(!JSON.stringify(discovery).includes(state));const operations=value(await f.manager.operations()) as unknown as Value[];
  value(await f.manager.manage({action:'operation/enable',operationRef:operations[0]!.operationRef,sessionRef:session.sessionRef}));
  for(const output of [await f.manager.status(),await f.execute('pap_status'),await f.execute('pap_operations')])assert(!JSON.stringify(output).includes(state));
  assert.equal(new URL(pending.authorizationUrl).searchParams.get('state'),state);assert(new URL(pending.authorizationUrl).searchParams.get('code_challenge'));
});
test('PAP product: explicit user account refresh uses its bound grant and rejects absent refresh without reauthorization',async t=>{
  const f=await fixture(t,{mode:'account'});const {engine,pending}=await accountConnection(f);const before=f.transport.calls.filter(call=>call.url.endsWith('/token')).length;
  assert.equal(value(await f.manager.manage({action:'account/refresh',accountSlot:pending.accountSlot})).status,'active');assert.equal(f.transport.calls.filter(call=>call.url.endsWith('/token')).length,before+1);
  assert(!f.tools.has('pap_refresh'));assert.equal(value(await f.manager.status()).accounts[0].canRefresh,true);
  await engine.store.transaction(state=>{for(const grant of Object.values(state.grants))delete grant.refreshToken;});
  error(await f.manager.manage({action:'account/refresh',accountSlot:pending.accountSlot}),'reauthorization_required');assert.equal(f.transport.calls.filter(call=>call.url.endsWith('/token')).length,before+1);
});
test('PAP product: a slow user refresh cannot return active after actual Loader unload',async t=>{
  const f=await fixture(t,{mode:'account'});const {pending}=await accountConnection(f);let entered!:()=>void;let release!:()=>void;const start=new Promise<void>(resolve=>entered=resolve);
  f.transport.override=url=>url.endsWith('/token')?new Promise(resolve=>{release=()=>resolve(jsonResponse(url,{access_token:'unit-late-access',refresh_token:'unit-late-refresh',token_type:'DPoP',expires_in:3600}));entered();}):undefined;
  const refreshing=f.manager.manage({action:'account/refresh',accountSlot:pending.accountSlot});await start;const entry=[...f.loader.entries()].find(item=>item.options.name===PAP_CONSUMER)!;
  await f.loader.update(entry.id,{disabled:true});release();const result=await refreshing;assert.equal(result.ok,false);assert(!JSON.stringify(result).includes('unit-late'));assert(!JSON.stringify(result).includes('"status":"active"'));
});
test('PAP product: callback collection revalidates expired discovery before requesting a new C target',async t=>{
  const f=await fixture(t,{mode:'account'});const {session,operation}=await connected(f);
  const pending=value(await f.manager.manage({action:'account/sign-in',sessionRef:session.sessionRef,operationRef:operation.operationRef,scopes:['orders:read']}));
  const authorize=new URL(pending.authorizationUrl);f.setResponse({state:authorize.searchParams.get('state')!,iss:f.transport.issuer,code:'unit-callback-code'});
  const engine=(f.service as unknown as {client:PapClient}).client;await engine.store.transaction(state=>{for(const company of Object.values(state.companies))company.expiresAt=Date.now()-1;});
  const before=f.transport.calls.filter(call=>call.url.endsWith('poppy.json')).length;value(await f.manager.manage({action:'account/collect',transactionRef:pending.transactionRef}));
  assert.equal(f.transport.calls.filter(call=>call.url.endsWith('poppy.json')).length,before+1);assert.equal(f.counts.claimCount,1);
});

// Domain-mode product coverage uses the real Loader, store and signed-request path.
test('PAP domain mode: discovers and connects once, enables only reads and preserves owner fences', async t => {
  const f = await fixture(t, { autoConnect: true });
  const first = value(await f.execute('pap_connect', { domain: 'shop.example' }));
  assert(first.operations.length > 0);
  assert(first.operations.every((operation: Value) => ['GET', 'HEAD'].includes(operation.method)));
  assert.equal(value(await f.execute('pap_status')).sessions.length, 1);
  const operation = first.operations.find((entry: Value) => entry.path === '/api/cart'); assert(operation);
  assert.equal(value(await f.execute('pap_request', { operationRef: operation.operationRef })).status, 200);
  await Promise.all([f.execute('pap_connect', { domain: 'shop.example' }), f.execute('pap_connect', { domain: 'shop.example' })]);
  assert.equal(value(await f.execute('pap_status')).sessions.length, 1);
  value(await f.manager.manage({ action: 'operation/disable', operationRef: operation.operationRef }));
  const again = value(await f.execute('pap_connect', { domain: 'shop.example' }));
  assert(!again.operations.some((entry: Value) => entry.operationRef === operation.operationRef));
  error(await f.execute('pap_request', { operationRef: operation.operationRef }), 'permission_denied');
  const status = value(await f.manager.status());
  value(await f.manager.manage({ action: 'session/disconnect', sessionRef: status.sessions[0].sessionRef }));
  error(await f.execute('pap_connect', { domain: 'shop.example' }), 'disconnected');
  assert(!f.transport.calls.some(call => call.url.endsWith('/token')));
});
test('PAP domain mode: global opt-in is required and malformed domains never dispatch', async t => {
  const f = await fixture(t, { autoConnect: true });
  error(await f.execute('pap_connect', { domain: 'https://shop.example' }), 'unsafe_destination');
  f.disableDomain();
  error(await f.execute('pap_connect', { domain: 'shop.example' }), 'domain_access_disabled');
  assert.equal(f.transport.calls.length, 0);
  const legacy = await fixture(t);
  error(await legacy.execute('pap_connect', { domain: 'shop.example' }), 'not_configured');
  assert.equal(legacy.transport.calls.length, 0);
});

async function domainWrite(f: Awaited<ReturnType<typeof fixture>>, requiresApproval=true) {
  value(await f.execute('pap_connect',{domain:'shop.example'}));
  const operations=value(await f.execute('pap_operations')) as unknown as Value[];
  const write=operations.find(operation=>operation.method==='POST'&&operation.path==='/api/cart'); assert(write);
  assert.equal(write.enabled,!requiresApproval);assert.equal(write.requiresApproval,requiresApproval);
  return write;
}
async function untilConsent(f: Awaited<ReturnType<typeof fixture>>) {
  for(let index=0;index<100&&!f.consent.requests;index++)await new Promise(resolve=>setTimeout(resolve,5));
  assert.equal(f.consent.requests,1);
}
test('PAP domain consent: an advertised write waits for one exact owner grant without enabling its route', async t=>{
  const f=await fixture(t,{autoConnect:true});const write=await domainWrite(f);
  const pending=f.execute('pap_request',{operationRef:write.operationRef,body:{message:'approved body'}});
  await untilConsent(f);assert.equal(f.transport.calls.filter(call=>call.options?.method==='POST'&&call.url.includes('/api/')).length,0);
  assert.equal(await f.consent.request!.clone().text(),'{"message":"approved body"}');
  f.consent.approve();assert.equal(value(await pending).status,200);assert.equal(f.consent.executions,1);
  const current=value(await f.execute('pap_operations')) as unknown as Value[];
  assert.equal(current.find(operation=>operation.operationRef===write.operationRef)!.enabled,false);
  assert.equal(f.transport.calls.filter(call=>call.options?.method==='POST'&&call.url.includes('/api/')).length,1);
});
test('PAP domain consent: denial, timeout and permanent grants never send a write',async t=>{
  for(const outcome of ['deny','timeout','permanent']){
    const f=await fixture(t,{autoConnect:true,approvalWaitMs:outcome==='timeout'?20:2000});const write=await domainWrite(f);
    const pending=f.execute('pap_request',{operationRef:write.operationRef,body:{message:'not sent'}});
    await untilConsent(f);
    if(outcome==='deny')f.consent.deny();else if(outcome==='permanent')f.consent.approve('permanent');
    const result=await pending;
    if(outcome==='timeout')assert.deepEqual(result,{ok:false,error:{code:'identity_authorization_required',approval:{requestId:'fixture-consent',presentation:'dialog',status:'pending'},phase:'approval',businessRequest:'not_sent'}});
    else error(result,outcome==='deny'?'identity_authorization_denied':'permission_denied');
    assert.equal(f.consent.executions,0);assert.equal(f.transport.calls.filter(call=>call.url.includes('/api/')).length,0);
  }
});
test('PAP domain consent: cancellation and unload cancel pending approval and never send after a late click',async t=>{
  for(const unload of [false,true]){
    const f=await fixture(t,{autoConnect:true});const write=await domainWrite(f);const controller=new AbortController();
    const pending=f.execute('pap_request',{operationRef:write.operationRef,body:{}},controller.signal);
    await untilConsent(f);
    if(unload)await f.ctx.fiber.dispose();else controller.abort();
    error(await pending,'disconnected');assert.equal(f.consent.cancels,1);assert.equal(f.consent.status,'cancelled');f.consent.approve();
    assert.equal(f.transport.calls.filter(call=>call.url.includes('/api/')).length,0);
  }
});
test('PAP domain consent: disable/disconnect/revocation while awaiting or signing fences actual send',async t=>{
  for(const action of ['disable','disconnect','revoke']){
    const f=await fixture(t,{autoConnect:true});const write=await domainWrite(f);
    if(action==='revoke'){
      const acquire=f.host.acquire.bind(f.host);
      f.host.acquire=async(...args)=>{const lease=await acquire(...args);return {...lease,signPapSessionRequest:async input=>{const signed=await lease.signPapSessionRequest(input);f.consent.revoke();return signed;}};};
    }
    const pending=f.execute('pap_request',{operationRef:write.operationRef,body:{}});await untilConsent(f);
    if(action==='disable')value(await f.manager.manage({action:'operation/disable',operationRef:write.operationRef}));
    if(action==='disconnect'){const status=value(await f.manager.status());value(await f.manager.manage({action:'session/disconnect',sessionRef:status.sessions[0].sessionRef}));}
    f.consent.approve();const result=await pending;assert.equal(result.ok,false);
    assert.equal(f.transport.calls.filter(call=>call.url.includes('/api/')).length,0);
  }
});
test('PAP domain consent: a session_ended response cannot replay a once-approved POST',async t=>{
  const f=await fixture(t,{autoConnect:true});const write=await domainWrite(f);
  f.transport.override=(url,options)=>url.includes('/api/cart')&&options?.method==='POST'?jsonResponse(url,{error:'session_ended'},409):undefined;
  const pending=f.execute('pap_request',{operationRef:write.operationRef,body:{}});await untilConsent(f);f.consent.approve();
  const result=await pending;error(result,'session_ended');assert(!result.ok);assert.equal(result.error.businessRequest,'response_received');assert.equal(result.error.httpStatus,409);assert.equal(f.transport.calls.filter(call=>call.url.includes('/api/cart')).length,1);
});

test('PAP domain consent: GET operations with advertised extra scopes are not automatic reads',async t=>{
  const f=await fixture(t,{autoConnect:true});
  f.transport.override=url=>new URL(url).pathname==='/openapi.json'?jsonResponse(url,{openapi:'3.1.0',servers:[{url:'https://shop.example'}],paths:{'/api/extra':{get:{security:[{oauth:['account.read']}]}}}}):undefined;
  const connected=value(await f.execute('pap_connect',{domain:'shop.example'}));assert.deepEqual(connected.operations,[]);
  const operations=value(await f.execute('pap_operations')) as unknown as Value[];assert.equal(operations.length,1);
  assert.equal(operations[0]!.requiresApproval,true);assert.equal(operations[0]!.enabled,false);
  const pending=f.execute('pap_request',{operationRef:operations[0]!.operationRef});await untilConsent(f);
  assert.equal(f.transport.calls.filter(call=>call.url.endsWith('/api/extra')).length,0);f.consent.approve();
  assert.equal(value(await pending).status,200);assert.equal(f.consent.executions,1);
});

test('PAP domain consent: timeout retries preserve the original request owner until approval',async t=>{
  const f=await fixture(t,{autoConnect:true,approvalWaitMs:0});const write=await domainWrite(f);
  const args={operationRef:write.operationRef,body:{message:'same exact request'}};
  const first=await f.execute('pap_request',args);assert.equal(first.ok,false);
  const again=await f.execute('pap_request',args);assert.deepEqual(again,first);
  assert.equal(f.consent.requests,1);assert.equal(f.consent.bindings,1);
  assert.equal(f.transport.calls.filter(call=>call.url.includes('/api/')).length,0);
  f.consent.approve();const approved=value(await f.execute('pap_request',args));assert.equal(approved.status,200);
  assert.equal(f.consent.executions,1);assert.equal(f.consent.requests,1);
  assert.equal(f.transport.calls.filter(call=>call.url.includes('/api/')).length,1);
});
test('PAP domain consent: a refused pending request stays refused on retry without sending',async t=>{
  const f=await fixture(t,{autoConnect:true,approvalWaitMs:0});const write=await domainWrite(f);
  const args={operationRef:write.operationRef,body:{message:'refused'}};
  await f.execute('pap_request',args);f.consent.deny();
  error(await f.execute('pap_request',args),'identity_authorization_denied');
  assert.equal(f.consent.requests,1);assert.equal(f.consent.executions,0);
  assert.equal(f.transport.calls.filter(call=>call.url.includes('/api/')).length,0);
});

test('PAP business diagnostics do not report an attempted transport failure as definitely unsent',async t=>{
  const f=await fixture(t,{autoConnect:true});const write=await domainWrite(f);
  f.transport.override=(url,options)=>{if(url.includes('/api/cart')&&options?.method==='POST')throw new Error('Isolated lost response');return undefined;};
  const pending=f.execute('pap_request',{operationRef:write.operationRef,body:{}});await untilConsent(f);f.consent.approve();
  const result=await pending;assert(!result.ok);assert.equal(result.error.businessRequest,'unknown');assert.equal(result.error.phase,'request');
  assert.equal(f.consent.executions,1);assert.equal(f.transport.calls.filter(call=>call.url.includes('/api/cart')).length,1);
});

test('PAP business diagnostics retain a received response when a later local consent check fails',async t=>{
  const f=await fixture(t,{autoConnect:true});const write=await domainWrite(f);
  f.transport.override=(url,options)=>{if(url.includes('/api/cart')&&options?.method==='POST'){f.consent.revoke();return jsonResponse(url,{created:true},200);}return undefined;};
  const pending=f.execute('pap_request',{operationRef:write.operationRef,body:{}});await untilConsent(f);f.consent.approve();
  const result=await pending;assert(!result.ok);assert.equal(result.error.businessRequest,'response_received');assert.equal(result.error.httpStatus,200);
  assert.equal(f.transport.calls.filter(call=>call.url.includes('/api/cart')).length,1);
});

test('PAP shared policy: all writes execute without a dialog but do not persist route permission',async t=>{
  const f=await fixture(t,{autoConnect:true});f.policy.set('write','allow');const write=await domainWrite(f,false);
  assert.equal(value(await f.execute('pap_request',{operationRef:write.operationRef,body:{content:'owner-enabled write'}})).status,200);
  assert.equal(f.consent.requests,0);assert.equal(f.consent.executions,0);
  assert.equal(f.transport.calls.filter(call=>call.url.includes('/api/cart')).length,1);
  const state=await (f.service as unknown as {client:PapClient}).client.store.read();assert.equal(state.product?.operations[write.operationRef],undefined);
});
test('PAP shared policy: read and write denials both prevent business dispatch, including formerly enabled reads',async t=>{
  const f=await fixture(t,{autoConnect:true});const connected=value(await f.execute('pap_connect',{domain:'shop.example'}));
  const read=connected.operations.find((entry:Value)=>entry.path==='/api/cart');
  const write=value(await f.execute('pap_operations')).find((entry:Value)=>entry.method==='POST');
  f.policy.set('read','deny');f.policy.set('write','deny');
  error(await f.execute('pap_request',{operationRef:read.operationRef}),'protocol_permission_denied');
  error(await f.execute('pap_request',{operationRef:write.operationRef,body:{}}),'protocol_permission_denied');
  assert(value(await f.execute('pap_operations')).filter((entry:Value)=>[read.operationRef,write.operationRef].includes(entry.operationRef)).every((entry:Value)=>entry.blocked));
  assert.equal(f.consent.requests,0);assert.equal(f.transport.calls.filter(call=>call.url.includes('/api/')).length,0);
});
test('PAP shared policy: revocation during signing invalidates allowed reads and writes before physical send',async t=>{
  for(const method of ['GET','POST']){
    const f=await fixture(t,{autoConnect:true});f.policy.set('write','allow');await f.execute('pap_connect',{domain:'shop.example'});
    const operation=value(await f.execute('pap_operations')).find((entry:Value)=>entry.path==='/api/cart'&&entry.method===method);
    let entered!:()=>void,release!:()=>void;const start=new Promise<void>(resolve=>entered=resolve),gate=new Promise<void>(resolve=>release=resolve);t.after(release);
    const acquire=f.host.acquire.bind(f.host);
    f.host.acquire=async(...args)=>{const lease=await acquire(...args),sign=lease.signPapSessionRequest;lease.signPapSessionRequest=async input=>{const result=await sign(input);entered();await gate;return result;};return lease;};
    const pending=f.execute('pap_request',{operationRef:operation.operationRef,...(method==='POST'?{body:{}}:{})});
    await start;f.policy.set(method==='POST'?'write':'read','deny');release();
    const result=await pending;error(result,'protocol_policy_changed');assert(!result.ok);assert.equal(result.error.businessRequest,'not_sent');
    assert.equal(f.transport.calls.filter(call=>call.url.includes('/api/')).length,0);
  }
});
test('PAP shared policy: an allowed POST is never replayed after session_ended and retains received-response diagnostics',async t=>{
  const f=await fixture(t,{autoConnect:true});f.policy.set('write','allow');const write=await domainWrite(f,false);
  f.transport.override=(url,options)=>url.includes('/api/cart')&&options?.method==='POST'?jsonResponse(url,{error:'session_ended'},409):undefined;
  const result=await f.execute('pap_request',{operationRef:write.operationRef,body:{}});error(result,'session_ended');
  assert(!result.ok);assert.equal(result.error.httpStatus,409);assert.equal(result.error.businessRequest,'response_received');
  assert.equal(f.transport.calls.filter(call=>call.url.includes('/api/cart')).length,1);assert.equal(f.consent.requests,0);
});
test('PAP shared policy: response-time revocation reports a received response, not an unsent write',async t=>{
  const f=await fixture(t,{autoConnect:true});f.policy.set('write','allow');const write=await domainWrite(f,false);
  f.transport.override=(url,options)=>{if(url.includes('/api/cart')&&options?.method==='POST'){f.policy.set('write','deny');return jsonResponse(url,{created:true},200);}return undefined;};
  const result=await f.execute('pap_request',{operationRef:write.operationRef,body:{}});error(result,'protocol_policy_changed');
  assert(!result.ok);assert.equal(result.error.httpStatus,200);assert.equal(result.error.businessRequest,'response_received');
  assert.equal(f.transport.calls.filter(call=>call.url.includes('/api/cart')).length,1);
});
test('PAP shared policy: explicit POST read semantics use read rules, while declared payments still ask under all-write permission',async t=>{
  const f=await fixture(t,{autoConnect:true});f.policy.set('write','allow');
  f.transport.override=url=>new URL(url).pathname==='/openapi.json'?jsonResponse(url,{openapi:'3.1.0',paths:{
    '/api/query':{post:{'x-agent-effect':'read',requestBody:{}}},'/api/pay':{post:{'x-agent-effect':'payment',requestBody:{}}},
  }}):undefined;
  const connected=value(await f.execute('pap_connect',{domain:'shop.example'}));assert(connected.operations.some((entry:Value)=>entry.path==='/api/query'&&entry.method==='POST'));
  const operations=value(await f.execute('pap_operations')),read=operations.find((entry:Value)=>entry.path==='/api/query'),pay=operations.find((entry:Value)=>entry.path==='/api/pay');
  await f.execute('pap_request',{operationRef:read.operationRef,body:{query:'read'}});assert.equal(f.consent.requests,0);
  const pending=f.execute('pap_request',{operationRef:pay.operationRef,body:{amount:1}});await untilConsent(f);
  assert.equal(f.transport.calls.filter(call=>call.url.endsWith('/api/pay')).length,0);f.consent.approve();await pending;
  assert.equal(f.consent.executions,1);assert.equal(f.transport.calls.filter(call=>call.url.endsWith('/api/pay')).length,1);
});
test('PAP shared policy: an unrelated legacy discovery cache cannot poison a fresh domain connection',async t=>{
  const f=await fixture(t,{autoConnect:true});value(await f.execute('pap_connect',{domain:'shop.example'}));
  const engine=(f.service as unknown as {client:PapClient}).client;
  await engine.store.transaction(state=>{
    const existing=Object.values(state.companies)[0]!;
    const {discoveryOrigin:_origin,...legacy}=existing;
    state.companies['legacy-company']={...legacy,ref:'legacy-company',domain:'old.example',companyId:'https://old.example',routes:[{method:'GET',template:'https://old.example/api/old',resource:'https://old.example'}]};
  });
  const connected=value(await f.execute('pap_connect',{domain:'shop.example'}));assert(connected.operations.length>0);
  const operations=value(await f.execute('pap_operations')) as Value[];
  assert.equal(operations.find(operation=>operation.path==='/api/old')?.unavailableReason,'protocol_rediscovery_required');
  assert.equal(operations.find(operation=>operation.path==='/api/old')?.enabled,false);
  const current=operations.find(operation=>operation.path==='/api/cart'&&operation.method==='GET')!;
  assert.equal(value(await f.execute('pap_request',{operationRef:current.operationRef})).status,200);
});

// The Host owns selection and the client only adopts it on a fresh explicit connection.
test('domain reconnect adopts a changed default epoch without letting old requests silently change authority', async t => {
  const f = await fixture(t, { autoConnect: true });
  value(await f.execute('pap_connect', { domain: 'shop.example' }));
  const operations = value(await f.execute('pap_operations')) as unknown as Value[];
  const read = operations.find(operation => operation.method === 'GET')!; assert(read);
  value(await f.execute('pap_request', { operationRef: read.operationRef }));
  f.changeDefaultEpoch();
  const before = f.transport.calls.length;
  const stale = await f.execute('pap_request', { operationRef: read.operationRef });
  assert.equal(stale.ok, false);
  if (!stale.ok) assert.equal(stale.error.businessRequest, 'not_sent');
  assert.equal(f.transport.calls.length, before);
  value(await f.execute('pap_connect', { domain: 'shop.example' }));
  const refreshed = value(await f.execute('pap_operations')) as unknown as Value[];
  value(await f.execute('pap_request', { operationRef: refreshed.find(operation => operation.method === 'GET')!.operationRef }));
});


test('PAP business: exact installed consumer only, bounded data and live revocation', async t => {
  const f = await fixture(t, {autoConnect:true,businessConsumers:['example/shop']});
  assert.throws(()=>f.service.acquireBusiness(f.ctx),PapError);
  const manager=[...f.loader.entries()].find(item=>item.options.name===PAP_MANAGER)!;
  assert.throws(()=>f.service.acquireBusiness(manager.fiber!.ctx),PapError);
  const entry=[...f.loader.entries()].find(item=>item.options.name==='example/shop')!;
  const business=f.service.acquireBusiness(entry.fiber!.ctx);
  value(await business.connect('shop.example'));
  const status=value(await business.status());assert.equal(status.companies[0].domain,'shop.example');assert.equal(status.companies[0].companyId,'https://shop.example');
  assert(!JSON.stringify(value(await f.execute('pap_status'))).includes('https://'));
  const operations=value(await business.operations()) as unknown as Value[];
  const read=operations.find(op=>op.method==='GET'&&op.path==='/api/cart')!;assert(read);
  const data='x'.repeat(70000);
  f.transport.override=url=>url.endsWith('/api/cart')?Promise.resolve(jsonResponse(url,{description:data,access_token:'secret'})):undefined;
  const received=value(await business.request({operationRef:read.operationRef}));
  assert.equal(received.body.description,data);assert.equal(received.body.access_token,'[redacted]');
  const tool=value(await f.execute('pap_request',{operationRef:read.operationRef}));assert.equal(tool.bodyAvailable,false);
  await f.loader.update(entry.id,{disabled:true});
  const before=f.transport.calls.length;
  error(await business.request({operationRef:read.operationRef}),'permission_denied');
  assert.equal(f.transport.calls.length,before);
});

test('PAP business: an installed plugin without Host opt-in has no facade',async t=>{
  const f=await fixture(t,{businessConsumers:[]});
  const entry=[...f.loader.entries()].find(item=>item.options.name==='example/shop')!;
  assert.throws(()=>f.service.acquireBusiness(entry.fiber!.ctx),PapError);
});

test('PAP business: writes wait for the existing once-approval and send only once',async t=>{
  const f=await fixture(t,{autoConnect:true,businessConsumers:['example/shop']});
  const entry=[...f.loader.entries()].find(item=>item.options.name==='example/shop')!;
  const business=f.service.acquireBusiness(entry.fiber!.ctx);
  const write=await domainWrite(f);
  const pending=business.request({operationRef:write.operationRef,body:{quantity:1}});
  await untilConsent(f);
  assert.equal(f.transport.calls.filter(call=>call.url.includes('/api/cart')&&call.options?.method==='POST').length,0);
  f.consent.approve();assert.equal(value(await pending).status,200);
  assert.equal(f.consent.executions,1);
  assert.equal(f.transport.calls.filter(call=>call.url.includes('/api/cart')&&call.options?.method==='POST').length,1);
});


test('PAP user status restores domain state locally without connecting or sending',async t=>{
  const f=await fixture(t,{autoConnect:true});
  assert.equal(value(await f.manager.status()).state,'ready');
  assert.deepEqual(value(await f.manager.status()).sessions,[]);
  assert.equal(f.transport.calls.length,0);
  value(await f.execute('pap_connect',{domain:'shop.example'}));
  const before=value(await f.manager.status());
  value(await f.manager.manage({action:'session/disconnect',sessionRef:before.sessions[0].sessionRef}));
  const calls=f.transport.calls.length;
  const view=value(await f.manager.status());
  assert.equal(view.sessions[0].connected,false);
  assert.equal(f.transport.calls.length,calls);
});

test('PAP business status restores local sessions after PAP restart without connecting or reviving disconnects', async t => {
  for (const disconnect of [false, true]) {
    const f = await fixture(t, {autoConnect:true,businessConsumers:['example/shop']});
    const caller = [...f.loader.entries()].find(entry => entry.options.name === 'example/shop')!;
    const business = f.service.acquireBusiness(caller.fiber!.ctx);
    value(await business.connect('shop.example'));
    const before = value(await business.status());
    if (disconnect) value(await f.manager.manage({action:'session/disconnect',sessionRef:before.sessions[0].sessionRef}));
    const entry = [...f.loader.entries()].find(entry => entry.options.name === PAP_CONSUMER)!;
    await f.loader.update(entry.id, {disabled:true});
    await f.loader.update(entry.id, {disabled:false});
    await f.loader.await();
    const restored = f.ctx.pap.acquireBusiness(caller.fiber!.ctx);
    const sends = f.transport.calls.length;
    const results = await Promise.all([restored.status(), restored.status()]);
    for (const result of results) {
      const state = value(result);
      assert.equal(state.state, 'ready');
      assert.deepEqual(state.identity, before.identity);
      assert.equal(state.companies[0].companyRef, before.companies[0].companyRef);
      assert.equal(state.companies[0].domain, 'shop.example');
      assert.equal(state.sessions[0].connected, !disconnect);
    }
    assert.equal(f.transport.calls.length, sends, 'Status recovery must not discover or connect remotely');
    f.host.active = false;
    error(await restored.status(), 'permission_denied');
  }
});
