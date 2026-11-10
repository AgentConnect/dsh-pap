import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Context } from '@deepseek-ai/cordis';
import Loader from '@deepseek-ai/cordis-plugin-loader';
import * as plugin from '../src/plugin.js';
import ManagerRemote from '../src/management-remote.js';
import * as toolPlugin from '../src/tools.js';
import { PAP_CONSUMER, PAP_MANAGER, PAP_TOOLS, type PapHostConsumer, type ProductResult } from '../src/product-api.js';
import type { ProtocolIdentityClient, ProtocolKeyReference, ProtocolSignerLease } from '../src/protocol-adapter.js';
import type { Company, KeyRef, KeyScope } from '../src/types.js';
import { PapError, requirePap } from '../src/errors.js';
import { binding, FixtureHost, FixtureTransport, jsonResponse, secrets } from './fixture.js';
import { publicResponse } from '../src/product-operations.js';
import { publicResult } from '../src/plugin.js';
import { PapClient } from '../src/client.js';
import type { PolicyClient, PolicyClassification } from '../src/protocol-policy.js';

type Value = Record<string, any>;
function value(result: ProductResult): Value { assert.equal(result.ok, true, result.ok ? undefined : result.error.code); return (result as { value: Value }).value; }
function error(result: ProductResult, code: string) { assert.equal(result.ok,false); if(result.ok)throw new Error('Expected refusal'); assert.equal(result.error.code,code); assert(Object.keys(result.error).every(key=>['code','phase','businessRequest','httpStatus','retryAfterSeconds','approval'].includes(key))); }

/** Unit C boundary with real fixture cryptography. This is not evidence for the C factory. */
async function fixture(t: test.TestContext, options: { enabled?: boolean; mode?: FixtureTransport['mode']; missingConfig?: boolean; blockedSecrets?: boolean; missingFactory?: boolean; autoConnect?: boolean; approvalWaitMs?: number } = {}) {
  const root = await mkdtemp(join(tmpdir(), 'pap-product-unit-'));
  const ctx = new Context(); const host = new FixtureHost(); const transport = new FixtureTransport(); transport.mode = options.mode ?? 'none';
  const tools = new Map<string, any>(); const targetRefs = new WeakSet<object>(); const contexts: Context[] = []; const namespaces: string[] = []; let providerGeneration = 1; let registerCount = 0; let claimCount = 0; let disposedCallbacks = 0; let response: { state: string; iss: string; code: string } | undefined;
  let domainPolicyRef = 'host-approved';
  const protocol: ProtocolIdentityClient = {
    registerValidatedTarget: async input => {
      const targetRef = {}; targetRefs.add(targetRef);
      const company = { companyId: input.discovery.companyId, issuer: input.discovery.issuer } as Company;
      const lease = await host.acquire(binding, company); const scopes = new WeakMap<object, KeyScope>(); const keys = new WeakMap<object, KeyRef>();
      const scope = (ref: object) => { const found = scopes.get(ref); assert(found); return found; };
      const key = (ref: object) => { const found = keys.get(ref); assert(found); return found; };
      const publicKey = (value: KeyRef): ProtocolKeyReference => { const ref = {}; keys.set(ref, value); return { keyRef: ref, handle: value.handle, generation: value.generation, purpose: value.purpose, publicJwk: value.public_jwk, thumbprint: value.thumbprint }; };
      const raw: ProtocolSignerLease = {
        targetRef,
        getOAuthClientIdentity: async () => ({ clientId: binding.clientId, algorithm: 'ES256', keyId: host.identityKid, publicJwk: host.identity.jwk, redirectUris: ['https://agent.example/pap-callback'] }),
        assertActive: async () => { requirePap(input.discovery.expiresAt>Date.now(),'permission_denied');await lease.assertActive(); },
        signOAuthClientAssertion: () => lease.signOAuthClientAssertion(),
        bindPapScope: input => { const ref = {}; scopes.set(ref, { owner: binding.ownerRef, company_id: company.companyId, user_id: input.userId, ...(input.accountSlot ? { account_slot: input.accountSlot } : {}) }); return ref; },
        createDelegatedKey: async (ref, operation) => publicKey(await lease.createDelegatedKey(scope(ref), operation)),
        createDpopKey: async (ref, operation) => publicKey(await lease.createDpopKey(scope(ref), operation)),
        restorePapKey: async (ref, input) => { const found = host.keys.get(input.handle); assert(found); assert.equal(found.scope, JSON.stringify(scope(ref))); return publicKey(found.descriptor); },
        issuePapDelegation: (ref, input) => lease.issuePapDelegation(key(input.keyRef), scope(ref), input.ttlSeconds),
        signPapSessionRequest: (ref, input) => { const { keyRef, ...request } = input; return lease.signPapSessionRequest({ ...request, key: key(keyRef), scope: scope(ref) }); },
        signDpopProof: (ref, input) => { const { keyRef, ...request } = input; return lease.signDpopProof({ ...request, key: key(keyRef), scope: scope(ref) }); },
        retireTemporaryKey: (ref, input) => lease.retireTemporaryKey(key(input), scope(ref)), dispose() {},
      }; return raw;
    },
  };
  const consumer: PapHostConsumer = {
    assertActive: () => requirePap(host.active, 'permission_denied'), dispose() {},
    resolveBinding: async (reference, policyRef, profile) => { assert.deepEqual(reference, binding.identityRef); assert.equal(policyRef, domainPolicyRef); return { binding, ...(profile === 'pap_account' ? { redirectUri: 'https://agent.example/pap-callback' } : {}) }; },
    callbackManagementFor: async input => {
      assert(targetRefs.has(input.targetRef)); assert.deepEqual(input.identityRef, binding.identityRef); assert.equal(input.policyRef, 'host-approved');
      return { execute: (async (operation: any) => {
        if (operation.action === 'pap-callback-register') { registerCount++; return { transaction_id: operation.callback.transaction_id, callback_uri: operation.callback.redirect_uri, expires_at: operation.callback.expires_at }; }
        claimCount++; assert(response); return response;
      }) as any, dispose() { disposedCallbacks++; } };
    },
  };
  let domainEnabled = true;
  let consentDecision = {id:'fixture-consent',status:'pending',version:1,grantId:undefined as string|undefined,mode:undefined as string|undefined};
  let consentBindings = 0;
  let consentRequests = 0, consentExecutions = 0, consentCancels = 0, consentActive = true;
  let signalConsentRequested!: () => void;
  const consentRequested = new Promise<void>(resolve => { signalConsentRequested = resolve; });
  let consentRequest: Request | undefined;
  let expectedRequest: string | undefined;
  let policyVersion=0;
  const decisions:Record<PolicyClassification['effect'],'allow'|'ask'|'deny'>={read:'allow',write:'ask',unknown:'ask',payment:'ask'};
  const policyTargets=new WeakSet<object>();
  const policy:PolicyClient={
    async assertNoDenial(request){assert(!request.headers.has('poppy-session'));},
    classifyHttp(input){
      const security=input.security;
      const extraPermissions=security!==undefined&&(!Array.isArray(security)||security.some(item=>!item||typeof item!=='object'||Object.values(item).some(value=>!Array.isArray(value)||value.length>0)));
      const effect=input.declaredEffect==='payment'?'payment':input.declaredEffect==='read'?'read':input.declaredEffect==='write'?'write'
        :['GET','HEAD'].includes(input.method)?input.hasRequestBody?'unknown':'read':'write';
      return {effect,extraPermissions};
    },
    register(input){assert(input.discoveryOrigin.startsWith('https://'));const target={protocolTarget:true as const};policyTargets.add(target);return target;},
    forget(target){policyTargets.delete(target);},
    async evaluate(target,input){
      assert(policyTargets.has(target));const version=policyVersion;
      const selected=decisions[input.effect],decision=selected==='deny'?'deny':input.extraPermissions||input.effect==='payment'||input.effect==='unknown'?'ask':selected;
      return {decision,version,async assertActive(){if(!policyTargets.has(target)||version!==policyVersion||decision==='deny')throw Object.assign(new Error('Policy changed'),{code:'protocol_policy_changed'});}};
    },
  };
  const requestFingerprint = async (request: Request) => JSON.stringify([request.method,request.url,[...request.headers],await request.clone().text()]);
  const consent = {
    async request(input: {requestId:string;purpose:string;request:Request}) {
      assert(input.purpose.startsWith('PAP exact operation'));
      assert(!input.request.headers.has('poppy-session') && !input.request.headers.has('authorization') && !input.request.headers.has('dpop'));
      consentRequests++; consentRequest=input.request.clone(); expectedRequest=await requestFingerprint(input.request);
      signalConsentRequested();
      return {...consentDecision};
    },
    async status(id: string) {assert.equal(id,consentDecision.id);return {...consentDecision};},
    async cancel(id: string) {assert.equal(id,consentDecision.id);consentCancels++;consentDecision.status='cancelled';return {...consentDecision};},
    async execute<T>(grantId: string, request: Request, effect: (assertActive:()=>Promise<void>)=>Promise<T>): Promise<T> {
      assert.equal(grantId,'once-grant');assert.equal(consentDecision.mode,'once');assert.equal(consentDecision.status,'approved');
      assert.equal(await requestFingerprint(request),expectedRequest);
      consentExecutions++;consentDecision.status='consumed';
      const check=async()=>{if(!consentActive)throw Object.assign(new Error('Revoked'),{code:'grant_inactive'});};
      await check();const response=await effect(check);await check();return response;
    },
  };
  ctx.provide('anpIdentity', {
    bindProtocolPolicy(context:Context,protocol:string){contexts.push(context);assert.equal(protocol,'pap');return policy;},
    bindDomainOperationConsumer(context: Context) {
      contexts.push(context); consentBindings++;
      const owned = new Set<string>();
      return {
        async request(input: Parameters<typeof consent.request>[0]) { const decision = await consent.request(input); owned.add(decision.id); return decision; },
        async status(id: string) { if (!owned.has(id)) throw Object.assign(new Error('Request belongs to a different bound facade'), {code:'consumer_forbidden'}); return consent.status(id); },
        async cancel(id: string) { if (!owned.has(id)) throw Object.assign(new Error('Request belongs to a different bound facade'), {code:'consumer_forbidden'}); return consent.cancel(id); },
        execute: consent.execute,
      };
    },
    async resolveDomainAccess(context: Context, profile: string) {
      assert.equal(profile, 'pap_session'); contexts.push(context);
      if (!domainEnabled) throw Object.assign(new Error('Disabled'), {code:'domain_access_disabled'});
      return { identityRef: binding.identityRef, policyRef: domainPolicyRef, stateRoot: root, secretsRoot: root + '-keys', secretStore: 'local-file' };
    },
    ...(options.missingFactory ? {} : { bindPapHostConsumer(context: Context) {
      contexts.push(context); const generation = providerGeneration; let disposed = false;
      return { ...consumer, assertActive() { if (disposed || generation !== providerGeneration) throw Object.assign(new Error('Disposed fixture facade'), { code: 'provider_disposed' }); consumer.assertActive(); }, dispose() { disposed = true; } };
    } }),
    bindProtocolConsumer(context: Context) { contexts.push(context); return protocol; },
  });
  let pauseKey: { entered(): void; gate: Promise<void> } | undefined;
  const spySecrets = { getEncryptionKey: async (namespace: string) => { namespaces.push(namespace); const pause = pauseKey; pauseKey = undefined; if (pause) { pause.entered(); await pause.gate; } return secrets.getEncryptionKey(); }, getOrCreateEncryptionKey: async (namespace: string) => { namespaces.push(namespace); return secrets.getOrCreateEncryptionKey(); } };
  ctx.provide('papHost', { secrets: options.blockedSecrets ? { getEncryptionKey: async () => { throw new PapError('credential_unavailable'); }, getOrCreateEncryptionKey: async () => { throw new PapError('credential_unavailable'); } } : spySecrets, transport });
  ctx.provide('tools', { register(definition: any) { tools.set(definition.name, definition); } });
  ctx.provide('typert', { register() { return () => {}; } });
  await ctx.plugin(Loader, {}); const loader = ctx.get('loader') as Loader;
  const modules: Record<string, unknown> = { [PAP_CONSUMER]: plugin, [PAP_MANAGER]: ManagerRemote, [PAP_TOOLS]: toolPlugin };
  loader.import = async name => { assert(Object.hasOwn(modules, name)); return modules[name]; };
  const config = options.autoConnect ? { enabled: true, autoConnect: true, approvalWaitMs: options.approvalWaitMs ?? 2000, approvalPollMs: 10 } : options.missingConfig ? { enabled: true } : { enabled: options.enabled ?? true, stateRoot: root, policyRef: 'host-approved', keyringService: 'pap-isolated-unit-never-created' };
  await loader.create({ name: PAP_CONSUMER, config });
  await loader.create({ name: PAP_MANAGER }); await loader.create({ name: PAP_TOOLS }); await loader.await();
  const service = ctx.pap; const manager = ctx.get('papManager') as unknown as InstanceType<typeof ManagerRemote>;
  const execute = async (name: string, args: unknown = {}, signal = new AbortController().signal) => tools.get(name).execute(args, { agent: {}, signal });
  t.after(async () => { await ctx.fiber.dispose(); await rm(root, { recursive: true, force: true }); await rm(root + '-keys', { recursive: true, force: true }); });
  return { root, ctx, loader, host, transport,
    policy:{set(effect:PolicyClassification['effect'],decision:'allow'|'ask'|'deny'){decisions[effect]=decision;policyVersion++;}},
    consent: {requested:consentRequested,approve(mode='once') {consentDecision={...consentDecision,status:'approved',grantId:'once-grant',mode};},deny(){consentDecision.status='denied';},revoke(){consentActive=false;},get bindings(){return consentBindings;},get requests(){return consentRequests;},get executions(){return consentExecutions;},get cancels(){return consentCancels;},get status(){return consentDecision.status;},get request(){return consentRequest;}},
    changeDefaultEpoch() { domainPolicyRef += '-next'; },
    disableDomain() { domainEnabled = false; }, service, manager, execute, tools, contexts, namespaces, config, select: async () => manager.manage({ action: 'identity/select', reference: binding.identityRef }),
    setResponse(value: typeof response) { response = value; }, advanceProvider() { providerGeneration++; },
    pauseNextKeyRead() { let entered!: () => void; let release!: () => void; const start = new Promise<void>(resolve => entered = resolve); const gate = new Promise<void>(resolve => release = resolve); pauseKey = { entered, gate }; return { start, release }; },
    get counts() { return { registerCount, claimCount, disposedCallbacks }; } };
}
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
  f.transport.override=url=>url.endsWith('/poppy.json')?jsonResponse(url,{protocol_version:'0.3',organization:{name:`Company ${token}`,domain:'shop.example'},auth:{issuer:f.transport.issuer,scopes:{'orders:read':'Orders'}},apis:[{type:'openapi',url:'https://shop.example/openapi.json'}]}):url.endsWith('/openapi.json')?jsonResponse(url,{openapi:'3.1.0',servers:[{url:'https://shop.example'}],paths:{['/api/'+token]:{get:{}}}}):undefined;
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
  f.transport.override=url=>url.endsWith('/poppy.json')?jsonResponse(url,{protocol_version:'0.3',organization:{name:`Company ${state}`,domain:'shop.example'},auth:{issuer:f.transport.issuer,scopes:{'orders:read':'Orders'}},apis:[{type:'openapi',url:'https://shop.example/openapi.json'}]}):url.endsWith('/openapi.json')?jsonResponse(url,{openapi:'3.1.0',servers:[{url:'https://shop.example'}],paths:{['/api/'+state]:{get:{}}}}):undefined;
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
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([f.consent.requested, new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error('PAP consent request did not arrive')), 30000);
    })]);
  } finally { clearTimeout(timer); }
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
