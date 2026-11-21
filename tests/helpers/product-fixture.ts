import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type test from 'node:test';
import { Context } from '@deepseek-ai/cordis';
import Loader from '@deepseek-ai/cordis-plugin-loader';
import * as plugin from '../../src/plugin.js';
import ManagerRemote from '../../src/management-remote.js';
import * as toolPlugin from '../../src/tools.js';
import { PAP_CONSUMER, PAP_MANAGER, PAP_TOOLS, type PapHostConsumer } from '../../src/product-api.js';
import type { ProtocolIdentityClient, ProtocolKeyReference, ProtocolSignerLease } from '../../src/protocol-adapter.js';
import type { Company, HttpTransport, KeyRef, KeyScope } from '../../src/types.js';
import { PapError, requirePap } from '../../src/errors.js';
import type { PolicyClient, PolicyClassification } from '../../src/protocol-policy.js';
import { binding, FixtureHost, FixtureTransport, secrets } from '../fixture.js';

/** Unit C boundary with real fixture cryptography. This is not evidence for the C factory. */
export async function fixture(t: test.TestContext, options: { enabled?: boolean; mode?: FixtureTransport['mode']; missingConfig?: boolean; blockedSecrets?: boolean; missingFactory?: boolean; autoConnect?: boolean; approvalWaitMs?: number; businessConsumers?: string[]; transport?: HttpTransport; ucpPlatformProfileUrl?: string } = {}) {
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
  ctx.provide('papHost', { secrets: options.blockedSecrets ? { getEncryptionKey: async () => { throw new PapError('credential_unavailable'); }, getOrCreateEncryptionKey: async () => { throw new PapError('credential_unavailable'); } } : spySecrets, transport: options.transport ?? transport });
  ctx.provide('tools', { register(definition: any) { tools.set(definition.name, definition); } });
  ctx.provide('typert', { register() { return () => {}; } });
  await ctx.plugin(Loader, {}); const loader = ctx.get('loader') as Loader;
  const modules: Record<string, unknown> = { [PAP_CONSUMER]: plugin, [PAP_MANAGER]: ManagerRemote, [PAP_TOOLS]: toolPlugin, "example/shop": { apply() {} } };
  loader.import = async name => { assert(Object.hasOwn(modules, name)); return modules[name]; };
  const config = options.autoConnect ? { enabled: true, autoConnect: true, approvalWaitMs: options.approvalWaitMs ?? 2000, approvalPollMs: 10 } : options.missingConfig ? { enabled: true } : { enabled: options.enabled ?? true, stateRoot: root, policyRef: 'host-approved', keyringService: 'pap-isolated-unit-never-created' };
  await loader.create({ name: PAP_CONSUMER, config: {...config,businessConsumers:options.businessConsumers ?? [],ucpPlatformProfileUrl:options.ucpPlatformProfileUrl} });
  if (options.businessConsumers) await loader.create({name:"example/shop"});
  await loader.create({ name: PAP_MANAGER }); await loader.create({ name: PAP_TOOLS }); await loader.await();
  const service = ctx.pap; const manager = ctx.get('papManager') as unknown as InstanceType<typeof ManagerRemote>;
  const execute = async (name: string, args: unknown = {}, signal = new AbortController().signal) => tools.get(name).execute(args, { agent: {}, signal });
  t.after(async () => { await ctx.fiber.dispose(); await rm(root, { recursive: true, force: true }); await rm(root + '-keys', { recursive: true, force: true }); });
  return { root, ctx, loader, host, transport,
    policy:{set(effect:PolicyClassification['effect'],decision:'allow'|'ask'|'deny'){decisions[effect]=decision;policyVersion++;}},
    consent: {approve(mode='once') {consentDecision={...consentDecision,status:'approved',grantId:'once-grant',mode};},deny(){consentDecision.status='denied';},revoke(){consentActive=false;},get bindings(){return consentBindings;},get requests(){return consentRequests;},get executions(){return consentExecutions;},get cancels(){return consentCancels;},get status(){return consentDecision.status;},get request(){return consentRequest;}},
    changeDefaultEpoch() { domainPolicyRef += '-next'; },
    disableDomain() { domainEnabled = false; }, service, manager, execute, tools, contexts, namespaces, config, select: async () => manager.manage({ action: 'identity/select', reference: binding.identityRef }),
    setResponse(value: typeof response) { response = value; }, advanceProvider() { providerGeneration++; },
    pauseNextKeyRead() { let entered!: () => void; let release!: () => void; const start = new Promise<void>(resolve => entered = resolve); const gate = new Promise<void>(resolve => release = resolve); pauseKey = { entered, gate }; return { start, release }; },
    get counts() { return { registerCount, claimCount, disposedCallbacks }; } };
}
