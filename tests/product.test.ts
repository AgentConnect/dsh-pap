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

type Value = Record<string, any>;
function value(result: ProductResult): Value { assert.equal(result.ok, true, result.ok ? undefined : result.error.code); return (result as { value: Value }).value; }
function error(result: ProductResult, code: string) { assert.deepEqual(result, { ok: false, error: { code } }); }

/** Unit C boundary with real fixture cryptography. This is not evidence for the C factory. */
async function fixture(t: test.TestContext, options: { enabled?: boolean; mode?: FixtureTransport['mode']; missingConfig?: boolean; blockedSecrets?: boolean; missingFactory?: boolean } = {}) {
  const root = await mkdtemp(join(tmpdir(), 'pap-product-unit-'));
  const ctx = new Context(); const host = new FixtureHost(); const transport = new FixtureTransport(); transport.mode = options.mode ?? 'none';
  const tools = new Map<string, any>(); const targetRefs = new WeakSet<object>(); const contexts: Context[] = []; const namespaces: string[] = []; let registerCount = 0; let claimCount = 0; let disposedCallbacks = 0; let response: { state: string; iss: string; code: string } | undefined;
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
        assertActive: () => lease.assertActive(),
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
    resolveBinding: async (reference, policyRef, profile) => { assert.deepEqual(reference, binding.identityRef); assert.equal(policyRef, 'host-approved'); return { binding, ...(profile === 'pap_account' ? { redirectUri: 'https://agent.example/pap-callback' } : {}) }; },
    callbackManagementFor: async input => {
      assert(targetRefs.has(input.targetRef)); assert.deepEqual(input.identityRef, binding.identityRef); assert.equal(input.policyRef, 'host-approved');
      return { execute: (async (operation: any) => {
        if (operation.action === 'pap-callback-register') { registerCount++; return { transaction_id: operation.callback.transaction_id, callback_uri: operation.callback.redirect_uri, expires_at: operation.callback.expires_at }; }
        claimCount++; assert(response); return response;
      }) as any, dispose() { disposedCallbacks++; } };
    },
  };
  ctx.provide('anpIdentity', {
    ...(options.missingFactory ? {} : { bindPapHostConsumer(context: Context) { contexts.push(context); return consumer; } }),
    bindProtocolConsumer(context: Context) { contexts.push(context); return protocol; },
  });
  const spySecrets = { getEncryptionKey: async (namespace: string) => { namespaces.push(namespace); return secrets.getEncryptionKey(); }, getOrCreateEncryptionKey: async (namespace: string) => { namespaces.push(namespace); return secrets.getOrCreateEncryptionKey(); } };
  ctx.provide('papHost', { secrets: options.blockedSecrets ? { getEncryptionKey: async () => { throw new PapError('credential_unavailable'); }, getOrCreateEncryptionKey: async () => { throw new PapError('credential_unavailable'); } } : spySecrets, transport });
  ctx.provide('tools', { register(definition: any) { tools.set(definition.name, definition); } });
  ctx.provide('typert', { register() { return () => {}; } });
  await ctx.plugin(Loader, {}); const loader = ctx.get('loader') as Loader;
  const modules: Record<string, unknown> = { [PAP_CONSUMER]: plugin, [PAP_MANAGER]: ManagerRemote, [PAP_TOOLS]: toolPlugin };
  loader.import = async name => { assert(Object.hasOwn(modules, name)); return modules[name]; };
  const config = options.missingConfig ? { enabled: true } : { enabled: options.enabled ?? true, stateRoot: root, policyRef: 'host-approved', keyringService: 'pap-isolated-unit-never-created' };
  await loader.create({ name: PAP_CONSUMER, config });
  await loader.create({ name: PAP_MANAGER }); await loader.create({ name: PAP_TOOLS }); await loader.await();
  const service = ctx.pap; const manager = ctx.get('papManager') as unknown as InstanceType<typeof ManagerRemote>;
  const execute = async (name: string, args: unknown = {}) => tools.get(name).execute(args, { agent: {}, signal: new AbortController().signal });
  t.after(async () => { await ctx.fiber.dispose(); await rm(root, { recursive: true, force: true }); });
  return { root, ctx, loader, host, transport, service, manager, execute, tools, contexts, namespaces, config, select: async () => manager.manage({ action: 'identity/select', reference: binding.identityRef }),
    setResponse(value: typeof response) { response = value; }, get counts() { return { registerCount, claimCount, disposedCallbacks }; } };
}
async function connected(f: Awaited<ReturnType<typeof fixture>>) {
  value(await f.select()); const company = value(await f.manager.manage({ action: 'company/discover', domain: 'shop.example' }));
  const session = value(await f.manager.manage({ action: 'session/connect', companyRef: company.companyRef }));
  const operations = value(await f.manager.operations()) as unknown as Value[];
  const operation = operations.find(item => item.method === 'GET' && item.path === '/api/cart')!;
  return { company, session, operation };
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
  assert.deepEqual([...f.tools.keys()], ['pap_status','pap_operations','pap_request']);
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
  await f.loader.update(entry.id, { config: { ...f.config } }); await f.loader.await();
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
  value(await f.execute('pap_request', { operationRef: operation.operationRef, query: { q: 'one & two' } }));
  assert.equal(f.transport.calls.at(-1)!.url, 'https://shop.example/api/cart?q=one+%26+two');
});
