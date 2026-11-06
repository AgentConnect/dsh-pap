/** Missing P02/P04/P05/P07 unit contracts. Crypto/HTTP are explicit owner fixtures, not an AS/native lane. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PapClient } from '../src/client.js';
import { PapDiscovery } from '../src/discovery.js';
import { PapError } from '../src/errors.js';
import { jwtParts } from '../src/util.js';
import { binding, FixtureHost, FixtureTransport, jsonResponse, secrets } from './fixture.js';

const failure = (code: string) => (error: unknown) => error instanceof PapError && error.code === code;
const discoveryUrl = (domain: string) => `https://${domain}/.well-known/poppy.json`;
const issuerMetadataUrl = (issuer: string) => `${issuer}/.well-known/oauth-authorization-server`;
function document(domain: string, issuer?: string) {
  return { protocol_version: '0.3', organization: { name: 'Discovery contract fixture', domain },
    apis: [{ type: 'openapi', url: `https://${domain}/openapi.json` }],
    ...(issuer ? { auth: { issuer, scopes: { 'orders:read': 'Read fixture orders' } } } : {}) };
}
function metadata(issuer: string, resources = ['https://shop.example']) {
  return { issuer, protected_resources: resources, token_endpoint: issuer + '/token', authorization_endpoint: issuer + '/authorize',
    revocation_endpoint: issuer + '/revoke', grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['private_key_jwt'], code_challenge_methods_supported: ['S256'], dpop_signing_alg_values_supported: ['ES256'] };
}
async function clientFixture(t: test.TestContext) {
  const root = await mkdtemp(join(tmpdir(), 'pap-discovery-contract-'));
  const transport = new FixtureTransport(); transport.mode = 'account';
  const host = new FixtureHost();
  const options = { stateRoot: root, binding, secretStore: secrets, identityHost: host,
    callbackHandoff: { register: async () => ({ callbackRef: 'unit-user-claim' }), collect: async () => ({}) } };
  const client = new PapClient(options, transport);
  t.after(async () => { client.close(); await rm(root, { recursive: true, force: true }); });
  return { client, transport, options, host };
}

test('P02 canonical HTTPS redirect works, while final wrong path, query and HTTP downgrade are rejected', async () => {
  const first = discoveryUrl('shop.example');
  const canonical = discoveryUrl('canonical.example');
  const valid = new FixtureTransport();
  valid.override = url => url === first ? jsonResponse(url, {}, 302, { location: canonical }) : undefined;
  const company = await new PapDiscovery(valid).resolve('shop.example');
  assert.equal(company.companyId, 'https://canonical.example');
  assert.equal(company.domain, 'canonical.example');
  assert(valid.calls.some(call => call.url === canonical));
  for (const destination of ['https://canonical.example/other/poppy.json', canonical + '?tracking=1']) {
    const transport = new FixtureTransport();
    transport.override = url => url === first ? jsonResponse(url, {}, 307, { location: destination })
      : url === destination ? jsonResponse(url, document('canonical.example')) : undefined;
    await assert.rejects(new PapDiscovery(transport).resolve('shop.example'), failure('discovery_failed'));
    assert.equal(transport.calls.length, 2, 'invalid final location must stop before PRM or API discovery');
  }
  const downgrade = new FixtureTransport();
  downgrade.override = url => url === first ? jsonResponse(url, {}, 302, { location: 'http://canonical.example/.well-known/poppy.json' }) : undefined;
  await assert.rejects(new PapDiscovery(downgrade).resolve('shop.example'), failure('unsafe_destination'));
  assert.equal(downgrade.calls.length, 1, 'no cleartext request is sent');
});

test('P04 timeout, HTTP500, malformed metadata and AS issuer failure preserve the known account namespace', async t => {
  const f = await clientFixture(t);
  const known = await f.client.resolvePapCompany('shop.example');
  const before = await f.client.store.read();
  const prm = 'https://shop.example/.well-known/oauth-protected-resource';
  const cases: Array<{ name: string; override: NonNullable<FixtureTransport['override']> }> = [
    { name: 'transport timeout', override: url => { if (url === prm) throw new DOMException('Fixture timeout', 'TimeoutError'); return undefined; } },
    { name: 'HTTP500', override: url => url === prm ? jsonResponse(url, {}, 500) : undefined },
    { name: 'invalid PRM JSON', override: url => url === prm ? { ...jsonResponse(url, {}), body: Buffer.from('{invalid') } : undefined },
    { name: 'AS issuer mismatch', override: url => url === issuerMetadataUrl(f.transport.issuer) ? jsonResponse(url, metadata('https://wrong.example')) : undefined },
  ];
  for (const item of cases) {
    f.transport.override = item.override;
    const calls = f.transport.calls.length;
    await assert.rejects(f.client.resolvePapCompany('shop.example'), failure('discovery_failed'), item.name);
    const current = await f.client.store.read();
    assert.deepEqual(current.companies, before.companies, item.name);
    assert.equal(current.companies[known.companyRef]!.companyId, f.transport.issuer);
    assert.equal(current.companies[known.companyRef]!.authMode, 'account');
    assert(!f.transport.calls.slice(calls).some(call => /\/(token|authorize|revoke)$/u.test(new URL(call.url).pathname)));
  }
});

function issuerTransport(servers: string[], selected?: string, returnedIssuer?: string, resources?: string[]) {
  const transport = new FixtureTransport();
  transport.override = url => {
    if (url === discoveryUrl('shop.example')) return jsonResponse(url, document('shop.example', selected));
    if (url === 'https://shop.example/.well-known/oauth-protected-resource') return jsonResponse(url, { resource: 'https://shop.example', authorization_servers: servers });
    const chosen = selected ?? servers[0]!;
    if (url === issuerMetadataUrl(chosen)) return jsonResponse(url, metadata(returnedIssuer ?? chosen, resources));
    return undefined;
  };
  return transport;
}

test('P05 a single issuer needs no auth selector, and multiple issuers fetch only the explicitly selected AS', async () => {
  const one = 'https://single-auth.example';
  const single = issuerTransport([one]);
  const oneCompany = await new PapDiscovery(single).resolve('shop.example');
  assert.equal(oneCompany.companyId, one); assert.equal(oneCompany.authMode, 'account');
  const unselected = 'https://unselected-auth.example', selected = 'https://selected-auth.example';
  const multi = issuerTransport([unselected, selected], selected);
  const company = await new PapDiscovery(multi).resolve('shop.example');
  assert.equal(company.companyId, selected);
  assert(multi.calls.some(call => call.url === issuerMetadataUrl(selected)));
  assert(!multi.calls.some(call => new URL(call.url).origin === unselected));
});

test('P05 ambiguous or conflicting issuer selection and missing exact protected_resources binding fail closed', async () => {
  const one = 'https://first-auth.example', two = 'https://second-auth.example';
  for (const [name, transport] of [
    ['multiple without selector', issuerTransport([one, two])],
    ['selector absent from PRM', issuerTransport([one, two], 'https://outside-auth.example')],
    ['single conflicting selector', issuerTransport([one], two)],
    ['reverse resource wrong path', issuerTransport([one], one, one, ['https://shop.example/other'])],
  ] as const) {
    await assert.rejects(new PapDiscovery(transport).resolve('shop.example'), failure('discovery_failed'), name);
    assert(!transport.calls.some(call => /\/(token|authorize|revoke)$/u.test(new URL(call.url).pathname)));
  }
});

test('P07 two Company namespaces keep stable distinct User/Agent IDs, and anonymous requests cannot borrow an account', async t => {
  const f = await clientFixture(t);
  const issuers = new Map([['https://shop.example', 'https://auth.shop.example'], ['https://other.example', 'https://auth.other.example']]);
  f.transport.override = url => {
    const target = new URL(url), issuer = issuers.get(target.origin);
    if (target.pathname === '/.well-known/poppy.json' && issuer) return jsonResponse(url, document(target.host, issuer));
    if (target.pathname === '/.well-known/oauth-protected-resource' && issuer) return jsonResponse(url, { resource: target.origin, authorization_servers: [issuer] });
    for (const [origin, candidate] of issuers) if (url === issuerMetadataUrl(candidate)) return jsonResponse(url, metadata(candidate, [origin]));
    return undefined;
  };
  const first = await f.client.resolvePapCompany('shop.example'), second = await f.client.resolvePapCompany('other.example');
  const a = await f.client.getOrCreatePapUser(first.companyRef, 'regular', true);
  const b = await f.client.getOrCreatePapUser(second.companyRef, 'regular', true);
  const original = await f.client.store.read();
  assert.notEqual(original.subjects[a.subjectRef]!.userId, original.subjects[b.subjectRef]!.userId);
  assert.notEqual(original.subjects[a.subjectRef]!.agentId, original.subjects[b.subjectRef]!.agentId);
  const restarted = new PapClient(f.options, f.transport); t.after(() => restarted.close());
  assert.equal((await restarted.getOrCreatePapUser(first.companyRef, 'regular', true)).subjectRef, a.subjectRef);
  assert.equal((await restarted.getOrCreatePapUser(second.companyRef, 'regular', true)).subjectRef, b.subjectRef);
  const login = await f.client.startSignIn(a.subjectRef, { scopes: ['orders:read'], resource: 'https://shop.example', redirectUri: 'https://agent.example/pap-callback', callbackMode: 'handoff' });
  const tx = (await f.client.store.read()).transactions[login.transactionRef]!;
  const grant = await f.client.completeSignIn(login.transactionRef, { state: tx.state, iss: tx.issuer, code: 'unit-code' });
  const regular = await f.client.openPapSession(a.subjectRef, grant.accountSlot);
  await f.client.dispatchPap(regular.sessionRef, { url: 'https://shop.example/api/cart' });
  assert.equal(f.transport.calls.at(-1)!.options?.headers?.authorization, 'DPoP access-fixture');
  await assert.rejects(f.client.openPapSession(b.subjectRef, grant.accountSlot), failure('reauthorization_required'));
  const anon = await f.client.getOrCreatePapUser(first.companyRef, 'anonymous', true);
  const anon2 = await f.client.getOrCreatePapUser(first.companyRef, 'anonymous', true);
  const state = await f.client.store.read();
  assert.notEqual(state.subjects[anon.subjectRef]!.userId, state.subjects[a.subjectRef]!.userId);
  assert.notEqual(state.subjects[anon.subjectRef]!.userId, state.subjects[anon2.subjectRef]!.userId);
  assert.notEqual(state.subjects[anon.subjectRef]!.agentId, state.subjects[anon2.subjectRef]!.agentId);
  await assert.rejects(f.client.openPapSession(anon.subjectRef, grant.accountSlot), failure('permission_denied'));
  const anonymous = await f.client.openPapSession(anon.subjectRef);
  const tokensBefore = f.transport.calls.filter(call => new URL(call.url).pathname === '/token').length;
  await f.client.dispatchPap(anonymous.sessionRef, { url: 'https://shop.example/api/cart' });
  const request = f.transport.calls.at(-1)!;
  assert.equal(request.options?.headers?.authorization, undefined);
  assert.equal(request.options?.headers?.dpop, undefined);
  const session = jwtParts(request.options!.headers!['poppy-session']!);
  assert.equal(session.payload.sub, state.subjects[anon.subjectRef]!.userId);
  assert.equal(session.payload.agent_id, state.subjects[anon.subjectRef]!.agentId);
  assert(!Object.hasOwn(session.payload, 'ath'));
  assert.equal(f.transport.calls.filter(call => new URL(call.url).pathname === '/token').length, tokensBefore);
});
