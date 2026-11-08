/** Real default HTTPS relay: F -> C/A/B -> G account, with no Agent key export or fake callback. */
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { createInterface } from 'node:readline';
import { readFile, writeFile, mkdtemp, mkdir, rm } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { PapClient } from '../src/client.js';
import { DeviceCallbackHandoff, type DeviceManagementOperations } from '../src/callback-handoff.js';
import { PapError } from '../src/errors.js';
import { SafeHttpsTransport } from '../src/network.js';
import { ProtocolIdentityHost, type ProtocolIdentityClient } from '../src/protocol-adapter.js';
import { parseJson } from '../src/util.js';
import { strictJson } from '../src/strict-json.js';
import type { Binding, HttpTransport } from '../src/types.js';

interface NativeFixture {
  reference: Binding['identityRef']; client: ProtocolIdentityClient; policyRef: string;
  publicMaterials: { metadata: string; jwks: string }; callbackManagement: DeviceManagementOperations; clientId: string; origin: string; fetch: typeof fetch; dispose(): Promise<void>;
}
const [fixtureArgument, bSourceArgument, pythonArgument, materialsArgument, publicationOrigin = 'https://agent.test:29443'] = process.argv.slice(2);
assert(fixtureArgument && bSourceArgument && pythonArgument && materialsArgument, 'Managed fixture, B source, Python and public materials path are required');
const fixturePath = resolve(fixtureArgument); const materialsPath = resolve(materialsArgument);
const companyOrigin = 'https://company-a.test';
const expectedNative = 'e2c4b86a0b3622aaefa70b44d3dc31cdab579b1237a4418d349bd294c52663ef';
const root = await mkdtemp(join(tmpdir(), 'pap-native-frontvia-')); const master = randomBytes(32);
let fixture: NativeFixture | undefined; let engine: PapClient | undefined; let stage = 'native_setup'; let materialsCreated = false; let completionPath: string | undefined; let completionSent = false;
let forwardedCallbacks = 0; let receivedCallbacks = 0;
const callbackPath = '/user-service/v1/pap-callback';
const callbackErrors: Record<number, Set<string>> = { 400: new Set(['invalid_callback','callback_expired','callback_issuer_mismatch']), 409: new Set(['callback_conflict']), 503: new Set(['callback_unavailable']) };
const loopback = http.createServer(async (request, response) => {
  response.setHeader('content-type', 'application/json'); response.setHeader('cache-control', 'no-store'); response.setHeader('referrer-policy', 'no-referrer');
  const raw = request.url ?? ''; const path = raw.split('?', 1)[0];
  if (!fixture || request.method !== 'GET' || path !== callbackPath || raw.length > 8192 || raw.includes('#') || ['authorization','cookie','dpop','poppy-session','proxy-authorization'].some(name => request.headers[name] !== undefined)) {
    response.statusCode = 400; response.end(JSON.stringify({ error: 'invalid_callback' })); return;
  }
  try {
    // Preserve the path/query only in-flight; do not parse, store, claim or log a code here.
    const reply = await fixture.fetch(new Request(fixture.origin + raw, { method: 'GET', redirect: 'manual' }));
    const reader = reply.body?.getReader(); const parts: Uint8Array[] = []; let size = 0;
    try { while (reader) { const part = await reader.read(); if (part.done) break; size += part.value.length; if (size > 4096) throw new Error('Callback response too large'); parts.push(part.value); } }
    finally { await reader?.cancel(); reader?.releaseLock(); }
    const body = strictJson(Buffer.concat(parts)) as Record<string, unknown>; forwardedCallbacks++;
    if (reply.status === 200 && Object.keys(body).join(',') === 'state' && body.state === 'received') { receivedCallbacks++; response.end(JSON.stringify({ state: 'received' })); }
    else if (Object.keys(body).join(',') === 'error' && typeof body.error === 'string' && callbackErrors[reply.status]?.has(body.error)) { response.statusCode = reply.status; response.end(JSON.stringify({ error: body.error })); }
    else { response.statusCode = 502; response.end(JSON.stringify({ error: 'callback_unavailable' })); }
  } catch { response.statusCode = 502; response.end(JSON.stringify({ error: 'callback_unavailable' })); }
});
await new Promise<void>(resolve => loopback.listen(0, '127.0.0.1', resolve));
try {
  const redirectUri = publicationOrigin + callbackPath;
  const callbackForward = `http://127.0.0.1:${(loopback.address() as { port: number }).port}${callbackPath}`;
  const helperSha256 = createHash('sha256').update(await readFile(fixturePath)).digest('hex');
  const bridgePath = resolve(bSourceArgument, 'tests/app/cimd/management_bridge.py'); const bridgeSha256 = createHash('sha256').update(await readFile(bridgePath)).digest('hex');
  const nativeSha256 = createHash('sha256').update(await readFile(resolve(dirname(fixturePath), '../../../../bindings/node/anp-identity.linux-x64-gnu.node'))).digest('hex');
  assert.equal(nativeSha256, expectedNative);
  const { createManagedCallbackFixture } = await import(pathToFileURL(fixturePath).href);
  fixture = await createManagedCallbackFixture({ source: resolve(bSourceArgument), python: resolve(pythonArgument), profile: 'e1', publicationOrigin, consumer: '@awiki/dsh-pap', profiles: ['pap_session','pap_account'], issuers: [companyOrigin], resources: [companyOrigin, companyOrigin + '/api/pap03'], scopes: ['profile:read'] }) as NativeFixture;
  const metadata = strictJson(Buffer.from(fixture.publicMaterials.metadata)) as Record<string, unknown>;
  const jwks = strictJson(Buffer.from(fixture.publicMaterials.jwks)) as { keys: Record<string, unknown>[] };
  assert.equal(new URL(String(metadata.client_id)).origin, publicationOrigin);
  assert((metadata.redirect_uris as string[]).includes(redirectUri), 'Real B publication must advertise the fixed HTTPS relay callback');
  assert(jwks.keys.length > 0 && jwks.keys.every(key => !Object.hasOwn(key, 'd')));
  await mkdir(dirname(materialsPath), { recursive: true, mode: 0o700 });
  await writeFile(materialsPath, JSON.stringify({ client_id: metadata.client_id, metadata: fixture.publicMaterials.metadata, jwks: fixture.publicMaterials.jwks }), { mode: 0o600, flag: 'wx' });
  materialsCreated = true;
  console.log(JSON.stringify({ stage: 'public_materials_ready', publicMaterials: materialsPath, fixtureOrigin: publicationOrigin, callbackForward, callbackUri: redirectUri, nativeSha256, helperSha256, bridgeSha256 }));
  // The peer starts its isolated public publisher and supplies only a manifest path on stdin.
  stage = 'await_peer';
  const lines = createInterface({ input: process.stdin });
  const manifestPath = await new Promise<string>((resolve, reject) => {
    const timeout = setTimeout(() => { lines.close(); reject(new Error('Peer manifest timeout')); }, 300000);
    lines.once('line', line => { clearTimeout(timeout); resolve(line.trim()); lines.close(); });
    lines.once('close', () => { clearTimeout(timeout); reject(new Error('Peer manifest input closed')); });
  });
  const manifest = strictJson(await readFile(resolve(manifestPath))) as Record<string, unknown>;
  assert.equal(manifest.origin, companyOrigin); assert.equal(manifest.client_id, metadata.client_id); assert.equal(manifest.callback_forward, callbackForward); assert.equal(manifest.callback_uri, redirectUri);
  if (typeof manifest.completion_file === 'string') { completionPath = resolve(manifest.completion_file); assert.equal(dirname(completionPath), dirname(resolve(manifestPath))); }
  assert.equal(manifest.identity_key, undefined, 'Native component must not receive an Agent private key');
  const transport = new SafeHttpsTransport({ ca: await readFile(String(manifest.ca)), privateOrigins: [companyOrigin, publicationOrigin], portOverrides: { [companyOrigin]: Number(manifest.tls_port) }, lookup: async () => [{ address: '127.0.0.1', family: 4 }] });
  const actualMetadata = await transport.request(String(metadata.client_id)); const actualJwks = await transport.request(String(metadata.jwks_uri));
  assert.equal(actualMetadata.status, 200); assert.equal(actualJwks.status, 200);
  assert(Buffer.from(actualMetadata.body).equals(Buffer.from(fixture.publicMaterials.metadata)), 'Publisher metadata bytes differ from C confirmation');
  assert(Buffer.from(actualJwks.body).equals(Buffer.from(fixture.publicMaterials.jwks)), 'Publisher JWKS bytes differ from C confirmation');
  const metadataSha256 = createHash('sha256').update(actualMetadata.body).digest('hex'); const jwksSha256 = createHash('sha256').update(actualJwks.body).digest('hex');
  let tokenRequests = 0; let revocationRequests = 0;
  const observed: HttpTransport = { request: async (url, options) => { if (url.endsWith('/api/pap03/oauth/token')) { tokenRequests++; assert(!options?.headers?.['poppy-session']); const form = new URLSearchParams(options?.body); for (const field of ['sid','session_id','sub','agent_id']) assert(!form.has(field)); } if (url.endsWith('/api/pap03/oauth/revoke')) revocationRequests++; return transport.request(url, options); } };
  const binding: Binding = { identityRef: fixture.reference, ownerRef: 'native-account-component', clientId: String(metadata.client_id) };
  const options = { stateRoot: join(root, 'pap'), binding, callbackHandoff: new DeviceCallbackHandoff(fixture.callbackManagement), secretStore: { getEncryptionKey: async () => master, getOrCreateEncryptionKey: async () => master } };
  engine = new PapClient({ ...options, identityHost: new ProtocolIdentityHost(fixture.client, fixture.policyRef) }, observed);
  stage = 'discovery';
  const company = await engine.resolvePapCompany(new URL(companyOrigin).host); const subject = await engine.getOrCreatePapUser(company.companyRef); const signedOut = await engine.openPapSession(subject.subjectRef);
  assert.equal((await engine.dispatchPap(signedOut.sessionRef, { url: companyOrigin + '/api/pap03/session' })).status, 200); assert.equal(tokenRequests, 0);
  const userRequest = async (path: string, body: object, headers: Record<string, string> = {}) => {
    const response = await transport.request(companyOrigin + path, { method: 'POST', headers: { 'content-type': 'application/json', origin: companyOrigin, ...headers }, body: JSON.stringify(body) });
    assert.equal(response.status, 200, 'Isolated browser component request failed'); return parseJson(response);
  };
  stage = 'direct_sign_in';
  const login = await engine.startSignIn(subject.subjectRef, { scopes: ['profile:read'], resource: companyOrigin + '/api/pap03', redirectUri, callbackMode: 'handoff' });
  const challenge = await userRequest('/v1/personal/otp/request', { channel: 'email', target: 'mvp1@example.test', purpose: 'signin' });
  const person = await userRequest('/v1/personal/otp/verify', { challenge_id: challenge.challenge_id, code: '246810' });
  const consent = await transport.request(login.authorizationUrl); assert.equal(consent.status, 200);
  const match = new TextDecoder('utf-8', { fatal: true }).decode(consent.body).match(/const page=(.*?);let challenge/); assert(match);
  const page = strictJson(Buffer.from(match[1]!)) as { id: string; csrf: string };
  const approved = await userRequest('/api/pap03/oauth/approve/' + page.id, { csrf: page.csrf, approve: true }, { authorization: 'Bearer ' + person.access_token, ...(consent.headers['set-cookie'] ? { cookie: consent.headers['set-cookie'].split(';')[0]! } : {}) });
  const redirect = new URL(String(approved.redirect)); assert.equal(redirect.origin + redirect.pathname, redirectUri);
  stage = 'actual_https_callback_delivery';
  const delivered = await transport.request(redirect.href); assert.equal(delivered.status, 200); assert.equal(parseJson(delivered).state, 'received'); assert.equal(receivedCallbacks, 1);
  stage = 'original_device_collect_and_pkce';
  const grant = await engine.collectSignIn(login.transactionRef); assert.equal(tokenRequests, 1);
  await assert.rejects(engine.collectSignIn(login.transactionRef), error => error instanceof PapError && error.code === 'invalid_authorization_response');
  stage = 'account_and_restart';
  const accountSession = await engine.openPapSession(subject.subjectRef, grant.accountSlot);
  const accountOperation = { url: companyOrigin + '/api/pap03/account', scopes: ['profile:read'] };
  assert.equal(parseJson(await engine.dispatchPap(accountSession.sessionRef, accountOperation)).account_id, person.user_id);
  engine.close(); engine = new PapClient({ ...options, identityHost: new ProtocolIdentityHost(fixture.client, fixture.policyRef) }, observed); await engine.recover();
  assert.equal(parseJson(await engine.dispatchPap(accountSession.sessionRef, accountOperation)).account_id, person.user_id);
  await engine.rotateDelegation(subject.subjectRef); assert.equal(parseJson(await engine.dispatchPap(accountSession.sessionRef, accountOperation)).account_id, person.user_id); assert.equal(tokenRequests, 1);
  stage = 'refresh_and_revoke';
  await engine.refreshAccountGrant(grant.grantRef); assert.equal(tokenRequests, 2); assert.equal(parseJson(await engine.dispatchPap(accountSession.sessionRef, accountOperation)).account_id, person.user_id);
  assert.equal((await engine.signOutAccount(subject.subjectRef, grant.accountSlot)).status, 'signed_out'); assert.equal(revocationRequests, 1);
  assert.equal((await engine.dispatchPap(accountSession.sessionRef, { url: companyOrigin + '/api/pap03/session' })).status, 200);
  assert.equal(createHash('sha256').update(await readFile(fixturePath)).digest('hex'), helperSha256, 'Managed helper changed during run'); assert.equal(createHash('sha256').update(await readFile(bridgePath)).digest('hex'), bridgeSha256, 'B bridge changed during run');
  if (completionPath) { await writeFile(completionPath, 'done\n', { mode: 0o600 }); completionSent = true; }
  console.log(JSON.stringify({ passed: true, lane: 'F-C-A-B-fixed-HTTPS-relay-G-same-native-account', nativeSha256, metadataSha256, jwksSha256, companyBinarySha256: manifest.binary_sha256, custody: 'real-C-context-A-native-only', publication: 'real-approved-E1-C-B-PAP-v2', secretStore: 'isolated-test-master', directPkceStateIssuer: true, defaultHttpsRelay: true, actualBCallbackHandler: true, originalDeviceCollected: true, proxyStoresCode: false, callbackForwarded: forwardedCallbacks, callbackReceived: receivedCallbacks, helperSha256, bridgeSha256, dpopRestoredAfterRestart: true, delegationRotated: true, tokenRequests, refresh: true, revoked: true, signedOutContinued: true }));
} catch (error) {
  console.error(JSON.stringify({ passed: false, stage, errorCode: error instanceof PapError ? error.code : 'component_failed' })); process.exitCode = 1;
} finally {
  if (completionPath && !completionSent) await writeFile(completionPath, 'failed\n', { mode: 0o600 }).catch(() => {});
  engine?.close(); await new Promise<void>((resolve, reject) => loopback.close(error => error ? reject(error) : resolve())); await fixture?.dispose(); master.fill(0); await rm(root, { recursive: true, force: true }); if (materialsCreated) await rm(materialsPath, { force: true });
}
