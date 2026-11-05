/** F handoff -> C exact-device Host driver -> B production ASGI/MySQL callback component. */
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { DeviceCallbackHandoff, type DeviceManagementOperations } from '../src/callback-handoff.js';

interface ManagedCallbackFixture {
  callbackManagement: DeviceManagementOperations; clientId: string; origin: string;
  fetch: typeof fetch; dispose(): Promise<void>;
}
const [fixtureArgument, source, python] = process.argv.slice(2);
assert(fixtureArgument && source && python, 'C fixture, B source and Python executable are required');
let fixture: ManagedCallbackFixture | undefined; let stage = 'real_registration_and_publication';
const codeIs = (...codes: string[]) => (error: unknown) => Boolean(error && typeof error === 'object' && codes.includes(String((error as { code?: string }).code)));
try {
  const fixturePath = resolve(fixtureArgument);
  const nativeSha256 = createHash('sha256').update(await readFile(resolve(dirname(fixturePath), '../../../../bindings/node/anp-identity.linux-x64-gnu.node'))).digest('hex');
  assert.equal(nativeSha256, 'e2c4b86a0b3622aaefa70b44d3dc31cdab579b1237a4418d349bd294c52663ef');
  const { createManagedCallbackFixture } = await import(pathToFileURL(fixturePath).href);
  fixture = await createManagedCallbackFixture({ source: resolve(source), python: resolve(python), profile: 'e1' }) as ManagedCallbackFixture;
  const handoff = new DeviceCallbackHandoff(fixture.callbackManagement);
  const redirectUri = fixture.origin + '/user-service/v1/pap-callback'; const issuer = 'https://company.example';
  const transactionId = 'callback_' + randomBytes(24).toString('base64url'); const state = randomBytes(32).toString('base64url'); const syntheticCode = randomBytes(32).toString('base64url');
  stage = 'register_and_not_ready';
  const registered = await handoff.register({ transactionId, clientId: fixture.clientId, issuer, redirectUri, state, expiresAt: Date.now() + 300000 });
  await assert.rejects(handoff.collect(registered.callbackRef), codeIs('callback_not_ready'));
  const stolenStateReference = { ...JSON.parse(registered.callbackRef), claimSecret: state };
  await assert.rejects(handoff.collect(JSON.stringify(stolenStateReference)), codeIs('permission_denied'));
  stage = 'public_callback';
  const callback = new URL(redirectUri); callback.searchParams.set('state', state); callback.searchParams.set('iss', issuer); callback.searchParams.set('code', syntheticCode);
  const wrongIssuer = new URL(callback); wrongIssuer.searchParams.set('iss', 'https://different-company.example');
  assert.equal((await fixture.fetch(new Request(wrongIssuer, { redirect: 'manual' }))).status, 400);
  const received = await fixture.fetch(new Request(callback, { redirect: 'manual' })); assert.equal(received.status, 200); assert.equal(received.headers.get('cache-control'), 'no-store'); assert.equal(received.headers.get('referrer-policy'), 'no-referrer');
  stage = 'original_device_claim';
  const response = await handoff.collect(registered.callbackRef); assert.equal(response.code, syntheticCode); assert.equal(response.state, state); assert.equal(response.iss, issuer); assert.equal(response.error, undefined);
  await assert.rejects(handoff.collect(registered.callbackRef), codeIs('callback_claimed'));
  stage = 'oauth_denial_callback';
  const denialId = 'denial_' + randomBytes(24).toString('base64url'); const denialState = randomBytes(32).toString('base64url');
  const denial = await handoff.register({ transactionId: denialId, clientId: fixture.clientId, issuer, redirectUri, state: denialState, expiresAt: Date.now() + 300000 });
  const denied = new URL(redirectUri); denied.searchParams.set('state', denialState); denied.searchParams.set('iss', issuer); denied.searchParams.set('error', 'access_denied');
  assert.equal((await fixture.fetch(new Request(denied, { redirect: 'manual' }))).status, 200);
  const denialResponse = await handoff.collect(denial.callbackRef); assert.equal(denialResponse.error, 'access_denied'); assert.equal(denialResponse.state, denialState); assert.equal(denialResponse.iss, issuer); assert.equal(denialResponse.code, undefined);
  console.log(JSON.stringify({ passed: true, lane: 'F-handoff-C-exact-device-B-ASGI-MySQL', nativeSha256, nativeDeviceProof: true, registration: 'real-approved-E1-register-ready-admin', publication: 'real-C-B-PAP-v2', callback: 'fixed-HTTPS-relay', notReadyRejected: true, stateCannotClaim: true, issuerMismatchRejected: true, originalDeviceClaimed: true, duplicateClaimRejected: true, accessDeniedIssuerStatePreserved: true, accountOAuth: 'not-run', secretStore: 'isolated-component-master' }));
} catch (error) {
  console.error(JSON.stringify({ passed: false, stage, errorCode: typeof (error as { code?: unknown })?.code === 'string' ? (error as { code: string }).code : 'component_failed' })); process.exitCode = 1;
} finally { await fixture?.dispose(); }
