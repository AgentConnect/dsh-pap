import test from 'node:test';
import assert from 'node:assert/strict';
import { CredentialHistory } from '../src/credential-history.js';
import { PapError } from '../src/errors.js';

test('S15 credential history uses monotonic known lifetime and never shortens a prior observation', () => {
  let now = 0; const history = new CredentialHistory(() => now);
  history.observe({ accessToken:'first-test-credential', accessExpiresInMs:1000 }); now = 500;
  history.observe({ accessToken:'first-test-credential', accessExpiresInMs:100 }); now = 900;
  assert(history.values().includes('first-test-credential')); now = 1001; assert.deepEqual(history.values(),[]);
});
test('S15 in-flight pin retains an expired credential until the final possible response completes', () => {
  let now = 0; const history = new CredentialHistory(() => now);
  history.observe({ accessToken:'pinned-test-credential', accessExpiresInMs:10 }); const pin = history.begin(); now = 100;
  assert(history.values().includes('pinned-test-credential')); history.end(pin); assert.deepEqual(history.values(),[]);
});
test('S15 credentials first seen during another in-flight call are also pinned for its late response', () => {
  let now = 0; const history = new CredentialHistory(() => now); const pin = history.begin();
  history.observe({ accessToken:'new-test-credential', accessExpiresInMs:10 }); now = 100;
  assert(history.values().includes('new-test-credential')); history.end(pin); assert.deepEqual(history.values(),[]);
});
test('S15 refresh and unknown-lifetime credentials are not assigned a guessed expiry', () => {
  let now = 0; const history = new CredentialHistory(() => now);
  history.observe({ accessToken:'unknown-test-credential', refreshToken:'refresh-test-credential' }); now = 1e12;
  assert.equal(history.values().length,2); history.dispose(); assert.throws(() => history.values(),PapError);
});
test('S15 exhausted entry or byte budget latches output closed instead of evicting a live credential', () => {
  for (const history of [new CredentialHistory(() => 0,1,1024),new CredentialHistory(() => 0,100,40)]) {
    history.observe({ accessToken:'first-test-credential' }); const pin = history.begin();
    history.observe({ accessToken:'second-test-credential' }); assert.throws(() => history.values(),error => error instanceof PapError && error.code === 'credential_unavailable');
    history.end(pin); assert.throws(() => history.begin(),PapError);
  }
});
