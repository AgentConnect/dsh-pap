import assert from 'node:assert/strict';
import test from 'node:test';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { KeyringSecretStore } from '../src/keyring.js';
import { publicResult } from '../src/plugin.js';
import { PapStore } from '../src/store.js';

test('unsupported platforms report an unsupported backend without creating a fallback key', { skip: process.platform === 'linux' }, async t => {
  const root = await mkdtemp(join(tmpdir(), 'pap-unsupported-backend-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const store = new KeyringSecretStore('pap-platform-test', join(tmpdir(), 'pap-platform-test-locks'));
  await assert.rejects(store.getEncryptionKey('test'), { code: 'credential_backend_unsupported' });
  await assert.rejects(store.getOrCreateEncryptionKey('test'), { code: 'credential_backend_unsupported' });
  const state = new PapStore(root, store, 'test');
  assert.deepEqual(await publicResult(() => state.transaction(() => null)), {
    ok: false, error: { code: 'credential_backend_unsupported' },
  });
  assert.deepEqual(await readdir(root), []);
});
