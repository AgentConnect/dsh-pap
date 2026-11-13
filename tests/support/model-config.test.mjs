import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, writeFile, chmod, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadModelSettings } from './config.mjs';

async function fixture(run) {
  const root = await mkdtemp(join(tmpdir(), 'dsh-model-config-test-'));
  const path = join(root, 'model.env'), previous = process.env.AWIKI_DEEPSEEK_CONFIG_FILE;
  try {
    process.env.AWIKI_DEEPSEEK_CONFIG_FILE = path;
    await writeFile(path, 'AMATCH_CHAT_BASE_URL=https://api.deepseek.com\nAMATCH_CHAT_MODEL=deepseek-v4-flash\nDEEPSEEK_API_KEY=synthetic-ignored-secret\n', { mode: 0o600 });
    await run(path);
  } finally {
    if (previous === undefined) delete process.env.AWIKI_DEEPSEEK_CONFIG_FILE;
    else process.env.AWIKI_DEEPSEEK_CONFIG_FILE = previous;
    await rm(root, { recursive: true });
  }
}
test('model settings reuse only the configured model and Messages origin', () => fixture(async () => {
  assert.deepEqual(await loadModelSettings(), { model: 'deepseek-v4-flash', baseURL: 'https://api.deepseek.com/anthropic' });
}));
test('model settings refuse exposed files and alternate credential destinations', () => fixture(async path => {
  await chmod(path, 0o644);
  await assert.rejects(loadModelSettings(), { code: 'acceptance_model_config_insecure' });
  await chmod(path, 0o600);
  await writeFile(path, 'AMATCH_CHAT_BASE_URL=https://foreign.example\nAMATCH_CHAT_MODEL=deepseek-v4-flash\n');
  await assert.rejects(loadModelSettings(), { code: 'acceptance_model_config_unsupported' });
}));
