import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRuntime } from '../support/runtime.mjs';

test('PAP-S01 the installed disabled PAP client has no identity or business session', { timeout: 180000 }, async t => {
  const runtime = await createRuntime({ subjectEnabled: false });
  try {
    await runtime.start();
    const installation = runtime.evidence.installation;
    assert.equal(installation.subject.version, runtime.evidence.candidateVersion);
    assert.equal(installation.identity.version, runtime.evidence.identityVersion);
    assert.equal(installation.platform, process.platform);
    assert.equal(installation.arch, process.arch);
    assert.match(installation.subject.tarballSha256, /^[a-f0-9]{64}$/u);
    assert.match(installation.native.sha256, /^[a-f0-9]{64}$/u);
    assert.equal(installation.native.version, installation.native.wrapperVersion);
    assert.ok(installation.native.path.startsWith(runtime.profile + '/node_modules/'));
    t.diagnostic(JSON.stringify(installation));
    assert.ok((await runtime.rpc('tools')).includes('pap_status'));
    const result = await runtime.rpc('tool', { name: 'pap_status', arguments: {} });
    assert.equal(result.isError, false);
    assert.deepEqual(result.value, { ok: true, value: { state: 'disabled' } });
    assert.deepEqual(await runtime.rpc('manager/listIdentities'), []);
  } finally { await runtime.dispose(); }
});
