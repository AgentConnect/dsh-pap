import assert from 'node:assert/strict';
import { test } from 'node:test';
import { withPublishedIdentity } from '../support/published-identity.mjs';
import { operations, request } from '../support/protocol-tools.mjs';

test('PAP-S08 real proof purposes remain isolated and Session failure never falls back to ANP or Bearer', { timeout: 240000 }, () =>
  withPublishedIdentity('e1', async runtime => {
    const catalog = await operations(runtime);
    const read = catalog.find(operation => operation.operationId === 'protocol_list');
    assert.ok((await request(runtime, read)).versions.length > 0);
    const headers = await runtime.rpc('proof/header-status');
    assert.ok(headers.length > 0);
    assert.ok(headers.every(value => value.poppy && !value.bearer && !value.signature && !value.dpop));
    for (const wrong of ['bearer-on-pap', 'pap-on-anp']) {
      const rejected = await runtime.rpc('proof/wrong-protocol', wrong);
      assert.ok([400, 401, 403].includes(rejected.status));
    }
    await runtime.rpc('network/reset');
    await runtime.rpc('fault/pap-response', 'invalid_session');
    const failure = await runtime.rpc('tool', { name: 'pap_request', arguments: { operationRef: read.operationRef } });
    assert.equal(failure.value.ok, false);
    assert.equal(failure.value.error.code, 'invalid_session');
    const audit = await runtime.rpc('network/status');
    assert.equal(audit.businessRequests, 1);
    assert.equal(audit.anpBusinessRequests, 0);
    assert.equal(audit.oauthRequests, 0);
    assert.ok((await runtime.rpc('proof/header-status')).every(value => value.poppy && !value.bearer && !value.signature && !value.dpop));
  }));
