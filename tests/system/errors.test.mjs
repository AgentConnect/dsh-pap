import assert from 'node:assert/strict';
import { test } from 'node:test';
import { withPublishedIdentity } from '../support/published-identity.mjs';
import { operations, request, ownedPost } from '../support/protocol-tools.mjs';
import { postOperator } from '../support/post-operator.mjs';

test('PAP-S11 injected Session and rate errors retain codes and Retry-After without replaying writes', { timeout: 300000 }, () =>
  withPublishedIdentity('e1', async (runtime, published) => {
    const catalog = await operations(runtime);
    const read = catalog.find(operation => operation.operationId === 'protocol_list');
    const create = catalog.find(operation => operation.operationId === 'post_create');
    await runtime.rpc('network/reset');
    await runtime.rpc('fault/pap-response', 'invalid_session');
    const invalid = await runtime.rpc('tool', { name: 'pap_request', arguments: { operationRef: read.operationRef } });
    assert.equal((await runtime.rpc('fault/pap-response-status')).applied, true);
    assert.equal(invalid.value.ok, false);
    assert.equal(invalid.value.error.code, 'invalid_session');
    assert.equal((await runtime.rpc('network/status')).businessRequests, 1);
    assert.ok((await request(runtime, read)).versions.length > 0);
    for (const kind of ['rate_limited', 'session_ended']) {
      await runtime.rpc('network/reset');
      await ownedPost(runtime, published, async (scope, decide) => {
        await runtime.rpc('fault/pap-response', kind);
        const error = await decide('approve', () => runtime.rpc('tool', { name: 'pap_request',
          arguments: { operationRef: create.operationRef, body: { content: scope.marker } } }));
        assert.equal((await runtime.rpc('fault/pap-response-status')).applied, true);
        assert.equal(error.value.ok, false);
        assert.equal(error.value.error.code, kind);
        if (kind === 'rate_limited') {
          const seconds = Number(error.value.error.retryAfterSeconds);
          assert.ok(seconds > 0 && seconds <= 5);
          // A real server deadline, never a mocked clock. Do not retry the POST.
          await new Promise(resolve => setTimeout(resolve, 5200));
        }
        const audit = await runtime.rpc('network/status');
        assert.equal(audit.postWrites, 1); assert.equal(audit.postResponses, 1);
        assert.equal((await postOperator({ action: 'locate', ...scope })).ids.length, 1);
        assert.ok((await request(runtime, read)).versions.length > 0);
        assert.equal((await runtime.rpc('network/status')).postWrites, 1);
      });
    }
  }));
