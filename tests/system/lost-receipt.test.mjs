import assert from 'node:assert/strict';
import { test } from 'node:test';
import { withPublishedIdentity } from '../support/published-identity.mjs';
import { operations, request, ownedPost } from '../support/protocol-tools.mjs';
import { postOperator } from '../support/post-operator.mjs';

test('PAP-S12 committed write with an injected lost receipt is queried, never replayed, and cleaned exactly', { timeout: 240000 }, () =>
  withPublishedIdentity('e1', async (runtime, published) => {
    const catalog = await operations(runtime);
    const create = catalog.find(operation => operation.operationId === 'post_create');
    await ownedPost(runtime, published, async (scope, decide) => {
      await runtime.rpc('network/reset');
      await runtime.rpc('fault/lost-receipt');
      const outcome = await decide('approve', () => runtime.rpc('tool', { name: 'pap_request',
        arguments: { operationRef: create.operationRef, body: { content: scope.marker } } }));
      assert.equal((await runtime.rpc('fault/receipt-status')).applied, true);
      assert.equal(outcome.value.ok, true);
      assert.equal(outcome.value.value.status, 200);
      assert.equal(outcome.value.value.bodyAvailable, false);
      const audit = await runtime.rpc('network/status');
      assert.equal(audit.postWrites, 1);
      assert.equal(audit.postResponses, 1);
      const committed = await postOperator({ action: 'locate', ...scope });
      assert.equal(committed.ids.length, 1);
      const list = await request(runtime, catalog.find(operation => operation.operationId === 'post_list'));
      assert.equal(list.posts.filter(post => post.id === committed.ids[0] && post.content === scope.marker).length, 1);
      assert.equal((await runtime.rpc('network/status')).postWrites, 1);
    });
  }));
