import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { withPublishedIdentity } from '../support/published-identity.mjs';
import { operations, ownedPost } from '../support/protocol-tools.mjs';
import { postOperator } from '../support/post-operator.mjs';

test('PAP-S06 real denial, cancellation and deadline send no write and reject late approval', { timeout: 600000 }, async t => {
  for (const mode of ['deny', 'cancel', 'timeout', 'unload']) await t.test(mode, { timeout: 180000 }, () =>
    withPublishedIdentity('e1', async (runtime, published) => {
      const available = await operations(runtime);
      const write = available.find(operation => operation.operationId === 'post_create');
      assert.ok(write);
      await ownedPost(runtime, published, async scope => {
        await runtime.rpc('network/reset');
        const callId = randomUUID();
        let settled = false;
        const executing = runtime.rpc('tool', { callId, timeoutMs: mode === 'timeout' ? 5000 : 15000,
          name: 'pap_request', arguments: { operationRef: write.operationRef, body: { content: scope.marker } } })
          .finally(() => { settled = true; });
        executing.catch(() => {});
        try {
          let pending;
          const deadline = Date.now() + 4000;
          while (Date.now() < deadline && !settled) {
            pending = (await runtime.rpc('manager/listRequests')).find(request => request.kind === 'access' && request.status === 'pending');
            if (pending) break;
            await new Promise(resolve => setTimeout(resolve, 50));
          }
          assert.ok(pending, 'No real pending operation was established');
          const review = await runtime.rpc('manager/getRequest', pending.id);
          if (mode === 'deny') await runtime.rpc('manager/decide', { requestId: pending.id, expectedVersion: pending.version, decision: 'deny' });
          else if (mode === 'cancel') assert.equal((await runtime.rpc('tool/cancel', callId)).cancelled, true);
          else if (mode === 'unload') {
            const pid = runtime.evidence.pid;
            await runtime.stop();
            assert.equal(runtime.lastNetworkAudit.postWrites, 0);
            await runtime.start();
            assert.notEqual(runtime.evidence.pid, pid);
          }
          const result = await executing;
          assert.ok(result.isError === true || result.value?.ok === false);
          const final = await runtime.rpc('manager/getRequest', pending.id);
          assert.equal(final.request.status, mode === 'deny' ? 'denied' : 'cancelled');
          assert.equal(final.grant, undefined);
          await assert.rejects(runtime.rpc('manager/decide', { requestId: pending.id, expectedVersion: pending.version,
            decision: 'approve', identity: published.reference, mode: 'once', reviewedSnapshot: review.snapshot }));
          const audit = await runtime.rpc('network/status');
          assert.equal(audit.businessRequests, 0);
          t.diagnostic(JSON.stringify({ mode, callId, method: 'POST', origin: 'https://agent.agent-network-protocol.com',
            path: '/pap/api/posts', sent: audit.postWrites }));
          assert.deepEqual((await postOperator({ action: 'locate', ...scope })).ids, []);
        } catch (error) { await runtime.stop(); throw error; }
      });
    }));
  await t.test('runner-error', { timeout: 180000 }, () => withPublishedIdentity('e1', async (runtime, published) => {
    const available = await operations(runtime);
    const write = available.find(operation => operation.operationId === 'post_create');
    let pending, review, executing, selectedScope;
    const callId = randomUUID();
    await assert.rejects(ownedPost(runtime, published, async scope => {
      selectedScope = scope;
      executing = runtime.rpc('tool', { callId, name: 'pap_request', timeoutMs: 15000,
        arguments: { operationRef: write.operationRef, body: { content: scope.marker } } });
      executing.catch(() => {});
      const deadline = Date.now() + 4000;
      while (Date.now() < deadline) {
        pending = (await runtime.rpc('manager/listRequests')).find(request => request.kind === 'access' && request.status === 'pending');
        if (pending) break;
        await new Promise(resolve => setTimeout(resolve, 50));
      }
      assert.ok(pending);
      review = await runtime.rpc('manager/getRequest', pending.id);
      throw Object.assign(new Error('Acceptance actor stopped before deciding'), { code: 'acceptance_actor_failure' });
    }), { code: 'acceptance_actor_failure' });
    // The runner, not this actor, must already have stopped the Host before cleaning.
    await assert.rejects(runtime.rpc('health'), { code: 'acceptance_host_unavailable' });
    const result = await executing;
    assert.ok(result.isError === true || result.value?.ok === false);
    assert.equal(runtime.lastNetworkAudit.postWrites, 0);
    assert.equal(runtime.lastNetworkAudit.postResponses, 0);
    t.diagnostic(JSON.stringify({ mode: 'runner-error', callId, method: 'POST', origin: 'https://agent.agent-network-protocol.com',
      path: '/pap/api/posts', sent: runtime.lastNetworkAudit.postWrites }));
    await runtime.start();
    assert.equal((await runtime.rpc('manager/getRequest', pending.id)).request.status, 'cancelled');
    await assert.rejects(runtime.rpc('manager/decide', { requestId: pending.id, expectedVersion: pending.version,
      decision: 'approve', identity: published.reference, mode: 'once', reviewedSnapshot: review.snapshot }));
    assert.deepEqual((await postOperator({ action: 'locate', ...selectedScope })).ids, []);
    assert.equal((await runtime.rpc('network/status')).businessRequests, 0);
  }));
});
