import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { writeFile, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { postOperator } from './post-operator.mjs';

export async function tool(runtime, name, args = {}) {
  const result = await runtime.rpc('tool', { name, arguments: args });
  assert.equal(result.isError, false);
  assert.equal(result.value.ok, true, typeof result.value.error === 'string' ? result.value.error : result.value.error?.code);
  return result.value.value;
}
export function assertWritesSettled(before, after) {
  assert.ok(before && after && [before.postWrites, before.postResponses, after.postWrites, after.postResponses]
    .every(value => Number.isInteger(value) && value >= 0), 'Write observation is unavailable; preserve recovery input');
  const sent = after.postWrites - before.postWrites, responses = after.postResponses - before.postResponses;
  assert.ok(sent >= 0 && responses >= 0, 'Write counters changed generation; preserve recovery input');
  assert.equal(sent, responses, 'A write has no observed HTTP response; preserve recovery input');
}
export async function operations(runtime) {
  if ("pap" === 'pap') {
    await tool(runtime, 'pap_connect', { domain: 'agent-network-protocol.com' });
    return tool(runtime, 'pap_operations');
  }
  const directory = await tool(runtime, 'anp_discover', { domain: 'agent-network-protocol.com' });
  const description = await tool(runtime, 'anp_describe', { agentRef: directory.agents[0].agentRef });
  const link = description.links.find(link => link.kind === 'interface' && link.protocol === 'OpenAPI');
  assert.ok(link);
  return (await tool(runtime, 'anp_read', { resourceRef: link.resourceRef })).operations;
}
export async function request(runtime, operation, args = {}) {
  const value = await tool(runtime, "pap" === 'anp' ? 'anp_call' : 'pap_request', { operationRef: operation.operationRef, ...args });
  if ("pap" === 'pap') { assert.equal(value.status, 200); return value.body; }
  return value.content;
}
async function decidePending(runtime, decision, execute) {
  const prior = new Set((await runtime.rpc('manager/listRequests')).map(value => value.id));
  let settled = false;
  const operation = execute().finally(() => { settled = true; });
  operation.catch(() => {});
  const deadline = Date.now() + 10000;
  let pending;
  while (Date.now() < deadline && !settled) {
    pending = (await runtime.rpc('manager/listRequests')).find(value => value.kind === 'access' && value.status === 'pending' && !prior.has(value.id));
    if (pending) break;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  if (!pending) { await operation; assert.fail('The write did not request an exact user decision'); }
  const review = await runtime.rpc('manager/getRequest', pending.id);
  await runtime.rpc('manager/decide', { requestId: pending.id, expectedVersion: pending.version, decision,
    ...(decision === 'approve' ? { identity: pending.identity, mode: 'once', reviewedSnapshot: review.snapshot } : {}) });
  return operation;
}
export async function ownedPost(runtime, published, execute) {
  assert.equal((await postOperator({ action: 'preflight' })).ready, true);
  const scope = { protocol: "pap", subject: "pap" === 'anp' ? published.reference.did : published.clientId,
    marker: 'dsh-' + "pap" + '-acceptance-' + randomUUID() };
  const recovery = join(runtime.root, 'post-recovery.json');
  const quota = (await postOperator({ action: 'quota', ...scope })).count;
  const before = await runtime.rpc('network/status');
  const recoveryInput = { scope, quotaBaseline: quota, before: { postWrites: before.postWrites, postResponses: before.postResponses } };
  await writeFile(recovery, JSON.stringify(recoveryInput), { mode: 0o600, flag: 'wx' });
  let stoppedAfterFailure = true;
  try { await execute(scope, (decision, run) => decidePending(runtime, decision, run)); }
  catch (error) {
    stoppedAfterFailure = false;
    await runtime.stop();
    stoppedAfterFailure = true;
    throw error;
  }
  finally {
    let stage = 'quiesce';
    try {
      assert.ok(stoppedAfterFailure, 'Host stop is unconfirmed; preserve recovery input');
      stage = 'locate';
      const found = await postOperator({ action: 'locate', ...scope });
      assert.ok(found.ids.length <= 1);
      stage = 'write_observation';
      const after = await runtime.rpc('network/status').catch(() => runtime.lastNetworkAudit);
      await writeFile(recovery, JSON.stringify({ ...recoveryInput,
        after: after ? { postWrites: after.postWrites, postResponses: after.postResponses } : null }), { mode: 0o600 });
      assertWritesSettled(before, after);
      stage = 'delete';
      for (const id of found.ids) {
        assert.equal((await postOperator({ action: 'cleanup', ...scope, id })).cleanupComplete, true);
      }
      stage = 'verify_absent';
      assert.deepEqual((await postOperator({ action: 'locate', ...scope })).ids, []);
      stage = 'verify_quota';
      assert.equal((await postOperator({ action: 'quota', ...scope })).count, quota);
      stage = 'remove_recovery';
      await unlink(recovery);
    } catch (error) {
      runtime.businessRecoveryPending = true;
      runtime.businessRecoveryReason = stage + '_' + (/^[a-zA-Z_]{1,80}$/u.test(error.code ?? '') ? error.code : 'error');
      throw error;
    }
  }
}
