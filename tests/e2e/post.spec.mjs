import assert from 'node:assert/strict';
import { test } from 'node:test';
import { withPublishedIdentity } from '../support/published-identity.mjs';
import { withUserBrowser } from '../support/browser-actor.mjs';
import { ownedPost } from '../support/protocol-tools.mjs';
import { postOperator } from '../support/post-operator.mjs';
import { createHash } from 'node:crypto';

test('PAP-E03 real model posts only after actual UI once approval and verifies its receipt', { timeout: 300000 }, () =>
  withPublishedIdentity('e1', async (runtime, published) => {
    await withUserBrowser(runtime, async actor => {
      await actor.openIdentities();
      await ownedPost(runtime, published, async scope => {
        const model = runtime.rpc('model/task', { task:
          '通过 PAP 在 agent-network-protocol.com 发布一条帖子，正文精确为：' + scope.marker
          + '。我会在界面批准本次写入。成功后请查询列表确认，再报告记录 ID。只提交一次，结果不确定时不要重发。' }, { timeoutMs: 180000 });
        model.catch(() => {});
        try {
          const allow = /^(?:允许本次操作|允许授权)$/u;
          const approval = actor.page.getByRole('dialog').filter({ has: actor.page.getByRole('button', { name: allow }) });
          const phase = await Promise.race([
            approval.waitFor({ state: 'visible', timeout: 120000 }).then(() => 'approval'),
            model.then(() => 'model_finished'),
          ]);
          assert.equal(phase, 'approval', 'The model did not reach a real user approval');
          assert.ok((await approval.innerText()).includes('agent.agent-network-protocol.com'));
          const preview = approval.locator('dl[aria-label="本次操作范围"]');
          assert.ok((await preview.getByLabel('参数摘要', { exact: true }).innerText()).includes(scope.marker));
          const bytes = JSON.stringify({ content: scope.marker });
          const hex = createHash('sha256').update(bytes).digest('hex');
          const digest = await preview.locator('code').innerText();
          assert.ok([hex, 'sha256:' + hex, 'sha256:' + createHash('sha256').update(bytes).digest('base64url')].includes(digest),
            'The UI request body digest does not match the exact requested post');
          const pending = (await runtime.rpc('manager/listRequests')).filter(request => request.kind === 'access' && request.status === 'pending');
          assert.equal(pending.length, 1);
          const requestId = pending[0].id;
          if (await approval.getByRole('button', { name: '允许本次操作', exact: true }).isVisible()) {
            assert.equal(await approval.getByRole('radio', { name: /^永久授权/u }).count(), 0);
          } else {
            await approval.getByRole('radio', { name: /^单次授权/u }).check();
          }
          await approval.getByRole('button', { name: allow }).click();
          const result = await model;
          const calls = result.calls.filter(call => call.name === 'pap_request' && call.value?.ok);
          const receipt = calls.map(call => call.value.value.body).find(value => value?.content === scope.marker && typeof value.id === 'string');
          assert.ok(receipt, 'No successful model-selected post receipt');
          assert.equal((await postOperator({ action: 'observe', ...scope, id: receipt.id })).matches, 1);
          assert.ok(calls.some(call => call.value.value.body?.posts?.some(post => post.id === receipt.id && post.content === scope.marker)));
          assert.ok(result.output.includes(receipt.id));
          const reviewed = await runtime.rpc('manager/getRequest', requestId);
          assert.equal(reviewed.request.status, 'approved');
          assert.equal(reviewed.request.mode, 'once');
          assert.equal(reviewed.grant.mode, 'once');
          assert.equal(reviewed.grant.status, 'consumed');
          assert.equal(reviewed.grant.caller.consumer, pending[0].caller.consumer);
          assert.equal((await runtime.rpc('manager/grants', published.reference)).some(grant => grant.mode === 'permanent'), false);
        } catch (error) {
          await runtime.stop();
          throw error;
        }
      });
    });
  }, { web: true, realModel: true }));
