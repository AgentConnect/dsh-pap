import assert from 'node:assert/strict';
import { test } from 'node:test';
import { validatePostRequest, postOperator } from './post-operator.mjs';

const id = '12345678-1234-1234-1234-123456789abc';
const scope = { action: 'cleanup', id, protocol: 'anp',
  subject: 'did:wba:awiki.me:awiki:user:owned:e1_test', marker: 'dsh-anp-acceptance-' + id };
test('post cleanup accepts only a complete exact owned ANP or PAP scope', () => {
  assert.doesNotThrow(() => validatePostRequest(scope));
  const { id: _id, ...locate } = scope;
  assert.doesNotThrow(() => validatePostRequest({ ...locate, action: 'locate' }));
  assert.doesNotThrow(() => validatePostRequest({ ...scope, protocol: 'pap',
    marker: 'dsh-pap-acceptance-' + id, subject: 'https://awiki.me/awiki/user/owned/client.json' }));
  for (const change of [{ id: "' OR true--" }, { subject: 'did:wba:awiki.info:foreign' },
    { marker: 'arbitrary public post' }, { protocol: 'mcp' }, { action: 'delete-all' },
    { phone: '+12025550123' }]) {
    assert.throws(() => validatePostRequest({ ...scope, ...change }), { code: 'acceptance_invalid_post_scope' });
  }
});
test('PAP cleanup rejects foreign origins, credentials and query selectors', () => {
  for (const subject of ['https://awiki.me.evil.test/id', 'https://user:pass@awiki.me/id',
    'https://awiki.me/id?token=x', 'https://awiki.me/id#fragment', 'http://awiki.me/id', 'https://awiki.me/']) {
    assert.throws(() => validatePostRequest({ ...scope, protocol: 'pap',
      marker: 'dsh-pap-acceptance-' + id, subject }), { code: 'acceptance_invalid_post_scope' });
  }
});
test('post preflight has no selectors and invalid input fails before SSH', async () => {
  assert.doesNotThrow(() => validatePostRequest({ action: 'preflight' }));
  assert.throws(() => validatePostRequest({ action: 'preflight', id }), { code: 'acceptance_invalid_post_scope' });
  await assert.rejects(postOperator({ ...scope, id: 'bad' }), { code: 'acceptance_invalid_post_scope' });
  await assert.rejects(postOperator({ action: 'preflight' }, { host: '-oProxyCommand=unsafe' }), { code: 'acceptance_invalid_ssh_host' });
});
