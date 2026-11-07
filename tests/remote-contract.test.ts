import test from 'node:test';
import assert from 'node:assert/strict';
import contribution from '../src/remote.js';

test('Harness 0.2.2 Remote codecs materialize strict management parsers', () => {
  const manage = contribution.descriptors.find(item => item.method === 'manage')!;
  const input = manage.parameters[0]!.codec;
  assert.equal(input.mode, 'strict');
  if (input.mode !== 'strict') throw new Error('Expected strict management codec');
  const request = { action: 'company/discover', domain: 'pap-demo.awiki.info' };
  assert.deepEqual(input.create().parse(request), request);
  assert.throws(() => input.create().parse({ ...request, headers: { authorization: 'forbidden' } }));
  for (const descriptor of contribution.descriptors) {
    const output = descriptor.result;
    assert.equal(output.mode, 'strict');
    if (output.mode !== 'strict') throw new Error('Expected strict result codec');
    assert.deepEqual(output.create().parse({ ok: true, value: null }), { ok: true, value: null });
    assert.throws(() => output.create().parse({ ok: true, value: null, token: 'forbidden' }));
  }
});
