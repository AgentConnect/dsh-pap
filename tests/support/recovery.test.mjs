import assert from 'node:assert/strict';
import { test } from 'node:test';
import { assertWritesSettled } from './protocol-tools.mjs';

test('recovery cleanup needs a response for each observed write, even after an empty DB query', () => {
  const before = { postWrites: 0, postResponses: 0 };
  assert.doesNotThrow(() => assertWritesSettled(before, before));
  assert.doesNotThrow(() => assertWritesSettled(before, { postWrites: 1, postResponses: 1 }));
  assert.throws(() => assertWritesSettled(before, { postWrites: 1, postResponses: 0 }), /preserve recovery input/u);
  assert.throws(() => assertWritesSettled(before, undefined), /preserve recovery input/u);
  assert.throws(() => assertWritesSettled({ postWrites: 2, postResponses: 2 }, before), /changed generation/u);
});
