import test from 'node:test';
import assert from 'node:assert/strict';
import { Context } from '@deepseek-ai/cordis';
import { z } from 'zod';
import { apply } from '../src/tools.js';
import { operationRequestSchema } from '../src/product-api.js';

async function fixture() {
  const ctx = new Context();
  const tools = new Map<string, any>();
  const calls: unknown[] = [];
  ctx.provide('pap', { acquireTools() { return {
    status: async () => ({ ok: true, value: {} }),
    operations: async () => ({ ok: true, value: [] }),
    request: async (input: unknown) => { calls.push(input); return { ok: true, value: {} }; },
  }; } });
  ctx.provide('tools', { register(definition: any) { tools.set(definition.name, definition); } });
  apply(ctx);
  return { ctx, tool: tools.get('pap_request'), calls };
}

test('PAP tool path/query JSON schemas match the strict backend string records', async () => {
  const f = await fixture();
  try {
    const backend = z.toJSONSchema(operationRequestSchema);
    for (const key of ['path', 'query'] as const) {
      const advertised = f.tool.parameters.properties[key];
      assert.equal(advertised.type, 'object');
      assert.equal(advertised.additionalProperties.type, 'string');
      const expected = backend.properties?.[key];
      assert(expected && typeof expected === 'object');
      assert.deepEqual(advertised.additionalProperties, expected.additionalProperties);
    }
    assert.equal(f.tool.parameters.additionalProperties, false);
    assert.deepEqual(f.tool.parameters.properties.body, {});
    assert(f.tool.description.includes('query: {page: "1"}'));
    assert(f.tool.parameters.properties.query.description.includes('not page: 1'));
  } finally { await f.ctx.fiber.dispose(); }
});

test('PAP pagination keeps string values and preserves JSON body types without coercion', async () => {
  const f = await fixture();
  try {
    const input = { operationRef: 'operation-reference', path: { version: '1.2' }, query: { page: '1' }, body: { count: 1, enabled: true } };
    assert.deepEqual(operationRequestSchema.parse(input), input);
    await f.tool.execute(input, { agent: {}, signal: new AbortController().signal });
    assert.deepEqual(f.calls, [input]);
    for (const value of [1, true, null, { page: 1 }, ['1']]) {
      assert.equal(operationRequestSchema.safeParse({ operationRef: 'operation-reference', query: { page: value } }).success, false);
      assert.equal(operationRequestSchema.safeParse({ operationRef: 'operation-reference', path: { version: value } }).success, false);
    }
    assert.equal(operationRequestSchema.safeParse({ operationRef: 'operation-reference', query: { page: 'x'.repeat(4097) } }).success, false);
    assert.equal(operationRequestSchema.safeParse({ operationRef: 'operation-reference', path: { version: 'x'.repeat(1025) } }).success, false);
  } finally { await f.ctx.fiber.dispose(); }
});
