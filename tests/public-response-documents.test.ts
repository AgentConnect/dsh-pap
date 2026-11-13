import test from 'node:test';
import assert from 'node:assert/strict';
import { publicResponse } from '../src/product-operations.js';
import type { HttpResponse } from '../src/types.js';

const response = (body: unknown): HttpResponse => ({ status: 200,
  url: 'https://agent.agent-network-protocol.com/pap/api/protocols/1.2/did-authentication',
  headers: { 'content-type': 'application/json' }, body: Buffer.from(JSON.stringify(body)) });

test('protocol documentation preserves explicit angle-bracket authorization placeholders', () => {
  const content = '# Authentication\n\n```http\nAuthorization: Bearer <access_token>\n```\n\nAuthorization: DPoP <bound_token>\n';
  const document = { version: '1.2', language: 'zh', document: 'did-authentication', content };
  assert.deepEqual(publicResponse(response(document)), { status: 200, body: document });
});

test('documentation placeholders never exempt known credentials or private field names', () => {
  const content = 'Authorization: Bearer <access_token>';
  assert.deepEqual(publicResponse(response({ content }), ['<access_token>']),
    { status: 200, body: { content: '[redacted]' } });
  assert.deepEqual(publicResponse(response({ authorization: content, access_token: '<access_token>' })),
    { status: 200, body: { authorization: '[redacted]', access_token: '[redacted]' } });
});

test('ordinary bearer values, DPoP values and complete compact assertions stay redacted', () => {
  for (const content of ['Authorization: Bearer real-fixture-token', 'Authorization: DPoP real-fixture-token',
    'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.c2lnbmF0dXJl']) {
    assert.deepEqual(publicResponse(response({ content })), { status: 200, body: { content: '[redacted]' } });
  }
});
