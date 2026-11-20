import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { orderPdf } from '../src/product-operations.js';
import type { Route } from '../src/types.js';

test('only a verified order file returns bytes and the digest to the business UI', () => {
  const origin = 'https://store.example';
  const route: Route = { method: 'GET', resource: origin, operationId: 'commerce.orders.file',
    template: origin + '/commerce/v1/stores/{store_id}/orders/{order_id}/lines/{line_id}/files/{sha256}' };
  const body = Buffer.from('%PDF-1.7\norder fixture\n%%EOF');
  const sha256 = createHash('sha256').update(body).digest('hex');
  const headers = { 'content-type': 'application/pdf', 'x-frontvia-sha256': sha256, 'set-cookie': 'private-cookie' };
  const response = { status: 200, body, headers, url: origin };
  assert.deepEqual(orderPdf(response, route, {sha256}, []), {status: 200, body: {bytes_base64: body.toString('base64'), sha256}});
  assert.throws(() => orderPdf(response, {...route, template: origin + '/other/{sha256}'}, {sha256}, []));
  assert.throws(() => orderPdf({...response, status: 403}, route, {sha256}, []));
  assert.throws(() => orderPdf(response, route, {sha256: '0'.repeat(64)}, []));
  assert.throws(() => orderPdf({...response, body: Buffer.from('%PDF-changed')}, route, {sha256}, []));
  assert.throws(() => orderPdf(response, route, {sha256}, ['order fixture']));
});
