import assert from 'node:assert/strict';
import { test } from 'node:test';
import { withPublishedIdentity } from '../support/published-identity.mjs';
import { operations, request, tool } from '../support/protocol-tools.mjs';

test('PAP-S07 real one-hour delegation expiry rotates the key and rejects the old proof', { timeout: 3900000 }, () =>
  withPublishedIdentity('e1', async runtime => {
    const catalog = await operations(runtime);
    assert.ok((await request(runtime, catalog.find(operation => operation.operationId === 'protocol_list'))).versions.length > 0);
    const first = (await runtime.rpc('delegation/status'))[0];
    assert.ok(first, 'The actual outgoing signed proof was not observed');
    assert.equal(first.expires - first.issued, 3600);
    console.log('PAP-S07 waiting for actual delegation expiry at ' + new Date(first.expires * 1000).toISOString());
    const session = (await tool(runtime, 'pap_status')).sessions.find(session => session.connected && !session.account);
    assert.ok(session);
    // Use real wall time. Periodic RPCs also verify that this exact Host remains live.
    while (Date.now() <= first.expires * 1000 + 6000) {
      await new Promise(resolve => setTimeout(resolve, Math.min(30000, first.expires * 1000 + 6001 - Date.now())));
      assert.notEqual((await runtime.rpc('health')).status, 'unavailable');
    }
    assert.ok([400, 401].includes((await runtime.rpc('delegation/replay-original-read')).status));
    const refreshed = await operations(runtime);
    assert.ok((await request(runtime, refreshed.find(operation => operation.operationId === 'protocol_list'))).versions.length > 0);
    const last = (await runtime.rpc('delegation/status')).at(-1);
    assert.ok(last.issued >= first.expires);
    assert.ok(last.expires > first.expires);
    assert.notEqual(last.publicThumbprint, first.publicThumbprint);
    assert.ok((await tool(runtime, 'pap_status')).sessions.some(value => value.sessionRef === session.sessionRef && value.connected));
  }));
