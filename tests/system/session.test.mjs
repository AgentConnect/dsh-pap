import assert from 'node:assert/strict';
import { test } from 'node:test';
import { withPublishedIdentity } from '../support/published-identity.mjs';

test('PAP-S03 a published awiki.me identity establishes a real signed-out Session', { timeout: 240000 }, () =>
  withPublishedIdentity('e1', async runtime => {
    const connected = await runtime.rpc('tool', { name: 'pap_connect', arguments: { domain: 'agent-network-protocol.com' } });
    assert.equal(connected.isError, false);
    assert.equal(connected.value.ok, true, connected.value.error?.code);
    const status = await runtime.rpc('tool', { name: 'pap_status', arguments: {} });
    assert.equal(status.isError, false);
    assert.equal(status.value.ok, true);
    assert.equal(status.value.value.state, 'ready');
    assert.ok(status.value.value.sessions.some(session => session.connected && !session.account));
    assert.deepEqual(status.value.value.accounts, []);
    const operations = await runtime.rpc('tool', { name: 'pap_operations', arguments: {} });
    assert.equal(operations.value.ok, true);
    assert.ok(operations.value.value.length > 0);
    const read = operations.value.value.find(operation => operation.operationId === 'protocol_list');
    assert.ok(read);
    const response = await runtime.rpc('tool', { name: 'pap_request', arguments: { operationRef: read.operationRef } });
    assert.equal(response.isError, false);
    assert.equal(response.value.ok, true, response.value.error?.code);
    assert.equal(response.value.value.status, 200);
    const proof = (await runtime.rpc('delegation/status'))[0];
    assert.ok(proof, 'No metadata from the actual outgoing delegation was observed');
    assert.equal(proof.expires - proof.issued, 3600);
    assert.equal(typeof proof.publicThumbprint, 'string');
  }));
