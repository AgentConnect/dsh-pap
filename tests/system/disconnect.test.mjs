import assert from 'node:assert/strict';
import { test } from 'node:test';
import { withPublishedIdentity } from '../support/published-identity.mjs';
import { operations, request, tool } from '../support/protocol-tools.mjs';

test('PAP-S09 explicit disconnect survives real Host restart until an explicit user reconnect', { timeout: 240000 }, () =>
  withPublishedIdentity('e1', async runtime => {
    const catalog = await operations(runtime);
    const read = catalog.find(operation => operation.operationId === 'protocol_list');
    assert.ok((await request(runtime, read)).versions.length > 0);
    assert.ok((await runtime.rpc('network/status')).businessRequests > 0);
    const status = await tool(runtime, 'pap_status');
    const session = status.sessions.find(session => session.connected && !session.account);
    assert.ok(session);
    const disconnected = await runtime.rpc('pap/manage', { action: 'session/disconnect', sessionRef: session.sessionRef });
    assert.equal(disconnected.ok, true);
    const pid = runtime.evidence.pid;
    await runtime.stop(); await runtime.start();
    assert.notEqual(runtime.evidence.pid, pid);
    await runtime.rpc('network/reset');
    const automatic = await runtime.rpc('tool', { name: 'pap_connect', arguments: { domain: 'agent-network-protocol.com' } });
    assert.equal(automatic.value.ok, false);
    assert.equal(automatic.value.error.code, 'disconnected');
    assert.equal((await runtime.rpc('network/status')).businessRequests, 0);
    const restored = await tool(runtime, 'pap_status');
    assert.ok(restored.sessions.some(value => value.sessionRef === session.sessionRef && !value.connected));
    assert.equal(restored.sessions.some(value => value.connected), false);
    const reconnected = await runtime.rpc('pap/manage', { action: 'session/connect', companyRef: restored.companies[0].companyRef });
    assert.equal(reconnected.ok, true);
    const current = await operations(runtime);
    assert.ok((await request(runtime, current.find(operation => operation.operationId === 'protocol_list'))).versions.length > 0);
    assert.ok((await runtime.rpc('network/status')).businessRequests > 0);
  }));
