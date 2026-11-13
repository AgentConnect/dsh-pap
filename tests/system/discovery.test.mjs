import assert from 'node:assert/strict';
import { test } from 'node:test';
import { withPublishedIdentity } from '../support/published-identity.mjs';
import { operations, request, tool } from '../support/protocol-tools.mjs';

test('PAP-S02 real root-domain discovery follows anonymous metadata to the declared OpenAPI', { timeout: 360000 }, t =>
  withPublishedIdentity('e1', async runtime => {
    await runtime.rpc('network/reset');
    const found = await operations(runtime);
    assert.ok(found.some(operation => operation.operationId === 'protocol_list'));
    const { discoveryResponses } = await runtime.rpc('network/status');
    assert.ok(discoveryResponses.some(response => response.host === 'agent-network-protocol.com'
      && response.path === '/.well-known/poppy.json' && [301, 302, 303, 307, 308].includes(response.status)));
    assert.ok(discoveryResponses.some(response => response.host === 'agent.agent-network-protocol.com'
      && response.path === '/.well-known/poppy.json' && response.status === 200));
    assert.ok(discoveryResponses.some(response => response.host === 'agent.agent-network-protocol.com'
      && response.path === '/pap/openapi.json' && response.status === 200));
    assert.ok(discoveryResponses.every(response => response.credentials === false));
    for (const [kind, code, hits] of [
      ['redirect-loop', 'discovery_failed', 6],
      ['unsafe-target', 'unsafe_destination', 1],
      ['private-target', 'unsafe_destination', 1],
      ['wrong-company', 'discovery_failed', 1],
      ['oversized-document', 'discovery_failed', 1],
      ['aggregate-budget', 'discovery_failed', 5],
    ]) await t.test(kind, async () => {
      await runtime.rpc('network/reset');
      await runtime.rpc('fault/pap-discovery', kind);
      try {
        const failure = await runtime.rpc('tool', { name: 'pap_connect', timeoutMs: 40000,
          arguments: { domain: 'agent-network-protocol.com' } }, { timeoutMs: 45000 });
        assert.equal(failure.isError, false);
        assert.equal(failure.value.ok, false);
        assert.equal(failure.value.error.code, code);
        const fault = await runtime.rpc('fault/pap-discovery-status');
        assert.equal(fault.hits, hits);
        assert.equal(fault.privateTargetRequests, 0);
        if (kind === 'aggregate-budget') {
          assert.equal(fault.largestBodyBytes, 1024 * 1024 - 1);
          assert.ok(fault.totalBodyBytes > 4 * 1024 * 1024);
        }
        const audit = await runtime.rpc('network/status');
        assert.equal(audit.businessRequests, 0);
        assert.equal(audit.oauthRequests, 0);
        assert.ok(audit.discoveryResponses.length > 0);
        assert.ok(audit.discoveryResponses.every(response => response.credentials === false));
      } finally { await runtime.rpc('fault/pap-discovery', 'off'); }
    });
    // Failed rediscovery cannot poison the working Session or its public source references.
    assert.ok((await request(runtime, found.find(operation => operation.operationId === 'protocol_list'))).versions.length > 0);
  }));

test('PAP-S10 the real NoAS Company needs no account or OAuth endpoint calls', { timeout: 240000 }, () =>
  withPublishedIdentity('e1', async runtime => {
    await runtime.rpc('network/reset');
    const found = await operations(runtime);
    const status = await tool(runtime, 'pap_status');
    assert.ok(status.companies.length > 0);
    assert.ok(status.companies.every(company => company.authMode === 'no_as'));
    assert.deepEqual(status.accounts, []);
    assert.ok(status.sessions.every(session => !session.account));
    assert.ok((await request(runtime, found.find(operation => operation.operationId === 'protocol_list'))).versions.length > 0);
    const audit = await runtime.rpc('network/status');
    assert.ok(audit.businessRequests > 0);
    assert.equal(audit.oauthRequests, 0);
  }));
