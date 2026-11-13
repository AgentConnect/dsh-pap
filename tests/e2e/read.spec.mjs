import assert from 'node:assert/strict';
import { test } from 'node:test';
import { withPublishedIdentity } from '../support/published-identity.mjs';
import { protocolDocument } from '../support/protocol-document.mjs';
import { createHash } from 'node:crypto';

test('PAP-E01 real DSH DeepSeek connects and reads the live protocol catalog', { timeout: 300000 }, () =>
  withPublishedIdentity('e1', async runtime => {
    const result = await runtime.rpc('model/task', { task:
      '通过 PAP 访问 agent-network-protocol.com，连接并读取网站真实返回的协议文档目录，用中文列出支持的协议版本和返回数据的语言。请只读，不发布内容。' }, { timeoutMs: 180000 });
    assert.equal(result.model, runtime.evidence.model);
    for (const name of ['pap_connect', 'pap_request'])
      assert.ok(result.calls.some(call => call.name === name && !call.isError && call.value?.ok === true), 'Missing successful actual model call: ' + name);
    const catalog = result.calls.filter(call => call.name === 'pap_request').map(call => call.value?.value?.body)
      .find(content => Array.isArray(content?.versions) && Array.isArray(content?.documents));
    assert.ok(catalog, 'No real catalog returned to the model');
    for (const version of catalog.versions) assert.ok(result.output.includes(version));
    assert.ok(result.output.length > 0);
  }, { realModel: true }));


test('PAP-E02 real DSH DeepSeek reads the requested Chinese protocol document', { timeout: 300000 }, () =>
  withPublishedIdentity('e1', async runtime => {
    const result = await runtime.rpc('model/task', { task:
      '通过 PAP 访问 agent-network-protocol.com，读取 ANP 1.2 版本的中文 did-authentication 文档，报告文档版本、语言，并简要说明内容。请只读。' }, { timeoutMs: 180000 });
    assert.equal(result.model, runtime.evidence.model);
    const documents = result.calls.filter(call => call.name === 'pap_request')
      .map(call => call.value?.value?.body);
    const document = documents.find(value => value?.version === '1.2' && value.language === 'zh'
      && value.document === 'did-authentication' && typeof value.content === 'string');
    assert.ok(document, 'The requested document was not returned by a real model-selected operation');
    assert.ok(document.content.length > 0);
    const expected = await protocolDocument({ version: '1.2', language: 'zh', document: 'did-authentication' });
    assert.equal(createHash('sha256').update(document.content).digest('hex'), expected.sha256);
    assert.ok(result.output.includes('1.2'));
  }, { realModel: true }));
