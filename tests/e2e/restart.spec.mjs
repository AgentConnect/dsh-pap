import assert from 'node:assert/strict';
import { test } from 'node:test';
import { withPublishedIdentity } from '../support/published-identity.mjs';
import { withUserBrowser } from '../support/browser-actor.mjs';

const query='通过 PAP 访问 agent-network-protocol.com，实际读取协议文档目录并报告协议版本。只读，不使用其他通道或修改权限。';
const catalog=result=>result.calls.some(call=>call.name==='pap_request'&&!call.isError&&call.value?.ok===true
  &&call.value.value?.body?.versions?.length>0&&call.value.value?.body?.documents?.length>0);

test('PAP-E05 real UI disconnect persists across Host restart until user reconnects', {timeout:900000},()=>
  withPublishedIdentity('e1',async(runtime,published)=>{
    const first=await runtime.rpc('model/task',{task:query},{timeoutMs:180000});
    assert.ok(catalog(first));
    await withUserBrowser(runtime,async actor=>{
      await actor.openPapConnections();
      const disconnect=actor.page.getByRole('button',{name:'断开连接',exact:true});
      assert.equal(await actor.page.getByRole('alert').count(),0,'Connection settings reported an error');
      assert.equal(await disconnect.count(),1,'Expected one actual Session control');
      assert.equal(await disconnect.isEnabled(),true,'Session control is disabled');
      await disconnect.click();
      await actor.page.getByText(/已断开/).waitFor();
    });
    const pid=runtime.evidence.pid;await runtime.stop();await runtime.start();
    assert.notEqual(runtime.evidence.pid,pid);
    await withUserBrowser(runtime,async actor=>{
      await actor.openPapConnections();
      await actor.page.getByText(/已断开/).waitFor();
    });
    await runtime.rpc('network/reset');
    const denied=await runtime.rpc('model/resume',{sessionId:first.sessionId,task:query},{timeoutMs:180000});
    assert.equal(denied.sessionId,first.sessionId);assert.equal(catalog(denied),false);
    assert.ok(denied.calls.some(call=>call.name==='pap_connect'&&call.value?.error?.code==='disconnected'));
    assert.equal((await runtime.rpc('network/status')).businessRequests,0);
    assert.equal(denied.calls.some(call=>/^(anp_|mcp_|bash$|pwsh$|web_fetch$)/u.test(call.name)),false);
    await withUserBrowser(runtime,async actor=>{
      await actor.openPapConnections();
      await actor.page.getByRole('button',{name:'重新连接',exact:true}).click();
      await actor.page.getByText(/· 已连接/).waitFor();
    });
    const restored=await runtime.rpc('model/followup',{task:'我已在 PAP 连接页面重新连接。请再次通过 PAP 读取刚才网站的协议目录，报告实际版本。'},{timeoutMs:180000});
    assert.equal(restored.sessionId,first.sessionId);assert.ok(catalog(restored));
    assert.ok((await runtime.rpc('network/status')).businessRequests>0);
    assert.deepEqual((await runtime.rpc('manager/listIdentities')).map(x=>x.reference),[published.reference]);
  },{web:true,realModel:true}));
