import { useState,useSyncExternalStore,type ReactNode } from 'react';
import { PapSettingsController,identityKey,type SettingsView } from './controller.js';
const stateNames:Record<string,string>={disabled:'未启用',unconfigured:'未配置身份',credential_unavailable:'受保护凭据不可用',migration_required:'旧凭据历史需要管理处理',ready:'可用',waiting:'等待 Host'};
function httpsLink(value?:string):string|undefined {try{const url=new URL(value??'');return url.protocol==='https:'&&!url.username&&!url.password&&!url.hash?url.href:undefined;}catch{return undefined;}}
const styles = `
.dsh-pap-settings{display:grid;gap:16px;max-width:960px;font:14px/1.6 system-ui,sans-serif;color:var(--dsw-alias-label-primary,inherit)}
.dsh-pap-settings h2,.dsh-pap-settings h3,.dsh-pap-settings p{margin:0}
.dsh-pap-settings h2{font-size:22px}.dsh-pap-settings h3{font-size:17px}
.dsh-pap-settings form,.dsh-pap-settings .pap-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.dsh-pap-settings input,.dsh-pap-settings select,.dsh-pap-settings button{font:inherit;box-sizing:border-box;border:1px solid var(--dsw-alias-border-l2,#8885);border-radius:8px;padding:7px 10px;color:inherit;background:var(--dsw-alias-bg-layer-2,transparent)}
.dsh-pap-settings input,.dsh-pap-settings select{max-width:100%}.dsh-pap-settings button:not(:disabled){cursor:pointer}
.dsh-pap-settings button:disabled{opacity:.5}.dsh-pap-settings select{min-width:180px}
.dsh-pap-settings article{border:1px solid var(--dsw-alias-border-l2,#8885);border-radius:12px;padding:16px;display:grid;gap:12px}
.dsh-pap-settings .pap-operation{border-top:1px solid var(--dsw-alias-border-l2,#8885);padding-top:12px;display:grid;gap:8px}
.dsh-pap-settings .pap-route{font:13px/1.7 ui-monospace,SFMono-Regular,monospace;overflow-wrap:anywhere}
.dsh-pap-settings .pap-muted{font-size:12px;color:var(--dsw-alias-label-tertiary,#888)}
.dsh-pap-settings summary{cursor:pointer;font-size:13px;user-select:none}.dsh-pap-settings details[open]>summary{margin-bottom:10px}
.dsh-pap-settings .pap-session{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:6px 0}
.dsh-pap-settings .pap-badge{font-size:12px;padding:2px 7px;border-radius:6px;background:var(--dsw-alias-bg-layer-2,#8881)}
.dsh-pap-settings [role=alert]{color:var(--dsw-alias-status-error,#c33)}
`;
export function PapSettings({controller}:{controller:PapSettingsController}):ReactNode {
  const view=useSyncExternalStore(controller.subscribe,controller.getSnapshot,controller.getSnapshot);
  const [choice,setIdentity]=useState<string|null>(null);const [domain,setDomain]=useState('');const busy=view.pending||view.loading;
  const identity=choice??(view.status.identity?identityKey(view.status.identity):'');
  const run=(input:Parameters<PapSettingsController['execute']>[0])=>{void controller.execute(input);};
  return <section aria-label="PAP 设置" className="dsh-pap-settings">
    <style>{styles}</style>
    <div className="pap-actions"><h2>PAP Company 连接</h2><span className="pap-badge" role="status">{stateNames[view.status.state]??'暂不可用'}</span><button disabled={busy} onClick={()=>{void controller.refresh();}}>刷新状态</button></div>
    <p>选择身份 → 填写 Company → 建立连接 → 允许所需操作。只有明确允许的操作会提供给 Agent。</p>
    <p className="pap-muted">免登录服务无需账户、scope 或验证码。连接编号、账户权限和排查信息在下方高级设置中。</p>
    {view.error&&<p role="alert">{view.error}</p>}
    {view.status.authenticationHints.map(hint=><p key={hint.operationRef} role="status">该操作需要检查账户权限：{hint.scope?.join('、')??'请检查当前账户授权'} {httpsLink(hint.resourceMetadataUrl)&&<a href={httpsLink(hint.resourceMetadataUrl)} target="_blank" rel="noopener noreferrer">查看资源授权说明</a>}</p>)}
    {view.status.state==='disabled'&&<p>请先在 Host 配置中启用 PAP，并配置已批准的身份政策。</p>}
    {view.status.state==='migration_required'&&<div><p>旧账户凭据历史不完整，Agent 操作已停止。退出当前账户不会证明全部旧凭据已失效；请保留加密状态，由受信管理核验全部旧凭据撤销后处理。</p>{view.status.accounts.map(account=><p key={account.accountSlot}>账户 {account.accountSlot.slice(-8)} · {account.status} <button disabled={busy||account.status==='signed_out'} onClick={()=>run({action:'account/sign-out',accountSlot:account.accountSlot})}>撤销当前账户</button></p>)}</div>}
    {view.waitingIdentity&&<p role="status">等待身份管理服务。请先在“身份”设置中完成注册和发布，再刷新。</p>}
    {!view.waitingIdentity&&view.identities.length===0&&<p>暂无支持 PAP Session 的已发布身份，请先在“身份”设置中完成发布。</p>}
    <form onSubmit={event=>{event.preventDefault();const selected=view.identities.find(item=>identityKey(item.reference)===identity);if(selected)run({action:'identity/select',reference:selected.reference});}}>
      <label>已发布身份 <select aria-label="PAP 身份" value={identity} disabled={busy||view.status.state==='disabled'} onChange={event=>setIdentity(event.target.value)}><option value="">请选择身份</option>{view.identities.map(item=><option key={identityKey(item.reference)} value={identityKey(item.reference)}>{item.label}</option>)}</select></label>
      <button disabled={busy||!identity||view.status.state==='disabled'}>使用此身份</button>
    </form>
    <form onSubmit={event=>{event.preventDefault();run({action:'company/discover',domain:domain.trim()});}}>
      <label>Company 域名 <input aria-label="Company 域名" value={domain} placeholder="company.example" onChange={event=>setDomain(event.target.value)} disabled={busy||view.status.state!=='ready'}/></label>
      <button disabled={busy||!domain.trim()||view.status.state!=='ready'}>发现 Company</button>
    </form>
    {view.status.companies.map(company=><Company key={company.companyRef} company={company} view={view} controller={controller}/>)}
    {view.status.pendingSignIns.map(pending=><div key={pending.transactionRef}>
      <p>账户登录等待完成。</p>
      {view.authorization?.transactionRef===pending.transactionRef&&<a href={view.authorization.url} target="_blank" rel="noopener noreferrer">在浏览器中完成账户登录</a>}
      <button disabled={busy} onClick={()=>run({action:'account/collect',transactionRef:pending.transactionRef})}>领取登录结果</button>
      <button disabled={busy} onClick={()=>run({action:'account/sign-out',accountSlot:pending.accountSlot})}>取消账户登录</button>
    </div>)}
  </section>;
}
function Company({company,view,controller}:{company:SettingsView['status']['companies'][number];view:SettingsView;controller:PapSettingsController}):ReactNode {
  const sessions=view.status.sessions.filter(session=>session.companyRef===company.companyRef&&session.connected);
  const accounts=view.status.accounts.filter(account=>account.companyRef===company.companyRef);
  const operations=view.operations.filter(operation=>operation.companyRef===company.companyRef);
  const connected=sessions.some(session=>!session.account);const busy=view.pending||view.loading;
  const run=(input:Parameters<PapSettingsController['execute']>[0])=>{void controller.execute(input);};
  return <article>
    <div className="pap-actions"><h3>{company.name}</h3><span className="pap-badge">{company.authMode==='no_as'?'免登录':company.authMode==='disabled'?'暂停新账户登录':'账户登录可选'}</span></div>
    <div className="pap-actions"><span>{sessions.length?'已连接':'尚未连接'} · 已允许 {operations.filter(item=>item.enabled).length} 个操作</span>
      <button disabled={busy||connected} onClick={()=>run({action:'session/connect',companyRef:company.companyRef})}>{connected?'连接已建立':'建立未登录连接'}</button>
    </div>
    {operations.map(operation=><Operation key={operation.operationRef} operation={operation} company={company} view={view} controller={controller}/>)}
    {(company.authMode!=='no_as'||accounts.length>0)&&<details><summary>账户与登录（可选）</summary>
      <p className="pap-muted">只有操作明确要求账户权限时才需要登录。先在该操作的高级设置中选择权限，再发起登录。</p>
      {accounts.map(account=><div key={account.accountSlot} className="pap-session">
        <span>账户 {account.accountSlot.slice(-8)} · {account.status} · {account.scopes.join('、')}</span>
        {account.status==='active'&&<button disabled={busy} onClick={()=>run({action:'session/connect',companyRef:company.companyRef,accountSlot:account.accountSlot})}>建立账户连接</button>}
        {account.status==='active'&&<button disabled={busy||!account.canRefresh} onClick={()=>run({action:'account/refresh',accountSlot:account.accountSlot})}>刷新账户</button>}
        {account.status!=='signed_out'&&<button disabled={busy} onClick={()=>run({action:'account/sign-out',accountSlot:account.accountSlot})}>退出账户</button>}
      </div>)}
    </details>}
    <details><summary>连接管理与诊断（{sessions.length} 个连接）</summary>
      <p className="pap-muted">普通使用只需一个未登录连接。已有连接不会自动合并或删除；确认不再使用后可手动断开。</p>
      {sessions.map(session=><p key={session.sessionRef} className="pap-session">{session.account?'账户连接':'未登录连接'} {session.sessionRef.slice(-8)} <button disabled={busy} onClick={()=>run({action:'session/disconnect',sessionRef:session.sessionRef})}>断开连接 {session.sessionRef.slice(-8)}</button></p>)}
    </details>
  </article>;
}
function Operation({operation,company,view,controller}:{operation:SettingsView['operations'][number];company:SettingsView['status']['companies'][number];view:SettingsView;controller:PapSettingsController}):ReactNode {
  const [choice,setSession]=useState<string|null>(null);const [scopes,setScopes]=useState<string[]>([]);
  const sessions=view.status.sessions.filter(session=>session.companyRef===company.companyRef&&session.connected);
  const sessionRef=choice??sessions.find(session=>!session.account)?.sessionRef??'';
  const selected=sessions.find(session=>session.sessionRef===sessionRef);const busy=view.pending||view.loading;
  const enable=()=>{void controller.execute({action:'operation/enable',operationRef:operation.operationRef,sessionRef,scopes:selected?.account?scopes:[]});};
  return <div className="pap-operation">
    <div className="pap-actions"><strong className="pap-route">{operation.method} {operation.path}</strong><span className="pap-badge">{operation.enabled?'已允许 Agent 调用':'未允许 Agent 调用'}</span></div>
    <div className="pap-actions">
      {!operation.enabled&&<button disabled={busy||!selected} onClick={enable}>允许 Agent 调用</button>}
      {operation.enabled&&<button disabled={busy} onClick={()=>{void controller.execute({action:'operation/disable',operationRef:operation.operationRef});}}>撤销操作许可</button>}
      {!selected&&!operation.enabled&&<span className="pap-muted">请先建立连接</span>}
    </div>
    <details><summary>高级：连接与账户权限</summary>
      <p className="pap-muted">仅在需要更换连接或登录账户时设置。下方选择只在明确保存授权时生效，不表示当前授权的绑定。</p>
      <label>操作连接 <select aria-label={`连接 ${operation.method} ${operation.path}`} value={sessionRef} onChange={event=>setSession(event.target.value)} disabled={busy}><option value="">选择连接</option>{sessions.map(session=><option key={session.sessionRef} value={session.sessionRef}>{session.account?'账户':'未登录'} {session.sessionRef.slice(-8)}</option>)}</select></label>
      {company.authMode==='account'&&<div>
        {!!company.scopes.length&&<div>账户权限 {company.scopes.map(scope=><label key={scope}><input type="checkbox" checked={scopes.includes(scope)} disabled={busy} onChange={event=>setScopes(event.target.checked?[...scopes,scope]:scopes.filter(item=>item!==scope))}/>{scope}</label>)}</div>}
        <button disabled={busy||!selected||scopes.length===0} onClick={()=>{void controller.execute({action:'account/sign-in',sessionRef,operationRef:operation.operationRef,scopes});}}>发起账户登录</button>
      </div>}
      {operation.enabled&&<button disabled={busy||!selected} onClick={enable}>更新操作连接</button>}
    </details>
  </div>;
}
