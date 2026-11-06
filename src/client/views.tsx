import { useState,useSyncExternalStore,type ReactNode } from 'react';
import { PapSettingsController,identityKey,type SettingsView } from './controller.js';
const stateNames:Record<string,string>={disabled:'未启用',unconfigured:'未配置身份',credential_unavailable:'受保护凭据不可用',migration_required:'旧凭据历史需要管理处理',ready:'可用',waiting:'等待 Host'};
function httpsLink(value?:string):string|undefined {try{const url=new URL(value??'');return url.protocol==='https:'&&!url.username&&!url.password&&!url.hash?url.href:undefined;}catch{return undefined;}}
export function PapSettings({controller}:{controller:PapSettingsController}):ReactNode {
  const view=useSyncExternalStore(controller.subscribe,controller.getSnapshot,controller.getSnapshot);
  const [identity,setIdentity]=useState('');const [domain,setDomain]=useState('');const busy=view.pending||view.loading;
  const run=(input:Parameters<PapSettingsController['execute']>[0])=>{void controller.execute(input);};
  return <section aria-label="PAP 设置" style={{display:'grid',gap:12,maxWidth:960}}>
    <h2>PAP Company 连接</h2><p role="status">状态：{stateNames[view.status.state]??'暂不可用'}</p>
    <p>先选择已发布身份，再发现 Company 并建立连接。只有你明确允许的操作会提供给 Agent。</p>
    <button disabled={busy} onClick={()=>{void controller.refresh();}}>刷新状态</button>
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
    {view.status.companies.map(company=><article key={company.companyRef} style={{border:'1px solid #8885',padding:12}}>
      <h3>{company.name}</h3><p>{company.authMode==='no_as'?'无需账户即可使用 Session':company.authMode==='disabled'?'暂停新账户登录，已有账户按授权继续使用':'支持独立账户登录'}</p>
      <button disabled={busy} onClick={()=>run({action:'session/connect',companyRef:company.companyRef})}>建立未登录连接</button>
      {view.status.sessions.filter(session=>session.companyRef===company.companyRef&&session.connected).map(session=><p key={session.sessionRef}>{session.account?'账户连接':'未登录连接'} {session.sessionRef.slice(-8)} <button disabled={busy} onClick={()=>run({action:'session/disconnect',sessionRef:session.sessionRef})}>断开连接 {session.sessionRef.slice(-8)}</button></p>)}
      {view.status.accounts.filter(account=>account.companyRef===company.companyRef).map(account=><div key={account.accountSlot}>
        <span>账户 {account.accountSlot.slice(-8)} · {account.status} · {account.scopes.join('、')}</span>
        {account.status==='active'&&<button disabled={busy} onClick={()=>run({action:'session/connect',companyRef:company.companyRef,accountSlot:account.accountSlot})}>建立账户连接</button>}
        {account.status==='active'&&<button disabled={busy||!account.canRefresh} onClick={()=>run({action:'account/refresh',accountSlot:account.accountSlot})}>刷新账户</button>}
        {!['signed_out'].includes(account.status)&&<button disabled={busy} onClick={()=>run({action:'account/sign-out',accountSlot:account.accountSlot})}>退出账户</button>}
      </div>)}
      {view.operations.filter(operation=>operation.companyRef===company.companyRef).map(operation=><Operation key={operation.operationRef} operation={operation} company={company} view={view} controller={controller}/>)}
    </article>)}
    {view.status.pendingSignIns.map(pending=><div key={pending.transactionRef}>
      <p>账户登录等待完成。</p>
      {view.authorization?.transactionRef===pending.transactionRef&&<a href={view.authorization.url} target="_blank" rel="noopener noreferrer">在浏览器中完成账户登录</a>}
      <button disabled={busy} onClick={()=>run({action:'account/collect',transactionRef:pending.transactionRef})}>领取登录结果</button>
      <button disabled={busy} onClick={()=>run({action:'account/sign-out',accountSlot:pending.accountSlot})}>取消账户登录</button>
    </div>)}
  </section>;
}
function Operation({operation,company,view,controller}:{operation:SettingsView['operations'][number];company:SettingsView['status']['companies'][number];view:SettingsView;controller:PapSettingsController}):ReactNode {
  const [sessionRef,setSession]=useState('');const [scopes,setScopes]=useState<string[]>([]);const sessions=view.status.sessions.filter(session=>session.companyRef===company.companyRef&&session.connected);const selected=sessions.find(session=>session.sessionRef===sessionRef);const busy=view.pending||view.loading;
  return <fieldset><legend>{operation.method} {operation.path}</legend>
    <p>{operation.enabled?'已允许 Agent 调用':'未允许 Agent 调用'}</p>
    <label>操作连接 <select aria-label={`连接 ${operation.method} ${operation.path}`} value={sessionRef} onChange={event=>setSession(event.target.value)} disabled={busy}><option value="">选择连接</option>{sessions.map(session=><option key={session.sessionRef} value={session.sessionRef}>{session.account?'账户':'未登录'} {session.sessionRef.slice(-8)}</option>)}</select></label>
    {!!company.scopes.length&&<div>账户权限 {company.scopes.map(scope=><label key={scope}><input type="checkbox" checked={scopes.includes(scope)} disabled={busy} onChange={event=>setScopes(event.target.checked?[...scopes,scope]:scopes.filter(item=>item!==scope))}/>{scope}</label>)}</div>}
    <button disabled={busy||!selected} onClick={()=>{void controller.execute({action:'operation/enable',operationRef:operation.operationRef,sessionRef,scopes:selected?.account?scopes:[]});}}>允许 Agent 调用</button>
    {operation.enabled&&<button disabled={busy} onClick={()=>{void controller.execute({action:'operation/disable',operationRef:operation.operationRef});}}>撤销操作许可</button>}
    <button disabled={busy||!selected||scopes.length===0||company.authMode!=='account'} onClick={()=>{void controller.execute({action:'account/sign-in',sessionRef,operationRef:operation.operationRef,scopes});}}>发起账户登录</button>
  </fieldset>;
}
