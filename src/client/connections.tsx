import { useSyncExternalStore } from 'react';
import type { PapSettingsController } from './controller.js';

/** User-only lifecycle controls; protocol permissions remain in shared settings. */
export function PapConnections({controller}:{controller:PapSettingsController}) {
  const view=useSyncExternalStore(controller.subscribe,controller.getSnapshot);
  const busy=view.loading||view.pending;
  return <section aria-label="PAP 连接">
    <h2>PAP 连接</h2>
    <p>断开后，Agent 无法自动重新连接。需要你在此页面重新连接。</p>
    <button disabled={busy} onClick={()=>void controller.refresh()}>刷新连接状态</button>
    {view.error&&<p role="alert">{view.error}</p>}
    {!view.status.sessions.length&&<p>暂无 PAP 连接。通过 Agent 访问服务后，可在此管理连接。</p>}
    {view.status.sessions.map(session=><div key={session.sessionRef}>
      <p>{view.status.companies.find(company=>company.companyRef===session.companyRef)?.name??'PAP 服务'} · {session.connected?'已连接':'已断开'}</p>
      <button disabled={busy||!session.connected} onClick={()=>void controller.execute({action:'session/disconnect',sessionRef:session.sessionRef})}>断开连接</button>
      <button disabled={busy||session.connected||!session.companyRef} onClick={()=>{
        if(session.companyRef)void controller.execute({action:'session/connect',companyRef:session.companyRef,...(session.accountSlot?{accountSlot:session.accountSlot}:{})});
      }}>重新连接</button>
    </div>)}
  </section>;
}
