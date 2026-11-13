import type { Context } from '@deepseek-ai/cordis';
import type {} from '@deepseek-ai/dsh-api-remotes/client';
import type {} from '@deepseek-ai/dsh-client-ui-renderer/client';
import type {} from '@deepseek-ai/dsh-client-ui-layout/client';
import type {} from '@deepseek-ai/dsh-client-ui-settings/client';
import contribution from '../remote.js';
import { PapSettingsController,type UserPapRemote } from './controller.js';
import { PapConnections } from './connections.js';
export const inject=['slots','remote','connection'];
export async function apply(ctx:Context):Promise<()=>Promise<void>> {
  const unmount=await ctx.remote.$mount(contribution);
  const controller=new PapSettingsController(()=>({pap:ctx.get('remote.papManager') as unknown as UserPapRemote}));
  let remove:(()=>void)|undefined;
  try{
    remove=ctx.slots.inject('settings.section',()=>ctx.slots.register({
      name:'settings.section',id:'pap-connections',label:'PAP 连接',order:42,
      inject:()=>({controller}),
    },PapConnections));
    await controller.refresh();
  }catch(error){controller.dispose();remove?.();await unmount();throw error;}
  return async()=>{controller.dispose();remove?.();await unmount();};
}
