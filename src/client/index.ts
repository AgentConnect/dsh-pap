import type { Context } from '@deepseek-ai/cordis';
import type {} from '@deepseek-ai/dsh-api-remotes/client';
import type {} from '@deepseek-ai/dsh-client-ui-renderer/client';
import type {} from '@deepseek-ai/dsh-client-ui-layout/client';
import type {} from '@deepseek-ai/dsh-client-ui-settings/client';
import contribution from '../remote.js';
import { PapSettingsController,type UserPapRemote,type PublicIdentityRemote } from './controller.js';
import { PapSettings } from './views.js';
export const inject=['slots','remote','connection'];
export async function apply(ctx:Context):Promise<()=>Promise<void>> {
  let unmount:(()=>Promise<void>)|undefined;
  try{unmount=await ctx.remote.$mount(contribution);}catch{}
  const controller=new PapSettingsController(()=>{
    const identities=ctx.get('remote.anpIdentityManager') as unknown as PublicIdentityRemote|undefined;
    return {pap:ctx.get('remote.papManager') as unknown as UserPapRemote|undefined,
      identities:identities?{listIdentities:()=>identities.listIdentities(),publicationStatus:reference=>identities.publicationStatus(reference)}:undefined};
  });
  let unregister:()=>void;
  try{
    unregister=ctx.slots.inject('settings.section',()=>ctx.slots.register({name:'settings.section',id:'pap-companies',label:'PAP 连接',order:45,inject:()=>({controller})},PapSettings));
    void controller.refresh();
  }catch(error){controller.dispose();await unmount?.();throw error;}
  return async()=>{controller.dispose();unregister();await unmount?.();};
}
export { PapSettingsController,PapSettings };
