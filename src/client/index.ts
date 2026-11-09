import type { Context } from '@deepseek-ai/cordis';
import type {} from '@deepseek-ai/dsh-api-remotes/client';
import type {} from '@deepseek-ai/dsh-client-ui-renderer/client';
import type {} from '@deepseek-ai/dsh-client-ui-layout/client';
import type {} from '@deepseek-ai/dsh-client-ui-settings/client';
import contribution from '../remote.js';
export const inject=['slots','remote','connection'];
export async function apply(ctx:Context):Promise<()=>Promise<void>> {
  let unmount:(()=>Promise<void>)|undefined;
  try{unmount=await ctx.remote.$mount(contribution);}catch{}
  // The Identity client owns the single shared Protocol Management section.
  // Keep diagnostics and legacy state available without restoring the manual connection UI.
  return async()=>{await unmount?.();};
}
