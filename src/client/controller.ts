import { z } from 'zod';
import type { PapManagementRequest } from '../product-api.js';
const reference = z.object({ storeId:z.string(),identityId:z.string(),did:z.string() });
const company = z.object({ companyRef:z.string(),name:z.string(),authMode:z.enum(['no_as','account','disabled']),scopes:z.array(z.string()) });
const session = z.object({ sessionRef:z.string(),companyRef:z.string().optional(),connected:z.boolean(),account:z.boolean(),accountSlot:z.string().optional() });
const account = z.object({ accountSlot:z.string(),companyRef:z.string().optional(),status:z.string(),scopes:z.array(z.string()),canRefresh:z.boolean().default(false) });
const pending = z.object({ transactionRef:z.string(),accountSlot:z.string(),companyRef:z.string().optional(),expiresAt:z.number() });
const hint=z.object({operationRef:z.string(),scheme:z.enum(['Bearer','DPoP']),scope:z.array(z.string()).optional(),resourceMetadataUrl:z.string().optional()});
const status = z.object({ state:z.string(),error:z.string().optional(),identity:reference.optional(),companies:z.array(company).default([]),sessions:z.array(session).default([]),accounts:z.array(account).default([]),pendingSignIns:z.array(pending).default([]),authenticationHints:z.array(hint).default([]) });
const operation = z.object({ operationRef:z.string(),companyRef:z.string(),method:z.string(),path:z.string(),enabled:z.boolean(),account:z.boolean() });
export interface UserPapRemote { status():Promise<any>;operations():Promise<any>;manage(input:PapManagementRequest):Promise<any> }
export interface PublicIdentityRemote { listIdentities():Promise<any>;publicationStatus(identity:z.infer<typeof reference>):Promise<any> }
export interface SettingsView {
  status:z.infer<typeof status>; operations:z.infer<typeof operation>[];
  identities:{reference:z.infer<typeof reference>;label:string}[];
  loading:boolean;pending:boolean;waitingIdentity:boolean;error:string|null;
  authorization:{transactionRef:string;url:string}|null;
}
const messages:Record<string,string> = {
  credential_history_incomplete:'旧账户凭据历史不完整。请先处理原账户并由受信管理核验，不能继续提供给 Agent。',
  not_configured:'请先在 Host 配置中启用 PAP，并指定已批准的身份政策。',credential_unavailable:'受保护凭据暂不可用，请检查系统秘密存储后重试。',
  permission_denied:'当前操作未获允许，请检查身份、连接与权限。',consumer_forbidden:'PAP 身份许可暂不可用。',provider_disposed:'身份服务已更新，请重新选择身份。',
  not_published:'请先在身份设置中完成注册和发布。',unsupported_sign_in:'此 Company 当前不支持发起账户登录。',insufficient_scope:'请选择此 Company 提供的账户权限。',
  callback_not_ready:'浏览器登录尚未完成，请完成后再次领取。',callback_claimed:'该登录结果已领取，请刷新状态或重新发起。',callback_expired:'登录已过期，请重新发起。',
  reauthorization_required:'账户需要重新登录。',revocation_pending:'本地已停止账户使用，远端撤销仍待确认。',state_conflict:'连接状态已变化，请刷新后重试。',
  disconnected:'连接已停止，请刷新状态。',request_uncertain:'请求结果不确定，请先确认远端状态。',rate_limited:'请求暂受限，请稍后重试。',
};
class SafeMessage extends Error { constructor(readonly displayText:string){super('PAP user operation unavailable');} }
function unwrap(response:any):unknown {
  if (!response || response.ok !== true || !response.value) throw new SafeMessage('等待 PAP Host 服务，请连接后刷新。');
  if (response.value.ok !== true) throw new SafeMessage(messages[response.value.error?.code] ?? '操作暂不可用，请刷新状态后重试。');
  return response.value.value;
}
export const identityKey = (value:z.infer<typeof reference>) => JSON.stringify([value.storeId,value.identityId,value.did]);
export class PapSettingsController {
  private view:SettingsView = { status:{state:'waiting',companies:[],sessions:[],accounts:[],pendingSignIns:[],authenticationHints:[]},operations:[],identities:[],loading:true,pending:false,waitingIdentity:true,error:null,authorization:null };
  private readonly listeners = new Set<()=>void>(); private disposed = false; private refreshing = false;
  constructor(private readonly remotes:()=>{pap?:UserPapRemote;identities?:PublicIdentityRemote}) {}
  getSnapshot = () => this.view;
  subscribe = (listener:()=>void) => { this.listeners.add(listener); return ()=>{this.listeners.delete(listener);}; };
  private patch(value:Partial<SettingsView>):void { if(this.disposed)return;this.view={...this.view,...value};for(const listener of this.listeners)listener(); }
  dispose():void { this.disposed=true;this.listeners.clear();this.view.authorization=null; }
  async refresh():Promise<void> {
    if(this.refreshing||this.disposed)return;this.refreshing=true;
    try {
      const remote=this.remotes();if(!remote.pap)throw new SafeMessage('等待 PAP Host 服务，请连接后刷新。');
      const snapshot=status.parse(unwrap(await remote.pap.status()));
      const operations=snapshot.state==='ready'?z.array(operation).parse(unwrap(await remote.pap.operations())):[];
      let identities:SettingsView['identities']=[];let waitingIdentity=true;
      if(remote.identities)try{
        const result=await remote.identities.listIdentities();if(result?.ok&&Array.isArray(result.value)){
          const candidates=result.value.flatMap((item:unknown)=>{const parsed=z.object({reference,label:z.string().optional(),handle:z.string().optional(),catalogState:z.string()}).safeParse(item);return parsed.success&&parsed.data.catalogState==='active'?[{reference:parsed.data.reference,label:parsed.data.label??parsed.data.handle??parsed.data.reference.did}]:[];});
          identities=(await Promise.all(candidates.map(async(item:SettingsView['identities'][number])=>{const publication=await remote.identities!.publicationStatus(item.reference);return publication?.ok&&publication.value?.state==='published'&&publication.value.capabilities?.papSession===true?item:undefined;}))).filter((item):item is SettingsView['identities'][number]=>Boolean(item));waitingIdentity=false;
        }
      }catch{}
      this.patch({status:snapshot,operations,identities,waitingIdentity,loading:false,error:null,
        ...(this.view.authorization&&!snapshot.pendingSignIns.some(item=>item.transactionRef===this.view.authorization!.transactionRef)?{authorization:null}:{})});
    }catch(error){this.patch({loading:false,authorization:null,error:error instanceof SafeMessage?error.displayText:'PAP 状态暂不可用，请刷新后重试。'});}
    finally{this.refreshing=false;}
  }
  async execute(input:PapManagementRequest):Promise<void> {
    if(this.view.pending||this.disposed)return;this.patch({pending:true,error:null,...(input.action==='identity/select'?{authorization:null}:{})});
    try{
      const remote=this.remotes().pap;if(!remote)throw new SafeMessage('等待 PAP Host 服务，请连接后刷新。');
      const value=unwrap(await remote.manage(input));
      if(input.action==='account/sign-in'){
        const result=z.object({transactionRef:z.string(),authorizationUrl:z.string()}).parse(value);const url=new URL(result.authorizationUrl);
        if(url.protocol!=='https:'||url.username||url.password||url.hash)throw new SafeMessage('登录链接暂不可用，请重新发起。');
        this.patch({authorization:{transactionRef:result.transactionRef,url:url.href}});
      }
      await this.refresh();
    }catch(error){this.patch({error:error instanceof SafeMessage?error.displayText:'PAP 操作暂不可用，请刷新后重试。'});}
    finally{this.patch({pending:false});}
  }
}
