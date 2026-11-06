import test,{afterEach,after} from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { createElement } from 'react';
import { Context } from '@deepseek-ai/cordis';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
import * as ReactModule from 'react';
import * as JsxRuntime from 'react/jsx-runtime';
import { PapSettingsController,identityKey } from '../src/client/controller.js';
import { PapSettings } from '../src/client/views.js';
import { apply as applyClient } from '../src/client/index.js';
const dom=new JSDOM('<!doctype html><html><body></body></html>',{url:'https://app.test'});
for(const name of ['window','document','HTMLElement','HTMLInputElement','Event','MouseEvent','Node','MutationObserver','navigator'])Object.defineProperty(globalThis,name,{value:(dom.window as any)[name],configurable:true});
(globalThis as any).IS_REACT_ACT_ENVIRONMENT=true;
const {render,screen,fireEvent,waitFor,cleanup,act}=await import('@testing-library/react');
afterEach(()=>cleanup());after(()=>dom.window.close());
const ref={storeId:'public-store',identityId:'public-agent',did:'did:wba:identity.example:one'};
const outer=(value:unknown)=>({ok:true,value:{ok:true,value}});
function world(initial='unconfigured'){
  const state:any={state:initial,companies:[],sessions:[],accounts:[],pendingSignIns:[]};const operations:any[]=[];const calls:any[]=[];let rejected=false;
  const pap={status:async()=>outer(structuredClone(state)),operations:async()=>outer(structuredClone(operations)),manage:async(input:any)=>{
    calls.push(structuredClone(input));if(rejected)throw new Error('sensitive transport payload must not be displayed');
    if(input.action==='identity/select'){state.state='ready';state.identity=ref;}
    if(input.action==='company/discover'){state.companies=[{companyRef:'cmp1',name:'User selected Company',authMode:'account',scopes:['orders:read']}];operations.push({operationRef:'op1',companyRef:'cmp1',method:'GET',path:'/orders',enabled:false,account:false});}
    if(input.action==='session/connect')state.sessions.push({sessionRef:input.accountSlot?'session-account':'session-one',companyRef:'cmp1',connected:true,account:Boolean(input.accountSlot),...(input.accountSlot?{accountSlot:input.accountSlot}:{})});
    if(input.action==='operation/enable')operations[0].enabled=true;
    if(input.action==='operation/disable')operations[0].enabled=false;
    if(input.action==='session/disconnect')state.sessions.find((item:any)=>item.sessionRef===input.sessionRef).connected=false;
    if(input.action==='account/sign-in'){state.pendingSignIns=[{transactionRef:'tx-user',accountSlot:'account-user',companyRef:'cmp1',expiresAt:Date.now()+600000}];return outer({transactionRef:'tx-user',accountSlot:'account-user',authorizationUrl:'https://issuer.example/authorize?state=user-state&code_challenge=public-challenge'});}
    if(input.action==='account/collect'){state.pendingSignIns=[];state.accounts=[{accountSlot:'account-user',companyRef:'cmp1',status:'active',scopes:['orders:read'],canRefresh:true}];}
    if(input.action==='account/sign-out'){const account=state.accounts.find((item:any)=>item.accountSlot===input.accountSlot);if(account)account.status='signed_out';}
    return outer(input.action==='account/sign-out'?{status:'signed_out'}:null);
  }};
  const identities={listIdentities:async()=>({ok:true,value:[{reference:ref,label:'Published Agent',catalogState:'active',unexpectedCredential:'must-not-enter-snapshot'}]}),publicationStatus:async()=>({ok:true,value:{state:'published',capabilities:{papSession:true}}})};
  const controller=new PapSettingsController(()=>({pap,identities}));
  return{state,operations,calls,pap,identities,controller,reject(){rejected=true;}};
}
async function show(f:ReturnType<typeof world>){render(createElement(PapSettings,{controller:f.controller}));await act(()=>f.controller.refresh());}
async function click(name:string){fireEvent.click(screen.getByRole('button',{name}));await waitFor(()=>assert.equal((screen.getByRole('button',{name:'刷新状态'}) as HTMLButtonElement).disabled,false));}

test('PAP settings: explicit identity, Company, Session and operation permission use only user Remote',async()=>{
  const f=world();await show(f);assert(!JSON.stringify(f.controller.getSnapshot()).includes('must-not-enter-snapshot'));
  fireEvent.change(screen.getByLabelText('PAP 身份'),{target:{value:identityKey(ref)}});await click('使用此身份');
  fireEvent.change(screen.getByLabelText('Company 域名'),{target:{value:'company.example'}});await click('发现 Company');await click('建立未登录连接');
  fireEvent.change(screen.getByLabelText('连接 GET /orders'),{target:{value:'session-one'}});await click('允许 Agent 调用');
  assert.deepEqual(f.calls.slice(0,4),[{action:'identity/select',reference:ref},{action:'company/discover',domain:'company.example'},{action:'session/connect',companyRef:'cmp1'},{action:'operation/enable',operationRef:'op1',sessionRef:'session-one',scopes:[]}]);
  await click('撤销操作许可');assert.equal(f.calls.at(-1).action,'operation/disable');assert(!JSON.stringify(f.calls).includes('policyRef'));assert(!JSON.stringify(f.calls).includes('targetRef'));
  f.controller.dispose();
});
test('PAP settings: browser login link is user-only, explicit and isolated from credential/callback payloads',async()=>{
  const f=world('ready');f.state.companies=[{companyRef:'cmp1',name:'Company',authMode:'account',scopes:['orders:read']}];f.state.sessions=[{sessionRef:'session-one',companyRef:'cmp1',connected:true,account:false}];f.operations.push({operationRef:'op1',companyRef:'cmp1',method:'GET',path:'/orders',enabled:false,account:false});
  let opened=0;dom.window.open=()=>{opened++;return null;};await show(f);
  fireEvent.change(screen.getByLabelText('连接 GET /orders'),{target:{value:'session-one'}});fireEvent.click(screen.getByLabelText('orders:read'));await click('发起账户登录');
  const link=screen.getByRole('link',{name:'在浏览器中完成账户登录'});assert.equal(link.getAttribute('target'),'_blank');assert.equal(link.getAttribute('rel'),'noopener noreferrer');assert(link.getAttribute('href')!.includes('state=user-state'));assert.equal(opened,0);
  assert.deepEqual(f.calls[0],{action:'account/sign-in',sessionRef:'session-one',operationRef:'op1',scopes:['orders:read']});
  await click('领取登录结果');assert.deepEqual(f.calls.at(-1),{action:'account/collect',transactionRef:'tx-user'});assert(!screen.queryByRole('link'));
  await click('建立账户连接');await click('刷新账户');assert.deepEqual(f.calls.at(-1),{action:'account/refresh',accountSlot:'account-user'});await click('退出账户');assert.deepEqual(f.calls.at(-1),{action:'account/sign-out',accountSlot:'account-user'});
  assert(!JSON.stringify(f.calls).includes('verifier'));assert(!JSON.stringify(f.calls).includes('claim_secret'));f.controller.dispose();
});
test('PAP settings: disabled and missing C services render a waiting state without fallback or mutation',async()=>{
  const f=world('disabled');const controller=new PapSettingsController(()=>({pap:f.pap}));render(createElement(PapSettings,{controller}));await act(()=>controller.refresh());
  assert(screen.getByText(/请先在 Host 配置中启用 PAP/));assert(screen.getByText(/等待身份管理服务/));assert.equal((screen.getByRole('button',{name:'使用此身份'}) as HTMLButtonElement).disabled,true);assert.deepEqual(f.calls,[]);controller.dispose();
});
test('PAP settings: public identity list alone does not qualify an unpublished or PAP-disabled identity',async()=>{
  const f=world();f.identities.publicationStatus=async()=>({ok:true,value:{state:'published',capabilities:{papSession:false}}});await show(f);
  assert(screen.getByText(/暂无支持 PAP Session 的已发布身份/));assert.equal((screen.getByRole('button',{name:'使用此身份'}) as HTMLButtonElement).disabled,true);assert.deepEqual(f.calls,[]);f.controller.dispose();
});
test('PAP settings: legacy history shows only closed account handling, no weak reset/confirmation',async()=>{
  const f=world('migration_required');f.state.accounts=[{accountSlot:'old-account',status:'active',scopes:[]}];await show(f);
  assert(screen.getByText(/旧账户凭据历史不完整/));await click('撤销当前账户');assert.equal(f.state.state,'migration_required');assert.deepEqual(f.calls,[{action:'account/sign-out',accountSlot:'old-account'}]);
  assert(!screen.queryByRole('checkbox'));assert(!screen.queryByRole('button',{name:/重置|确认迁移/}));f.controller.dispose();
});
test('PAP settings: transport descriptions are not displayed',async()=>{
  const f=world();await show(f);f.reject();fireEvent.change(screen.getByLabelText('PAP 身份'),{target:{value:identityKey(ref)}});await click('使用此身份');
  assert(screen.getByRole('alert'));assert(!document.body.textContent!.includes('sensitive transport payload'));f.controller.dispose();
});
test('PAP settings: validated management hints are user links and unsafe hint schemes are not rendered',async()=>{
  const f=world('ready');f.state.authenticationHints=[{operationRef:'op-hint',scheme:'Bearer',scope:['profile:read'],resourceMetadataUrl:'https://company.example/.well-known/oauth-protected-resource'}];await show(f);
  const link=screen.getByRole('link',{name:'查看资源授权说明'});assert.equal(link.getAttribute('rel'),'noopener noreferrer');
  f.state.authenticationHints[0].resourceMetadataUrl='javascript:invalid';await act(()=>f.controller.refresh());assert(!screen.queryByRole('link',{name:'查看资源授权说明'}));assert.deepEqual(f.calls,[]);f.controller.dispose();
});
test('PAP client entry registers actual settings.section with only the user manager Remote contract',async()=>{
  const f=world('disabled');const ctx=new Context();let contribution:any;let section:any;let component:any;let removed=0;let unmounted=0;
  ctx.provide('remote',{$mount:async(input:any)=>{contribution=input;return async()=>{unmounted++;};}});ctx.provide('remote.papManager',f.pap);ctx.provide('remote.anpIdentityManager',f.identities);
  ctx.provide('slots',{inject(_name:string,callback:()=>unknown){callback();return()=>{removed++;};},register(input:any,view:unknown){section=input;component=view;return()=>{};}});
  const dispose=await applyClient(ctx);assert.equal(section.name,'settings.section');assert.equal(section.id,'pap-companies');assert.equal(component,PapSettings);assert.deepEqual(contribution.descriptors.map((value:any)=>value.method),['status','operations','manage']);
  await dispose();assert.equal(removed,1);assert.equal(unmounted,1);await ctx.fiber.dispose();f.controller.dispose();
});
test('PAP browser artifact is a distinct module-loader client and contains no Host dependency graph',async()=>{
  const bytes=await readFile(new URL('../lib/browser-client.js',import.meta.url),'utf8');let loaded:any;
  runInNewContext(bytes,{window:{__ModuleLoader__:{load(value:unknown){loaded=value;}}}},{timeout:1000});
  assert.equal(loaded.id,'@agentconnect/dsh-pap');const module=loaded.factory((name:string)=>{if(name==='react')return ReactModule;if(name==='react/jsx-runtime')return JsxRuntime;throw new Error('Unexpected browser external');});
  assert.equal(typeof module.apply,'function');assert.equal(module.PapClient,undefined);
  const inputs=JSON.parse(await readFile(new URL('../.artifacts/browser-inputs.json',import.meta.url),'utf8'));
  assert.equal(inputs.hostModulesIncluded,false);assert(!inputs.inputs.some((path:string)=>/src\/(plugin|store|keyring|credential-history|protocol-adapter|client)\.ts$/.test(path)));
  for(const name of ['NativeStore','getEncryptionKey','bindPapHostConsumer','DeviceAccess','credentialVault','node:fs'])assert(!bytes.includes(name));
  const host=await readFile(new URL('../lib/client.js',import.meta.url),'utf8');assert(host.includes('class PapClient'));assert(!host.includes('window.__ModuleLoader__'));
});
