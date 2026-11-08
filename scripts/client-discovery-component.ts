/** Actual installed renderer registry locates the root marker and serves the declared browser artifact. */
import assert from 'node:assert/strict';
import { Context } from '@deepseek-ai/cordis';
import Loader from '@deepseek-ai/cordis-plugin-loader';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
const input=process.argv[2];assert(input,'An explicit installed client-modules entry is required');
const entry=resolve(input);const sha256=createHash('sha256').update(await readFile(entry)).digest('hex');
const {default:Registry}=await import(pathToFileURL(entry).href);
const ctx=new Context();
try{
  await ctx.plugin(Loader,{baseUrl:pathToFileURL(resolve('package.json')).href});
  // Actual root package exports; no engine or C capability is mounted by this row.
  const module=await import(pathToFileURL(resolve('lib/index.js')).href);
  ctx.loader.import=async name=>{assert.equal(name,'@awiki/dsh-pap');return module;};
  await ctx.loader.create({name:'@awiki/dsh-pap'});await ctx.loader.await();
  assert.equal(ctx.get('pap'),undefined);await ctx.plugin(Registry);
  const registry=ctx.get('clientModules') as any;const graph=registry.graph();const row=graph.entries.find((value:any)=>value.id==='@awiki/dsh-pap');assert(row);
  assert.equal(registry.clientPath(row.id),resolve('lib/browser-client.js'));
  const response=registry.fetchBundle(new Request('http://component.test'+row.url));assert.equal(response.status,200);const body=await response.text();assert(body.includes('@awiki/dsh-pap'));assert(!body.includes('NativeStore'));assert(!body.includes('credentialVault'));
  assert.equal(createHash('sha256').update(await readFile(entry)).digest('hex'),sha256);
  console.log(JSON.stringify({status:'passed',lane:'actual_renderer_ClientModuleRegistry_root_marker_browser_export',registryEntrySha256:sha256,
    markerHasPapService:false,discoveredPackage:row.id,selectedArtifact:registry.clientPath(row.id),servedBundle:true,browserDependencyPurity:true,productRendererBoot:false}));
}finally{await ctx.fiber.dispose();}
