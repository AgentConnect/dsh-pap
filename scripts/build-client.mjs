import { build } from 'esbuild';
import { writeFile,mkdir } from 'node:fs/promises';
const result=await build({entryPoints:['src/client/index.ts'],outfile:'lib/browser-client.js',bundle:true,platform:'browser',format:'cjs',target:'es2022',minify:true,metafile:true,sourcemap:true,sourcesContent:false,external:['react','react/jsx-runtime','@deepseek-ai/cordis'],define:{'process.env.NODE_ENV':'"production"'},
  banner:{js:'window.__ModuleLoader__.load({id:"@awiki/dsh-pap",factory:(require)=>{var module={exports:{}};var exports=module.exports;'},footer:{js:'return module.exports;}});'}});
const forbidden=Object.keys(result.metafile.inputs).filter(path=>/src\/(?:plugin|store|keyring|host-secrets|protocol-adapter|credential-history|callback-handoff|client)\.ts$/.test(path)||path.startsWith('node:'));
if(forbidden.length)throw new Error('PAP browser bundle includes a Host module');
await mkdir('.artifacts',{recursive:true});await writeFile('.artifacts/browser-inputs.json',JSON.stringify({inputs:Object.keys(result.metafile.inputs),hostModulesIncluded:false},null,2)+'\n');
