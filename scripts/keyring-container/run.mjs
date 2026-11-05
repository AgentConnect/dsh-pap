/** Build a unique local-only image; execute with no network and a read-only root filesystem. */
import { spawn } from 'node:child_process'
import { createWriteStream } from 'node:fs'
import { finished } from 'node:stream/promises'
import { randomBytes, createHash } from 'node:crypto'
import { mkdir, readFile, writeFile, copyFile, cp } from 'node:fs/promises'
import { dirname, resolve, join } from 'node:path'
import { fileURLToPath } from 'node:url'
const here=dirname(fileURLToPath(import.meta.url));const papRoot=resolve(here,'../..')
const defaultEvidence=resolve(papRoot,'../worktrees/20261104-dsh-shared-agent-identity/.artifacts/keyring-verification/secret-service-container')
const evidenceBase=resolve(process.argv[2]??defaultEvidence)
const run='run-'+new Date().toISOString().replace(/[^0-9T]/g,'').toLowerCase()+'-'+randomBytes(4).toString('hex')
const root=join(evidenceBase,run);const context=join(root,'context');const output=join(root,'output');const image='dsh-pap-secretservice-check:'+run
await mkdir(evidenceBase,{recursive:true,mode:0o700});await mkdir(root,{mode:0o700});await mkdir(context,{mode:0o700});await mkdir(output,{mode:0o700})
const command=(program,args,{cwd=papRoot,log}={})=>new Promise((resolve,reject)=>{
 const child=spawn(program,args,{cwd,stdio:['ignore','pipe','pipe']});let stdout='';let stderr=''
 child.stdout.on('data',chunk=>{if(log)log.write(chunk);else stdout+=String(chunk)});child.stderr.on('data',chunk=>{if(log)log.write(chunk);else stderr+=String(chunk)})
 child.once('error',reject);child.once('close',code=>resolve({code,stdout,stderr}))
})
const tar=join(papRoot,'.artifacts/agentconnect-dsh-pap-0.1.0.tgz');const packageHash=createHash('sha256').update(await readFile(tar)).digest('hex')
let result=await command('tar',['-xzf',tar,'-C',context]);if(result.code!==0)throw new Error('package_extract_failed')
await mkdir(join(context,'runtime_modules'),{mode:0o700});await mkdir(join(context,'source'),{mode:0o700})
for(const name of ['proper-lockfile','graceful-fs','retry','signal-exit'])await cp(join(papRoot,'node_modules',name),join(context,'runtime_modules',name),{recursive:true,dereference:true})
for(const name of ['keyring.ts','host-secrets.ts','store.ts'])await copyFile(join(papRoot,'src',name),join(context,'source',name))
for(const name of ['Dockerfile','verify.mjs'])await copyFile(join(here,name),join(context,name))
const buildStream=createWriteStream(join(root,'build.log'),{flags:'wx',mode:0o600})
console.log(JSON.stringify({stage:'building',runRoot:root,image,packageSha256:packageHash}))
try{result=await command('docker',['build','--pull=false','--tag',image,'--label','org.agentconnect.task=dsh-pap-secret-service-verification',context],{log:buildStream})}finally{buildStream.end();await finished(buildStream)}
if(result.code!==0){await writeFile(join(root,'status.json'),JSON.stringify({status:'image_build_failed',runRoot:root,image,packageSha256:packageHash})+'\n',{mode:0o600});throw new Error('image_build_failed')}
const inspect=await command('docker',['image','inspect',image]);if(inspect.code!==0)throw new Error('image_inspect_failed')
const [imageFacts]=JSON.parse(inspect.stdout);const identity=await command('id',['-u']);const group=await command('id',['-g']);const uid=identity.stdout.trim();const gid=group.stdout.trim()
const flags=['run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128','--memory','512m','--cpus','1','--user',uid+':'+gid,'--tmpfs',`/run/task:rw,nosuid,nodev,noexec,size=32m,mode=0700,uid=${uid},gid=${gid}`,'--tmpfs',`/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777,uid=${uid},gid=${gid}`,'--mount',`type=bind,src=${output},dst=/evidence`,image]
console.log(JSON.stringify({stage:'running',runRoot:root,imageId:imageFacts.Id,repoDigests:imageFacts.RepoDigests,network:'none',readOnly:true}))
const executed=await command('docker',flags);await writeFile(join(root,'runtime.json'),JSON.stringify({image,imageId:imageFacts.Id,repoDigests:imageFacts.RepoDigests,baseImage:'node:22.23.1-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3',packageSha256:packageHash,runFlags:flags,exitCode:executed.code,stdout:executed.stdout},null,2)+'\n',{mode:0o600})
if(executed.stdout)process.stdout.write(executed.stdout)
if(executed.code!==0)process.exitCode=1
console.log(JSON.stringify({stage:'complete',runRoot:root,image,imageId:imageFacts.Id,exitCode:executed.code}))
