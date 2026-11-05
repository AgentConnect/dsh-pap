/** Real isolated Secret Service test. Passwords and key material stay in stdin/memory. */
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { randomBytes, randomUUID, createHash } from 'node:crypto'
import { mkdir, readFile, writeFile, readdir, lstat, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import { networkInterfaces } from 'node:os'
import { KeyringSecretStore } from '/opt/dsh-pap/lib/keyring.js'
import { PapStore } from '/opt/dsh-pap/lib/store.js'

const digest = value => createHash('sha256').update(value).digest('hex')
const taskRoot = '/run/task'
const sourceFiles = ['keyring.ts','host-secrets.ts','store.ts']
const fixedFailure = code => Object.assign(new Error(code), { code })
const execute = (program, args, input, timeout = 10000) => new Promise((resolve, reject) => {
  const child = spawn(program, args, { stdio: ['pipe','pipe','ignore'], env: process.env })
  let stdout = ''; const timer = setTimeout(() => { child.kill('SIGKILL'); reject(fixedFailure('command_timeout')) }, timeout)
  child.stdout.on('data', chunk => { stdout += String(chunk); if (stdout.length > 131072) { child.kill('SIGKILL'); reject(fixedFailure('command_output_limit')) } })
  child.once('error', () => { clearTimeout(timer); reject(fixedFailure('command_failed')) })
  child.once('close', code => { clearTimeout(timer); resolve({ code, stdout }) })
  child.stdin.on('error', () => {}); child.stdin.end(input)
})
const call = async (destination, path, method, ...args) => {
  const result = await execute('dbus-send', ['--session','--print-reply',`--dest=${destination}`,path,method,...args])
  if (result.code !== 0) throw fixedFailure('dbus_call_failed')
  return result.stdout
}
const ownsSecrets = async () => (await call('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus.NameHasOwner','string:org.freedesktop.secrets')).includes('boolean true')
const waitFor = async (run, predicate, code) => {
  for (let count = 0; count < 80; count++) { const value = await run().catch(() => undefined); if (predicate(value)) return value; await new Promise(resolve => setTimeout(resolve, 100)) }
  throw fixedFailure(code)
}
const stop = async child => {
  if (!child || child.exitCode !== null || child.signalCode !== null) return
  await new Promise(resolve => {
    const timer = setTimeout(() => { child.kill('SIGKILL') }, 3000)
    child.once('close', () => { clearTimeout(timer); resolve() }); child.kill('SIGTERM')
  })
}
const rejectCredentials = async run => {
  try { await run() } catch (error) { if (error?.code === 'credential_unavailable') return; throw fixedFailure('unexpected_credential_error') }
  throw fixedFailure('credentials_unexpectedly_available')
}
const stdinJson = async () => { const parts=[]; for await (const chunk of process.stdin) parts.push(chunk); return JSON.parse(Buffer.concat(parts).toString('utf8')) }
if (process.argv[2] === '--child') {
  const input = await stdinJson()
  const secrets = new KeyringSecretStore(input.service, input.locks)
  const key = await secrets.getEncryptionKey(input.secretNamespace)
  assert(key && digest(key) === input.keyHash)
  const state = await new PapStore(input.papRoot, secrets, input.namespace).read()
  assert.equal(digest(state.nonces.marker), input.markerHash)
  key.fill(0)
  process.stdout.write(JSON.stringify({ passed: true, newProcessKeyAndStateRestored: true }))
  process.exit(0)
}

const started = new Date().toISOString(); const checks=[]; let stage='isolation_setup'; let bus; let daemon
const password = randomBytes(32).toString('base64url')
const secretBytes = []; const originalHome = process.env.HOME
const check = (name, details={}) => checks.push({name,result:'passed',...details})
const beforeSource = Object.fromEntries(await Promise.all(sourceFiles.map(async path => [path,digest(await readFile('/opt/dsh-pap/source/'+path))])))
let result
try {
  assert.equal(Object.keys(networkInterfaces()).filter(name=>name!=='lo').length,0)
  const rootMount = (await readFile('/proc/mounts','utf8')).split('\n').find(line=>line.split(' ')[1]==='/')
  assert(rootMount?.split(' ')[3]?.split(',').includes('ro'))
  for (const name of ['runtime','data','config','cache','state','control','locks','pap']) await mkdir(join(taskRoot,name),{recursive:true,mode:0o700})
  for (const [name,folder] of Object.entries({XDG_RUNTIME_DIR:'runtime',XDG_DATA_HOME:'data',XDG_CONFIG_HOME:'config',XDG_CACHE_HOME:'cache',XDG_STATE_HOME:'state',GNOME_KEYRING_CONTROL:'control'})) process.env[name]=join(taskRoot,folder)
  for(const name of ['DBUS_SESSION_BUS_ADDRESS','DBUS_STARTER_ADDRESS','DBUS_STARTER_BUS_TYPE','SSH_AUTH_SOCK','GPG_AGENT_INFO']) delete process.env[name]
  const config=join(taskRoot,'session.conf')
  await writeFile(config,'<busconfig><type>session</type><listen>unix:path='+join(taskRoot,'runtime/bus')+'</listen><auth>EXTERNAL</auth><policy context="default"><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>',{mode:0o600})
  bus=spawn('dbus-daemon',['--nofork','--config-file='+config,'--print-address=1'],{stdio:['ignore','pipe','ignore']})
  const address=await new Promise((resolve,reject)=>{const lines=createInterface({input:bus.stdout});const timer=setTimeout(()=>reject(fixedFailure('private_bus_timeout')),5000);lines.once('line',line=>{clearTimeout(timer);resolve(line);lines.close()});bus.once('error',()=>reject(fixedFailure('private_bus_failed')))})
  process.env.DBUS_SESSION_BUS_ADDRESS=address
  assert.equal(await ownsSecrets(),false)
  check('private_bus_network_none_readonly_root',{activationDirectories:false,hostHomePreserved:process.env.HOME===originalHome})
  const startDaemon = async () => {
    const child=spawn('gnome-keyring-daemon',['--foreground','--unlock','--components=secrets','--control-directory='+process.env.GNOME_KEYRING_CONTROL],{stdio:['pipe','ignore','ignore'],env:process.env})
    child.stdin.on('error',()=>{});child.stdin.end(password)
    await waitFor(ownsSecrets,value=>value===true,'secret_service_start_failed')
    return child
  }
  stage='create_and_get';daemon=await startDaemon()
  const service='dsh-pap-secretservice-'+randomUUID();const namespace='verification-'+randomUUID();const secretNamespace='pap/'+namespace
  const locks=join(taskRoot,'locks');const papRoot=join(taskRoot,'pap');const secrets=new KeyringSecretStore(service,locks)
  const key=await secrets.getOrCreateEncryptionKey(secretNamespace);secretBytes.push(Buffer.from(key))
  assert.equal(key.length,32);const again=await secrets.getEncryptionKey(secretNamespace);assert(again && Buffer.from(again).equals(Buffer.from(key)));again.fill(0)
  check('real_secret_service_create_get')
  const marker=randomBytes(32).toString('base64url');const pap=new PapStore(papRoot,secrets,namespace)
  await pap.transaction(state=>{state.nonces.marker=marker})
  const encryptedPath=join(papRoot,'pap-state.enc');const encryptedBefore=await readFile(encryptedPath);let stateHash=digest(encryptedBefore)
  assert(!encryptedBefore.includes(Buffer.from(marker))&&!encryptedBefore.includes(Buffer.from(key).toString('base64url')))
  check('real_pap_encrypted_transaction')
  const childInput=JSON.stringify({service,namespace,secretNamespace,locks,papRoot,keyHash:digest(key),markerHash:digest(marker)})
  const child=await execute(process.execPath,['/opt/verification/verify.mjs','--child'],childInput)
  assert.equal(child.code,0);assert.equal(JSON.parse(child.stdout).passed,true)
  check('new_node_process_key_and_state_recovery')
  stage='daemon_restart';const oldPid=daemon.pid;await stop(daemon);daemon=undefined;await waitFor(ownsSecrets,value=>value===false,'secret_service_did_not_stop')
  await rm(join(taskRoot,'control'),{recursive:true,force:true});await mkdir(join(taskRoot,'control'),{mode:0o700});daemon=await startDaemon();assert.notEqual(daemon.pid,oldPid)
  const afterRestart=await secrets.getEncryptionKey(secretNamespace);assert(afterRestart&&Buffer.from(afterRestart).equals(Buffer.from(key)));afterRestart.fill(0)
  assert.equal((await pap.read()).nonces.marker,marker)
  check('gnome_keyring_daemon_restart_existing_encrypted_state');stateHash=digest(await readFile(encryptedPath))
  stage='locked_collection';const alias=await call('org.freedesktop.secrets','/org/freedesktop/secrets','org.freedesktop.Secret.Service.ReadAlias','string:default')
  const collection=alias.match(/object path "([^"]+)"/)?.[1];assert(collection&&collection!=='/')
  await call('org.freedesktop.secrets','/org/freedesktop/secrets','org.freedesktop.Secret.Service.Lock','array:objpath:'+collection)
  const locked=await call('org.freedesktop.secrets',collection,'org.freedesktop.DBus.Properties.Get','string:org.freedesktop.Secret.Collection','string:Locked');assert(locked.includes('boolean true'))
  stage='locked_key_lookup';
  let inaccessible=false;try{const value=await secrets.getEncryptionKey(secretNamespace);inaccessible=value===undefined;if(value)value.fill(0)}catch(error){inaccessible=error?.code==='credential_unavailable'}assert(inaccessible)
  stage='locked_key_create';await rejectCredentials(()=>secrets.getOrCreateEncryptionKey(secretNamespace));
  stage='locked_state_read';await rejectCredentials(()=>pap.read());
  stage='locked_state_unchanged';assert.equal(digest(await readFile(encryptedPath)),stateHash)
  check('locked_secret_service_denies_credentials_and_state_unchanged')
  stage='restart_unlock_after_lock';await stop(daemon);daemon=undefined;await waitFor(ownsSecrets,value=>value===false,'locked_daemon_did_not_stop')
  await rm(join(taskRoot,'control'),{recursive:true,force:true});await mkdir(join(taskRoot,'control'),{mode:0o700});daemon=await startDaemon()
  await waitFor(()=>call('org.freedesktop.secrets',collection,'org.freedesktop.DBus.Properties.Get','string:org.freedesktop.Secret.Collection','string:Locked'),value=>value?.includes('boolean false'),'secret_service_restart_unlock_failed')
  assert.equal((await pap.read()).nonces.marker,marker);const restoredKey=await secrets.getEncryptionKey(secretNamespace);assert(restoredKey&&Buffer.from(restoredKey).equals(Buffer.from(key)));restoredKey.fill(0);check('daemon_restart_unlock_restores_same_existing_state');stateHash=digest(await readFile(encryptedPath))
  stage='missing_item';const cleared=await execute('secret-tool',['clear','service',service,'namespace',secretNamespace]);assert.equal(cleared.code,0);assert.equal(await secrets.getEncryptionKey(secretNamespace),undefined)
  await rejectCredentials(()=>pap.read());await rejectCredentials(()=>pap.transaction(state=>{state.nonces.unexpected='must-not-write'}))
  assert.equal(digest(await readFile(encryptedPath)),stateHash);assert.equal(await secrets.getEncryptionKey(secretNamespace),undefined)
  check('deleted_item_existing_encrypted_state_fails_without_recreation_or_rewrite')
  const sensitive=[Buffer.from(key),Buffer.from(key).toString('base64url'),marker,password].map(value=>Buffer.isBuffer(value)?value:Buffer.from(value))
  const scan=async directory=>{for(const name of await readdir(directory)){const path=join(directory,name);const info=await lstat(path);if(info.isDirectory())await scan(path);else if(info.isFile()){const bytes=await readFile(path);assert(sensitive.every(value=>!bytes.includes(value)))}}}
  await scan(taskRoot);check('no_plaintext_key_password_marker_or_file_fallback')
  key.fill(0)
  const afterSource=Object.fromEntries(await Promise.all(sourceFiles.map(async path=>[path,digest(await readFile('/opt/dsh-pap/source/'+path))])))
  assert.deepEqual(beforeSource,afterSource)
  result={schema_version:1,status:'passed',evidence_level:'isolated_container_real_secret_service',recorded_at:started,node:process.version,platform:process.platform,checks,source_sha256:beforeSource,package_versions:(await readFile('/opt/verification/dpkg-versions.tsv','utf8')).trim().split('\n').map(line=>{const [name,version]=line.split('\t');return{name,version}}),limits:{hostKeyringAccessed:false,sharedDaemonStarted:false,hostPackagesInstalled:false,agentPrivateKeysImported:false,network:'none',rootFilesystem:'read-only',password:'stdin-and-memory-only',keyringState:'private-tmpfs',hostHomePreserved:process.env.HOME===originalHome}}
} catch(error) {
  result={schema_version:1,status:'failed',evidence_level:'isolated_container_real_secret_service',recorded_at:started,stage,error_code:typeof error?.code==='string'&&/^[A-Za-z0-9_]+$/.test(error.code)?error.code:'verification_failed',checks,source_sha256:beforeSource}
  process.exitCode=1
} finally {
  await stop(daemon);await stop(bus);for(const value of secretBytes)value.fill(0)
  for(const name of await readdir(taskRoot).catch(()=>[]))await rm(join(taskRoot,name),{recursive:true,force:true})
  const privateStateRemoved=(await readdir(taskRoot).catch(()=>[])).length===0
  result.cleanup={secretServiceStopped:!daemon||daemon.exitCode!==null||daemon.signalCode!==null,privateBusStopped:!bus||bus.exitCode!==null||bus.signalCode!==null,privateStateRemoved}
  await writeFile('/evidence/result.json',JSON.stringify(result,null,2)+'\n',{mode:0o600})
  console.log(JSON.stringify({status:result.status,evidence_level:result.evidence_level,stage:result.stage,checks_passed:checks.length,cleanup:result.cleanup}))
}
