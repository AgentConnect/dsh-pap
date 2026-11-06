/** Focused Host KeyringSecretStore/PapStore check using a real private container backend. */
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn } from 'node:child_process';
import { KeyringSecretStore } from '../src/keyring.js';
import { PapStore } from '../src/store.js';
import { archiveCredentials } from '../src/credential-history.js';
import { createSecretServiceSidecar } from './helpers/secret-service-sidecar.js';

const originalPath = process.env.PATH; const originalHome = process.env.HOME;
const root = await mkdtemp(join(tmpdir(),'pap-sidecar-component-'));
let sidecar: Awaited<ReturnType<typeof createSecretServiceSidecar>> | undefined;
let cleanup: unknown;
try {
  sidecar = await createSecretServiceSidecar(); process.env.PATH = sidecar.binDirectory+':'+originalPath;
  const service = 'pap-sidecar-'+randomUUID(); const namespace = 'isolated-'+randomUUID();
  const locks = join(root,'locks'); const stateRoot = join(root,'state');
  const secret = new KeyringSecretStore(service,locks); const store = new PapStore(stateRoot,secret,namespace);
  const marker = randomUUID(); const privateToken=randomUUID(); await store.transaction(state => { state.nonces.marker = marker; archiveCredentials(state,[privateToken]); });
  assert.equal((await store.read()).nonces.marker, marker);
  assert(!(await readFile(join(stateRoot,'pap-state.enc'))).includes(Buffer.from(marker)));
  assert(!(await readFile(join(stateRoot,'pap-state.enc'))).includes(Buffer.from(privateToken)));
  const key = await secret.getEncryptionKey('pap/'+namespace); assert.equal(key?.length,32); key?.fill(0);
  await sidecar.restart(); assert.equal((await store.read()).nonces.marker,marker);
  const code = 'import {PapStore} from '+JSON.stringify(new URL('../lib/store.js',import.meta.url).href)+';import{KeyringSecretStore}from '+JSON.stringify(new URL('../lib/keyring.js',import.meta.url).href)+';import{CredentialHistory}from '+JSON.stringify(new URL('../lib/credential-history.js',import.meta.url).href)+';let b="";for await(const c of process.stdin)b+=c;const p=JSON.parse(b);const s=await new PapStore(p.stateRoot,new KeyringSecretStore(p.service,p.locks),p.namespace).read();const history=new CredentialHistory();history.restore(s);if(s.nonces.marker!==p.marker||!history.values().includes(p.privateToken)||s.credentialVault.completeness!=="complete")process.exit(1);console.log(JSON.stringify({passed:true}));';
  const child = spawn(process.execPath,['--input-type=module','-e',code],{stdio:['pipe','pipe','ignore'],env:process.env});
  let output = ''; child.stdout.on('data',chunk=>{output+=String(chunk);}); child.stdin.end(JSON.stringify({stateRoot,service,locks,namespace,marker,privateToken}));
  const exit = await new Promise(resolve=>child.once('close',resolve)); assert.equal(exit,0); assert.equal(JSON.parse(output).passed,true);
  const facts = { imageId:sidecar.imageId, socket:sidecar.socket, packages:sidecar.facts.packages };
  cleanup = await sidecar.stop(); sidecar = undefined;
  assert.equal((cleanup as any).containerRemoved,true); assert.equal((cleanup as any).cleanup.privateStateRemoved,true);
  assert.equal(process.env.HOME,originalHome);
  console.log(JSON.stringify({stage:'passed',boundary:'host_real_F_secret_tool_shim_to_private_container_SecretService',
    checks:['actual_secret_service_key_create_get','actual_PapStore_encrypted_state_and_private_vault','daemon_restart_same_key_state','new_Host_Node_process_and_vault_restore'],
    facts,defaultBackendClass:'KeyringSecretStore',memorySecret:false,hostPackagesInstalled:false,hostKeyringAccessed:false,homePreserved:true,cleanup}));
} finally { process.env.PATH=originalPath; await sidecar?.stop(); await rm(root,{recursive:true,force:true}); }
