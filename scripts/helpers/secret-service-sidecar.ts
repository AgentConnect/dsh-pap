/** Reuses a task-owned cached image as daemon/secret-tool only; F and C remain Host processes. */
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, mkdtemp, readFile, rm, writeFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { createInterface } from 'node:readline';
import { tmpdir } from 'node:os';

const exec = promisify(execFile);
export const SECRET_SERVICE_IMAGE = 'sha256:fea7c2a0f03570a8bc636c1d3c19505a79964bb0b7f573363d7473fe039aa72c';
export async function createSecretServiceSidecar(options: { signal?: AbortSignal } = {}) {
  const root = await mkdtemp(join(tmpdir(), 'pap-secretservice-sidecar-')); const bin = join(root,'bin'); await mkdir(bin, { mode:0o700 });
  let cleanupStartup = async () => { await rm(root, { recursive:true, force:true }); };
  let cancelContainer: (() => void) | undefined;
  const abort = () => cancelContainer?.(); options.signal?.addEventListener('abort', abort, { once:true });
  try {
  if (options.signal?.aborted) throw new Error('Secret Service sidecar cancelled');
  const socket = '/var/run/docker.sock'; const socketUrl = `unix://${socket}`;
  const dockerConfig = join(root,'docker-config'); await mkdir(dockerConfig, { mode:0o700 });
  const cliEnv = { PATH:process.env.PATH, HOME:process.env.HOME, DOCKER_CONFIG:dockerConfig };
  let docker: string; let image: any;
  try {
    if (!(await stat(socket)).isSocket()) throw new Error('A local Docker socket is required');
    docker = (await exec('which', ['docker'])).stdout.trim();
    image = JSON.parse((await exec(docker, ['--host',socketUrl,'image','inspect',SECRET_SERVICE_IMAGE], { env:cliEnv })).stdout)[0];
  } catch { await rm(root, { recursive:true, force:true }); throw new Error('The required local Secret Service image is unavailable'); }
  if (image.Id !== SECRET_SERVICE_IMAGE) throw new Error('Unexpected Secret Service image');
  const name = `pap-secretservice-${randomBytes(8).toString('hex')}`;
  const uid = String(process.getuid!()); const gid = String(process.getgid!());
  const daemon = await readFile(fileURLToPath(new URL('./secret-service-sidecar-daemon.mjs',import.meta.url)), 'utf8');
  if (options.signal?.aborted) throw new Error('Secret Service sidecar cancelled');
  const flags = ['--host',socketUrl,'run','--rm','--name',name,'--label','org.agentconnect.task=pap-private-secretservice-sidecar','--interactive','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','96','--memory','256m','--cpus','1','--user',`${uid}:${gid}`,
    '--tmpfs',`/run/task:rw,nosuid,nodev,noexec,size=32m,mode=0700,uid=${uid},gid=${gid}`,'--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777','--entrypoint','node',SECRET_SERVICE_IMAGE,'--input-type=module','-e',daemon];
  const child = spawn(docker, flags, { stdio:['pipe','pipe','ignore'], env:cliEnv });
  cancelContainer = () => { void exec(docker, ['--host',socketUrl,'rm','--force',name], { env:cliEnv }).catch(() => {}); };
  child.stdin.on('error', () => {});
  const exit = new Promise<number>(resolve => { child.once('error', () => resolve(-1)); child.once('close', code => resolve(code ?? -1)); });
  const queued: unknown[] = []; let pending: ((value: any) => void) | undefined;
  child.once('close', () => { if (pending) { const next = pending; pending = undefined; next({ stage:'failed' }); } });
  const lines = createInterface({ input: child.stdout });
  lines.on('line', line => { let value: unknown; try { value = JSON.parse(line); } catch { value = { stage:'failed' }; } if (pending) { const next = pending; pending = undefined; next(value); } else queued.push(value); });
  const receive = async () => {
    if (queued.length) return queued.shift() as any;
    return new Promise<any>((resolve, reject) => { const timer = setTimeout(() => { pending = undefined; reject(new Error('Secret Service sidecar readiness failed')); }, 15000); pending = value => { clearTimeout(timer); resolve(value); }; });
  };
  let stopped: Promise<any> | undefined;
  const stop = () => stopped ??= (async () => {
    let cleanup: unknown; let graceful = false;
    try { if (child.exitCode === null && child.signalCode === null) { child.stdin.write(JSON.stringify({ action:'stop' })+'\n'); const result = await receive(); cleanup = result.cleanup; graceful = result.stage === 'stopped'; child.stdin.end(); } } catch {}
    if (!graceful) await exec(docker, ['--host',socketUrl,'rm','--force',name], { env:cliEnv }).catch(() => {});
    const code = await exit; lines.close();
    let absent = false; try { await exec(docker, ['--host',socketUrl,'inspect',name], { env:cliEnv }); } catch { absent = true; }
    await rm(root, { recursive:true, force:true });
    options.signal?.removeEventListener('abort', abort);
    return { graceful, exitCode:code, containerRemoved:absent, shimRemoved:true, cleanup };
  })();
  cleanupStartup = async () => { await stop(); };
  try {
    const password = randomBytes(32); child.stdin.write(JSON.stringify({ action:'initialize', password:password.toString('base64url') })+'\n'); password.fill(0);
    const ready = await receive(); if (ready.stage !== 'ready') throw new Error('Secret Service sidecar failed');
    if (options.signal?.aborted) throw new Error('Secret Service sidecar cancelled');
    const container = JSON.parse((await exec(docker, ['--host',socketUrl,'inspect',name], { env:cliEnv })).stdout)[0];
    if (!/^[0-9a-f]{64}$/.test(container.Id) || container.Image !== SECRET_SERVICE_IMAGE || container.State.Running !== true || container.HostConfig.NetworkMode !== 'none' || container.HostConfig.ReadonlyRootfs !== true) throw new Error('Unexpected Secret Service container');
    const environment = { DBUS_SESSION_BUS_ADDRESS:'unix:path=/run/task/runtime/bus', XDG_RUNTIME_DIR:'/run/task/runtime', XDG_DATA_HOME:'/run/task/data', XDG_CONFIG_HOME:'/run/task/config', XDG_CACHE_HOME:'/run/task/cache', XDG_STATE_HOME:'/run/task/state', GNOME_KEYRING_CONTROL:'/run/task/control' };
    const args = ['--host',socketUrl,'exec','--interactive',...Object.entries(environment).flatMap(([key,value]) => ['--env',`${key}=${value}`]),container.Id,'/usr/bin/secret-tool'];
    const shim = '#!'+process.execPath+'\n'+
      "const {spawnSync}=require('node:child_process');const a=process.argv.slice(2);"+
      "const ok=((a[0]==='lookup'||a[0]==='clear')&&a.length===5&&a[1]==='service'&&a[3]==='namespace')||(a[0]==='store'&&a.length===6&&a[1]==='--label=DSH PAP encrypted state'&&a[2]==='service'&&a[4]==='namespace');"+
      "if(!ok||a.some(v=>v.length>2048||/[\\x00-\\x1f\\x7f]/.test(v)))process.exit(2);"+
      'const r=spawnSync('+JSON.stringify(docker)+','+JSON.stringify(args)+'.concat(a),{stdio:"inherit",env:'+JSON.stringify(cliEnv)+'});process.exit(r.status??2);\n';
    await writeFile(join(bin,'secret-tool'), shim, { mode:0o700 });
    return { binDirectory:bin, containerName:name, containerId:container.Id, socket:socketUrl, imageId:image.Id, facts:ready,
      async restart() { child.stdin.write(JSON.stringify({ action:'restart' })+'\n'); const result = await receive(); if (result.stage !== 'restarted') throw new Error('Secret Service restart failed'); }, stop };
  } catch (error) { await stop(); throw error; }
  } catch (error) { await cleanupStartup(); options.signal?.removeEventListener('abort', abort); throw error; }
}
