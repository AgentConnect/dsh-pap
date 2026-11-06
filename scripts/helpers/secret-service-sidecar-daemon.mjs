/** Container-only private DBus/Secret Service. Control payloads and passwords are never logged. */
import { spawn } from 'node:child_process';
import { mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createInterface } from 'node:readline';

const root = '/run/task'; let bus; let daemon; let password;
const execute = (program, args) => new Promise((resolve, reject) => {
  const child = spawn(program, args, { stdio: ['ignore','pipe','ignore'], env: process.env }); let output = '';
  child.stdout.on('data', chunk => { output += String(chunk); if (output.length > 8192) child.kill('SIGKILL'); });
  child.once('error', () => reject(new Error('sidecar_command_failed'))); child.once('close', code => resolve({ code, output }));
});
const owns = async () => {
  const result = await execute('dbus-send', ['--session','--print-reply','--dest=org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus.NameHasOwner','string:org.freedesktop.secrets']);
  return result.code === 0 && result.output.includes('boolean true');
};
const wait = async predicate => {
  for (let count = 0; count < 80; count++) { if (await predicate()) return; await new Promise(resolve => setTimeout(resolve, 100)); }
  throw new Error('sidecar_readiness_failed');
};
const stopChild = async child => {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  await new Promise(resolve => { const timer = setTimeout(() => child.kill('SIGKILL'), 3000); child.once('close', () => { clearTimeout(timer); resolve(); }); child.kill('SIGTERM'); });
};
const startDaemon = async () => {
  daemon = spawn('gnome-keyring-daemon', ['--foreground','--unlock','--components=secrets','--control-directory='+join(root,'control')], { stdio: ['pipe','ignore','ignore'], env: process.env });
  daemon.stdin.on('error', () => {}); daemon.stdin.end(password); await wait(owns);
};
const cleanup = async () => {
  await stopChild(daemon); await stopChild(bus); password = undefined;
  for (const name of await readdir(root).catch(() => [])) await rm(join(root,name), { recursive:true, force:true });
  return { secretServiceStopped: !daemon || daemon.exitCode !== null || daemon.signalCode !== null, privateBusStopped: !bus || bus.exitCode !== null || bus.signalCode !== null, privateStateRemoved: (await readdir(root)).length === 0 };
};
const lines = createInterface({ input: process.stdin });
try {
  for await (const line of lines) {
    let input;
    try { input = JSON.parse(line); } catch { throw new Error('sidecar_invalid_control'); }
    if (input.action === 'initialize' && !bus && typeof input.password === 'string') {
      password = input.password;
      for (const folder of ['runtime','data','config','cache','state','control']) await mkdir(join(root,folder), { recursive:true, mode:0o700 });
      for (const [name, folder] of Object.entries({ XDG_RUNTIME_DIR:'runtime', XDG_DATA_HOME:'data', XDG_CONFIG_HOME:'config', XDG_CACHE_HOME:'cache', XDG_STATE_HOME:'state', GNOME_KEYRING_CONTROL:'control' })) process.env[name] = join(root,folder);
      for (const name of ['DBUS_SESSION_BUS_ADDRESS','DBUS_STARTER_ADDRESS','DBUS_STARTER_BUS_TYPE','SSH_AUTH_SOCK','GPG_AGENT_INFO']) delete process.env[name];
      await writeFile(join(root,'session.conf'), '<busconfig><type>session</type><listen>unix:path=/run/task/runtime/bus</listen><auth>EXTERNAL</auth><policy context="default"><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>', { mode:0o600 });
      bus = spawn('dbus-daemon', ['--nofork','--config-file='+join(root,'session.conf')], { stdio:['ignore','ignore','ignore'] });
      process.env.DBUS_SESSION_BUS_ADDRESS = 'unix:path=/run/task/runtime/bus';
      await wait(async () => { const result = await execute('dbus-send', ['--session','--print-reply','--dest=org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus.ListNames']); return result.code === 0; });
      await startDaemon();
      const packages = await execute('dpkg-query', ['-W','-f=${Package}=${Version}\n','libsecret-tools','gnome-keyring','dbus']);
      if (packages.code !== 0) throw new Error('sidecar_package_facts_failed');
      console.log(JSON.stringify({ stage:'ready', packages:packages.output.trim().split('\n'), privateBus:true, activationDirectories:false }));
    } else if (input.action === 'restart' && bus) {
      await stopChild(daemon); await wait(async () => !(await owns()));
      await rm(join(root,'control'), { recursive:true, force:true }); await mkdir(join(root,'control'), { mode:0o700 });
      await startDaemon(); console.log(JSON.stringify({ stage:'restarted' }));
    } else if (input.action === 'stop') {
      console.log(JSON.stringify({ stage:'stopped', cleanup:await cleanup() })); lines.close(); break;
    } else throw new Error('sidecar_invalid_control');
  }
} catch { console.log(JSON.stringify({ stage:'failed', error:'secret_service_sidecar_failed' })); process.exitCode = 1; }
finally { await cleanup(); }
