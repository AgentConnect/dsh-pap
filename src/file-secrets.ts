import { randomBytes, createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, lstat, mkdir, open, link, rm } from 'node:fs/promises';
import { isAbsolute, join, resolve, relative, sep } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { HostSecretStore } from './host.js';
import { PapError, requirePap } from './errors.js';

const execute = promisify(execFile);

/** Protect only this user's directory/file; Windows uses DACLs rather than chmod. */
async function protect(path: string, directory: boolean): Promise<void> {
  const info = await lstat(path);
  requirePap(!info.isSymbolicLink() && (directory ? info.isDirectory() : info.isFile()), 'credential_unavailable');
  if (process.platform !== 'win32') {
    requirePap(typeof process.getuid === 'function' && info.uid === process.getuid(), 'credential_unavailable');
    await chmod(path, directory ? 0o700 : 0o600);
    return;
  }
  // Paths travel in the child environment, never as executable PowerShell text.
  const script = `
$ErrorActionPreference = 'Stop'
$p = $env:DSH_PAP_PROTECT_PATH
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$old = Get-Acl -LiteralPath $p
if ($old.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) { throw 'Unexpected owner' }
$acl = $old
if ($env:DSH_PAP_PROTECT_DIRECTORY -eq '1') {
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
} else {
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')
}
$acl.SetAccessRuleProtection($true, $false)
foreach ($existing in @($acl.Access)) { $acl.RemoveAccessRuleSpecific($existing) }
$acl.AddAccessRule($rule)
if ($env:DSH_PAP_PROTECT_DIRECTORY -eq '1') {
  [System.IO.Directory]::SetAccessControl($p, $acl)
} else {
  [System.IO.File]::SetAccessControl($p, $acl)
}
`;
  const env: NodeJS.ProcessEnv = { ...process.env, DSH_PAP_PROTECT_PATH: path, DSH_PAP_PROTECT_DIRECTORY: directory ? '1' : '0' };
  // Windows PowerShell must resolve its own modules instead of inheriting PowerShell 7 paths.
  delete env.PSModulePath;
  await execute('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], {
    env,
    timeout: 10000, windowsHide: true, maxBuffer: 4096,
  });
}

/** Flush directories where the OS supports opening them; Windows still flushes files. */
export async function syncDirectory(path: string): Promise<void> {
  if (process.platform === 'win32') return;
  const directory = await open(path, 'r');
  try { await directory.sync(); } finally { await directory.close(); }
}

/** File-backed PAP state encryption keys. Identity/signing keys remain in native custody. */
export class FileSecretStore implements HostSecretStore {
  readonly root: string;
  constructor(root: string) {
    requirePap(isAbsolute(root), 'credential_unavailable');
    this.root = resolve(root);
  }
  assertSeparateFrom(stateRoot: string): void {
    const inside = (parent: string, child: string) => {
      const path = relative(resolve(parent), resolve(child));
      return path === '' || (path !== '..' && !path.startsWith('..' + sep) && !isAbsolute(path));
    };
    requirePap(!inside(stateRoot, this.root) && !inside(this.root, stateRoot), 'credential_unavailable');
  }
  private path(namespace: string): string {
    requirePap(typeof namespace === 'string' && namespace.length > 0, 'credential_unavailable');
    return join(this.root, createHash('sha256').update(namespace).digest('hex') + '.key');
  }
  private async prepare(): Promise<void> {
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    await protect(this.root, true);
  }
  private async read(path: string): Promise<Uint8Array | undefined> {
    try {
      await protect(path, false);
      const file = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      try {
        const info = await file.stat();
        requirePap(info.isFile() && info.size === 32, 'credential_unavailable');
        const value = await file.readFile();
        requirePap(value.length === 32, 'credential_unavailable');
        return value;
      } finally { await file.close(); }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      throw new PapError('credential_unavailable');
    }
  }
  async getEncryptionKey(namespace: string): Promise<Uint8Array | undefined> {
    try { await this.prepare(); return await this.read(this.path(namespace)); }
    catch { throw new PapError('credential_unavailable'); }
  }
  async getOrCreateEncryptionKey(namespace: string): Promise<Uint8Array> {
    let temporary: string | undefined;
    let material: Buffer | undefined;
    try {
      await this.prepare();
      const path = this.path(namespace);
      const existing = await this.read(path);
      if (existing) return existing;
      temporary = join(this.root, '.' + randomBytes(16).toString('hex') + '.tmp');
      const file = await open(temporary, 'wx', 0o600);
      try {
        await protect(temporary, false);
        material = randomBytes(32);
        await file.writeFile(material); await file.sync();
      } finally { await file.close(); }
      // A hard link publishes a fully written key atomically without replacing a winner.
      try { await link(temporary, path); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
      await syncDirectory(this.root);
      const result = await this.read(path);
      requirePap(result, 'credential_unavailable');
      return result;
    } catch { throw new PapError('credential_unavailable'); }
    finally { material?.fill(0); if (temporary) await rm(temporary, { force: true }).catch(() => { throw new PapError('credential_unavailable'); }); }
  }
}
