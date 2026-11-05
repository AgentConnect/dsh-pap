import { spawn } from 'node:child_process';
import { mkdir } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { randomBytes } from 'node:crypto';
import lockfile from 'proper-lockfile';
import type { HostSecretStore } from './host.js';
import { PapError, requirePap } from './errors.js';

/** Linux Secret Service adapter. No file fallback; a locked/missing keyring blocks credentials. */
export class KeyringSecretStore implements HostSecretStore {
  constructor(private readonly service: string, private readonly locksRoot: string) {
    requirePap(service.length > 0 && isAbsolute(locksRoot), 'credential_unavailable');
  }
  private command(args: string[], input?: string): Promise<{ code: number; value: string }> {
    return new Promise((resolve, reject) => {
      const child = spawn('secret-tool', args, { stdio: ['pipe','pipe','ignore'], env: process.env });
      let value = ''; const timeout = setTimeout(() => { child.kill('SIGKILL'); reject(new PapError('credential_unavailable')); }, 5000);
      child.stdout.on('data', chunk => { value += String(chunk); if (value.length > 256) { child.kill('SIGKILL'); clearTimeout(timeout); reject(new PapError('credential_unavailable')); } });
      child.on('error', () => { clearTimeout(timeout); reject(new PapError('credential_unavailable')); });
      child.on('close', code => { clearTimeout(timeout); resolve({ code: code ?? -1, value: value.trim() }); });
      child.stdin.on('error', () => {}); child.stdin.end(input === undefined ? undefined : `${input}\n`);
    });
  }
  async getEncryptionKey(namespace: string): Promise<Uint8Array | undefined> {
    requirePap(process.platform === 'linux', 'credential_unavailable');
    const result = await this.command(['lookup','service',this.service,'namespace',namespace]);
    if (result.code === 1 && result.value === '') return undefined;
    requirePap(result.code === 0 && /^[A-Za-z0-9_-]{43}$/.test(result.value), 'credential_unavailable');
    return Buffer.from(result.value,'base64url');
  }
  async getOrCreateEncryptionKey(namespace: string): Promise<Uint8Array> {
    requirePap(process.platform === 'linux', 'credential_unavailable');
    await mkdir(this.locksRoot, { recursive:true, mode:0o700 });
    const release = await lockfile.lock(this.locksRoot, { retries: { retries: 60, minTimeout: 50, maxTimeout: 100 }, stale: 30000 });
    try {
      const attributes = ['service', this.service, 'namespace', namespace];
      const existing = await this.command(['lookup', ...attributes]);
      if (existing.code === 0) {
        requirePap(/^[A-Za-z0-9_-]{43}$/.test(existing.value), 'credential_unavailable');
        return Buffer.from(existing.value,'base64url');
      }
      requirePap(existing.code === 1 && existing.value === '', 'credential_unavailable');
      const key = randomBytes(32); const encoded=key.toString('base64url');
      const stored=await this.command(['store','--label=DSH PAP encrypted state',...attributes],encoded);
      requirePap(stored.code === 0, 'credential_unavailable');
      const checked=await this.command(['lookup',...attributes]);
      requirePap(checked.code===0&&checked.value===encoded, 'credential_unavailable');return key;
    } finally { await release(); }
  }
}
