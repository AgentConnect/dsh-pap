import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { mkdir, open, readFile, rename, rm } from 'node:fs/promises';
import { join } from 'node:path';
import lockfile from 'proper-lockfile';
import type { HostSecretStore } from './host.js';
import type { PapState } from './types.js';
import { PapError, requirePap } from './errors.js';
import { syncDirectory } from './file-secrets.js';
import { ensureCredentialVault } from './credential-history.js';
const empty = (): PapState => ({ schemaVersion: 1, generation: 0, companies: {}, subjects: {}, sessions: {}, delegations: {}, grants: {}, transactions: {}, nonces: {}, cooldowns: {}, retirements: {}, accountSlots: {}, delegationAttempts: {},credentialVault:{version:1,completeness:'complete',entries:{},blocked:false} });

/** Encrypted, cross-process serialized transactions. The master key stays in Host secret storage. */
export class PapStore {
  private readonly path: string;
  constructor(readonly root: string, private readonly secrets: HostSecretStore, private readonly namespace: string) { this.path = join(root, 'pap-state.enc'); }
  private async key(existing: boolean): Promise<Buffer> {
    try {
      const material = existing ? await this.secrets.getEncryptionKey(`pap/${this.namespace}`) : await this.secrets.getOrCreateEncryptionKey(`pap/${this.namespace}`);
      requirePap(material, 'credential_unavailable');
      const key = Buffer.from(material);
      requirePap(key.length === 32, 'credential_unavailable'); return key;
    } catch { throw new PapError('credential_unavailable'); }
  }
  async transaction<T>(fn: (state: PapState) => T | Promise<T>): Promise<T> {
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    const release = await lockfile.lock(this.root, { realpath: true, stale: 30000, update: 5000, retries: { retries: 80, minTimeout: 10, maxTimeout: 100 } });
    let key: Buffer | undefined;
    try {
      let bytes: Buffer | undefined;
      try { bytes = await readFile(this.path); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw new PapError('state_corrupt'); }
      key = await this.key(bytes !== undefined);
      let state: PapState;
      try {
        if (!bytes) state = empty();
        else {
        requirePap(bytes.length > 33 && bytes.subarray(0, 5).toString() === 'PAP01', 'state_corrupt');
        const decipher = createDecipheriv('aes-256-gcm', key, bytes.subarray(5, 17));
        decipher.setAAD(Buffer.from(`pap-state/1/${this.namespace}`));
        decipher.setAuthTag(bytes.subarray(17, 33));
        state = JSON.parse(Buffer.concat([decipher.update(bytes.subarray(33)), decipher.final()]).toString());
        requirePap(state.schemaVersion === 1 && Number.isSafeInteger(state.generation) && state.companies && state.subjects && state.sessions && state.delegations && state.grants && state.transactions && state.nonces && state.retirements, 'state_corrupt');
        // Additive migration of the first private candidate; closed slots stay closed.
        state.accountSlots ??= {}; state.delegationAttempts ??= {}; state.cooldowns ??= {};
        for (const grant of Object.values(state.grants)) {
          grant.accountEpoch ??= 1;
          const slot = state.accountSlots[grant.accountSlot] ??= { subjectRef: grant.subjectRef, epoch: grant.accountEpoch, signedOut: false };
          if (['signed_out','revocation_pending'].includes(grant.status)) slot.signedOut = true;
        }
        for (const tx of Object.values(state.transactions)) {
          tx.accountEpoch ??= 1;
          const slot = state.accountSlots[tx.accountSlot] ??= { subjectRef: tx.subjectRef, epoch: tx.accountEpoch, signedOut: false };
          if (slot.signedOut) { tx.status = 'cancelled'; tx.verifier = ''; delete tx.callbackRef; }
        }
        ensureCredentialVault(state);
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') state = empty();
        else throw new PapError('state_corrupt');
      }
      const result = await fn(state);
      state.generation++;
      const iv = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', key, iv);
      cipher.setAAD(Buffer.from(`pap-state/1/${this.namespace}`));
      const encrypted = Buffer.concat([cipher.update(JSON.stringify(state)), cipher.final()]);
      const temp = join(this.root, `.pap-${randomBytes(12).toString('hex')}.tmp`);
      try {
        const file = await open(temp, 'wx', 0o600);
        try { await file.writeFile(Buffer.concat([Buffer.from('PAP01'), iv, cipher.getAuthTag(), encrypted])); await file.sync(); } finally { await file.close(); }
        await rename(temp, this.path);
        await syncDirectory(this.root);
      } finally { await rm(temp, { force: true }); }
      return structuredClone(result);
    } finally { key?.fill(0); await release(); }
  }
  async read(): Promise<PapState> { return this.transaction(state => state); }
  async recover(): Promise<void> {
    await this.transaction(state => {
      for (const grant of Object.values(state.grants)) if (grant.status === 'refreshing') { grant.status = 'uncertain'; grant.generation++; }
      for (const tx of Object.values(state.transactions)) if (tx.status === 'exchanging') tx.status = 'failed';
    });
  }
}
