import { PapError } from './errors.js';
import { createHash } from 'node:crypto';
import type { PapState } from './types.js';

const MAX_ENTRIES = 4096; const MAX_BYTES = 4 * 1024 * 1024;
export function ensureCredentialVault(state: PapState): NonNullable<PapState['credentialVault']> {
  if (!state.credentialVault) {
    const accountEvidence = Object.keys(state.grants).length > 0 || Object.keys(state.transactions).length > 0 || Object.keys(state.accountSlots ?? {}).length > 0
      || Object.keys(state.nonces).some(key => key.startsWith('authorization:')) || Object.values(state.retirements).some(value => value.key.purpose === 'pap_dpop');
    state.credentialVault = { version:1,completeness:accountEvidence?'legacy_incomplete':'complete',entries:{},blocked:false };
    // Seeding known current values never claims to reconstruct older replaced credentials.
    if (accountEvidence) for (const grant of Object.values(state.grants)) archiveCredentials(state,[grant.accessToken,grant.refreshToken]);
  }
  return state.credentialVault;
}
/** Called inside existing encrypted state transactions before replacing/clearing a credential. */
export function archiveCredentials(state: PapState, values: readonly (string | undefined)[]): void {
  const vault = ensureCredentialVault(state);
  let bytes = Object.values(vault.entries).reduce((total,value) => total + Buffer.byteLength(value),0);
  for (const value of values) {
    if (!value) continue;
    const key = createHash('sha256').update(JSON.stringify(value)).digest('hex'); if (vault.entries[key] !== undefined) continue;
    const size = Buffer.byteLength(value);
    if (Object.keys(vault.entries).length >= MAX_ENTRIES || bytes + size > MAX_BYTES) { vault.blocked = true; continue; }
    vault.entries[key] = value; bytes += size;
  }
}

export interface CredentialObservation { accessToken: string; accessExpiresInMs?: number; refreshToken?: string }
/** Service-private redaction history. Live/unknown credentials are never evicted to fit a budget. */
export class CredentialHistory {
  private readonly entries = new Map<string, { deadline: number; pins: Set<symbol> }>();
  private readonly active = new Set<symbol>();
  private bytes = 0;
  private blocked = false;
  private closed = false;
  constructor(private readonly clock = () => performance.now(), private readonly maxEntries = MAX_ENTRIES, private readonly maxBytes = MAX_BYTES) {}
  private sweep(): void {
    const now = this.clock();
    for (const [secret, entry] of this.entries) if (entry.deadline <= now && entry.pins.size === 0) { this.entries.delete(secret); this.bytes -= Buffer.byteLength(secret); }
  }
  assertUsable(): void { if (this.closed || this.blocked) throw new PapError('credential_unavailable'); }
  restore(state: PapState): void {
    if (state.credentialVault?.blocked) this.blocked = true;
    for (const value of Object.values(state.credentialVault?.entries ?? {})) this.rememberIfAbsent(value);
  }
  /** Never throws while an AS response is being persisted; a limit latches public output closed. */
  observe(input: CredentialObservation): void {
    this.remember(input.accessToken, input.accessExpiresInMs);
    if (input.refreshToken) this.remember(input.refreshToken);
  }
  /** Restored values have no trustworthy process-monotonic remaining lifetime. */
  rememberIfAbsent(secret: string): void { if (secret && !this.entries.has(secret)) this.remember(secret); }
  private remember(secret: string, lifetime?: number): void {
    if (!secret || this.closed || this.blocked) return;
    this.sweep();
    const deadline = lifetime === undefined || !Number.isFinite(lifetime) ? Infinity : this.clock() + Math.max(0, lifetime);
    const previous = this.entries.get(secret);
    if (previous) { previous.deadline = Math.max(previous.deadline, deadline); for (const pin of this.active) previous.pins.add(pin); return; }
    const size = Buffer.byteLength(secret);
    if (this.entries.size >= this.maxEntries || this.bytes + size > this.maxBytes) { this.blocked = true; return; }
    this.entries.set(secret, { deadline, pins: new Set(this.active) }); this.bytes += size;
  }
  begin(): symbol {
    this.assertUsable(); this.sweep(); const pin = Symbol(); this.active.add(pin);
    for (const entry of this.entries.values()) entry.pins.add(pin);
    return pin;
  }
  values(): string[] { this.assertUsable(); this.sweep(); return [...this.entries.keys()]; }
  end(pin: symbol): void { this.active.delete(pin); for (const entry of this.entries.values()) entry.pins.delete(pin); this.sweep(); }
  dispose(): void { this.closed = true; this.entries.clear(); this.active.clear(); this.bytes = 0; }
}
