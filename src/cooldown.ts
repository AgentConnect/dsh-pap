import { PapError, requirePap } from './errors.js';
import type { HttpResponse, PapState } from './types.js';
import { sha256 } from './util.js';

export const resourceCooldownKey = (companyId: string, resource: string) => sha256(JSON.stringify(['resource', companyId, resource]));
export const asCooldownKey = (companyId: string, issuer: string) => sha256(JSON.stringify(['authorization_server', companyId, issuer]));
export function responseHeader(response: HttpResponse, name: string): string | undefined {
  const found = Object.entries(response.headers).filter(([key]) => key.toLowerCase() === name.toLowerCase());
  return found.length === 1 ? found[0]![1] : undefined;
}
const nowValue = (now: number): bigint => { requirePap(Number.isSafeInteger(Math.floor(now)) && now >= 0, 'state_conflict'); return BigInt(Math.floor(now)); };
const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
function httpDate(value: string, now: number): number | undefined {
  let year: number; let month: number; let day: number; let hour: number; let minute: number; let second: number;
  const modern = value.match(/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), ([0-9]{2}) ([A-Z][a-z]{2}) ([0-9]{4}) ([0-9]{2}):([0-9]{2}):([0-9]{2}) GMT$/);
  const old = value.match(/^(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), ([0-9]{2})-([A-Z][a-z]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2}) GMT$/);
  const ascii = value.match(/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) ([A-Z][a-z]{2}) ([ 0-9][0-9]) ([0-9]{2}):([0-9]{2}):([0-9]{2}) ([0-9]{4})$/);
  if (modern || old) {
    const match = (modern ?? old)!; day = Number(match[1]); month = months.indexOf(match[2]!); year = Number(match[3]); hour = Number(match[4]); minute = Number(match[5]); second = Number(match[6]);
    if (old) { const currentYear = new Date(now).getUTCFullYear(); year += Math.floor(currentYear / 100) * 100; if (year > currentYear + 50) year -= 100; }
  } else if (ascii) { month = months.indexOf(ascii[1]!); day = Number(ascii[2]); hour = Number(ascii[3]); minute = Number(ascii[4]); second = Number(ascii[5]); year = Number(ascii[6]); }
  else return undefined;
  if (month < 0 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59) return undefined;
  const date = new Date(Date.UTC(year, month, day, hour, minute, second));
  if (!Number.isFinite(date.getTime()) || date.getUTCFullYear() !== year || date.getUTCMonth() !== month || date.getUTCDate() !== day) return undefined;
  return date.getTime();
}
/** Delta-seconds are stored as exact integer milliseconds, never capped to a shorter server window. */
export function retryAfterUntil(value: string | undefined, now: number): string {
  const current = nowValue(now); const input = value?.trim();
  if (input && /^[0-9]{1,16384}$/.test(input)) return (current + BigInt(input) * 1000n).toString();
  if (input && input.length <= 128) { const date = httpDate(input, now); if (date !== undefined) return (BigInt(Math.trunc(date)) > current ? BigInt(Math.trunc(date)) : current).toString(); }
  // Missing/malformed Retry-After gets a local one-second fence, not an inferred remote lifetime.
  return (current + 1000n).toString();
}
export function remainingCooldownMs(state: PapState, key: string, now: number): bigint {
  const record = state.cooldowns[key]; if (!record) return 0n;
  requirePap(/^[0-9]{1,16416}$/.test(record.notBeforeMs), 'state_corrupt');
  const remaining = BigInt(record.notBeforeMs) - nowValue(now); return remaining > 0n ? remaining : 0n;
}
export function cooldownError(state: PapState, key: string, now: number): PapError {
  const seconds = (remainingCooldownMs(state, key, now) + 999n) / 1000n;
  return new PapError('rate_limited', seconds <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(seconds) : seconds.toString());
}
export function assertCooldownElapsed(state: PapState, key: string, now: number): void {
  if (remainingCooldownMs(state, key, now) > 0n) throw cooldownError(state, key, now);
}
export function recordCooldown(state: PapState, key: string, response: HttpResponse, now: number): void {
  const until = retryAfterUntil(responseHeader(response, 'retry-after'), now); const previous = state.cooldowns[key];
  if (!previous || BigInt(until) > BigInt(previous.notBeforeMs)) state.cooldowns[key] = { notBeforeMs: until, generation: (previous?.generation ?? 0) + 1 };
}
