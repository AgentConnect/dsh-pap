import { createHash, randomBytes } from 'node:crypto';
import { strictJson } from './strict-json.js';
import { PapError, requirePap } from './errors.js';
import type { HttpResponse, JsonObject, KeyScope, Subject } from './types.js';
export const id = (prefix: string) => `${prefix}_${randomBytes(24).toString('base64url')}`;
export const sha256 = (value: string | Uint8Array) => createHash('sha256').update(value).digest('base64url');
export const sha256Hex = (value: string | Uint8Array) => createHash('sha256').update(value).digest('hex');
export const scopeFor = (subject: Subject, accountSlot?: string): KeyScope => ({ owner: subject.binding.ownerRef, company_id: subject.companyId, user_id: subject.userId, ...(accountSlot ? { account_slot: accountSlot } : {}) });
export function object(value: unknown): JsonObject {
  requirePap(value && typeof value === 'object' && !Array.isArray(value), 'discovery_failed');
  return value as JsonObject;
}
export function strings(value: unknown): string[] {
  requirePap(Array.isArray(value) && value.every(x => typeof x === 'string'), 'discovery_failed');
  return value as string[];
}
export function httpsUrl(value: unknown): URL {
  requirePap(typeof value === 'string', 'unsafe_destination');
  let url: URL;
  try { url = new URL(value); } catch { throw new PapError('unsafe_destination'); }
  requirePap(url.protocol === 'https:' && !url.username && !url.password && !url.hash, 'unsafe_destination');
  return url;
}
export function htu(value: string): string { const url = httpsUrl(value); url.search = ''; return url.href; }
export function parseJson(response: HttpResponse): JsonObject {
  try {
    const mediaType = response.headers['content-type']?.split(';')[0]?.trim().toLowerCase();
    requirePap(mediaType && ['application/json','application/problem+json','application/vnd.oai.openapi+json','application/openapi+json'].includes(mediaType), 'discovery_failed');
    return object(strictJson(response.body));
  } catch { throw new PapError('discovery_failed'); }
}
export function jwtParts(compact: string): { header: JsonObject; payload: JsonObject } {
  try {
    const parts = compact.split('.');
    requirePap(compact.length <= 131072 && parts.length === 3 && parts.every(part => /^[A-Za-z0-9_-]+$/.test(part) && Buffer.from(part, 'base64url').toString('base64url') === part), 'delegation_blocked');
    return { header: object(strictJson(Buffer.from(parts[0]!, 'base64url'), 32768)), payload: object(strictJson(Buffer.from(parts[1]!, 'base64url'), 16384)) };
  } catch { throw new PapError('delegation_blocked'); }
}
export function matchedRoute(template: string, actual: string): boolean {
  const expected = httpsUrl(template.replace(/\{[^{}]+\}/g, '__pap_parameter__'));
  const url = httpsUrl(actual);
  if (url.origin !== expected.origin || /%2f|%5c|\\/i.test(url.pathname)) return false;
  const parts = expected.pathname.split('/');
  const got = url.pathname.split('/');
  return got.length === parts.length && parts.every((part, index) => part === '__pap_parameter__' ? Boolean(got[index]) && !['.', '..'].includes(got[index]!) : part === got[index]);
}
export function retryAfter(response: HttpResponse): number | undefined {
  const value = response.headers['retry-after'];
  if (!value) return undefined;
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric >= 0 ? Math.min(numeric, 300) : undefined;
}

/** Explicit PAP account callback lane; this exception never applies to public or resource URLs. */
export function isPapLoopbackRedirect(value: string): boolean {
  if (typeof value !== 'string' || value.length > 2048 || /[^\x21-\x7e]|\\/.test(value) || /%(?![0-9a-fA-F]{2})/.test(value)) return false;
  const match = value.match(/^http:\/\/(?:127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})(\/[^?#]*)$/);
  if (!match || Number(match[1]) > 65535) return false;
  return match[2]!.split('/').every(segment => !['.','..'].includes(segment.replace(/%2e/gi, '.')));
}
