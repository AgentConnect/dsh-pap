import https from 'node:https';
import { lookup as dnsLookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';
import type { HttpResponse, HttpTransport } from './types.js';
import { PapError, requirePap } from './errors.js';
import { httpsUrl } from './util.js';

const denied = new BlockList();
for (const [address, prefix] of [['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['169.254.0.0',16],['172.16.0.0',12],['192.0.0.0',24],['192.0.2.0',24],['192.168.0.0',16],['198.18.0.0',15],['198.51.100.0',24],['203.0.113.0',24],['224.0.0.0',4],['240.0.0.0',4]] as const) denied.addSubnet(address, prefix, 'ipv4');
const deniedV6 = new BlockList();
for (const [address, prefix] of [['2001::',23],['2001:db8::',32],['2002::',16],['3fff::',20]] as const) deniedV6.addSubnet(address,prefix,'ipv6');
export function isPublicAddress(address: string): boolean {
  if (isIP(address) === 4) return !denied.check(address, 'ipv4');
  if (isIP(address) !== 6) return false;
  // Only globally routable unicast IPv6; mapped IPv4 and special ranges are excluded.
  const first = Number.parseInt(address.split(':')[0]!, 16);
  return first >= 0x2000 && first <= 0x3fff && !deniedV6.check(address,'ipv6');
}
export interface SafeHttpsOptions {
  timeoutMs?: number; maxBytes?: number; maxRequestBytes?: number; maxConcurrent?: number;
  /** Explicit isolated deployment/test exception; exact origins only. TLS still verified. */
  privateOrigins?: readonly string[]; ca?: string | Buffer;
  /** Exact-origin mapping for isolated HTTPS component environments; requires privateOrigins. */
  portOverrides?: Readonly<Record<string, number>>;
  lookup?: (host: string) => Promise<{ address: string; family: number }[]>;
}
export class SafeHttpsTransport implements HttpTransport {
  private active = 0;
  constructor(private readonly options: SafeHttpsOptions = {}) {}
  async request(value: string, options: Parameters<HttpTransport['request']>[1] = {}): Promise<HttpResponse> {
    const url = httpsUrl(value);
    requirePap(url.href.length <= 8192 && Buffer.byteLength(options.body ?? '') <= (this.options.maxRequestBytes ?? 1024 * 1024), 'unsafe_destination');
    requirePap(Object.keys(options.headers ?? {}).length <= 64 && Object.entries(options.headers ?? {}).every(([key,value]) => key.length + value.length <= 131072 && !/[\r\n]/.test(key + value)), 'unsafe_destination');
    requirePap(this.active < (this.options.maxConcurrent ?? 8), 'rate_limited');
    this.active++;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.options.timeoutMs ?? 10000);
    const abort = () => controller.abort();
    options.signal?.addEventListener('abort', abort, { once: true });
    try {
      const host = url.hostname.replace(/^\[|\]$/g, '');
      const lookup = this.options.lookup ?? (async (name: string) => dnsLookup(name, { all: true, verbatim: true }));
      const addresses = await Promise.race([
        isIP(host) ? Promise.resolve([{ address: host, family: isIP(host) }]) : lookup(host),
        new Promise<never>((_, reject) => controller.signal.addEventListener('abort', () => reject(new PapError('request_uncertain')), { once: true })),
      ]);
      requirePap(addresses.length > 0 && addresses.length <= 32, 'unsafe_destination');
      const allowPrivate = this.options.privateOrigins?.includes(url.origin) === true;
      requirePap(allowPrivate || addresses.every(item => isPublicAddress(item.address)), 'unsafe_destination');
      requirePap(!controller.signal.aborted && !options.signal?.aborted, 'request_uncertain');
      // Resolution is pinned to this connection. The HTTP stack never resolves the host again.
      const address = addresses[0]!;
      return await new Promise<HttpResponse>((resolve, reject) => {
        const request = https.request(url, {
          method: options.method ?? 'GET', headers: { ...options.headers, host: url.host }, signal: controller.signal,
          ca: this.options.ca, agent: false,
          ...(this.options.portOverrides?.[url.origin] !== undefined && allowPrivate ? { port: this.options.portOverrides[url.origin] } : {}),
          lookup: ((_hostname: string, _options: unknown, callback: (error: Error | null, address: unknown, family?: number) => void) => {
            if ((_options as { all?: boolean }).all) callback(null, [address]);
            else callback(null, address.address, address.family);
          }) as never,
        }, response => {
          const chunks: Buffer[] = []; let bytes = 0;
          response.on('data', (chunk: Buffer) => {
            bytes += chunk.length;
            if (bytes > (this.options.maxBytes ?? 1024 * 1024)) { response.destroy(); reject(new PapError('request_uncertain')); }
            else chunks.push(chunk);
          });
          response.on('error', () => reject(new PapError('request_uncertain')));
          response.on('end', () => resolve({
            status: response.statusCode ?? 0, body: Buffer.concat(chunks), url: url.href,
            headers: Object.fromEntries(Object.entries(response.headers).map(([key, value]) => [key, Array.isArray(value) ? value.join(', ') : value ?? ''])),
          }));
        });
        request.on('error', () => reject(new PapError('request_uncertain')));
        if (options.body !== undefined) request.write(options.body);
        request.end();
      });
    } finally {
      clearTimeout(timeout); options.signal?.removeEventListener('abort', abort); this.active--;
    }
  }
}
