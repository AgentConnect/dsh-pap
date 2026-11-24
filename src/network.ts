import https from 'node:https';
import { lookup as dnsLookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';
import { z } from 'zod';
import type { HttpResponse, HttpTransport } from './types.js';
import { PapError, requirePap } from './errors.js';
import { strictJson } from './strict-json.js';
import { httpsUrl } from './util.js';

const fakeIpv4 = new BlockList();
fakeIpv4.addSubnet('198.18.0.0', 15, 'ipv4');
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
export const orderPdfMaxBytes = 10 * 1024 * 1024;

const dohMaxBytes = 16 * 1024;
const dnsReply = z.object({
  Status: z.union([z.literal(0), z.literal(2)]),
  TC: z.literal(false).optional(),
  Question: z.tuple([z.object({ name: z.string().max(254), type: z.number() })]),
  Answer: z.array(z.object({ name: z.string().max(254), type: z.number(), data: z.string().max(254) })).max(32).default([]),
});
const dnsName = (name: string) => name.toLowerCase().replace(/\.$/, '');

function isPublicDnsName(name: string): boolean {
  return name.length <= 253 && name.includes('.') &&
    name.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) &&
    !/(?:^|\.)(?:alt|example|home\.arpa|internal|invalid|local|localhost|onion|test)$/.test(name);
}

async function resolveFakeIp(host: string, signal: AbortSignal): Promise<{ address: string; family: number }[]> {
  // Bootstrap independently of system DNS, which can also synthesize an address
  // for dns.google. The pinned IP still uses dns.google's SNI and certificate.
  const dns = new SafeHttpsTransport({
    lookup: async () => [{ address: '8.8.8.8', family: 4 }],
    maxBytes: dohMaxBytes,
  });
  const dnsSignal = AbortSignal.any([signal, AbortSignal.timeout(4000)]);
  const resolved: { address: string; family: number }[] = [];
  // Validate both families before connecting, keeping IPv4 first for the pinned address.
  for (const [type, family] of [[1, 4], [28, 6]] as const) {
    const query = new URLSearchParams({ name: host, type: String(type), edns_client_subnet: '0.0.0.0/0' });
    const response = await dns.request(`https://dns.google/resolve?${query}`, {
      headers: { accept: 'application/dns-json' }, signal: dnsSignal,
    }).catch(error => {
      // An uncertain resolver request cannot have reached the original destination.
      if (error instanceof PapError && error.code === 'request_uncertain')
        throw new PapError('request_not_sent');
      throw error;
    });
    requirePap(response.status !== 429 && response.status < 500, 'request_not_sent');
    requirePap(response.status === 200, 'unsafe_destination');
    let payload: unknown;
    try { payload = strictJson(response.body, dohMaxBytes); }
    catch { throw new PapError('unsafe_destination'); }
    const reply = dnsReply.safeParse(payload);
    requirePap(reply.success, 'unsafe_destination');
    const { Status: status, Question: [question], Answer: records } = reply.data;
    requirePap(question.type === type && dnsName(question.name) === host, 'unsafe_destination');
    requirePap(status === 0, 'request_not_sent');
    let owner = host;
    const visited = new Set<string>();
    for (;;) {
      requirePap(isPublicDnsName(owner) && !visited.has(owner), 'unsafe_destination');
      visited.add(owner);
      const matching = records.filter(record => dnsName(record.name) === owner);
      const aliases = matching.filter(record => record.type === 5);
      const answers = matching.filter(record => record.type === type);
      if (!aliases.length) {
        const addresses = answers.map(record => ({ address: record.data, family }));
        requirePap(addresses.every(item => isIP(item.address) === family && isPublicAddress(item.address)), 'unsafe_destination');
        resolved.push(...addresses);
        break;
      }
      requirePap(aliases.length === 1 && !answers.length, 'unsafe_destination');
      owner = dnsName(aliases[0]!.data);
    }
  }
  requirePap(!dnsSignal.aborted, 'request_not_sent');
  return resolved;
}

export class SafeHttpsTransport implements HttpTransport {
  private active = 0;
  constructor(private readonly options: SafeHttpsOptions = {}) {}
  request(value: string, options: Parameters<HttpTransport['request']>[1] = {}): Promise<HttpResponse> {
    return this.send(value, options, false);
  }

  requestOrderPdf(value: string, options: NonNullable<Parameters<HttpTransport['request']>[1]>): Promise<HttpResponse> {
    return this.send(value, options, true);
  }

  private async send(value: string, options: NonNullable<Parameters<HttpTransport['request']>[1]>, orderPdf: boolean): Promise<HttpResponse> {
    const url = httpsUrl(value);
    requirePap(url.href.length <= 8192 && Buffer.byteLength(options.body ?? '') <= (this.options.maxRequestBytes ?? 1024 * 1024), 'unsafe_destination');
    requirePap(Object.keys(options.headers ?? {}).length <= 64 && Object.entries(options.headers ?? {}).every(([key,value]) => key.length + value.length <= 131072 && !/[\r\n]/.test(key + value)), 'unsafe_destination');
    requirePap(!options.signal?.aborted, 'request_uncertain');
    requirePap(this.active < (this.options.maxConcurrent ?? 8), 'rate_limited');
    this.active++;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.options.timeoutMs ?? 10000);
    const abort = () => controller.abort();
    options.signal?.addEventListener('abort', abort, { once: true });
    try {
      const host = url.hostname.replace(/^\[|\]$/g, '');
      const lookup = this.options.lookup ?? (async (name: string) => dnsLookup(name, { all: true, verbatim: true }));
      let addresses = await Promise.race([
        isIP(host) ? Promise.resolve([{ address: host, family: isIP(host) }]) : lookup(host),
        new Promise<never>((_, reject) => controller.signal.addEventListener('abort', () => reject(new PapError('request_uncertain')), { once: true })),
      ]);
      requirePap(addresses.length > 0 && addresses.length <= 32, 'unsafe_destination');
      const allowPrivate = this.options.privateOrigins?.includes(url.origin) === true;
      const name = dnsName(host);
      if (!allowPrivate && !this.options.lookup && !isIP(host) && isPublicDnsName(name) &&
          addresses.every(item => isIP(item.address) === 4 && fakeIpv4.check(item.address, 'ipv4'))) {
        addresses = await resolveFakeIp(name, controller.signal);
        requirePap(addresses.length > 0 && addresses.length <= 32, 'unsafe_destination');
      }
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
          const maxBytes = orderPdf && response.statusCode === 200 && response.headers['content-type']?.split(';')[0] === 'application/pdf'
            ? orderPdfMaxBytes : this.options.maxBytes ?? 1024 * 1024;
          const chunks: Buffer[] = []; let bytes = 0;
          response.on('data', (chunk: Buffer) => {
            bytes += chunk.length;
            if (bytes > maxBytes) { response.destroy(); reject(new PapError('request_uncertain')); }
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
