import assert from 'node:assert/strict';
import type { LookupAddress } from 'node:dns';
import dns from 'node:dns/promises';
import { EventEmitter } from 'node:events';
import type { ClientRequest, IncomingMessage } from 'node:http';
import https from 'node:https';
import { syncBuiltinESMExports } from 'node:module';
import { Readable } from 'node:stream';
import test, { type TestContext } from 'node:test';
import { SafeHttpsTransport } from '../src/network.js';

const shop = 'shop.example.com';
const documentUrl = `https://${shop}/.well-known/poppy.json`;
const fakeIp = { address: '198.18.1.25', family: 4 };
const shopIp = { address: '93.184.216.34', family: 4 };
const shopIpv6 = { address: '2606:4700:14::1234', family: 6 };
const record = (name: string, type: number, data: string) => ({ name, type, data, TTL: 60 });
const reply = (type: 1 | 28, answers: ReturnType<typeof record>[]) => ({
  Status: 0, TC: false, Question: [{ name: `${shop}.`, type }], Answer: answers,
});

function mockNetwork(
  t: TestContext,
  addresses: LookupAddress[],
  responseFor: (url: URL) => { body: unknown; status?: number } | undefined,
) {
  const calls: { url: URL; options: https.RequestOptions }[] = [];
  const resolverCalls: string[] = [];
  const lookup = t.mock.method(dns, 'lookup', (async (host: string) => {
    resolverCalls.push(host);
    assert.equal(host, shop);
    return addresses;
  }) as unknown as typeof dns.lookup);
  syncBuiltinESMExports();
  t.after(() => { lookup.mock.restore(); syncBuiltinESMExports(); });

  t.mock.method(https, 'request', ((url: URL, options: https.RequestOptions, callback: (response: IncomingMessage) => void) => {
    calls.push({ url, options });
    const request = Object.assign(new EventEmitter(), {
      write: () => true,
      end() {
        queueMicrotask(() => {
          const result = responseFor(url);
          if (!result) {
            options.signal?.addEventListener('abort', () => request.emit('error', new Error('aborted')), { once: true });
            return;
          }
          const response = Object.assign(Readable.from([Buffer.from(JSON.stringify(result.body))]), {
            statusCode: result.status ?? 200,
            headers: { 'content-type': url.hostname === shop ? 'application/json' : 'application/dns-json' },
          });
          callback(response as unknown as IncomingMessage);
        });
        return this;
      },
    });
    return request as unknown as ClientRequest;
  }) as typeof https.request);

  return { calls, resolverCalls };
}

async function pinnedAddress(url: URL, options: https.RequestOptions): Promise<LookupAddress[]> {
  assert.equal(typeof options.lookup, 'function');
  return new Promise((resolve, reject) => options.lookup!(url.hostname, { all: true }, (error, addresses) => {
    if (error) reject(error);
    else if (Array.isArray(addresses)) resolve(addresses);
    else reject(new Error('Pinned lookup did not honor all: true'));
  }));
}

test('TUN fake-IP resolves through pinned DoH and sends the PAP request only to the public merchant', async t => {
  const { calls, resolverCalls } = mockNetwork(t, [fakeIp, { address: '198.19.2.6', family: 4 }], url => {
    if (url.hostname === shop) return { body: { protocol_version: '1.0' } };
    const type = url.searchParams.get('type') === '1' ? 1 : 28;
    return { body: reply(type, [
      record(`${shop}.`, 5, 'edge.example.com.'),
      record('edge.example.com.', type, type === 1 ? shopIp.address : shopIpv6.address),
    ]) };
  });
  const headers = { 'Poppy-Session': 'fixture-session', authorization: 'DPoP fixture-token', dpop: 'fixture-proof' };
  const response = await new SafeHttpsTransport().request(documentUrl, { headers });
  assert.equal(response.status, 200);
  assert.equal(response.url, documentUrl);
  assert.deepEqual(resolverCalls, [shop]);
  assert.equal(calls.length, 3);
  const [a, aaaa, merchant] = calls;
  assert(a && aaaa && merchant);
  assert.deepEqual([a.url.searchParams.get('type'), aaaa.url.searchParams.get('type')], ['1', '28']);
  for (const resolver of [a, aaaa]) {
    assert.equal(resolver.url.origin, 'https://dns.google');
    assert.equal(resolver.url.searchParams.get('name'), shop);
    assert.deepEqual(resolver.options.headers, { accept: 'application/dns-json', host: 'dns.google' });
    assert.deepEqual(await pinnedAddress(resolver.url, resolver.options), [{ address: '8.8.8.8', family: 4 }]);
  }
  assert.equal(merchant.url.href, documentUrl);
  assert.equal(merchant.options.servername ?? merchant.url.hostname, shop);
  assert.notEqual(merchant.options.rejectUnauthorized, false);
  assert.deepEqual(merchant.options.headers, { ...headers, host: shop });
  assert.deepEqual(await pinnedAddress(merchant.url, merchant.options), [shopIp]);
});

test('TUN fake-IP can resolve a merchant with records in only one family', async t => {
  for (const [recordType, address] of [[1, shopIp], [28, shopIpv6]] as const) {
    await t.test(`records of type ${recordType}`, async t => {
      const { calls } = mockNetwork(t, [fakeIp], url => {
        if (url.hostname === shop) return { body: {} };
        const type = url.searchParams.get('type') === '1' ? 1 : 28;
        const body = type === recordType ? reply(type, [record(`${shop}.`, type, address.address)])
          : { Status: 0, Question: [{ name: `${shop}.`, type }] };
        return { body };
      });
      assert.equal((await new SafeHttpsTransport().request(documentUrl)).status, 200);
      const merchant = calls.at(-1);
      assert(merchant && calls.length === 3);
      assert.deepEqual(await pinnedAddress(merchant.url, merchant.options), [address]);
    });
  }
});

test('ordinary public DNS connects directly and unsafe or explicit resolutions do not fall back', async t => {
  await t.test('ordinary public answer retains pinned HTTPS', async t => {
    const { calls } = mockNetwork(t, [shopIp], () => ({ body: {} }));
    assert.equal((await new SafeHttpsTransport().request(documentUrl)).status, 200);
    const [merchant] = calls;
    assert(merchant && calls.length === 1);
    assert.equal(merchant.url.href, documentUrl);
    assert.deepEqual(await pinnedAddress(merchant.url, merchant.options), [shopIp]);
  });
  for (const [description, addresses, url, custom] of [
    ['literal fake IP', [], 'https://198.18.1.25/', false],
    ['private DNS answer', [{ address: '192.168.3.4', family: 4 }], documentUrl, false],
    ['mixed public and fake DNS answers', [shopIp, fakeIp], documentUrl, false],
    ['explicit resolver', [fakeIp], documentUrl, true],
  ] as const) {
    await t.test(description, async t => {
      const { calls } = mockNetwork(t, [...addresses], () => ({ body: {} }));
      const transport = new SafeHttpsTransport(custom ? { lookup: async () => [...addresses] } : {});
      await assert.rejects(transport.request(url), { code: 'unsafe_destination' });
      assert.deepEqual(calls, []);
    });
  }
});

test('unsafe or unrelated DNS-over-HTTPS answers never dial the merchant', async t => {
  const validAnswer = record(`${shop}.`, 1, shopIp.address);
  for (const [description, body] of [
    ['mixed public and private answers', reply(1, [validAnswer, record(`${shop}.`, 1, '127.0.0.1')])],
    ['truncated answer', { ...reply(1, [validAnswer]), TC: true }],
    ['wrong question', { ...reply(1, [validAnswer]), Question: [{ name: 'unrelated.example.com.', type: 1 }] }],
  ] as const) {
    await t.test(description, async t => {
      const { calls } = mockNetwork(t, [fakeIp], () => ({ body }));
      await assert.rejects(new SafeHttpsTransport().request(documentUrl), { code: 'unsafe_destination' });
      assert(calls.length > 0 && calls.every(call => call.url.hostname === 'dns.google'));
    });
  }
});

test('a failed AAAA query still stops the merchant request after a public A answer', async t => {
  for (const [description, aaaa, code] of [
    ['DNS error', { body: { ...reply(28, []), Status: 2 } }, 'unsafe_destination'],
    ['timeout', undefined, 'request_uncertain'],
  ] as const) {
    await t.test(description, async t => {
      const { calls } = mockNetwork(t, [fakeIp], url => {
        if (url.hostname === shop) return { body: {} };
        if (url.searchParams.get('type') === '1') return { body: reply(1, [record(`${shop}.`, 1, shopIp.address)]) };
        return aaaa;
      });
      await assert.rejects(new SafeHttpsTransport({ timeoutMs: 150 }).request(documentUrl), { code });
      assert.deepEqual(calls.map(call => call.url.searchParams.get('type')), ['1', '28']);
      if (code === 'request_uncertain') assert.equal(calls[1]?.options.signal?.aborted, true);
    });
  }
});
