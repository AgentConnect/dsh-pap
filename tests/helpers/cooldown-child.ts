/** Fresh process reads a persisted fence before any signer or physical HTTP request. */
import { PapClient } from '../../src/client.js';
import { PapError } from '../../src/errors.js';
const input: Buffer[] = []; for await (const chunk of process.stdin) input.push(Buffer.from(chunk));
const value = JSON.parse(Buffer.concat(input).toString()); const master = Buffer.from(value.master, 'base64url'); let signerCalls = 0; let networkCalls = 0;
const client = new PapClient({ binding: value.binding, stateRoot: value.stateRoot, inlineCooldownWaitMs: 0, secretStore: { getEncryptionKey: async () => master, getOrCreateEncryptionKey: async () => master }, identityHost: { acquire: async () => { signerCalls++; throw new Error('Unexpected signer'); } } }, { request: async () => { networkCalls++; throw new Error('Unexpected network'); } });
try { await client.recover(); await client.dispatchPap(value.sessionRef, value.operation); process.stdout.write(JSON.stringify({ code: 'unexpected_success', signerCalls, networkCalls })); }
catch (error) { process.stdout.write(JSON.stringify({ code: error instanceof PapError ? error.code : 'unexpected_error', retryAfterSeconds: error instanceof PapError ? error.retryAfterSeconds : undefined, signerCalls, networkCalls })); }
finally { client.close(); master.fill(0); }
