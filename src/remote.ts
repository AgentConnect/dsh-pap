/** User-only Typert contract. It is not included in model tools. */
import { z } from 'zod';
import type { TypertRemoteContribution } from '@deepseek-ai/dsh-typert-protocol';
import { managementRequestSchema } from './product-api.js';

const result = z.discriminatedUnion('ok', [
  z.object({ ok: z.literal(true), value: z.json().nullable() }).strict(),
  z.object({ ok: z.literal(false), error: z.object({ code: z.string(), retryAfterSeconds: z.union([z.number(), z.string()]).optional() }).strict() }).strict(),
]);
const methods = ['status', 'operations', 'manage'] as const;
const contribution: TypertRemoteContribution = {
  package: '@agentconnect/dsh-pap',
  descriptors: methods.map(method => ({
    id: `@agentconnect/dsh-pap#papManager/${method}`, service: 'papManager', namespace: 'papManager', method, invocation: { kind: 'direct' },
    parameters: method === 'manage' ? [{ name: 'input', wire: 'input', source: 'json', codec: { mode: 'strict', typeSymbol: 'dsh-pap/manager#Request', schema: managementRequestSchema } }] : [],
    result: { mode: 'strict', typeSymbol: 'dsh-pap/manager#Result', schema: result },
  })),
};
export default contribution;
