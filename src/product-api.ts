import { z } from 'zod';
import type { Binding, IdentityRef } from './types.js';
import type { DeviceManagementOperations } from './callback-handoff.js';

export const PAP_CONSUMER = '@awiki/dsh-pap/plugin';
export const PAP_MANAGER = '@awiki/dsh-pap/management-remote';
export const PAP_TOOLS = '@awiki/dsh-pap/tools';

/** C-owned capability. The caller is the actual installed F Context, never a wire name. */
export interface PapHostConsumer {
  resolveBinding(identityRef: IdentityRef, policyRef: string, profile: 'pap_session' | 'pap_account'): Promise<{ binding: Binding; redirectUri?: string }>;
  callbackManagementFor(input: { identityRef: IdentityRef; policyRef: string; targetRef: object }): Promise<DeviceManagementOperations & { dispose(): void }>;
  assertActive(): void | Promise<void>;
  dispose(): void;
}
const ref = z.string().min(1).max(256);
export const identityReferenceSchema = z.object({ storeId: ref, identityId: ref, did: ref }).strict();
const scope = z.string().min(1).max(256).regex(/^[\x21\x23-\x5b\x5d-\x7e]+$/);
export const managementRequestSchema = z.discriminatedUnion('action', [
  z.object({ action: z.literal('identity/select'), reference: identityReferenceSchema }).strict(),
  z.object({ action: z.literal('company/discover'), domain: z.string().min(1).max(253) }).strict(),
  z.object({ action: z.literal('session/connect'), companyRef: ref, mode: z.enum(['regular', 'anonymous']).optional(), accountSlot: ref.optional() }).strict(),
  z.object({ action: z.literal('session/disconnect'), sessionRef: ref }).strict(),
  z.object({ action: z.literal('operation/enable'), operationRef: ref, sessionRef: ref, scopes: z.array(scope).max(64).optional() }).strict(),
  z.object({ action: z.literal('operation/disable'), operationRef: ref }).strict(),
  z.object({ action: z.literal('account/sign-in'), sessionRef: ref, operationRef: ref, scopes: z.array(scope).min(1).max(64) }).strict(),
  z.object({ action: z.literal('account/collect'), transactionRef: ref }).strict(),
  z.object({ action: z.literal('account/sign-out'), accountSlot: ref }).strict(),
  z.object({ action: z.literal('account/refresh'), accountSlot: ref }).strict(),
]);
export type PapManagementRequest = z.infer<typeof managementRequestSchema>;
export const operationRequestSchema = z.object({
  operationRef: ref,
  path: z.record(z.string(), z.string().max(1024)).optional(),
  query: z.record(z.string(), z.string().max(4096)).optional(),
  body: z.json().optional(),
}).strict();
export type PapOperationRequest = z.infer<typeof operationRequestSchema>;
export type ProductResult = { ok: true; value: unknown } | { ok: false; error: { code: string; retryAfterSeconds?: number | string } };
