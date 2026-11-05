import { createHash, randomBytes } from 'node:crypto';
import type { CallbackHandoff } from './host.js';
import { PapError, requirePap } from './errors.js';

export interface DeviceManagementOperations {
  /** Implemented by the authenticated local identity management driver. It adds the current
   * checkpoint/device proof and sends only the fixed B device-management route. */
  execute(input: { action: 'pap-callback-register' | 'pap-callback-claim'; operationId: string; callback: Record<string,string> }): Promise<Record<string,unknown>>;
}
const hex = (value: string) => createHash('sha256').update(value,'utf8').digest('hex');
/** Fixed B callback relay, with an independent pickup secret. callbackRef is encrypted by PapStore. */
export class DeviceCallbackHandoff implements CallbackHandoff {
  constructor(private readonly management: DeviceManagementOperations) {}
  async register(input: Parameters<CallbackHandoff['register']>[0]): Promise<{callbackRef:string}> {
    const claimSecret = randomBytes(32).toString('base64url');
    const registration = {
      transaction_id: input.transactionId, client_id: input.clientId, issuer: input.issuer, redirect_uri: input.redirectUri,
      state_sha256: hex(input.state), claim_sha256: hex(claimSecret), expires_at: new Date(input.expiresAt).toISOString().replace(/\.\d{3}Z$/,'Z'),
    };
    const response = await this.management.execute({ action: 'pap-callback-register', operationId: `register_${input.transactionId}`, callback: registration });
    requirePap(response.transaction_id === input.transactionId && response.callback_uri === input.redirectUri, 'invalid_authorization_response');
    return { callbackRef: JSON.stringify({ transactionId: input.transactionId, claimSecret, expiresAt: input.expiresAt }) };
  }
  async collect(callbackRef: string): ReturnType<CallbackHandoff['collect']> {
    let reference: {transactionId:string;claimSecret:string;expiresAt:number};
    try { reference=JSON.parse(callbackRef); } catch { throw new PapError('invalid_authorization_response'); }
    requirePap(typeof reference.transactionId==='string'&&typeof reference.claimSecret==='string'&&/^[A-Za-z0-9_-]{43}$/.test(reference.claimSecret)&&reference.expiresAt>Date.now(), 'invalid_authorization_response');
    const response=await this.management.execute({action:'pap-callback-claim',operationId:`claim_${reference.transactionId}`,callback:{transaction_id:reference.transactionId,claim_secret:reference.claimSecret}});
    requirePap(typeof response.state==='string'&&typeof response.iss==='string'&&((typeof response.code==='string'&&!response.error)||(typeof response.error==='string'&&!response.code)), 'invalid_authorization_response');
    return {state:response.state,iss:response.iss,code:response.code as string|undefined,error:response.error as string|undefined};
  }
}
