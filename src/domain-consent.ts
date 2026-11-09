/** Host-owned single-operation consent. No protocol credential enters this API. */
import { PapError } from './errors.js';

export interface ConsentDecision { id: string; status: string; version: number; grantId?: string; mode?: string }
export interface DomainOperationConsumer {
  request(input: { requestId: string; purpose: string; request: Request }): Promise<ConsentDecision>;
  status(id: string): Promise<ConsentDecision>;
  cancel(id: string, version: number): Promise<ConsentDecision>;
  execute<T>(grantId: string, request: Request, effect: (assertActive: () => Promise<void>) => Promise<T>): Promise<T>;
}
export class PapConsentPending extends PapError {
  constructor(readonly requestId: string) { super('identity_authorization_required'); }
}
/** Wait only for an owner decision; timeout never implies approval or replay. */
export async function waitForConsent(consumer: DomainOperationConsumer, initial: ConsentDecision, signal: AbortSignal, waitMs: number, pollMs: number): Promise<ConsentDecision> {
  let decision = initial;
  const deadline = Date.now() + waitMs;
  while (decision.status === 'pending' && Date.now() < deadline) {
    await new Promise<void>((resolve, reject) => {
      const finish = () => { clearTimeout(timer); signal.removeEventListener('abort', abort); resolve(); };
      const abort = () => { clearTimeout(timer); signal.removeEventListener('abort', abort); reject(new PapError('disconnected')); };
      const timer = setTimeout(finish, Math.min(pollMs, Math.max(0, deadline - Date.now())));
      signal.addEventListener('abort', abort, { once: true });
      if (signal.aborted) abort();
    });
    decision = await consumer.status(decision.id);
  }
  return decision;
}
