/** Structural Host contract across independently versioned protocol packages; no policy mutation surface. */
import type { Context } from '@deepseek-ai/cordis';
import type { Company, Route } from './types.js';
import { requirePap } from './errors.js';
export interface PolicyTarget { readonly protocolTarget: true }
export interface PolicyClassification { effect: 'read'|'write'|'unknown'|'payment'; extraPermissions: boolean }
export interface PolicyAdmission { decision: 'allow'|'ask'|'deny'; version: number; assertActive(): Promise<void> }
export interface PolicyClient {
  assertNoDenial(request:Request): Promise<void>;
  classifyHttp(input: {method:string;hasRequestBody:boolean;security?:unknown;declaredEffect?:unknown;annotations?:unknown}): PolicyClassification;
  register(input: {discoveryOrigin:string;destinations:readonly string[]}): PolicyTarget;
  forget(target: PolicyTarget): void;
  evaluate(target: PolicyTarget, input: {url:string}&PolicyClassification): Promise<PolicyAdmission>;
}
export interface PolicyHost { bindProtocolPolicy(context:Context,protocol:'pap'): PolicyClient }
/** Discovery metadata is retained for the Host classifier; never accept effect labels from tool arguments. */
export function classifyRoute(policy: PolicyClient, route: Route): PolicyClassification {
  // Old stored routes did not retain semantic evidence. Rediscovery is required before automatic use.
  if (!route.policyEvidence) return {effect:'unknown',extraPermissions:Boolean(route.requiresConsent)};
  return policy.classifyHttp({...route.policyEvidence,method:route.method});
}
export class PapPolicyTargets {
  private readonly targets = new Map<string,{digest:string;target:PolicyTarget}>();
  constructor(readonly policy: PolicyClient) {}
  target(company:Company): PolicyTarget {
    requirePap(company.discoveryOrigin,'protocol_rediscovery_required');
    const digest=JSON.stringify([company.discoveryOrigin,company.metadataDigest]);
    const previous=this.targets.get(company.ref);
    if(previous?.digest===digest)return previous.target;
    if(previous)this.policy.forget(previous.target);
    const target=this.policy.register({discoveryOrigin:company.discoveryOrigin,destinations:[...new Set(company.routes.map(route=>new URL(route.template).origin))]});
    this.targets.set(company.ref,{digest,target});return target;
  }
  dispose():void{for(const entry of this.targets.values())this.policy.forget(entry.target);this.targets.clear();}
}
