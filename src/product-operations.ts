import { PapError, requirePap } from './errors.js';
import { httpsUrl, htu, sha256 } from './util.js';
import { strictJson } from './strict-json.js';
import type { Company, HttpResponse, Operation, PapState, ProductOperationApproval, Route } from './types.js';
import type { PapOperationRequest } from './product-api.js';

export function operationRef(company: Company, route: Route): string {
  return `op_${sha256(JSON.stringify([company.ref, route.method, route.template, route.resource, route.parameters ?? [], route.channel, ...(route.requiresConsent ? [true] : [])]))}`;
}
function supported(company: Company, route: Route): boolean {
  const reserved = [...company.sources.map(x => x.url), company.metadata?.token_endpoint, company.metadata?.authorization_endpoint, company.metadata?.revocation_endpoint].filter((value): value is string => Boolean(value));
  return route.channel !== 'mcp' && !reserved.some(value => htu(value) === htu(route.template.replace(/\{[^{}]+\}/g, '__parameter__')));
}
export function findOperation(state: PapState, reference: string): { company: Company; route: Route } {
  for (const company of Object.values(state.companies)) for (const route of company.routes) {
    if (operationRef(company, route) === reference && supported(company, route)) return { company, route };
  }
  throw new PapError('unsafe_destination');
}
export function publicOperations(state: PapState, enabledOnly = false): object[] {
  const entries: object[] = [];
  let schemaBytes=0;
  for (const company of Object.values(state.companies)) for (const route of company.routes) {
    if (!supported(company, route)) continue;
    const reference = operationRef(company, route); const approval = state.product?.operations[reference];
    if (enabledOnly && !approval) continue;
    const bytes=route.bodySchema===undefined?0:Buffer.byteLength(JSON.stringify(route.bodySchema));
    const includeSchema=route.bodySchema!==undefined&&bytes<=32768&&schemaBytes+bytes<=262144;
    if(includeSchema)schemaBytes+=bytes;
    entries.push({ operationRef: reference, companyRef: company.ref, method: route.method, path: new URL(route.template).pathname.replace(/%7b/gi, '{').replace(/%7d/gi, '}'),
      ...(route.operationId?{operationId:route.operationId}:{}),...(includeSchema?{bodySchema:route.bodySchema}:route.bodySchemaUnavailable||route.bodySchema!==undefined?{bodySchemaUnavailable:true}:{}),
      pathParameters: [...route.template.matchAll(/\{([A-Za-z0-9_.-]+)\}/g)].map(x => x[1]),
      queryParameters: (route.parameters ?? []).filter(x => x.in === 'query').map(x => ({ name: x.name, required: x.required })),
      enabled: Boolean(approval), account: approval ? Boolean(state.sessions[approval.sessionRef]?.accountSlot) : false,
      requiresApproval: !['GET','HEAD'].includes(route.method) || Boolean(route.requiresConsent),
      blocked: state.product?.disabled?.includes(reference) ?? false });
  }
  return entries;
}
export function assertApproval(state: PapState, reference: string, expected: ProductOperationApproval): void {
  const current = state.product?.operations[reference];
  requirePap(current && JSON.stringify(current) === JSON.stringify(expected), 'permission_denied');
  const { company, route } = findOperation(state, reference);
  requirePap(company.ref === current.companyRef && route.method === current.method && route.template === current.template && route.resource === current.resource, 'permission_denied');
  const session = state.sessions[current.sessionRef]; const subject = session && state.subjects[session.subjectRef];
  requirePap(session?.connected && subject?.companyRef === company.ref, 'disconnected');
}
export function prepareOperation(state: PapState, input: PapOperationRequest): { operation: Operation; approval: ProductOperationApproval } {
  const approval = state.product?.operations[input.operationRef]; requirePap(approval, 'permission_denied');
  assertApproval(state, input.operationRef, approval);
  return prepareDiscoveredOperation(state, input, approval);
}
/** Exact transient approval from the Host consent path; never persists a route permission. */
export function prepareDiscoveredOperation(state: PapState, input: PapOperationRequest, approval: ProductOperationApproval): { operation: Operation; approval: ProductOperationApproval } {
  const { route } = findOperation(state, input.operationRef);
  const pathNames = [...route.template.matchAll(/\{([A-Za-z0-9_.-]+)\}/g)].map(x => x[1]!);
  const path = input.path ?? {}; const query = input.query ?? {};
  requirePap(Object.keys(path).every(key => pathNames.includes(key)) && pathNames.every(key => typeof path[key] === 'string'), 'unsafe_destination');
  let destination = route.template.replace(/\{([A-Za-z0-9_.-]+)\}/g, (_all, key: string) => {
    const value = path[key]!;
    requirePap(value.length > 0 && value !== '.' && value !== '..' && !/[\/%\\\x00-\x20\x7f]/.test(value), 'unsafe_destination');
    return encodeURIComponent(value);
  });
  requirePap(!/[{}]/.test(destination), 'unsupported_profile');
  const url = httpsUrl(destination);
  requirePap(!url.search, 'unsafe_destination');
  const allowedQuery = (route.parameters ?? []).filter(x => x.in === 'query');
  requirePap(Object.keys(query).every(key => allowedQuery.some(x => x.name === key)) && allowedQuery.filter(x => x.required).every(x => query[x.name] !== undefined), 'unsafe_destination');
  for (const [key, value] of Object.entries(query)) { requirePap(!/[\x00-\x1f\x7f]/.test(value), 'unsafe_destination'); url.searchParams.set(key, value); }
  requirePap(url.href.length <= 8192, 'unsafe_destination');
  const body = input.body === undefined ? undefined : JSON.stringify(input.body);
  requirePap(body === undefined || ['POST','PUT','PATCH','DELETE'].includes(route.method) && Buffer.byteLength(body) <= 65536, 'permission_denied');
  return { approval: structuredClone(approval), operation: { url: url.href, method: route.method, resource: route.resource, scopes: [...approval.scopes],
    ...(body === undefined ? {} : { body, headers: { 'content-type': 'application/json' } }) } };
}

const privateFields = /^(?:token|access[_-]?token|refresh[_-]?token|id[_-]?token|authorization|proxy[_-]?authorization|dpop|poppy[_-]?session|private[_-]?key|client[_-]?secret|client[_-]?assertion|code[_-]?verifier|claim[_-]?secret|callbackRef)$/i;
export function privateValues(state: PapState, includeOAuthState = true): string[] {
  const values: (string | undefined)[] = [];
  for (const grant of Object.values(state.grants)) values.push(grant.accessToken, grant.refreshToken, grant.dpopKey?.handle);
  for (const subject of Object.values(state.subjects)) values.push(subject.userId, subject.agentId);
  for (const session of Object.values(state.sessions)) values.push(session.sid);
  for (const delegation of Object.values(state.delegations)) values.push(delegation.compact, delegation.key.handle);
  for (const tx of Object.values(state.transactions)) {
    values.push(includeOAuthState ? tx.state : undefined, tx.verifier, tx.callbackRef, tx.dpopKey?.handle);
    if (tx.callbackRef) try { const claim = JSON.parse(tx.callbackRef); if (typeof claim.claimSecret === 'string') values.push(claim.claimSecret); } catch { /* No cleartext fallback for an unknown callback reference. */ }
  }
  return [...new Set(values.filter((value): value is string => typeof value === 'string' && value.length > 0))];
}
export function sanitizePublicValue(value: unknown, secrets: readonly string[]): unknown { return redact(value,secrets); }
/** Angle-bracket documentation placeholders are invalid bearer credential lexemes. */
function credentialShape(text: string): boolean {
  if (/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(text)) return true;
  for (const match of text.matchAll(/(?:^|\s)(?:Bearer|DPoP)\s+(\S+)/g)) {
    if (!/^<[A-Za-z_][A-Za-z0-9_.-]{0,63}>$/.test(match[1]!)) return true;
  }
  return false;
}
/** Only business JSON crosses the tool boundary. Protocol headers and credential-shaped fields do not. */
function redact(value: unknown, secrets: readonly string[], depth = 0): unknown {
  requirePap(depth <= 32, 'unsupported_profile');
  const sensitive = (text: string) => secrets.some(secret => text.includes(secret)) || credentialShape(text);
  if (typeof value === 'string' && sensitive(value)) return '[redacted]';
  if (Array.isArray(value)) return value.map(item => redact(item, secrets, depth + 1));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [sensitive(key) ? '[redacted]' : key, privateFields.test(key) ? '[redacted]' : redact(item, secrets, depth + 1)]));
  return value;
}
export function publicResponse(response: HttpResponse, secrets: readonly string[] = [], maxBytes = 65536): object {
  requirePap(Number.isSafeInteger(maxBytes) && maxBytes >= 65536 && maxBytes <= 8*1024*1024, 'unsupported_profile');
  const type = response.headers['content-type']?.split(';')[0]?.trim().toLowerCase();
  if (type !== 'application/json' && type !== 'application/problem+json') return { status: response.status, bodyAvailable: false };
  try { return { status: response.status, body: redact(strictJson(response.body, maxBytes), secrets) }; }
  catch { return { status: response.status, bodyAvailable: false }; }
}
