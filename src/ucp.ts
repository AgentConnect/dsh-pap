import type { Company, JsonObject, Route, UcpMetadata } from './types.js';
import { requirePap } from './errors.js';
import { FRONTVIA_CHECKOUT_CONFIRMATION } from './frontvia-checkout.js';
import { httpsUrl, object, sha256Hex } from './util.js';

export const UCP_VERSION = '2026-08-25';
const frontviaCheckoutOperations = [
  ['/checkout-sessions/{id}/prepare', 'prepare_checkout'],
  ['/checkout-sessions/{id}/handoff/approve', 'approve_checkout_handoff'],
] as const;

export function supportsFrontviaConfirmation(company: Company, route: Route): boolean {
  return Boolean(company.ucp?.capabilities.includes(FRONTVIA_CHECKOUT_CONFIRMATION)
    && route.channel === 'ucp' && route.operationId === 'complete_checkout' && route.method === 'POST'
    && route.template === company.ucp.endpoint + '/checkout-sessions/{id}/complete');
}
/** Operation semantics are pinned to the dated Shopping REST contract, never merchant labels. */
const operations = [
  ['catalog.search','POST','/catalog/search','search_catalog'],
  ['catalog.lookup','POST','/catalog/lookup','lookup_catalog'],
  ['catalog.lookup','POST','/catalog/product','get_product'],
  ['cart','POST','/carts','create_cart'], ['cart','GET','/carts/{id}','get_cart'],
  ['cart','PUT','/carts/{id}','update_cart'], ['cart','POST','/carts/{id}/cancel','cancel_cart'],
  ['checkout','POST','/checkout-sessions','create_checkout'], ['checkout','GET','/checkout-sessions/{id}','get_checkout'],
  ['checkout','PUT','/checkout-sessions/{id}','update_checkout'], ['checkout','POST','/checkout-sessions/{id}/cancel','cancel_checkout'],
  ['checkout','POST','/checkout-sessions/{id}/complete','complete_checkout'], ['order','GET','/orders/{id}','get_order'],
] as const;
export function isUcpRead(route: Route): boolean {
  return route.channel === 'ucp' && operations.some(([capability,method,path,id]) =>
    route.method === method && route.operationId === id && (capability.startsWith('catalog.') || method === 'GET') && route.template.endsWith(path));
}
function capabilities(profile: JsonObject): string[] {
  const ucp = object(profile.ucp);
  requirePap(ucp.version === UCP_VERSION, 'unsupported_profile');
  object(ucp.services); object(ucp.payment_handlers);
  return Object.entries(object(ucp.capabilities)).filter(([, entries]) => Array.isArray(entries) && entries.some(entry => object(entry).version === UCP_VERSION)).map(([name]) => name);
}
export function negotiateUcp(business: JsonObject, platform: JsonObject, profileUrl: string, platformProfileUrl: string, resource: string): { ucp: UcpMetadata; routes: Route[] } {
  const supported = capabilities(platform);
  let negotiated = capabilities(business).filter(name => supported.includes(name));
  const definitions = object(object(business.ucp).capabilities);
  const checkout = 'dev.ucp.shopping.checkout';
  const published = (profile: JsonObject) => {
    const extension = object(object(profile.ucp).capabilities)[FRONTVIA_CHECKOUT_CONFIRMATION];
    return Array.isArray(extension) && extension.some(value => {
      const entry = object(value);
      return entry.version === UCP_VERSION && entry.extends === checkout;
    });
  };
  if (!published(business) || !published(platform))
    negotiated = negotiated.filter(name => name !== FRONTVIA_CHECKOUT_CONFIRMATION);
  for (;;) {
    const next = negotiated.filter(name => {
      const entry = (definitions[name] as unknown[]).map(object).find(value => value.version === UCP_VERSION)!;
      if (entry.extends === undefined) return true;
      const parents = typeof entry.extends === 'string' ? [entry.extends] : entry.extends;
      requirePap(Array.isArray(parents) && parents.length > 0 && parents.every(parent => typeof parent === 'string'), 'unsupported_profile');
      return parents.some(parent => negotiated.includes(parent));
    });
    if (next.length === negotiated.length) break;
    negotiated = next;
  }
  const services = object(object(business.ucp).services);
  const shopping = services['dev.ucp.shopping'];
  requirePap(Array.isArray(shopping), 'unsupported_profile');
  const rest = shopping.map(object).filter(entry => entry.transport === 'rest' && entry.version === UCP_VERSION);
  requirePap(rest.length === 1, 'unsupported_profile');
  const base = httpsUrl(rest[0]!.endpoint);
  requirePap(!base.search && !base.hash, 'unsupported_profile');
  const endpoint = base.href.replace(/\/$/, '');
  const routes: Route[] = operations.filter(([capability]) => negotiated.includes(`dev.ucp.shopping.${capability}`)).map(([,method,path,operationId]) => ({
    channel: 'ucp', method, template: endpoint + path, resource, operationId,
    parameters: path.includes('{id}') ? [{name:'id',in:'path',required:true}] : [],
    policyEvidence: {hasRequestBody: method !== 'GET'},
  }));
  if (negotiated.includes(FRONTVIA_CHECKOUT_CONFIRMATION) && negotiated.includes(checkout)) {
    for (const [path, operationId] of frontviaCheckoutOperations) routes.push({
      channel: 'ucp', method: 'POST', template: endpoint + path, resource, operationId,
      parameters: [{name:'id', in:'path', required:true}],
      requiresConsent: true,
      policyEvidence: {hasRequestBody:true},
    });
  }
  requirePap(routes.length > 0, 'unsupported_profile');
  return {ucp:{profileUrl,platformProfileUrl,version:UCP_VERSION,digest:sha256Hex(JSON.stringify([business,platform])),endpoint,capabilities:negotiated},routes};
}
