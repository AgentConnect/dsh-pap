import type { Company, JsonObject, Route, UcpMetadata } from './types.js';
import { PapError, requirePap } from './errors.js';
import { FRONTVIA_CHECKOUT_CONFIRMATION } from './frontvia-checkout.js';
import { httpsUrl, object, sha256Hex } from './util.js';

export const UCP_VERSION = '2026-08-25';
export const ASK_CAPABILITY = 'dev.ucp.common.ask';
const COMMON = 'dev.ucp.common';
const ASK_PATH = '/ask';
const ASK_OPERATION = 'ask_business';
const storeContext = 'com.frontvia.shopping.store_context';
const orderHistory = 'com.frontvia.shopping.order_history';
const checkout = 'dev.ucp.shopping.checkout';
const frontviaParents = [
  [storeContext, 'dev.ucp.shopping.catalog.search'],
  [orderHistory, 'dev.ucp.shopping.order'],
  [FRONTVIA_CHECKOUT_CONFIRMATION, checkout],
] as const;
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
  ['dev.ucp.shopping.catalog.search','POST','/catalog/search','search_catalog'],
  ['dev.ucp.shopping.catalog.lookup','POST','/catalog/lookup','lookup_catalog'],
  ['dev.ucp.shopping.catalog.lookup','POST','/catalog/product','get_product'],
  ['dev.ucp.shopping.cart','POST','/carts','create_cart'], ['dev.ucp.shopping.cart','GET','/carts/{id}','get_cart'],
  ['dev.ucp.shopping.cart','PUT','/carts/{id}','update_cart'], ['dev.ucp.shopping.cart','POST','/carts/{id}/cancel','cancel_cart'],
  [checkout,'POST','/checkout-sessions','create_checkout'], [checkout,'GET','/checkout-sessions/{id}','get_checkout'],
  [checkout,'PUT','/checkout-sessions/{id}','update_checkout'], [checkout,'POST','/checkout-sessions/{id}/cancel','cancel_checkout'],
  [checkout,'POST','/checkout-sessions/{id}/complete','complete_checkout'], ['dev.ucp.shopping.order','GET','/orders/{id}','get_order'],
  [storeContext,'GET','/store-context','get_store_context'],
  [orderHistory,'GET','/orders','list_orders'],
] as const;
export function isUcpRead(route: Route): boolean {
  return isUcpAsk(route) || route.channel === 'ucp' && operations.some(([capability,method,path,id]) =>
    route.method === method && route.operationId === id && (capability.startsWith('dev.ucp.shopping.catalog.') || method === 'GET') && route.template.endsWith(path));
}
export function isUcpAsk(route: Route): boolean {
  return route.channel === 'ucp' && route.method === 'POST' && route.operationId === ASK_OPERATION && route.template.endsWith(ASK_PATH);
}
function validAsk(entries: unknown): boolean {
  if (!Array.isArray(entries) || entries.some(entry => !entry || typeof entry !== 'object' || Array.isArray(entry))) return false;
  const exact = entries.filter(entry => entry.version === UCP_VERSION);
  return exact.length === 1 && exact[0].extends === undefined;
}
function capabilities(profile: JsonObject): string[] {
  const ucp = object(profile.ucp);
  requirePap(ucp.version === UCP_VERSION, 'unsupported_profile');
  object(ucp.services); object(ucp.payment_handlers);
  return Object.entries(object(ucp.capabilities)).filter(([name, entries]) => name === ASK_CAPABILITY
    ? validAsk(entries) : Array.isArray(entries) && entries.some(entry => object(entry).version === UCP_VERSION)).map(([name]) => name);
}
export function negotiateUcp(business: JsonObject, platform: JsonObject, profileUrl: string, platformProfileUrl: string, resource: string): { ucp: UcpMetadata; routes: Route[] } {
  const supported = capabilities(platform);
  let negotiated = capabilities(business).filter(name => supported.includes(name));
  const definitions = object(object(business.ucp).capabilities);
  const published = (profile: JsonObject, name: string, parent: string) => {
    const extension = object(object(profile.ucp).capabilities)[name];
    return Array.isArray(extension) && extension.some(value => {
      const entry = object(value);
      return entry.version === UCP_VERSION && entry.extends === parent;
    });
  };
  for (const [name, parent] of frontviaParents) {
    if (!negotiated.includes(parent) || !published(business, name, parent) || !published(platform, name, parent))
      negotiated = negotiated.filter(capability => capability !== name);
  }
  const fulfillment = 'dev.ucp.shopping.fulfillment';
  const fulfillmentParents = [checkout, 'dev.ucp.shopping.catalog.search', 'dev.ucp.shopping.catalog.lookup'].filter(parent =>
    negotiated.includes(parent) && [business, platform].every(profile => {
      const entries = object(object(profile.ucp).capabilities)[fulfillment];
      return Array.isArray(entries) && entries.some(value => {
        const entry = object(value);
        return entry.version === UCP_VERSION && (entry.extends === parent ||
          Array.isArray(entry.extends) && entry.extends.includes(parent));
      });
    }));
  if (!fulfillmentParents.length) negotiated = negotiated.filter(name => name !== fulfillment);
  const services = object(object(business.ucp).services);
  const restEntries = (service: unknown): JsonObject[] => {
    if (service === undefined) return [];
    requirePap(Array.isArray(service), 'unsupported_profile');
    return service.map(object).filter(entry => entry.transport === 'rest' && entry.version === UCP_VERSION);
  };
  const restEndpoint = (service: unknown): URL | undefined => {
    const entries = restEntries(service);
    if (!entries.length) return;
    requirePap(entries.length === 1, 'unsupported_profile');
    const endpoint = httpsUrl(entries[0]!.endpoint);
    requirePap(!endpoint.search && !endpoint.hash, 'unsupported_profile');
    return endpoint;
  };
  const base = restEndpoint(services['dev.ucp.shopping']);
  let common: URL | undefined;
  if (negotiated.includes(ASK_CAPABILITY)) {
    try {
      const platformCommon = object(object(platform.ucp).services)[COMMON];
      if (restEntries(platformCommon).length === 1) common = restEndpoint(services[COMMON]);
    } catch (error) {
      // Reject malformed optional Common routing without discarding valid Shopping routes.
      if (!(error instanceof PapError)) throw error;
    }
  }
  // Public questions are sent only to the discovered merchant's own origin.
  const commonEndpoint = common?.origin === new URL(profileUrl).origin ? common.href.replace(/\/$/, '') : undefined;
  if (!commonEndpoint) negotiated = negotiated.filter(name => name !== ASK_CAPABILITY);
  requirePap(base || commonEndpoint, 'unsupported_profile');
  if (!base) negotiated = negotiated.filter(name => name === ASK_CAPABILITY);
  // Frontvia's private extensions are defined at the merchant's own origin.
  // Standard shopping routes continue through PAP resource discovery.
  if (base && base.origin !== new URL(profileUrl).origin)
    negotiated = negotiated.filter(name => name !== storeContext && name !== orderHistory);
  const endpoint = base?.href.replace(/\/$/, '') ?? commonEndpoint!;
  for (;;) {
    const next = negotiated.filter(name => {
      if (name === fulfillment) return fulfillmentParents.some(parent => negotiated.includes(parent));
      if (name === ASK_CAPABILITY) return true;
      const entry = (definitions[name] as unknown[]).map(object).find(value => value.version === UCP_VERSION)!;
      if (entry.extends === undefined) return true;
      const parents = typeof entry.extends === 'string' ? [entry.extends] : entry.extends;
      requirePap(Array.isArray(parents) && parents.length > 0 && parents.every(parent => typeof parent === 'string'), 'unsupported_profile');
      return parents.some(parent => negotiated.includes(parent));
    });
    if (next.length === negotiated.length) break;
    negotiated = next;
  }
  const routes: Route[] = operations.filter(([capability]) => negotiated.includes(capability)).map(([,method,path,operationId]) => ({
    channel: 'ucp', method, template: endpoint + path, resource, operationId,
    parameters: path.includes('{id}') ? [{name:'id',in:'path',required:true}]
      : operationId === 'list_orders' ? ['limit', 'cursor'].map(name => ({name,in:'query' as const,required:false})) : [],
    policyEvidence: {hasRequestBody: method !== 'GET'},
  }));
  if (commonEndpoint && negotiated.includes(ASK_CAPABILITY)) {
    routes.push({channel:'ucp', method:'POST', template:commonEndpoint + ASK_PATH, resource,
      operationId:ASK_OPERATION, parameters:[], policyEvidence:{hasRequestBody:true}});
  }
  if (negotiated.includes(FRONTVIA_CHECKOUT_CONFIRMATION) && negotiated.includes(checkout)) {
    for (const [path, operationId] of frontviaCheckoutOperations) routes.push({
      channel: 'ucp', method: 'POST', template: endpoint + path, resource, operationId,
      parameters: [{name:'id', in:'path', required:true}],
      requiresConsent: true,
      policyEvidence: {hasRequestBody:true},
    });
  }
  requirePap(routes.length > 0, 'unsupported_profile');
  return {ucp:{profileUrl,platformProfileUrl,version:UCP_VERSION,digest:sha256Hex(JSON.stringify([business,platform])),endpoint,
    ...(commonEndpoint ? {commonEndpoint} : {}), capabilities:negotiated,fulfillmentParents:fulfillmentParents.filter(parent => negotiated.includes(parent))},routes};
}
