import type { AsMetadata, Company, HttpResponse, HttpTransport, JsonObject, Route } from './types.js';
import { PapError, requirePap } from './errors.js';
import { httpsUrl, id, object, parseJson, sha256, sha256Hex, strings } from './util.js';
const optionalStrings = (value: unknown) => value === undefined ? undefined : strings(value);
export class PapDiscovery {
  constructor(private readonly transport: HttpTransport, private readonly clock = () => Date.now()) {}
  async resolve(domain: string): Promise<Company> {
    try { return await this.discover(domain); }
    catch (error) { if (error instanceof PapError && ['unsupported_profile', 'unsafe_destination'].includes(error.code)) throw error; throw new PapError('discovery_failed'); }
  }
  private async discover(domain: string): Promise<Company> {
    requirePap(!/[/?#@\\]/.test(domain) && domain.length > 0, 'unsafe_destination');
    let url = httpsUrl(`https://${domain}/.well-known/poppy.json`);
    const sources: { url: string; digest: string }[] = [];
    const started = Date.now(); let requests = 0; let bytes = 0;
    const request = async (target: string): Promise<HttpResponse> => {
      requirePap(++requests <= 64 && Date.now() - started < 30000, 'discovery_failed');
      const response = await this.transport.request(target, { signal: AbortSignal.timeout(Math.max(1, Math.min(10000, 30000 - (Date.now() - started)))) });
      bytes += response.body.length; requirePap(bytes <= 4 * 1024 * 1024, 'discovery_failed'); return response;
    };
    let response: HttpResponse | undefined;
    for (let hop = 0; hop <= 5; hop++) {
      response = await request(url.href);
      if ([301,302,303,307,308].includes(response.status)) {
        requirePap(hop < 5 && response.headers.location, 'discovery_failed');
        url = httpsUrl(new URL(response.headers.location, url).href); continue;
      }
      break;
    }
    requirePap(response?.status === 200 && url.pathname === '/.well-known/poppy.json' && !url.search, 'discovery_failed');
    const doc = parseJson(response); const organization = object(doc.organization);
    requirePap(doc.protocol_version === '0.3', 'unsupported_profile');
    requirePap(typeof organization.domain === 'string' && organization.domain.toLowerCase() === url.host.toLowerCase() && typeof organization.name === 'string' && organization.name.length > 0, 'discovery_failed');
    // Host comparison includes explicit ports in deliberately configured isolated deployments.
    const origin = `https://${url.host.toLowerCase()}`;
    const record = (response: HttpResponse) => { sources.push({ url: response.url, digest: sha256(response.body) }); };
    record(response);
    const read = async (value: unknown): Promise<JsonObject> => {
      const target = httpsUrl(value); const result = await request(target.href);
      requirePap(result.status === 200, 'discovery_failed'); record(result); return parseJson(result);
    };
    const auth = doc.auth === undefined ? {} : object(doc.auth);
    requirePap(auth.disabled === undefined || typeof auth.disabled === 'boolean', 'discovery_failed');
    const prmResponse = await request(`${origin}/.well-known/oauth-protected-resource`);
    let servers: string[] = [];
    if (prmResponse.status !== 404) {
      requirePap(prmResponse.status === 200, 'discovery_failed'); record(prmResponse);
      const prm = parseJson(prmResponse); requirePap(prm.resource === origin, 'discovery_failed');
      servers = optionalStrings(prm.authorization_servers) ?? [];
      requirePap(new Set(servers).size === servers.length, 'discovery_failed');
      for (const server of servers) httpsUrl(server);
    }
    let issuer: string | undefined;
    if (servers.length === 0) requirePap(auth.issuer === undefined && auth.scopes === undefined && auth.scope_hints === undefined && auth.direct === undefined && auth.device === undefined && auth.custom_scopes === undefined, 'discovery_failed');
    else {
      if (servers.length === 1) { issuer = servers[0]!; requirePap(auth.issuer === undefined || auth.issuer === issuer, 'discovery_failed'); }
      else { requirePap(typeof auth.issuer === 'string' && servers.includes(auth.issuer), 'discovery_failed'); issuer = auth.issuer; }
    }
    const advertisedScopes = new Set<string>();
    let metadata: AsMetadata | undefined;
    if (issuer) {
      const issuerUrl = httpsUrl(issuer); requirePap(!issuerUrl.search && !issuerUrl.hash, 'discovery_failed');
      const metadataUrl = `${issuerUrl.origin}/.well-known/oauth-authorization-server${issuerUrl.pathname === '/' ? '' : issuerUrl.pathname}`;
      const meta = await read(metadataUrl);
      if (meta.scopes_supported !== undefined) strings(meta.scopes_supported).forEach(scope => advertisedScopes.add(scope));
      requirePap(meta.issuer === issuer, 'discovery_failed');
      const resources = strings(meta.protected_resources); requirePap(resources.includes(origin), 'discovery_failed'); resources.forEach(httpsUrl);
      httpsUrl(meta.token_endpoint);
      if (meta.authorization_endpoint !== undefined) httpsUrl(meta.authorization_endpoint);
      if (meta.revocation_endpoint !== undefined) httpsUrl(meta.revocation_endpoint);
      metadata = {
        issuer, token_endpoint: meta.token_endpoint as string, protected_resources: resources,
        authorization_endpoint: meta.authorization_endpoint as string | undefined, revocation_endpoint: meta.revocation_endpoint as string | undefined,
        grant_types_supported: optionalStrings(meta.grant_types_supported) ?? ['authorization_code', 'implicit'],
        token_endpoint_auth_methods_supported: optionalStrings(meta.token_endpoint_auth_methods_supported),
        dpop_signing_alg_values_supported: optionalStrings(meta.dpop_signing_alg_values_supported),
        code_challenge_methods_supported: optionalStrings(meta.code_challenge_methods_supported),
      };
    }
    const routes: Route[] = [];
    const discoveredScopes = new Set<string>();
    const resourceCache = new Map<string, string>();
    const serviceResource = async (service: string, mcp = false): Promise<string> => {
      if (resourceCache.has(service)) return resourceCache.get(service)!;
      const target = httpsUrl(service);
      const response = await request(`${target.origin}/.well-known/oauth-protected-resource${target.pathname === '/' ? '' : target.pathname}`);
      let resource = origin;
      if (response.status !== 404) {
        requirePap(response.status === 200, 'discovery_failed'); record(response);
        const metadata = parseJson(response); httpsUrl(metadata.resource);
        if (metadata.scopes_supported !== undefined) strings(metadata.scopes_supported).forEach(scope => advertisedScopes.add(scope));
        requirePap(metadata.resource === origin || metadata.resource === service, 'discovery_failed');
        if (mcp) requirePap(metadata.resource === service, 'discovery_failed');
        if (issuer && metadata.authorization_servers !== undefined) requirePap(strings(metadata.authorization_servers).includes(issuer), 'discovery_failed');
        resource = metadata.resource as string;
      } else requirePap(!mcp, 'discovery_failed');
      resourceCache.set(service, resource); return resource;
    };
    if (doc.apis !== undefined) {
      requirePap(Array.isArray(doc.apis) && doc.apis.length <= 32, 'discovery_failed');
      for (const item of doc.apis) {
        const api = object(item); const apiUrl = httpsUrl(api.url).href;
        if (api.type === 'mcp') {
          // MCP target metadata is checked independently; an account token targets the exact MCP URL.
          await serviceResource(apiUrl, true);
          routes.push({ method: 'POST', template: apiUrl, resource: apiUrl, channel: 'mcp' }, { method: 'GET', template: apiUrl, resource: apiUrl, channel: 'mcp' }, { method: 'DELETE', template: apiUrl, resource: apiUrl, channel: 'mcp' });
        } else if (api.type === 'openapi') {
          const spec = await read(apiUrl); requirePap(typeof spec.openapi === 'string' && spec.openapi.startsWith('3.'), 'unsupported_profile');
          const servers = spec.servers === undefined ? [{ url: new URL(apiUrl).origin }] : spec.servers;
          requirePap(Array.isArray(servers) && servers.length > 0 && servers.length <= 16, 'discovery_failed');
          const paths = object(spec.paths);
          if (spec.components !== undefined) {
            const schemes = object(spec.components).securitySchemes;
            if (schemes !== undefined) for (const scheme of Object.values(object(schemes))) {
              const entry = object(scheme);
              if (entry.type === 'oauth2' && entry.flows !== undefined) for (const flow of Object.values(object(entry.flows))) {
                const scopes = object(flow).scopes;
                if (scopes !== undefined) Object.keys(object(scopes)).forEach(value => discoveredScopes.add(value));
              }
            }
          }
          for (const server of servers) {
            const base = httpsUrl(new URL(String(object(server).url), apiUrl).href);
            requirePap(!base.search && !base.hash, 'discovery_failed');
            const resource = await serviceResource(base.href.replace(/\/$/, ''));
            for (const [path, value] of Object.entries(paths)) {
              requirePap(path.startsWith('/') && !path.startsWith('//') && !/[?#\\]/.test(path), 'discovery_failed');
              const pathItem = object(value);
              requirePap(pathItem.servers === undefined, 'unsupported_profile');
              for (const [method, operation] of Object.entries(pathItem)) if (['get','post','put','patch','delete','head','options'].includes(method)) {
                requirePap(object(operation).servers === undefined, 'unsupported_profile');
                const parameters: NonNullable<Route['parameters']> = [];
                for (const list of [pathItem.parameters, object(operation).parameters]) if (list !== undefined) {
                  requirePap(Array.isArray(list) && list.length <= 64, 'discovery_failed');
                  for (const raw of list) {
                    const parameter = object(raw);
                    // Unsupported references are not converted into a permissive tool parameter.
                    if (parameter.$ref !== undefined) continue;
                    if (parameter.in !== 'path' && parameter.in !== 'query') continue;
                    requirePap(typeof parameter.name === 'string' && /^[A-Za-z0-9_.-]{1,128}$/.test(parameter.name), 'discovery_failed');
                    const value = { name: parameter.name, in: parameter.in, required: parameter.required === true } as const;
                    const index = parameters.findIndex(p => p.name === value.name && p.in === value.in);
                    if (index >= 0) parameters[index] = value; else parameters.push(value);
                  }
                }
                const security = object(operation).security === undefined ? spec.security : object(operation).security;
                const requiresConsent = object(operation).requestBody !== undefined || security !== undefined &&
                  (!Array.isArray(security) || security.some(requirement => !requirement || typeof requirement !== 'object' || Array.isArray(requirement)
                    || Object.values(requirement).some(scopes => !Array.isArray(scopes) || scopes.length > 0)));
                routes.push({ method: method.toUpperCase(), template: `${base.href.replace(/\/$/, '')}${path}`, resource, parameters, channel: 'openapi', ...(requiresConsent ? { requiresConsent: true } : {}) });
              }
            }
          }
        }
      }
    }
    const protocols = doc.agent === undefined ? [] : object(doc.agent).protocols;
    if (Array.isArray(protocols)) for (const item of protocols) {
      const protocol = object(item);
      if (protocol.type === 'poppy') {
        const endpoint = httpsUrl(protocol.endpoint).href.replace(/\/$/, '');
        const resource = await serviceResource(endpoint);
        for (const [method, suffix] of [['POST',''],['GET','/{id}'],['GET','/{id}/messages'],['POST','/{id}/messages'],['POST','/{id}/close']] as const) routes.push({ method, template: endpoint + suffix, resource, channel: 'poppy' });
      }
    }
    requirePap(routes.length > 0 && routes.length <= 2048, 'unsupported_profile');
    const scopes = [...new Set([...(auth.scopes === undefined ? [] : Object.keys(object(auth.scopes))), ...discoveredScopes, ...advertisedScopes])];
    return { ref: id('cmp'), domain: url.host.toLowerCase(), name: organization.name, companyId: issuer ?? origin, issuer,
      authDisabled: auth.disabled === true, authMode: issuer ? auth.disabled === true ? 'disabled' : 'account' : 'no_as', metadata,
      routes, scopes, metadataDigest: sha256Hex(JSON.stringify(sources)), sources, expiresAt: this.clock() + 300000, generation: 1 };
  }
}
