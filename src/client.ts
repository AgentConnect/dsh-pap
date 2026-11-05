import { randomBytes, timingSafeEqual } from 'node:crypto';
import { PapDiscovery } from './discovery.js';
import { PapError, requirePap } from './errors.js';
import type { PapHostOptions, PapSigningLease } from './host.js';
import { PapStore } from './store.js';
import { DelegationAttemptFailure, newDelegation, thumbprint, verifyCompact } from './delegation.js';
import type { AuthTransaction, Company, Delegation, Grant, HttpResponse, HttpTransport, KeyRef, Operation, PapState, Session, Subject } from './types.js';
import { httpsUrl, htu, id, isPapLoopbackRedirect, jwtParts, matchedRoute, parseJson, retryAfter, scopeFor, sha256 } from './util.js';

function secureEqual(a: unknown, b: string): boolean {
  return typeof a === 'string' && Buffer.byteLength(a) === Buffer.byteLength(b) && timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
const protectedHeaders = new Set(['authorization','dpop','poppy-session','host','cookie','proxy-authorization','content-length','connection','transfer-encoding']);
const knownError = (response: HttpResponse): string | undefined => {
  try { const body = parseJson(response); if (typeof body?.error === 'string') return body.error; } catch {}
  const header = response.headers['www-authenticate']; return header?.match(/\berror="([a-z_]+)"/i)?.[1];
};
function sameBinding(subject: Subject, options: PapHostOptions): boolean {
  return JSON.stringify(subject.binding) === JSON.stringify(options.binding);
}

/** Host-only engine. UI receives safe summaries, never this object or signer capabilities. */
export class PapClient {
  readonly store: PapStore;
  private readonly discovery: PapDiscovery;
  private readonly clock: () => number;
  private closed = false;
  private readonly discoveryFlights = new Map<string, Promise<void>>();
  private readonly recentJtis = new Map<string, number>();
  private readonly refreshFlights = new Map<string, Promise<void>>();
  private readonly abortedSessions = new Map<string, Set<AbortController>>();
  constructor(private readonly options: PapHostOptions, private readonly transport: HttpTransport) {
    this.clock = options.clock ?? (() => Date.now());
    this.store = new PapStore(options.stateRoot, options.secretStore, sha256(JSON.stringify(options.binding)));
    this.discovery = new PapDiscovery(transport, this.clock);
  }
  close(): void { this.closed = true; for (const active of this.abortedSessions.values()) for (const controller of active) controller.abort(); this.options.identityHost.dispose?.(); }
  async recover(): Promise<void> { await this.store.recover(); }
  async resolvePapCompany(domain: string): Promise<{ companyRef: string; companyId: string; name: string; authMode: Company['authMode']; scopes: string[] }> {
    // Failed discovery never commits or erases a previous issuer.
    const discovered = await this.discovery.resolve(domain);
    const company = await this.store.transaction(state => {
      const previous = Object.values(state.companies).find(x => x.domain === discovered.domain && x.companyId === discovered.companyId);
      if (previous) discovered.ref = previous.ref;
      discovered.generation = state.generation + 1;
      state.companies[discovered.ref] = discovered;
      return discovered;
    });
    return { companyRef: company.ref, companyId: company.companyId, name: company.name, authMode: company.authMode, scopes: company.scopes };
  }
  async getOrCreatePapUser(companyRef: string, mode: 'regular' | 'anonymous' = 'regular', agent = false): Promise<{ subjectRef: string }> {
    requirePap(mode === 'regular' || mode === 'anonymous', 'permission_denied');
    return this.store.transaction(state => {
      const company = this.company(state, companyRef);
      let subject = Object.values(state.subjects).find(x => x.companyId === company.companyId && sameBinding(x, this.options) && mode !== 'anonymous' && x.mode === mode && Boolean(x.agentId) === agent);
      if (!subject) {
        const sameUser = mode === 'regular' ? Object.values(state.subjects).find(x => x.companyId === company.companyId && sameBinding(x, this.options) && x.mode === 'regular') : undefined;
        subject = { ref: id('subj'), companyRef, companyId: company.companyId, binding: this.options.binding, mode, userId: sameUser?.userId ?? id('usr'), ...(agent ? { agentId: id('agt') } : {}) };
        state.subjects[subject.ref] = subject;
      }
      return { subjectRef: subject.ref };
    });
  }
  async openPapSession(subjectRef: string, accountSlot?: string): Promise<{ sessionRef: string }> {
    return this.store.transaction(state => {
      const subject = this.subject(state, subjectRef);
      requirePap(!accountSlot || subject.mode === 'regular', 'permission_denied');
      requirePap(subject.mode !== 'anonymous' || !Object.values(state.sessions).some(x => x.subjectRef === subjectRef), 'permission_denied');
      if (accountSlot) requirePap(Object.values(state.grants).some(x => this.sameUser(state, x.subjectRef, subject) && x.accountSlot === accountSlot && x.status === 'active'), 'reauthorization_required');
      const session: Session = { ref: id('sesref'), subjectRef, sid: id('ses'), generation: 1, connected: true, ...(accountSlot ? { accountSlot } : {}) };
      state.sessions[session.ref] = session; return { sessionRef: session.ref };
    });
  }
  private company(state: PapState, ref: string): Company {
    const company = state.companies[ref]; requirePap(company, 'discovery_failed');
    const latest = Object.values(state.companies).filter(x => x.domain === company.domain).sort((a,b) => b.generation - a.generation)[0];
    requirePap(!latest || latest.companyId === company.companyId, 'namespace_changed'); return company;
  }
  private subject(state: PapState, ref: string): Subject {
    const subject = state.subjects[ref]; requirePap(subject && sameBinding(subject, this.options), 'permission_denied');
    this.company(state, subject.companyRef); return subject;
  }
  private sameUser(state: PapState, subjectRef: string, expected: Subject): boolean {
    const subject = state.subjects[subjectRef];
    return Boolean(subject && sameBinding(subject, this.options) && subject.companyId === expected.companyId && subject.userId === expected.userId);
  }
  private assertAccountEpoch(state: PapState, subject: Subject, accountSlot: string, epoch: number): void {
    const slot = state.accountSlots[accountSlot];
    requirePap(slot && this.sameUser(state, slot.subjectRef, subject) && slot.epoch === epoch && !slot.signedOut, 'reauthorization_required');
  }
  private session(state: PapState, ref: string): Session {
    const session = state.sessions[ref]; requirePap(session?.connected, 'disconnected'); this.subject(state, session.subjectRef); return session;
  }
  private async ensureCompanyFresh(subjectRef: string): Promise<void> {
    const state = await this.store.read(); const subject = this.subject(state, subjectRef); const company = this.company(state, subject.companyRef);
    if (company.expiresAt > this.clock()) return;
    const existing = this.discoveryFlights.get(company.domain); if (existing) return existing;
    const flight = this.resolvePapCompany(company.domain).then(result => { requirePap(result.companyId === company.companyId, 'namespace_changed'); });
    this.discoveryFlights.set(company.domain, flight);
    try { await flight; } finally { if (this.discoveryFlights.get(company.domain) === flight) this.discoveryFlights.delete(company.domain); }
  }
  private async lease(subject: Subject, purpose: 'pap_session' | 'pap_account', resource: string, destination?: string, requestedScopes: readonly string[] = []): Promise<PapSigningLease> {
    requirePap(!this.closed, 'disconnected');
    const state = await this.store.read(); const company = this.company(state, subject.companyRef);
    requirePap(company.expiresAt > this.clock(), 'discovery_failed');
    const lease = await this.options.identityHost.acquire(subject.binding, company, purpose, resource, destination, requestedScopes);
    const identity = await lease.getOAuthClientIdentity(); requirePap(identity.clientId === subject.binding.clientId, 'permission_denied'); await lease.assertActive(); return lease;
  }
  async rotateDelegation(subjectRef: string): Promise<void> {
    const subject = this.subject(await this.store.read(), subjectRef);
    const lease = await this.lease(subject, 'pap_session', subject.companyId);
    await this.delegation(subject, lease, true);
  }
  private async delegation(subject: Subject, lease: PapSigningLease, force = false): Promise<Delegation> {
    await this.cleanupRetirements(subject, lease);
    // Reserve before creating a key: failure/retirement must never roll back the create operation id.
    const reservation = await this.store.transaction(state => {
      this.subject(state, subject.ref);
      const existing = state.delegations[subject.ref];
      if (!force && existing && existing.expiresAt > this.clock() + 30000) return { existing };
      requirePap(!Object.values(state.retirements).some(x => x.subjectRef === subject.ref), 'delegation_blocked');
      const current = state.delegationAttempts[subject.ref];
      const attempt = current?.status === 'reserved' ? current : { sequence: (current?.sequence ?? 0) + 1, status: 'reserved' as const };
      state.delegationAttempts[subject.ref] = attempt;
      return { attempt };
    });
    if (reservation.existing) { await this.cleanupRetirements(subject, lease); return reservation.existing; }
    const attempt = reservation.attempt!;
    const result = await this.store.transaction(async state => {
      this.subject(state, subject.ref);
      const current = state.delegationAttempts[subject.ref];
      requirePap(current?.sequence === attempt.sequence, 'state_conflict');
      const existing = state.delegations[subject.ref];
      if (current.status === 'issued' && existing) return { delegation: existing };
      requirePap(current.status === 'reserved', 'delegation_blocked');
      try {
        const next = await newDelegation(subject, lease, (existing?.generation ?? 0) + 1, this.clock(), `pap-delegation/${subject.ref}/attempt-${attempt.sequence}`);
        state.delegations[subject.ref] = next; current.status = 'issued';
        if (existing) state.retirements[existing.key.handle] = { subjectRef: subject.ref, key: existing.key };
        return { delegation: next };
      } catch (error) {
        if (error instanceof DelegationAttemptFailure) {
          current.status = 'failed';
          if (!error.retired) state.retirements[error.key.handle] = { subjectRef: subject.ref, key: error.key };
        }
        // Before a handle was returned, creation may have succeeded: preserve its operation id for recovery.
        if (!force && existing && existing.expiresAt > this.clock()) {
          try { await lease.assertActive(); return { delegation: existing }; }
          catch (authorizationError) { return { errorCode: authorizationError instanceof PapError ? authorizationError.code : 'permission_denied' as const }; }
        }
        return { errorCode: error instanceof PapError || error instanceof DelegationAttemptFailure ? error.code : 'delegation_blocked' as const };
      }
    });
    if (result.errorCode) throw new PapError(result.errorCode);
    await this.cleanupRetirements(subject, lease);
    return result.delegation!;
  }
  private async cleanupRetirements(subject: Subject, lease: PapSigningLease): Promise<void> {
    const pending = Object.values((await this.store.read()).retirements).filter(x => x.subjectRef === subject.ref);
    for (const item of pending) {
      try {
        await lease.retireTemporaryKey(item.key, scopeFor(subject));
        await this.store.transaction(state => { delete state.retirements[item.key.handle]; });
      } catch { /* Keep the durable retry reference; an old Delegation is never selected again. */ }
    }
  }
  async dispatchPap(sessionRef: string, operation: Operation): Promise<HttpResponse> {
    // Freeze all caller inputs before any await, including the exact body and business idempotency key.
    const frozen = structuredClone(operation);
    const headers: Record<string,string> = {};
    for (const [name, value] of Object.entries(frozen.headers ?? {})) { requirePap(!protectedHeaders.has(name.toLowerCase()) && !/[\r\n]/.test(value), 'permission_denied'); headers[name.toLowerCase()] = value; }
    if (frozen.idempotencyKey) { requirePap(!headers['idempotency-key'] || headers['idempotency-key'] === frozen.idempotencyKey, 'permission_denied'); headers['idempotency-key'] = frozen.idempotencyKey; }
    let retriedSession = false; let retriedToken = false; let retriedNonce = false;
    let accountContext: { slot: string; epoch: number } | undefined;
    for (;;) {
      const initial = await this.store.read(); await this.ensureCompanyFresh(this.session(initial, sessionRef).subjectRef);
      const state = await this.store.read(); const session = this.session(state, sessionRef); const subject = this.subject(state, session.subjectRef); const company = this.company(state, subject.companyRef);
      const method = (frozen.method ?? 'GET').toUpperCase(); const url = httpsUrl(frozen.url).href;
      requirePap(/^[A-Z]+$/.test(method), 'unsafe_destination');
      const reserved = [...company.sources.map(x => x.url), company.metadata?.token_endpoint, company.metadata?.authorization_endpoint, company.metadata?.revocation_endpoint].filter((x): x is string => Boolean(x));
      requirePap(!reserved.some(value => htu(value) === htu(url)), 'unsafe_destination');
      const route = company.routes.find(x => x.method === method && matchedRoute(x.template, url)); requirePap(route, 'unsafe_destination');
      requirePap(!frozen.resource || frozen.resource === route.resource, 'unsafe_destination');
      let grant = session.accountSlot ? Object.values(state.grants).find(x => this.sameUser(state, x.subjectRef, subject) && x.accountSlot === session.accountSlot && x.resource === route.resource && ['active','refreshing'].includes(x.status)) : undefined;
      if (session.accountSlot && !grant) throw new PapError('reauthorization_required');
      if (!session.accountSlot) requirePap(!accountContext, 'reauthorization_required');
      if (grant) {
        this.assertAccountEpoch(state, subject, grant.accountSlot, grant.accountEpoch);
        requirePap(!accountContext || accountContext.slot === grant.accountSlot && accountContext.epoch === grant.accountEpoch, 'reauthorization_required');
        accountContext ??= { slot: grant.accountSlot, epoch: grant.accountEpoch };
        if (grant.status === 'refreshing') { await this.waitForRefresh(grant.ref, grant.accountEpoch, grant.generation); retriedToken = true; continue; }
        requirePap(subject.mode === 'regular' && grant.clientId === subject.binding.clientId && grant.issuer === company.issuer, 'permission_denied');
        requirePap((frozen.scopes ?? []).every(x => grant!.scope.includes(x)), 'insufficient_scope');
        if ((grant.expiresAt !== undefined && grant.expiresAt <= this.clock()) || grant.usableUntil <= this.clock()) {
          if (!retriedToken && grant.refreshToken) { await this.refreshAccountGrant(grant.ref); retriedToken = true; continue; }
          throw new PapError('reauthorization_required');
        }
      } else requirePap((frozen.scopes?.length ?? 0) === 0, 'reauthorization_required');
      const lease = await this.lease(subject, 'pap_session', route.resource, url);
      const delegation = await this.delegation(subject, lease);
      const sessionJwt = await lease.signPapSessionRequest({ key: delegation.key, scope: scopeFor(subject), delegation: delegation.compact, clientId: subject.binding.clientId, sid: session.sid, sub: subject.userId, agentId: subject.agentId, httpMethod: method, httpUri: url, accessToken: grant?.accessToken });
      this.checkSessionJwt(sessionJwt, delegation, subject, session, method, url, grant?.accessToken);
      const sentHeaders: Record<string, string> = { ...headers, 'poppy-session': sessionJwt };
      if (grant) {
        sentHeaders.authorization = `${grant.tokenType} ${grant.accessToken}`;
        if (grant.tokenType === 'DPoP') {
          requirePap(grant.dpopKey, 'credential_unavailable');
          const dpopLease = await this.lease(subject, 'pap_account', grant.resource, url, grant.scope);
          try {
            sentHeaders.dpop = await dpopLease.signDpopProof({ key: grant.dpopKey, scope: scopeFor(subject, grant.accountSlot), httpMethod: method, httpUri: url, accessToken: grant.accessToken, nonce: state.nonces[`resource:${new URL(url).origin}`] });
          } catch (error) {
            if (error instanceof PapError && error.code === 'credential_unavailable') await this.store.transaction(current => { const item = current.grants[grant.ref]; if (item?.generation === grant.generation) { item.status = 'reauthorization_required'; item.generation++; } });
            throw error;
          }
          await dpopLease.assertActive();
        }
      }
      await lease.assertActive();
      const controller = new AbortController();
      const active = this.abortedSessions.get(sessionRef) ?? new Set(); active.add(controller); this.abortedSessions.set(sessionRef, active);
      let response: HttpResponse;
      try {
        // Same lock orders local disconnect/signout versus actual dispatch. No await between final CAS and HTTP start.
        response = await this.store.transaction(async current => {
          const currentSession = this.session(current, sessionRef);
          requirePap(this.company(current, subject.companyRef).generation === company.generation && currentSession.generation === session.generation && current.delegations[subject.ref]?.generation === delegation.generation, 'state_conflict');
          if (grant) { this.assertAccountEpoch(current, subject, grant.accountSlot, grant.accountEpoch); requirePap(current.grants[grant.ref]?.generation === grant.generation && current.grants[grant.ref]?.status === 'active', 'state_conflict'); }
          return this.transport.request(url, { method, headers: sentHeaders, body: frozen.body, signal: controller.signal });
        });
      } catch (error) { if (error instanceof PapError) throw error; throw new PapError('request_uncertain'); }
      finally { active.delete(controller); if (active.size === 0) this.abortedSessions.delete(sessionRef); }
      if (response.status >= 300 && response.status < 400) throw new PapError('redirect_blocked');
      const error = knownError(response);
      if (error === 'session_ended') {
        if (retriedSession) throw new PapError('session_ended'); retriedSession = true;
        await this.store.transaction(current => { const value = this.session(current, sessionRef); requirePap(value.generation === session.generation, 'state_conflict'); value.sid = id('ses'); value.generation++; }); continue;
      }
      if (error === 'invalid_session') throw new PapError('invalid_session');
      if (response.status === 429) throw new PapError('rate_limited', retryAfter(response));
      if (grant && error === 'use_dpop_nonce' && response.headers['dpop-nonce'] && !retriedNonce) {
        retriedNonce = true; await this.saveNonce(`resource:${new URL(url).origin}`, response.headers['dpop-nonce']); continue;
      }
      if (grant && error === 'invalid_token') {
        if (!retriedToken && grant.refreshToken) { retriedToken = true; await this.refreshAccountGrant(grant.ref); continue; }
        throw new PapError('invalid_token');
      }
      if (error === 'insufficient_scope') throw new PapError('insufficient_scope');
      if (error === 'unauthorized_client') throw new PapError('unauthorized_client');
      return response;
    }
  }
  private checkSessionJwt(jwt: string, delegation: Delegation, subject: Subject, session: Session, method: string, url: string, token?: string): void {
    const { header, payload } = jwtParts(jwt);
    requirePap(header.typ === 'poppy-session+jwt' && header.alg === 'ES256' && header.kid === delegation.key.thumbprint && header.poppy_dlg === delegation.compact && verifyCompact(jwt, delegation.key.public_jwk), 'delegation_blocked');
    requirePap(payload.iss === subject.binding.clientId && payload.aud === subject.companyId && payload.sid === session.sid && payload.sub === subject.userId && payload.agent_id === subject.agentId && payload.htm === method && payload.htu === htu(url), 'delegation_blocked');
    requirePap(Number.isSafeInteger(payload.iat) && Math.abs(Number(payload.iat) * 1000 - this.clock()) <= 10000 && typeof payload.jti === 'string' && payload.jti.length >= 16, 'delegation_blocked');
    requirePap(Object.keys(payload).every(key => ['iss','aud','sid','sub','agent_id','htm','htu','iat','jti','ath'].includes(key)), 'delegation_blocked');
    for (const [jti, expires] of this.recentJtis) if (expires < this.clock()) this.recentJtis.delete(jti);
    requirePap(!this.recentJtis.has(String(payload.jti)) && this.recentJtis.size < 8192, 'delegation_blocked');
    this.recentJtis.set(String(payload.jti), this.clock() + 120000);
    requirePap(token ? payload.ath === sha256(token) : !Object.hasOwn(payload, 'ath'), 'delegation_blocked');
  }
  private async saveNonce(target: string, nonce: string): Promise<void> {
    requirePap(nonce.length > 0 && nonce.length <= 1024 && !/[\r\n]/.test(nonce), 'oauth_error');
    await this.store.transaction(state => { state.nonces[target] = nonce; });
  }
  async startSignIn(subjectRef: string, input: { scopes: string[]; resource: string; redirectUri: string; callbackMode: 'handoff' | 'loopback'; method?: 'direct' | 'device' }): Promise<{ transactionRef: string; authorizationUrl: string; accountSlot: string }> {
    requirePap(input.method === undefined || input.method === 'direct', 'unsupported_sign_in');
    await this.ensureCompanyFresh(subjectRef);
    const state = await this.store.read(); const subject = this.subject(state, subjectRef); const company = this.company(state, subject.companyRef);
    requirePap(subject.mode === 'regular' && company.issuer && company.metadata && !company.authDisabled, 'unsupported_sign_in');
    const metadata = company.metadata;
    requirePap(metadata.grant_types_supported.includes('authorization_code') && metadata.grant_types_supported.includes('refresh_token') && metadata.revocation_endpoint && metadata.authorization_endpoint && metadata.token_endpoint_auth_methods_supported?.includes('private_key_jwt') && metadata.code_challenge_methods_supported?.includes('S256'), 'unsupported_sign_in');
    requirePap(!metadata.dpop_signing_alg_values_supported?.length || metadata.dpop_signing_alg_values_supported.includes('ES256'), 'unsupported_sign_in');
    const scope = [...new Set(input.scopes)].sort();
    requirePap(scope.length > 0 && scope.every(x => company.scopes.includes(x) && /^[\x21\x23-\x5b\x5d-\x7e]+$/.test(x)) && company.routes.some(x => x.resource === input.resource), 'insufficient_scope');
    const lease = await this.lease(subject, 'pap_account', input.resource, undefined, scope); const identity = await lease.getOAuthClientIdentity();
    const client = httpsUrl(subject.binding.clientId);
    const loopback = isPapLoopbackRedirect(input.redirectUri);
    requirePap(input.callbackMode === 'handoff' ? httpsUrl(input.redirectUri).hostname === client.hostname && this.options.callbackHandoff : loopback, 'unsupported_sign_in');
    requirePap(identity.redirectUris?.some(value => {
      if (value === input.redirectUri) return true;
      if (!loopback || !isPapLoopbackRedirect(value)) return false;
      const configured = new URL(value); configured.port = ''; const actual = new URL(input.redirectUri); actual.port = ''; return configured.href === actual.href;
    }), 'unsupported_sign_in');
    const tx: AuthTransaction = { ref: id('auth'), subjectRef, accountSlot: id('acct'), issuer: company.issuer, clientId: subject.binding.clientId, redirectUri: input.redirectUri, state: id('state'), verifier: randomBytes(32).toString('base64url'), resource: input.resource, scope, expiresAt: this.clock() + 600000, accountEpoch: 1, status: 'pending' };
    if (metadata.dpop_signing_alg_values_supported?.includes('ES256')) tx.dpopKey = await lease.createDpopKey(scopeFor(subject, tx.accountSlot), `pap-dpop/${tx.ref}`);
    await this.store.transaction(current => { this.subject(current, subjectRef); current.accountSlots[tx.accountSlot] = { subjectRef, epoch: tx.accountEpoch, signedOut: false }; current.transactions[tx.ref] = tx; });
    if (input.callbackMode === 'handoff') {
      const registered = await this.options.callbackHandoff!.register({ transactionId: tx.ref, issuer: tx.issuer, clientId: tx.clientId, redirectUri: tx.redirectUri, state: tx.state, expiresAt: tx.expiresAt });
      await this.store.transaction(current => { requirePap(current.transactions[tx.ref]?.status === 'pending', 'state_conflict'); current.transactions[tx.ref]!.callbackRef = registered.callbackRef; });
    }
    const authorize = httpsUrl(metadata.authorization_endpoint); const params = authorize.searchParams;
    for (const [key,value] of Object.entries({ response_type: 'code', client_id: tx.clientId, redirect_uri: tx.redirectUri, scope: scope.join(' '), state: tx.state, code_challenge: sha256(tx.verifier), code_challenge_method: 'S256', resource: tx.resource })) params.set(key,value);
    // This is user-only browser data. It must not be emitted to an LLM tool response.
    return { transactionRef: tx.ref, authorizationUrl: authorize.href, accountSlot: tx.accountSlot };
  }
  async collectSignIn(transactionRef: string): Promise<{ grantRef: string; accountSlot: string }> {
    const tx = (await this.store.read()).transactions[transactionRef]; requirePap(tx?.callbackRef && this.options.callbackHandoff, 'invalid_authorization_response');
    return this.completeSignIn(transactionRef, await this.options.callbackHandoff.collect(tx.callbackRef));
  }
  /** Called only by an authenticated Host callback listener or handoff, never an arbitrary model tool. */
  async completeSignIn(transactionRef: string, response: { state?: string; iss?: string; code?: string; error?: string }): Promise<{ grantRef: string; accountSlot: string }> {
    const tx = await this.store.transaction(state => {
      const tx = state.transactions[transactionRef]; requirePap(tx && tx.status === 'pending' && tx.expiresAt > this.clock(), 'invalid_authorization_response');
      const subject = this.subject(state, tx.subjectRef); this.assertAccountEpoch(state, subject, tx.accountSlot, tx.accountEpoch);
      requirePap(secureEqual(response.state, tx.state) && secureEqual(response.iss, tx.issuer), 'invalid_authorization_response');
      if (response.error) { tx.status = 'failed'; return { ...tx, status: 'failed' as const }; }
      requirePap(typeof response.code === 'string' && response.code.length > 0 && response.code.length <= 8192, 'invalid_authorization_response'); tx.status = 'exchanging'; tx.exchangeInFlight = true; return tx;
    });
    if (tx.status === 'failed') throw new PapError('oauth_error');
    const state = await this.store.read(); const subject = this.subject(state, tx.subjectRef); const company = this.company(state, subject.companyRef);
    try {
      const result = await this.tokenRequest(subject, company, tx.resource, tx.accountSlot, tx.dpopKey, { grant_type: 'authorization_code', code: response.code!, redirect_uri: tx.redirectUri, code_verifier: tx.verifier, resource: tx.resource }, undefined, tx.scope, tx.accountEpoch);
      const grant = this.parseGrant(result, tx, tx.dpopKey);
      requirePap(grant.refreshToken, 'oauth_error');
      const committed = await this.store.transaction(current => {
        const subject = this.subject(current, tx.subjectRef); const active = current.transactions[tx.ref]; const slot = current.accountSlots[tx.accountSlot];
        const valid = active?.status === 'exchanging' && active.expiresAt > this.clock() && slot?.epoch === tx.accountEpoch && !slot.signedOut && this.sameUser(current, slot.subjectRef, subject);
        if (valid) current.grants[grant.ref] = grant;
        else current.grants[grant.ref] = { ...grant, accessToken: '', status: 'revocation_pending' };
        delete current.transactions[tx.ref]; return valid;
      });
      requirePap(committed, 'revocation_pending');
      return { grantRef: grant.ref, accountSlot: grant.accountSlot };
    } catch (error) {
      await this.store.transaction(current => {
        const active = current.transactions[tx.ref];
        if (active) { if (active.status !== 'cancelled') active.status = 'failed'; active.verifier = ''; active.exchangeInFlight = error instanceof PapError && error.code === 'request_uncertain'; }
      }); throw error;
    }
  }
  private parseGrant(response: HttpResponse, tx: Pick<AuthTransaction,'subjectRef'|'accountSlot'|'issuer'|'clientId'|'resource'|'scope'|'accountEpoch'>, dpopKey?: KeyRef, prior?: Grant): Grant {
    const body = parseJson(response);
    requirePap(response.status === 200 && body.error === undefined && typeof body.access_token === 'string' && body.access_token.length > 0 && body.access_token.length <= 65536 && !/[\r\n]/.test(body.access_token), 'oauth_error');
    requirePap(typeof body.token_type === 'string' && ['bearer','dpop'].includes(body.token_type.toLowerCase()), 'oauth_error');
    const type = body.token_type.toLowerCase() === 'dpop' ? 'DPoP' : 'Bearer'; requirePap(type !== 'DPoP' || dpopKey, 'credential_unavailable');
    requirePap(!prior || prior.tokenType !== 'DPoP' || type === 'DPoP', 'credential_unavailable');
    const scope = body.scope === undefined ? tx.scope : typeof body.scope === 'string' ? [...new Set(body.scope.split(' ').filter(Boolean))].sort() : [];
    requirePap(scope.length > 0 && scope.every(x => tx.scope.includes(x)), 'insufficient_scope');
    requirePap(body.expires_in === undefined || typeof body.expires_in === 'number' && Number.isFinite(body.expires_in) && body.expires_in > 0, 'oauth_error');
    requirePap(body.refresh_token === undefined || typeof body.refresh_token === 'string' && body.refresh_token.length > 0 && body.refresh_token.length <= 65536, 'oauth_error');
    return { ref: prior?.ref ?? id('grant'), subjectRef: tx.subjectRef, accountSlot: tx.accountSlot, issuer: tx.issuer, clientId: tx.clientId, resource: tx.resource, scope,
      accessToken: body.access_token, refreshToken: body.refresh_token as string | undefined ?? prior?.refreshToken, tokenType: type, dpopKey,
      expiresAt: body.expires_in === undefined ? undefined : this.clock() + Number(body.expires_in) * 1000,
      usableUntil: this.clock() + 86400000, accountEpoch: tx.accountEpoch, generation: (prior?.generation ?? 0) + 1, status: 'active' };
  }
  private async tokenRequest(subject: Subject, company: Company, resource: string, accountSlot: string, key: KeyRef | undefined, fields: Record<string,string>, endpoint?: string, requestedScopes: readonly string[] = [], accountEpoch?: number): Promise<HttpResponse> {
    const metadata = company.metadata; requirePap(metadata && company.issuer, 'unsupported_sign_in');
    const target = endpoint ?? metadata.token_endpoint; httpsUrl(target);
    let retriedNonce = false;
    for (;;) {
      const lease = await this.lease(subject, 'pap_account', resource, target, requestedScopes);
      const assertion = await lease.signOAuthClientAssertion();
      const parts = jwtParts(assertion); requirePap(parts.payload.iss === subject.binding.clientId && parts.payload.sub === subject.binding.clientId && parts.payload.aud === company.issuer, 'permission_denied');
      const body = new URLSearchParams({ ...fields, client_id: subject.binding.clientId, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: assertion }).toString();
      const headers: Record<string,string> = { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' };
      if (key) {
        requirePap(key.purpose === 'pap_dpop' && thumbprint(key.public_jwk) === key.thumbprint, 'credential_unavailable');
        const state = await this.store.read(); headers.dpop = await lease.signDpopProof({ key, scope: scopeFor(subject, accountSlot), httpMethod: 'POST', httpUri: target, nonce: state.nonces[`authorization:${company.issuer}`] });
      }
      await lease.assertActive();
      let result: HttpResponse;
      let sent: Promise<{ response?: HttpResponse; failed?: true }> | undefined;
      // Start under the slot lock, then release it while HTTP is in flight so signout can cancel promptly.
      await this.store.transaction(state => {
        if (accountEpoch !== undefined) this.assertAccountEpoch(state, this.subject(state, subject.ref), accountSlot, accountEpoch);
        sent = this.transport.request(target, { method: 'POST', headers, body }).then(response => ({ response }), () => ({ failed: true as const }));
      });
      const outcome = await sent!; requirePap(outcome.response && !outcome.failed, 'request_uncertain'); result = outcome.response;
      requirePap(result.status < 300 || result.status >= 400, 'redirect_blocked');
      if (key && knownError(result) === 'use_dpop_nonce' && result.headers['dpop-nonce'] && !retriedNonce) {
        retriedNonce = true; await this.saveNonce(`authorization:${company.issuer}`, result.headers['dpop-nonce']); continue;
      }
      if (knownError(result) === 'invalid_grant') throw new PapError('reauthorization_required');
      if (knownError(result) === 'unauthorized_client') throw new PapError('unauthorized_client');
      return result;
    }
  }
  async refreshAccountGrant(grantRef: string): Promise<void> {
    const prior = this.refreshFlights.get(grantRef); if (prior) return prior;
    const flight = this.refresh(grantRef); this.refreshFlights.set(grantRef, flight);
    try { await flight; } finally { if (this.refreshFlights.get(grantRef) === flight) this.refreshFlights.delete(grantRef); }
  }
  private async waitForRefresh(grantRef: string, accountEpoch: number, refreshingGeneration: number, joinLocal = true): Promise<void> {
    const local = joinLocal ? this.refreshFlights.get(grantRef) : undefined;
    if (local) await local;
    for (let attempt = 0; attempt < 120; attempt++) {
      const state = await this.store.read(); const grant = state.grants[grantRef];
      requirePap(grant && grant.accountEpoch === accountEpoch, 'reauthorization_required');
      this.assertAccountEpoch(state, this.subject(state, grant.subjectRef), grant.accountSlot, accountEpoch);
      if (grant.status === 'active' && grant.generation > refreshingGeneration) return;
      requirePap(grant.status === 'refreshing' && grant.generation === refreshingGeneration, 'reauthorization_required');
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    throw new PapError('reauthorization_required');
  }
  private async refresh(grantRef: string): Promise<void> {
    const claim = await this.store.transaction(state => {
      const grant = state.grants[grantRef]; requirePap(grant && grant.refreshToken, 'reauthorization_required');
      this.assertAccountEpoch(state, this.subject(state, grant.subjectRef), grant.accountSlot, grant.accountEpoch);
      if (grant.status === 'refreshing') return { waiting: grant };
      requirePap(grant.status === 'active', 'reauthorization_required');
      grant.status = 'refreshing'; grant.generation++; return { claimed: grant };
    });
    if (claim.waiting) { await this.waitForRefresh(grantRef, claim.waiting.accountEpoch, claim.waiting.generation, false); return; }
    const claimed = claim.claimed!;
    const state = await this.store.read(); const subject = this.subject(state, claimed.subjectRef); const company = this.company(state, subject.companyRef);
    try {
      const response = await this.tokenRequest(subject, company, claimed.resource, claimed.accountSlot, claimed.dpopKey, { grant_type: 'refresh_token', refresh_token: claimed.refreshToken!, resource: claimed.resource, scope: claimed.scope.join(' ') }, undefined, claimed.scope, claimed.accountEpoch);
      const next = this.parseGrant(response, claimed, claimed.dpopKey, claimed);
      const committed = await this.store.transaction(current => {
        const grant = current.grants[grantRef];
        if (grant?.generation === claimed.generation && grant.status === 'refreshing' && current.accountSlots[claimed.accountSlot]?.epoch === claimed.accountEpoch && !current.accountSlots[claimed.accountSlot]?.signedOut) { current.grants[grantRef] = next; return true; }
        if (grant && ['signed_out','revocation_pending'].includes(grant.status) && next.refreshToken) {
          const pending = { ...next, ref: id('pending_revoke'), accessToken: '', status: 'revocation_pending' as const };
          current.grants[pending.ref] = pending;
        }
        return false;
      });
      requirePap(committed, 'revocation_pending');
    } catch (error) {
      await this.store.transaction(current => { const grant = current.grants[grantRef]; if (grant?.generation === claimed.generation && grant.status === 'refreshing') { grant.status = error instanceof PapError && error.code === 'request_uncertain' ? 'uncertain' : 'reauthorization_required'; grant.generation++; } }); throw error;
    }
  }
  async signOutAccount(subjectRef: string, accountSlot: string): Promise<{ status: 'signed_out' | 'revocation_pending' }> {
    let refreshInFlight = false;
    const grants = await this.store.transaction(state => {
      const subject = this.subject(state, subjectRef);
      const slot = state.accountSlots[accountSlot];
      requirePap(!slot || this.sameUser(state, slot.subjectRef, subject), 'permission_denied');
      state.accountSlots[accountSlot] = { subjectRef, epoch: (slot?.epoch ?? 0) + 1, signedOut: true };
      for (const tx of Object.values(state.transactions)) if (this.sameUser(state, tx.subjectRef, subject) && tx.accountSlot === accountSlot) {
        if (tx.status === 'exchanging' || tx.exchangeInFlight) refreshInFlight = true;
        tx.status = 'cancelled'; tx.verifier = ''; delete tx.callbackRef;
      }
      const grants = Object.values(state.grants).filter(x => this.sameUser(state, x.subjectRef, subject) && x.accountSlot === accountSlot && x.status !== 'signed_out');
      for (const grant of grants) { if (grant.status === 'refreshing') refreshInFlight = true; grant.status = grant.refreshToken ? 'revocation_pending' : 'signed_out'; grant.accessToken = ''; grant.generation++; }
      for (const session of Object.values(state.sessions)) if (this.sameUser(state, session.subjectRef, subject) && session.accountSlot === accountSlot) { delete session.accountSlot; session.generation++; }
      return grants;
    });
    let pending = refreshInFlight;
    for (const grant of grants) {
      if (!grant.refreshToken) continue;
      const state = await this.store.read(); const subject = this.subject(state, subjectRef); const company = this.company(state, subject.companyRef);
      try {
        requirePap(company.metadata?.revocation_endpoint, 'revocation_pending');
        const result = await this.tokenRequest(subject, company, grant.resource, grant.accountSlot, grant.dpopKey, { token: grant.refreshToken, token_type_hint: 'refresh_token' }, company.metadata.revocation_endpoint, grant.scope);
        requirePap(result.status === 200, 'revocation_pending');
        await this.store.transaction(current => { const item = current.grants[grant.ref]; if (item && item.generation === grant.generation && item.status === 'revocation_pending') { item.status = 'signed_out'; delete item.refreshToken; item.generation++; } });
      } catch { pending = true; }
    }
    return { status: pending ? 'revocation_pending' : 'signed_out' };
  }
  async disconnectPap(sessionRef: string): Promise<void> {
    for (const controller of this.abortedSessions.get(sessionRef) ?? []) controller.abort();
    const ended = await this.store.transaction(state => { const session = state.sessions[sessionRef]; requirePap(session, 'disconnected'); const subject = this.subject(state, session.subjectRef); session.connected = false; session.generation++; return { subject, delegation: state.delegations[subject.ref] }; });
    if (ended.subject.mode === 'anonymous') {
      try { if (ended.delegation) { const lease = await this.lease(ended.subject, 'pap_session', ended.subject.companyId); await lease.retireTemporaryKey(ended.delegation.key, scopeFor(ended.subject)); } }
      finally { await this.store.transaction(state => { delete state.subjects[ended.subject.ref]; delete state.delegations[ended.subject.ref]; delete state.delegationAttempts[ended.subject.ref]; for (const [key,value] of Object.entries(state.retirements)) if (value.subjectRef === ended.subject.ref) delete state.retirements[key]; }); }
    }
  }
  async getPapStatus(): Promise<{ companies: { companyRef: string; name: string; authMode: Company['authMode'] }[]; sessions: { sessionRef: string; connected: boolean; account: boolean }[]; accounts: { grantRef: string; status: Grant['status']; scopes: string[] }[]; supportedSignIn: ['direct'] }> {
    const state = await this.store.read();
    return { companies: Object.values(state.companies).map(x => ({ companyRef: x.ref, name: x.name, authMode: x.authMode })),
      sessions: Object.values(state.sessions).map(x => ({ sessionRef: x.ref, connected: x.connected, account: Boolean(x.accountSlot) })),
      accounts: Object.values(state.grants).map(x => ({ grantRef: x.ref, status: x.status, scopes: x.scope })), supportedSignIn: ['direct'] };
  }
}
