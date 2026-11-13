import { bindIdentityClient } from '@agent-network-protocol/dsh-anp-identity/user-client';
import { createUserMessage } from '@deepseek-ai/dsh-llm';
import { channel } from 'node:diagnostics_channel';

export const name = "@anp-acceptance/pap-consumer";
export const inject = ['anpIdentity', 'anpIdentityManager', 'tools', 'agents', 'agentLoop', 'sessions'];

/** Private subprocess controller for deterministic system tests; never a model tool. */
export function apply(ctx) {
  if (!process.send) throw new Error('acceptance_ipc_required');
  const objects = new Map();
  let stopped = false;
  let agentHandle;
  const activeToolCalls = new Map();
  const activeOperations = new Set();
  let quiescing = false;
  let businessRequests = 0;
  let postWrites = 0, postResponses = 0;
  let lostReceipt = { armed: false, applied: false };
  let responseFault = { armed: false, applied: false, kind: '' };
  let discoveryFault = { armed: false, kind: '', hits: 0, totalBodyBytes: 0, largestBodyBytes: 0 };
  let privateTargetRequests = 0;
  const countedWrites = new WeakSet();
  const delegationObservations = [];
  const papHeaderObservations = [];
  let anpBusinessRequests = 0;
  let originalReadProof;
  let oauthRequests = 0;
  const discoveryResponses = [];
  const observeRequest = event => {
    try {
      const request = event.request;
      const origin = request.origin ? new URL(String(request.origin)).hostname : String(request.getHeader('host') ?? '').split(':')[0];
      const path = String(request.path ?? '').split('?')[0];
      if (origin === '127.0.0.1' && ['/acceptance-forbidden', 'http://127.0.0.1/acceptance-forbidden', 'https://127.0.0.1/acceptance-forbidden'].includes(path)) privateTargetRequests++;
      if (discoveryFault.armed && ['agent-network-protocol.com', 'agent.agent-network-protocol.com'].includes(origin)
        && (path === '/.well-known/poppy.json' || discoveryFault.kind === 'aggregate-budget' && path === '/pap/openapi.json')
        && typeof request.prependOnceListener === 'function') {
        request.prependOnceListener('response', response => {
          if (discoveryFault.kind === 'redirect-loop' && [200, 301, 302, 303, 307, 308].includes(response.statusCode)) {
            response.statusCode = 302; response.headers.location = '/.well-known/poppy.json';
            discoveryFault.hits++; return;
          }
          if (origin !== 'agent.agent-network-protocol.com' || response.statusCode !== 200 || response.headers['content-encoding']) return;
          discoveryFault.armed = discoveryFault.kind === 'aggregate-budget';
          const push = response.push.bind(response), chunks = [];
          let size = 0;
          delete response.headers['content-length'];
          response.push = chunk => {
            if (chunk !== null) {
              size += chunk.length;
              if (size > 65536) { response.destroy(new Error('Discovery fault input exceeds budget')); return false; }
              chunks.push(Buffer.from(chunk)); return true;
            }
            const metadata = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            if (discoveryFault.kind === 'unsafe-target') metadata.apis[0].url = 'http://127.0.0.1/acceptance-forbidden';
            else if (discoveryFault.kind === 'private-target') metadata.apis[0].url = 'https://127.0.0.1/acceptance-forbidden';
            else if (discoveryFault.kind === 'wrong-company') metadata.organization.domain = 'acceptance-disallowed.invalid';
            else if (discoveryFault.kind === 'aggregate-budget') {
              if (path === '/.well-known/poppy.json') {
                const api = metadata.apis[0];
                metadata.apis = Array.from({ length: 4 }, (_, index) => ({ ...api, url: api.url + '?acceptance_budget=' + index }));
              } else {
                metadata.acceptancePadding = '';
                metadata.acceptancePadding = 'x'.repeat(1024 * 1024 - 1 - Buffer.byteLength(JSON.stringify(metadata)));
              }
            }
            else metadata.acceptancePadding = 'x'.repeat(1024 * 1024 + 1);
            const body = Buffer.from(JSON.stringify(metadata));
            discoveryFault.hits++;
            discoveryFault.totalBodyBytes += body.length;
            discoveryFault.largestBodyBytes = Math.max(discoveryFault.largestBodyBytes, body.length);
            push(body); return push(null);
          };
        });
      }
      const faultPath = responseFault.kind === 'invalid_session' ? '/pap/api/protocols' : '/pap/api/posts';
      const faultMethod = responseFault.kind === 'invalid_session' ? 'GET' : 'POST';
      if (responseFault.armed && origin === 'agent.agent-network-protocol.com' && path === faultPath
        && request.method === faultMethod && typeof request.prependOnceListener === 'function') {
        responseFault.armed = false;
        request.prependOnceListener('response', response => {
          if (response.statusCode < 200 || response.statusCode >= 300 || response.headers['content-encoding']) return;
          const kind = responseFault.kind, push = response.push.bind(response);
          let size = 0, completed = false;
          response.statusCode = kind === 'rate_limited' ? 429 : 400;
          delete response.headers['content-length'];
          if (kind === 'rate_limited') response.headers['retry-after'] = '5';
          response.push = chunk => {
            if (chunk !== null) {
              size += Buffer.byteLength(chunk);
              if (size > 65536) { response.destroy(new Error('Fault response exceeds budget')); return false; }
              return true;
            }
            if (completed) return push(null);
            completed = true; responseFault.applied = true;
            push(Buffer.from(JSON.stringify({ error: kind })));
            return push(null);
          };
        });
      }
      if (origin === 'agent.agent-network-protocol.com' && path === '/pap/api/protocols' && request.method === 'GET') {
        if (typeof request.getHeader === 'function' && papHeaderObservations.length < 16) papHeaderObservations.push({
          poppy: Boolean(request.getHeader('poppy-session')), bearer: Boolean(request.getHeader('authorization')),
          signature: Boolean(request.getHeader('signature') || request.getHeader('signature-input')), dpop: Boolean(request.getHeader('dpop')) });
        try {
          const proof = request.getHeader?.('poppy-session');
          if (typeof proof === 'string') {
            const header = JSON.parse(Buffer.from(proof.split('.')[0], 'base64url').toString('utf8'));
            const claims = JSON.parse(Buffer.from(header.poppy_dlg.split('.')[1], 'base64url').toString('utf8'));
            if (Number.isInteger(claims.iat) && Number.isInteger(claims.exp) && typeof header.kid === 'string') {
              if (delegationObservations.length < 16) delegationObservations.push({ issued: claims.iat, expires: claims.exp, publicThumbprint: header.kid });
              originalReadProof ??= proof;
            }
          }
        } catch {}
      }
      if (origin === 'agent.agent-network-protocol.com' && path === '/pap/api/posts' && request.method === 'POST') {
        postWrites++; countedWrites.add(request);
        if (lostReceipt.armed && typeof request.prependOnceListener === 'function') {
          lostReceipt.armed = false;
          request.prependOnceListener('response', response => {
            if (response.statusCode < 200 || response.statusCode >= 300 || response.headers['content-encoding']) return;
            const push = response.push.bind(response);
            let size = 0, completed = false;
            delete response.headers['content-length'];
            response.push = chunk => {
              if (chunk !== null) {
                size += Buffer.byteLength(chunk);
                if (size > 65536) { response.destroy(new Error('Receipt exceeds fault budget')); return false; }
                return true;
              }
              if (completed) return push(null);
              completed = true;
              lostReceipt.applied = true;
              push(Buffer.from('{'));
              return push(null);
            };
          });
        }
      }
      if (/\/(?:oauth|authorize|token|refresh)(?:\/|$)/u.test(path)) oauthRequests++;
      if (origin === 'agent.agent-network-protocol.com' && path.startsWith('/anp/')) anpBusinessRequests++;
      if (origin === 'agent.agent-network-protocol.com' && (/^\/(?:anp|agents)\//u.test(path) || path.startsWith('/pap/api/'))) businessRequests++;
    } catch {}
  };
  for (const name of ['http.client.request.start', 'undici:request:create']) {
    const subscription = channel(name);
    subscription.subscribe(observeRequest);
    ctx.effect(() => () => subscription.unsubscribe(observeRequest));
  }
  const observeDiscovery = event => {
    try {
      const request = event.request;
      const host = request.origin ? new URL(String(request.origin)).hostname : String(request.getHeader('host') ?? '').split(':')[0];
      const path = String(request.path ?? '').split('?')[0];
      if (countedWrites.has(request)) { countedWrites.delete(request); postResponses++; }
      if (!['agent-network-protocol.com', 'agent.agent-network-protocol.com'].includes(host)
        || !['/.well-known/poppy.json', '/pap/openapi.json'].includes(path)) return;
      const names = ['authorization', 'signature', 'signature-input', 'poppy-session', 'dpop'];
      const credentials = request.getHeader ? names.some(name => Boolean(request.getHeader(name)))
        : typeof request.headers === 'string' ? /(?:^|\r\n)(?:authorization|signature|signature-input|poppy-session|dpop):/iu.test(request.headers)
        : Array.isArray(request.headers) ? request.headers.some((value, index) => index % 2 === 0 && names.includes(String(value).toLowerCase())) : null;
      if (discoveryResponses.length < 32) discoveryResponses.push({ host, path, status: event.response.statusCode, credentials });
    } catch {}
  };
  for (const name of ['http.client.response.finish', 'undici:request:headers']) {
    const subscription = channel(name);
    subscription.subscribe(observeDiscovery);
    ctx.effect(() => () => subscription.unsubscribe(observeDiscovery));
  }
  const ordinary = () => bindIdentityClient(ctx);
  const manager = () => ctx.get('anpIdentityManager');
  const managerMethods = new Set(['listIdentities', 'listRequests', 'getRequest', 'decide', 'grants',
    'revoke', 'deleteIdentity', 'publicDocument', 'publicationStatus', 'registrationOnboardingStatus',
    'registrationBootstrapStatus', 'startIdentityRegistration', 'submitRegistrationOtp',
    'registrationServiceSettings', 'configureRegistrationService', 'retryPublication',
    'protocolManagement', 'configureProtocolPolicy']);
  async function command(method, input) {
    if (stopped) throw Object.assign(new Error('acceptance_disposed'), { code: 'acceptance_disposed' });
    if (method === 'health') return ctx.anpIdentity.health();
    if (method === 'fault/pap-discovery') {
      if (input === 'off') { discoveryFault.armed = false; return { armed: false }; }
      if (!['redirect-loop', 'unsafe-target', 'private-target', 'wrong-company', 'oversized-document', 'aggregate-budget'].includes(input)) throw new Error('acceptance_fault_rejected');
      discoveryFault = { armed: true, kind: input, hits: 0, totalBodyBytes: 0, largestBodyBytes: 0 }; return { armed: true };
    }
    if (method === 'fault/pap-discovery-status') return { ...discoveryFault, privateTargetRequests };
    if (method === 'proof/header-status') return [...papHeaderObservations];
    if (method === 'proof/wrong-protocol') {
      if (!originalReadProof || !['bearer-on-pap', 'pap-on-anp'].includes(input)) throw new Error('acceptance_proof_probe_rejected');
      const pap = input === 'bearer-on-pap';
      const response = await fetch('https://agent.agent-network-protocol.com/' + (pap ? 'pap' : 'anp') + '/api/protocols', {
        redirect: 'error', signal: AbortSignal.timeout(15000),
        headers: pap ? { Authorization: 'Bearer ' + originalReadProof } : { 'Poppy-Session': originalReadProof } });
      await response.body?.cancel();
      return { status: response.status };
    }
    if (method === 'fault/pap-response') {
      if (!['invalid_session', 'session_ended', 'rate_limited'].includes(input)) throw new Error('acceptance_fault_kind_rejected');
      responseFault = { armed: true, applied: false, kind: input };
      return { armed: true };
    }
    if (method === 'fault/pap-response-status') return { ...responseFault };
    if (method === 'delegation/status') return [...delegationObservations];
    if (method === 'delegation/replay-original-read') {
      if (!originalReadProof) throw new Error('acceptance_original_proof_missing');
      const response = await fetch('https://agent.agent-network-protocol.com/pap/api/protocols', {
        method: 'GET', redirect: 'error', signal: AbortSignal.timeout(15000), headers: { 'Poppy-Session': originalReadProof } });
      await response.body?.cancel();
      return { status: response.status };
    }
    if (method === 'control/quiesce') {
      quiescing = true;
      for (const controller of activeToolCalls.values()) controller.abort();
      agentHandle?.agent.cancel();
      await Promise.allSettled([...activeOperations]);
      return { businessRequests, postWrites, postResponses };
    }
    if (quiescing && (method === 'tool' || method.startsWith('model/'))) throw new Error('acceptance_quiescing');
    if (method === 'pap/manage') {
      if (!['session/connect', 'session/disconnect'].includes(input?.action)) throw new Error('acceptance_pap_management_rejected');
      return ctx.get('papManager').manage(input);
    }
    if (method === 'fault/lost-receipt') { lostReceipt = { armed: true, applied: false }; return { armed: true }; }
    if (method === 'fault/receipt-status') return { ...lostReceipt };
    if (method === 'network/status') return { businessRequests, oauthRequests, discoveryResponses, postWrites, postResponses, anpBusinessRequests };
    if (method === 'network/reset') { businessRequests = 0; oauthRequests = 0; discoveryResponses.length = 0; postWrites = 0; postResponses = 0; anpBusinessRequests = 0; return { businessRequests }; }
    if (method === 'browser') {
      const server = ctx.get('webServer'), connection = ctx.get('connection');
      if (!server || !connection) throw new Error('acceptance_web_unavailable');
      const origin = server.getOrigin();
      if (!origin.startsWith('http://127.0.0.1:')) throw new Error('acceptance_web_not_loopback');
      return { origin, authenticatedUrl: connection.authenticatedUrl(origin) };
    }
    if (method === 'tools') return ctx.tools.definitions().map(tool => tool.name);
    if (method === 'tool/cancel') {
      const controller = activeToolCalls.get(input);
      if (!controller) throw new Error('acceptance_tool_not_active');
      controller.abort();
      return { cancelled: true };
    }
    if (method === 'model/task' || method === 'model/followup' || method === 'model/resume') {
      if (process.env.DSH_ACCEPTANCE_REAL_MODEL !== '1' || typeof input.task !== 'string' || input.task.length > 4000)
        throw new Error('acceptance_model_request_rejected');
      if (method === 'model/task' && agentHandle) throw new Error('acceptance_model_session_already_used');
      if (method === 'model/followup' && !agentHandle) throw new Error('acceptance_model_session_missing');
      if (method === 'model/resume' && (agentHandle || !/^[0-9a-f-]{36}$/u.test(input.sessionId ?? '')))
        throw new Error('acceptance_model_resume_rejected');
      let stage = 'create';
      try {
      if (method === 'model/resume') agentHandle = await ctx.agents.resume({ resumeSessionId: input.sessionId,
        agentOptions: { provider: 'deepseek-official', model: process.env.DSH_ACCEPTANCE_MODEL, maxTokens: 4096 } });
      agentHandle ??= await ctx.agents.create({ sessionId: crypto.randomUUID(), meta: { cwd: process.cwd() },
        agentOptions: { provider: 'deepseek-official', model: process.env.DSH_ACCEPTANCE_MODEL, maxTokens: 4096 } });
      const agent = agentHandle.agent, calls = [];
      if (quiescing) throw new Error('acceptance_quiescing');
      let output = '';
      const results = ctx.on('tools/result', (exec, result) => {
        if (exec.agent?.id === agent.id) calls.push({ name: exec.name, callId: exec.callId, isError: result.isError,
          ...(typeof exec.arguments?.operationRef === 'string' ? { operationRef: exec.arguments.operationRef } : {}),
          ...(result.isError ? {} : { value: result.value }) });
      });
      const events = ctx.on('session/event', (session, event) => {
        if (session.id === agent.id && event.type === 'assistant/message')
          output = event.data.message.content.filter(block => block.type === 'text').map(block => block.text).join('');
      });
      try {
        stage = 'idle'; await agent.whenIdle();
        stage = 'followup';
        agent.followup(createUserMessage({ content: [{ type: 'text', text: input.task }], source: { kind: 'user' } }));
        stage = 'turn'; await agent.whenIdle();
        stage = 'flush';
        const session = ctx.sessions.get(agent.id);
        if (!session) throw Object.assign(new Error('Model session disappeared'), { code: 'session_not_live' });
        await ctx.sessions.flush(session);
        return { model: process.env.DSH_ACCEPTANCE_MODEL, sessionId: agent.id, calls, output };
      } finally { results(); events(); }
      } catch (error) {
        if (stage === 'flush') {
          let detail = String(error.message ?? 'Session flush failed').slice(0, 600);
          for (const value of [process.env.DEEPSEEK_API_KEY, process.env.AWIKI_E2E_OTP_PHONE, process.env.AWIKI_E2E_OTP_CODE])
            if (value) detail = detail.replaceAll(value, '[redacted]');
          process.stderr.write('acceptance-session-flush: ' + detail + '\n');
        }
        const category = typeof error.code === 'string' ? error.code.toLowerCase() : (error.name ?? 'error').toLowerCase();
        throw Object.assign(new Error('Model task failed'), { code: 'acceptance_model_' + stage + '_' + (/^[a-z_]{1,40}$/u.test(category) ? category : 'error') });
      }
    }
    if (method === 'tool') {
      if (!/^(?:anp_|pap_|identity_)[a-z_]+$/u.test(input.name)) throw new Error('acceptance_tool_rejected');
      agentHandle ??= await ctx.agents.create({ sessionId: crypto.randomUUID() });
      if (quiescing) throw new Error('acceptance_quiescing');
      const id = input.callId ?? crypto.randomUUID();
      // Let the production 30-second discovery budget finish before the test controller expires.
      const timeout = input.timeoutMs ?? (input.name === 'pap_connect' ? 40000 : 15000);
      if (!/^[a-zA-Z0-9-]{1,64}$/u.test(id) || !Number.isInteger(timeout) || timeout < 100 || timeout > 45000 || activeToolCalls.has(id))
        throw new Error('acceptance_tool_control_invalid');
      const controller = new AbortController();
      activeToolCalls.set(id, controller);
      try {
        const result = await ctx.tools.execute({ agent: agentHandle.agent, signal: AbortSignal.any([controller.signal, AbortSignal.timeout(timeout)]),
          calls: [{ type: 'tool_call', id, name: input.name, arguments: JSON.stringify(input.arguments) }] });
        return result.results[0].result;
      } finally { activeToolCalls.delete(id); }
    }
    if (method === 'capabilities') return {
      anpDomain: typeof ctx.anpIdentity.bindAnpDomainConsumer === 'function'
        && typeof ctx.anpIdentity.resolveDomainAccess === 'function',
      papHost: typeof ctx.anpIdentity.bindPapHostConsumer === 'function',
      protocols: typeof ctx.anpIdentity.bindProtocolConsumer === 'function',
    };
    if (method.startsWith('manager/')) {
      const member = method.slice(8);
      if (!managerMethods.has(member)) throw new Error('acceptance_method_rejected');
      return manager()[member](input);
    }
    if (method === 'create') return ordinary().requestCreateIdentity(input);
    if (method === 'getCreate') return ordinary().getCreateRequest(input);
    if (method === 'cancelCreate') return ordinary().cancelCreateRequest(input.requestId, input.expectedVersion);
    if (method === 'access') {
      const operation = input.operation?.action === 'http'
        ? { action: 'http', request: new Request(input.operation.url, { method: 'GET' }) }
        : input.operation;
      return ordinary().requestAccess({ ...input, ...(operation ? { operation } : {}) });
    }
    if (method === 'getAccess') return ordinary().getAccessRequest(input);
    if (method === 'open') { await ordinary().openAuthorizedIdentity(input); return { opened: true }; }
    if (method === 'cancelAccess') return ordinary().cancelAccessRequest(input.requestId, input.expectedVersion);
    if (method === 'read') {
      if (!objects.has(input.grantId)) objects.set(input.grantId, await ordinary().openAuthorizedIdentity(input.grantId));
      return objects.get(input.grantId).publicIdentity(input.executionId);
    }
    if (method === 'execution') return ordinary().getExecution(input);
    if (method === 'http') {
      const url = new URL(input.url);
      if (url.origin !== 'https://agent.agent-network-protocol.com'
        || !['/anp/catalog.json', '/agents/official/ad.json', '/anp/openapi.json'].includes(url.pathname))
        throw new Error('acceptance_target_rejected');
      if (!objects.has(input.grantId)) objects.set(input.grantId, await ordinary().openAuthorizedIdentity(input.grantId));
      const response = await objects.get(input.grantId).authenticatedHttp.dispatch(new Request(url), input.executionId);
      const value = await response.json();
      return { status: response.status, value };
    }
    throw new Error('acceptance_method_rejected');
  }
  const listener = message => {
    if (!message || typeof message.id !== 'string' || typeof message.method !== 'string') return;
    const operation = Promise.resolve().then(() => command(message.method, message.input));
    if (message.method === 'tool' || message.method.startsWith('model/')) {
      activeOperations.add(operation);
      operation.finally(() => activeOperations.delete(operation)).catch(() => {});
    }
    operation.then(
      value => process.send?.({ id: message.id, ok: true, value }),
      error => process.send?.({ id: message.id, ok: false,
        code: typeof error?.code === 'string' && /^[a-z][a-z0-9_]{0,80}$/u.test(error.code)
          ? error.code : 'acceptance_operation_failed' }),
    );
  };
  process.on('message', listener);
  const disconnect = () => ctx.get('appExit')?.(1);
  process.once('disconnect', disconnect);
  ctx.effect(() => () => process.off('disconnect', disconnect));
  ctx.effect(() => async () => { stopped = true; objects.clear(); process.off('message', listener); await agentHandle?.dispose(); });
  setImmediate(async () => {
    try {
      const appReady = ctx.get('appReady');
      if (!appReady) throw new Error('acceptance_app_readiness_required');
      await new Promise(resolve => appReady.onReady(resolve));
      if (process.env.DSH_ACCEPTANCE_REAL_MODEL === '1') {
        const entries = [...ctx.get('loader').entries()];
        for (const id of ['real-deepseek', 'model-session-persistence']) {
          if (entries.find(entry => entry.options.id === id)?.fiber?.state !== 2)
            throw Object.assign(new Error('Required model plugin is inactive'), { code: 'acceptance_required_model_plugin_inactive' });
        }
      }
      const deadline = Date.now() + 15000;
      while ((await ctx.anpIdentity.health()).status === 'unavailable') {
        if (Date.now() >= deadline) throw new Error('provider_unavailable');
        await new Promise(resolve => setTimeout(resolve, 50));
      }
      // The actual Loader must have committed this installed consumer's Fiber.
      ordinary();
      process.send?.({ ready: true, pid: process.pid });
    } catch (error) { process.send?.({ ready: false,
      code: typeof error?.code === 'string' && /^[a-z][a-z0-9_]{0,80}$/u.test(error.code)
        ? error.code : 'acceptance_provider_unavailable' }); }
  });
}
