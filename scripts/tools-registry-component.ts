/** Focused real registry compatibility check; no model, credentials, Company or product boot. */
import assert from 'node:assert/strict';
import { Context } from '@deepseek-ai/cordis';
import Loader from '@deepseek-ai/cordis-plugin-loader';
import { readFile, realpath } from 'node:fs/promises';
import { dirname, isAbsolute, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import * as pap from '../src/plugin.js';
import * as tools from '../src/tools.js';
import { PAP_CONSUMER, PAP_TOOLS } from '../src/product-api.js';

const entry = process.argv[2]; assert(entry && isAbsolute(entry), 'An absolute installed DSH ToolRuntime entry is required');
const resolved = await realpath(entry); const bytes = await readFile(resolved);
const sha256 = createHash('sha256').update(bytes).digest('hex');
const manifest = JSON.parse(await readFile(join(dirname(resolved), '../package.json'), 'utf8'));
assert.equal(manifest.name, '@deepseek-ai/dsh-tools'); assert.equal(manifest.version, '0.1.5-rc.2');
const { ToolRuntime } = await import(pathToFileURL(resolved).href);
const ctx = new Context();
// The real ToolRuntime constructor needs its prompt-registration seam. No LLM runs.
ctx.provide('systemPrompt', { tools() { return () => {}; } });
ctx.provide('anpIdentity', {});
try {
  await ctx.plugin(ToolRuntime, {}); await ctx.plugin(Loader, {});
  const modules: Record<string, unknown> = { [PAP_CONSUMER]: pap, [PAP_TOOLS]: tools };
  ctx.loader.import = async name => { assert(Object.hasOwn(modules, name)); return modules[name]; };
  await ctx.loader.create({ name: PAP_CONSUMER, config: { enabled: false } });
  await ctx.loader.create({ name: PAP_TOOLS }); await ctx.loader.await();
  const runtime = ctx.get('tools') as { schemas(): { name: string }[]; execute(input: unknown): Promise<any> };
  const names = runtime.schemas().map(tool => tool.name); assert.deepEqual(names, ['pap_status', 'pap_operations', 'pap_request']);
  const execute = (name: string, args: unknown) => runtime.execute({ callId: `pap-registry-${name}`, name, arguments: args, agent: {}, signal: new AbortController().signal });
  const status = await execute('pap_status', {}); assert.equal(status.isError, false); assert.deepEqual(status.value, { ok: true, value: { state: 'disabled' } });
  const denied = await execute('pap_request', { operationRef: 'untrusted', url: 'https://untrusted.invalid', scopes: ['admin'] });
  assert.deepEqual(denied.value, { ok: false, error: { code: 'permission_denied' } });
  const noSetup = await execute('pap_operations', {}); assert.deepEqual(noSetup.value, { ok: false, error: { code: 'not_configured' } });
  assert.equal(createHash('sha256').update(await readFile(resolved)).digest('hex'), sha256);
  console.log(JSON.stringify({ stage: 'passed', boundary: 'actual_installed_dsh_tool_runtime_and_loader_no_model_no_company',
    package: manifest.name, version: manifest.version, resolvedEntry: resolved, entrySha256: sha256, entryUnchanged: true,
    tools: names, assertions: ['real_registry_registration','actual_execute_disabled_status','untrusted_wire_url_denied','unconfigured_operations_fail_closed'],
    promptRegistrationStub: true, identityServiceUnused: true, CNativeOrProductClaim: false }));
} finally { await ctx.fiber.dispose(); }
