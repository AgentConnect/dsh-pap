import type { Context } from '@deepseek-ai/cordis';
import { PAP_TOOLS } from './product-api.js';
import { requirePap } from './errors.js';

export const name = PAP_TOOLS;
export const inject = ['pap', 'tools'];
/** Structural public DSH ToolDefinition; registration uses the real Host registry. */
interface ToolDefinition {
  name: string; description: string; parameters: object;
  output: { schema: object; render(args: unknown, value: unknown): { type: 'text'; text: string }[] };
  execute(args: unknown, execution: { agent?: unknown; signal?: AbortSignal }): Promise<unknown>;
}
const output = {
  schema: { type: 'object', additionalProperties: true },
  render: (_args: unknown, value: unknown) => [{ type: 'text' as const, text: JSON.stringify(value) }],
};
/** No tools for identity selection, discovery, browser sign-in, callback collection or sign-out. */
export function apply(ctx: Context): void {
  const facade = ctx.pap.acquireTools(ctx);
  const registry = ctx.get('tools') as { register(tool: ToolDefinition): unknown } | undefined;
  requirePap(typeof registry?.register === 'function', 'permission_denied');
  const register = (tool: ToolDefinition) => { registry.register(tool); };
  const empty = { type: 'object', properties: {}, additionalProperties: false };
  const agent = (execution: { agent?: unknown; signal?: AbortSignal }) => requirePap(execution.agent && !execution.signal?.aborted, 'permission_denied');
  register({ name: 'pap_status', description: 'Read PAP connection and account status. Ask the user to configure PAP or sign in when required.', parameters: empty, output,
    execute: async (_args, execution) => { agent(execution); return facade.status(); } });
  register({ name: 'pap_operations', description: 'List Company operations explicitly enabled by the user. Use their opaque operationRef with pap_request.', parameters: empty, output,
    execute: async (_args, execution) => { agent(execution); return facade.operations(); } });
  register({ name: 'pap_request', description: 'Invoke one user-enabled Company operation. Supply its operationRef and only declared path/query parameters and optional JSON body. Path and query values must be strings, including numeric parameters (for example query: {page: "1"}). Account sign-in is a separate user action.',
    parameters: { type: 'object', additionalProperties: false, required: ['operationRef'], properties: {
      operationRef: { type: 'string' },
      path: { type: 'object', description: 'Declared path parameter values encoded as strings.', additionalProperties: { type: 'string', maxLength: 1024 } },
      query: { type: 'object', description: 'Declared query parameter values encoded as strings; use page: "1", not page: 1.', additionalProperties: { type: 'string', maxLength: 4096 } },
      body: {},
    } }, output,
    execute: async (args, execution) => { agent(execution); return facade.request(args, execution.signal); } });
}
