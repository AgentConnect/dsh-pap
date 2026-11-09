import type { Context } from '@deepseek-ai/cordis';
import { PAP_TOOLS } from './product-api.js';
import { requirePap } from './errors.js';

export const name = PAP_TOOLS;
export const inject = ['pap', 'tools'];
/** Structural public DSH ToolDefinition; registration uses the real Host registry. */
interface ToolDefinition {
  name: string; description: string; parameters: object; timeoutMs?: number;
  output: { schema: object; render(args: unknown, value: unknown): { type: 'text'; text: string }[] };
  execute(args: unknown, execution: { agent?: unknown; signal?: AbortSignal }): Promise<unknown>;
}
const output = {
  schema: { type: 'object', additionalProperties: true },
  render: (_args: unknown, value: unknown) => [{ type: 'text' as const, text: JSON.stringify(value) }],
};
/** Domain setup uses the Host opt-in; account login and write enablement remain owner-only. */
export function apply(ctx: Context): void {
  const facade = ctx.pap.acquireTools(ctx);
  const registry = ctx.get('tools') as { register(tool: ToolDefinition): unknown } | undefined;
  requirePap(typeof registry?.register === 'function', 'permission_denied');
  const register = (tool: ToolDefinition) => { const dispose = registry.register(tool); if (typeof dispose === 'function') ctx.effect(() => () => { dispose(); }); };
  const empty = { type: 'object', properties: {}, additionalProperties: false };
  const agent = (execution: { agent?: unknown; signal?: AbortSignal }) => requirePap(execution.agent && !execution.signal?.aborted, 'permission_denied');
  register({ name: 'pap_connect', description: '输入域名自动发现 PAP Company、使用 Host 默认公共身份、复用或建立 Session，返回可用只读操作。无需逐域名配置；不启用写操作或账户登录。domain_access_disabled 表示只需一次性启用全局域名接入，default_identity_required 表示需要选择一次默认身份。',
    parameters: { type: 'object', properties: { domain: { type: 'string', minLength: 1, maxLength: 253 } }, required: ['domain'], additionalProperties: false }, output,
    execute: async (args, execution) => { agent(execution); requirePap(args && typeof args === 'object' && Object.keys(args).length === 1 && 'domain' in args && typeof args.domain === 'string', 'unsafe_destination'); return facade.connect(args.domain); } });
  register({ name: 'pap_status', description: 'PAP 状态入口：读取已配置身份、Company、连接和登录状态。首次使用先看状态；没有公共身份请用 identity_status / identity_request_creation。访问新域名先调用 pap_connect；disabled/not_configured 检查一次性全局接入设置，不要查私钥或其他 CLI。示例 https://agent-network-protocol.com supports MCP, ANP and PAP；用途为访问 ANP 社区官网。', parameters: empty, output,
    execute: async (_args, execution) => { agent(execution); return facade.status(); } });
  register({ name: 'pap_operations', description: '列出 PAP 操作及 opaque operationRef。域名模式返回所有已发现操作：requiresApproval=true 的写入或额外权限操作会在 pap_request 时自动弹窗，只批准本次请求，不持久启用写权限；blocked=true 表示用户明确禁用。空列表先用 pap_connect({domain})，不要编造引用或直接 curl 业务接口。no_as 不需要账户登录或 scope。', parameters: empty, output,
    execute: async (_args, execution) => { agent(execution); return facade.operations(); } });
  register({ name: 'pap_request', timeoutMs: facade.requestTimeoutMs, description: '调用 pap_operations 返回的 operationRef。域名模式的写入和额外权限会自动显示仅本次操作授权对话框并等待用户点击，不要要求用户去设置页手动启用；被明确禁用的操作仍不可调用。只提供声明过的 path/query 和可选 JSON body，不提供 URL/sessionRef/token/policyRef。path/query 值必须是字符串，例如 query: {page: "1"}；JSON body 保留自身类型。permission_denied 检查明确禁用及参数类型；静态模式仍要求已启用，不绕过权限；no_as 无需浏览器登录。写入必须用户明确要求，结果不确定绝不重发 POST。',
    parameters: { type: 'object', additionalProperties: false, required: ['operationRef'], properties: {
      operationRef: { type: 'string' },
      path: { type: 'object', description: 'Declared path parameter values encoded as strings.', additionalProperties: { type: 'string', maxLength: 1024 } },
      query: { type: 'object', description: 'Declared query parameter values encoded as strings; use page: "1", not page: 1.', additionalProperties: { type: 'string', maxLength: 4096 } },
      body: {},
    } }, output,
    execute: async (args, execution) => { agent(execution); return facade.request(args, execution.signal); } });
}
