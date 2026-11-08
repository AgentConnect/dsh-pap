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
  register({ name: 'pap_status', description: 'PAP 状态入口：读取已配置身份、Company、连接和登录状态。首次使用先看状态；没有公共身份请用 identity_status / identity_request_creation。disabled/not_configured 请引导用户在设置中配置，不要查私钥或其他 CLI。示例 https://agent-network-protocol.com supports MCP, ANP and PAP；用途为访问 ANP 社区官网。', parameters: empty, output,
    execute: async (_args, execution) => { agent(execution); return facade.status(); } });
  register({ name: 'pap_operations', description: '列出用户已明确启用的 PAP 操作及 opaque operationRef。空列表时请用户到 PAP 连接选择已发布身份、发现 Company、建立连接并允许操作，不要编造 operationRef 或直接 curl 业务接口。no_as 不需要账户登录或 scope。', parameters: empty, output,
    execute: async (_args, execution) => { agent(execution); return facade.operations(); } });
  register({ name: 'pap_request', description: '调用 pap_operations 返回的已启用 operationRef。只提供声明过的 path/query 和可选 JSON body，不提供 URL/sessionRef/token/policyRef。path/query 值必须是字符串，例如 query: {page: "1"}；JSON body 保留自身类型。permission_denied 先检查操作是否启用及参数类型，不绕过权限；no_as 无需浏览器登录。写入必须用户明确要求，结果不确定绝不重发 POST。',
    parameters: { type: 'object', additionalProperties: false, required: ['operationRef'], properties: {
      operationRef: { type: 'string' },
      path: { type: 'object', description: 'Declared path parameter values encoded as strings.', additionalProperties: { type: 'string', maxLength: 1024 } },
      query: { type: 'object', description: 'Declared query parameter values encoded as strings; use page: "1", not page: 1.', additionalProperties: { type: 'string', maxLength: 4096 } },
      body: {},
    } }, output,
    execute: async (args, execution) => { agent(execution); return facade.request(args, execution.signal); } });
}
