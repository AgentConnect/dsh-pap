import { requirePap } from './errors.js';
import { strictJson } from './strict-json.js';
import type { Company, HttpResponse, Operation, Route } from './types.js';

export const POPPY_APPROVAL = 'poppy-approval';
const identifier = /^[A-Za-z0-9_.-]{1,200}$/;
const minor = /^(0|[1-9]\d{0,15})$/;
type Fields = Record<string, unknown>;

export type OperationChallenge = { id: string; revision: string; expiresAt: number; purpose: string };

const object = (value: unknown): value is Fields => Boolean(value && typeof value === 'object' && !Array.isArray(value));
const clean = (value: string) => value.replace(/[\p{Cc}\p{Cf}]/gu, ' ').trim();

export function isOperationsRoute(company: Company, route: Route): boolean {
  return company.extensions?.operations === '3' && route.channel === 'openapi' && route.method === 'POST' &&
    (route.operationId === 'aftersales.submit' || route.operationId === 'aftersales.withdraw') &&
    new URL(route.template).origin === company.discoveryOrigin;
}

function selections(value: unknown): { line_id: string; quantity: number; title?: string }[] | undefined {
  if (!Array.isArray(value) || !value.length || value.length > 100) return;
  const seen = new Set<string>();
  const rows: NonNullable<ReturnType<typeof selections>> = [];
  for (const row of value) {
    if (!object(row) || typeof row.line_id !== 'string' || !identifier.test(row.line_id) || seen.has(row.line_id) ||
        typeof row.quantity !== 'number' || !Number.isSafeInteger(row.quantity) || row.quantity < 1) return;
    seen.add(row.line_id);
    rows.push({line_id: row.line_id, quantity: row.quantity, ...(typeof row.title === 'string' ? {title: clean(row.title)} : {})});
  }
  return rows.sort((a,b) => a.line_id.localeCompare(b.line_id));
}

function money(amount: string, currency: string): string {
  const padded = amount.padStart(3, '0');
  return `${currency === 'CNY' ? '¥' : '$'}${padded.slice(0,-2)}.${padded.slice(-2)} ${currency}`;
}

/** Render trusted labels from checked terms. Company prose is never interpreted as a consent instruction. */
function aftersalesPurpose(terms: Fields, request: Operation): string {
  const url = new URL(request.url);
  const path = /^\/poppy\/v1\/aftersales\/orders\/([^/]+)\/cases(?:\/([^/]+)\/withdraw)?$/.exec(url.pathname);
  const input: unknown = JSON.parse(request.body ?? 'null');
  requirePap(path && object(input) && terms.store_origin === url.origin &&
    terms.order_id === path[1] && typeof input.reason === 'string' && terms.reason === input.reason.trim(),
  'unsupported_profile');
  const target = `${url.origin} · 订单 ${path[1]}`;
  if (path[2]) {
    requirePap(terms.action === 'withdraw' && terms.case_id === path[2] && terms.case_revision === input.revision &&
      terms.not_sent === (input.not_sent === true) &&
      ['cancel_return','release_fulfillment_hold','withdraw_request'].includes(String(terms.effect)) &&
      (terms.effect !== 'cancel_return' || terms.not_sent === true), 'unsupported_profile');
    const effect = terms.effect === 'cancel_return' ? '已确认尚未寄出，撤回会取消退货。' :
      terms.effect === 'release_fulfillment_hold' ? '撤回后店铺可以发货。' : '';
    return `${target} · 撤回售后申请 ${path[2]}。${effect}`;
  }
  const kind = input.kind;
  const cancel = kind === 'cancel_order';
  const rows = selections(terms.lines);
  const { total_minor: amount, original_shipping_minor: shipping, currency } = terms;
  requirePap(rows && (cancel || kind === 'refund_only' || kind === 'return_and_refund') &&
    terms.action === 'submit' && terms.kind === kind && terms.refund_limit_per_order === 1 &&
    terms.order_effect === (cancel ? 'cancel_after_merchant_approval' : 'request_merchant_decision') &&
    typeof amount === 'string' && minor.test(amount) && amount !== '0' &&
    typeof shipping === 'string' && minor.test(shipping) && BigInt(shipping) <= BigInt(amount) &&
    (currency === 'USD' || currency === 'CNY'), 'unsupported_profile');
  if (!cancel) {
    const requested = selections(input.lines);
    requirePap(requested?.length === rows.length && requested.every((row,i) =>
      row.line_id === rows[i]!.line_id && row.quantity === rows[i]!.quantity) &&
      input.requested_minor === amount && input.shipping_minor === shipping, 'unsupported_profile');
  }
  const effect = cancel
    ? `取消整张订单，原路退回 ${money(amount,currency)}，含运费 ${money(shipping,currency)}。店铺批准后取消订单并释放库存预留。`
    : `${kind === 'refund_only' ? '仅退款' : '退货退款'}，申请 ${money(amount,currency)}，含原运费 ${money(shipping,currency)}。最终金额由店铺裁定。`;
  const items = rows.map(row => `${row.title || row.line_id} × ${row.quantity}`).join('、');
  const products = items.length <= 530 ? items : `${rows.length} 个订单行，共 ${rows.reduce((sum,row) => sum + row.quantity,0)} 件。完整商品见当前订单和提交内容。`;
  return `${target} · ${effect} 商品：${products}。本单最多成功退款一次，部分退款也会用完这次机会。`;
}

export function operationChallenge(response: HttpResponse, request: Operation, now = Date.now()): OperationChallenge | undefined {
  if (response.status !== 403 || response.headers['content-type']?.split(';')[0]?.trim().toLowerCase() !== 'application/json') return;
  const body = strictJson(response.body, 65536);
  if (!object(body) || body.error !== 'approval_required') return;
  const operation = body.operation;
  requirePap(object(operation) && typeof operation.operation_id === 'string' && identifier.test(operation.operation_id) &&
    typeof operation.revision === 'string' && identifier.test(operation.revision) && object(operation.terms) &&
    typeof operation.expires_at === 'string', 'unsupported_profile');
  const expiresAt = Date.parse(operation.expires_at);
  requirePap(Number.isFinite(expiresAt) && expiresAt > now, 'identity_authorization_expired');
  return { id: operation.operation_id, revision: operation.revision, expiresAt, purpose: aftersalesPurpose(operation.terms, request) };
}

export function approvalHeader(challenge: OperationChallenge): string {
  requirePap(identifier.test(challenge.id) && identifier.test(challenge.revision), 'unsupported_profile');
  return `operation_id="${challenge.id}", revision="${challenge.revision}", approver="user"`;
}
