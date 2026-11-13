import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { AcceptanceError } from './config.mjs';

export function validatePostRequest(request) {
  const uuid = '[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}';
  if (!request || typeof request !== 'object' || Array.isArray(request)
    || !['preflight', 'quota', 'locate', 'observe', 'cleanup'].includes(request.action)) throw new AcceptanceError('acceptance_invalid_post_scope');
  const keys = request.action === 'preflight' ? ['action'] : ['locate', 'quota'].includes(request.action) ? ['action', 'subject', 'protocol', 'marker'] : ['action', 'id', 'subject', 'protocol', 'marker'];
  if (Object.keys(request).some(key => !keys.includes(key)) || keys.some(key => typeof request[key] !== 'string'))
    throw new AcceptanceError('acceptance_invalid_post_scope');
  if (request.action === 'preflight') return;
  if (!['locate', 'quota'].includes(request.action) && !new RegExp('^' + uuid + '$', 'u').test(request.id) || !['anp', 'pap'].includes(request.protocol)
    || !new RegExp('^dsh-' + request.protocol + '-acceptance-' + uuid + '$', 'u').test(request.marker))
    throw new AcceptanceError('acceptance_invalid_post_scope');
  if (request.protocol === 'anp') {
    if (!/^did:(?:wba|web):awiki\.me:[A-Za-z0-9_.:%-]+$/u.test(request.subject))
      throw new AcceptanceError('acceptance_invalid_post_scope');
  } else {
    let url;
    try { url = new URL(request.subject); } catch { throw new AcceptanceError('acceptance_invalid_post_scope'); }
    if (url.origin !== 'https://awiki.me' || url.username || url.password || url.pathname.length <= 1
      || url.search || url.hash) throw new AcceptanceError('acceptance_invalid_post_scope');
  }
}

/** Exact existing-server operator. Payload travels over stdin, never shell interpolation. */
export async function postOperator(request, { host = process.env.SERVICE_AGENT_SSH_HOST ?? 'guigu' } = {}) {
  validatePostRequest(request);
  if (!/^[a-zA-Z0-9_.-]+$/u.test(host) || host.startsWith('-')) throw new AcceptanceError('acceptance_invalid_ssh_host');
  const code = await readFile(new URL('./post-operator.py', import.meta.url), 'utf8');
  const quote = value => "'" + value.replaceAll("'", "'\\''") + "'";
  const child = spawn('ssh', ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', host,
    'sudo -n python3 -c ' + quote(code)], { stdio: ['pipe', 'pipe', 'pipe'] });
  let output = '';
  child.stdout.on('data', bytes => { output += bytes.toString(); if (output.length > 16384) child.kill(); });
  child.stderr.resume();
  child.stdin.on('error', () => {});
  child.stdin.end(JSON.stringify(request));
  const timer = setTimeout(() => child.kill(), 30000);
  try {
    const status = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); });
    if (status !== 0) throw new AcceptanceError('acceptance_post_operator_unavailable');
    const result = JSON.parse(output);
    if (result.error) throw new AcceptanceError('acceptance_post_operator_failed');
    return result;
  } catch (error) {
    if (error instanceof AcceptanceError) throw error;
    throw new AcceptanceError('acceptance_post_operator_failed');
  } finally { clearTimeout(timer); }
}
