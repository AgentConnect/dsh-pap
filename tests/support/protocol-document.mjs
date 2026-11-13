import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { AcceptanceError } from './config.mjs';

export function validateDocumentSelector(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).sort().join(',') !== 'document,language,version'
    || !['1.0','1.1','1.2'].includes(value.version) || !['en','zh'].includes(value.language)
    || typeof value.document !== 'string' || value.document.length > 256
    || !/^[a-z0-9_-]+(?:\/[a-z0-9_-]+)*$/u.test(value.document))
    throw new AcceptanceError('acceptance_invalid_document_selector');
}

/** Independent deployed-file oracle; it returns public metadata/hash only, never an API receipt. */
export async function protocolDocument(value) {
  validateDocumentSelector(value);
  const host = process.env.SERVICE_AGENT_SSH_HOST ?? 'guigu';
  if (!/^[a-zA-Z0-9_.-]+$/u.test(host) || host.startsWith('-')) throw new AcceptanceError('acceptance_invalid_ssh_host');
  const code = await readFile(new URL('./protocol-document-operator.py', import.meta.url), 'utf8');
  const quote = value => "'" + value.replaceAll("'", "'\\''") + "'";
  const child = spawn('ssh', ['-o','BatchMode=yes','-o','ConnectTimeout=10',host,
    'sudo -n python3 -c ' + quote(code)], { stdio: ['pipe','pipe','pipe'] });
  let output = '';
  child.stdout.on('data', bytes => { output += bytes.toString(); if (output.length > 4096) child.kill(); });
  child.stderr.resume(); child.stdin.on('error', () => {}); child.stdin.end(JSON.stringify(value));
  const timer = setTimeout(() => child.kill(), 30000);
  try {
    const status = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); });
    const result = JSON.parse(output);
    if (status !== 0 || result.error || !/^[a-f0-9]{64}$/u.test(result.sha256 ?? '')
      || !Number.isInteger(result.utf8Bytes) || result.utf8Bytes <= 0) throw new Error('unavailable');
    return result;
  } catch { throw new AcceptanceError('acceptance_protocol_document_oracle_unavailable'); }
  finally { clearTimeout(timer); }
}
