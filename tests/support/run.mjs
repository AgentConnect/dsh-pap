import { spawn } from 'node:child_process';
import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { AcceptanceError } from './config.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const prefix = "PAP";
const required = {
  system: Array.from({ length: 12 }, (_, index) => prefix + '-S' + String(index + 1).padStart(2, '0')),
  e2e: Array.from({ length: 5 }, (_, index) => prefix + '-E' + String(index + 1).padStart(2, '0')),
};
const accountCases = Array.from({ length: 5 }, (_, index) => 'PAP-A' + String(index + 1).padStart(2, '0'));

/** Narrow native node:test entrypoint; unimplemented or unmatched cases never pass. */
export async function runSuite(kind, args = process.argv.slice(2)) {
  const options = { list: false, all: false, cases: [] };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--list') options.list = true;
    else if (args[i] === '--all') options.all = true;
    else if (args[i] === '--case' && args[i + 1]) options.cases.push(...args[++i].split(','));
    else throw new AcceptanceError('acceptance_invalid_argument');
  }
  if (options.all && options.cases.length) throw new AcceptanceError('acceptance_conflicting_scope');
  const directory = join(root, 'tests', kind);
  const files = (await readdir(directory)).filter(file => file.endsWith(kind === 'system' ? '.test.mjs' : '.spec.mjs')).sort();
  const found = new Map();
  for (const file of files) {
    const source = await readFile(join(directory, file), 'utf8');
    for (const match of source.matchAll(/\btest\(['"]([A-Z]+-[SEA][0-9]{2}) /gu)) {
      if (found.has(match[1])) throw new AcceptanceError('acceptance_duplicate_case');
      found.set(match[1], file);
    }
  }
  const selected = options.cases.length ? [...new Set(options.cases)] : required[kind];
  for (const id of selected) if (![...required[kind], ...accountCases].includes(id)) throw new AcceptanceError('acceptance_unknown_case');
  const status = id => found.get(id) ?? (accountCases.includes(id)
    ? 'conditional_not_implemented_requires_real_AS_account_callback_cleanup' : 'not_implemented');
  if (options.list) {
    for (const id of selected) process.stdout.write(id + ' ' + status(id) + '\n');
    if (!options.cases.length) for (const id of accountCases)
      process.stdout.write(id + ' ' + status(id) + '\n');
    return;
  }
  if (!options.cases.length) process.stdout.write('Conditional account scope: ' + accountCases.join(', ')
    + '; not implemented or counted as passes. Eligibility requires real AS discovery, protected accounts and callback cleanup; NoAS is verified separately.\n');
  const missing = selected.filter(id => !found.has(id));
  const runnable = selected.filter(id => found.has(id));
  if (runnable.length) {
    const pattern = '^(' + runnable.join('|') + ') ';
    const testFiles = [...new Set(runnable.map(id => join(directory, found.get(id))))];
    const child = spawn(process.execPath, ['--test', '--test-concurrency=1', '--test-reporter=spec',
      '--test-name-pattern=' + pattern, ...testFiles], { cwd: root, stdio: 'inherit' });
    const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', value => resolve(value ?? 1)); });
    if (code) process.exitCode = code;
  }
  if (missing.length) {
    const ordinary = missing.filter(id => !accountCases.includes(id));
    const accounts = missing.filter(id => accountCases.includes(id));
    if (ordinary.length) process.stderr.write('Required cases are not implemented: ' + ordinary.join(', ') + '\n');
    if (accounts.length) process.stderr.write('Conditional account cases are not implemented: ' + accounts.join(', ')
      + '; requires real AS discovery, protected accounts and callback cleanup.\n');
    process.exitCode = 1;
  }
  if (!runnable.length && !missing.length) throw new AcceptanceError('acceptance_zero_cases');
}
