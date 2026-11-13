import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const run = args => spawnSync(process.execPath, [fileURLToPath(new URL('./run-system.mjs', import.meta.url)), ...args],
  { encoding: 'utf8', timeout: 10000, env: { ...process.env, DSH_CLI: '/must-not-start-an-acceptance-host' } });

test('case listing is offline and names the actual requested scope', () => {
  const result = run(['--list', '--case', 'PAP-S01']);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /^PAP-S01 /u);
  assert.equal(result.stdout.trim().split('\n').length, 1);
});
test('an unknown case fails before installing or starting a Host', () => {
  const result = run(['--case', 'UNKNOWN-S99']);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /acceptance_unknown_case/u);
  assert.equal(result.stderr.includes('acceptance_dsh_cli_missing'), false);
});
test('full and focused scope cannot be silently combined', () => {
  const result = run(['--all', '--case', 'PAP-S01']);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /acceptance_conflicting_scope/u);
});
test('the full offline plan explicitly lists unavailable conditional account coverage', () => {
  const result = run(['--list']);
  assert.equal(result.status, 0);
  for (const id of ['PAP-A01', 'PAP-A02', 'PAP-A03', 'PAP-A04', 'PAP-A05'])
    assert.ok(result.stdout.includes(id + ' conditional_not_implemented_requires_real_AS_account_callback_cleanup'));
});
test('an explicitly selected conditional account case fails without starting a Host', () => {
  const listed = run(['--list', '--case', 'PAP-A01']);
  assert.equal(listed.status, 0);
  assert.match(listed.stdout, /^PAP-A01 conditional_not_implemented_requires_real_AS_account_callback_cleanup/u);
  const result = run(['--case', 'PAP-A01']);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Conditional account cases are not implemented: PAP-A01/u);
  assert.equal(result.stderr.includes('acceptance_dsh_cli_missing'), false);
});
