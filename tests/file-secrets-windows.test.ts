import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { FileSecretStore } from '../src/file-secrets.js';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

test('Windows file custody resolves Windows PowerShell modules independently of the parent shell', { skip: process.platform !== 'win32' }, async t => {
  const root = await mkdtemp(join(tmpdir(), 'pap-file-custody-'));
  const original = process.env.PSModulePath;
  process.env.PSModulePath = join(root, 'unrelated-shell-modules');
  t.after(async () => {
    if (original === undefined) delete process.env.PSModulePath; else process.env.PSModulePath = original;
    await rm(root, { recursive: true, force: true });
  });
  const store = new FileSecretStore(join(root, 'keys'));
  assert.equal(await store.getEncryptionKey('missing'), undefined);
  const first = await store.getOrCreateEncryptionKey('existing');
  assert.equal(first.length, 32);
  assert.deepEqual(await store.getEncryptionKey('existing'), first);
  assert.deepEqual(await store.getOrCreateEncryptionKey('existing'), first);
  const env: NodeJS.ProcessEnv = { ...process.env, PAP_TEST_KEYS_ROOT: store.root };
  delete env.PSModulePath;
  const script = `$ErrorActionPreference='Stop'; $sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; $items=@(Get-Item -LiteralPath $env:PAP_TEST_KEYS_ROOT)+@(Get-ChildItem -LiteralPath $env:PAP_TEST_KEYS_ROOT); foreach($item in $items) { $acl=Get-Acl -LiteralPath $item.FullName; if(-not $acl.AreAccessRulesProtected) {throw 'Inherited access remains'}; foreach($rule in $acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])) { if($rule.IdentityReference.Value -ne $sid -or $rule.AccessControlType -ne 'Allow') {throw 'Unexpected access rule'} } }; Write-Output 'private'`;
  const checked = await promisify(execFile)('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], { env, windowsHide: true, timeout: 10000 });
  assert.equal(checked.stdout.trim(), 'private');
  first.fill(0);
});
