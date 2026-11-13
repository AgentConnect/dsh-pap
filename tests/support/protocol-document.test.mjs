import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { validateDocumentSelector } from './protocol-document.mjs';

const good = {version:'1.2',language:'zh',document:'did-authentication'};
const bad = [{...good,document:'../../runtime.env'},{...good,document:'https://example.invalid/x'},
  {...good,document:'a%2fb'},{...good,version:'9.9'},{...good,language:'xx'},{...good,path:'/etc/passwd'}];
test('read-only document oracle accepts only bounded public selectors', () => {
  assert.doesNotThrow(() => validateDocumentSelector(good));
  for(const value of bad) assert.throws(() => validateDocumentSelector(value),{code:'acceptance_invalid_document_selector'});
});
test('remote document selector rejects filesystem/URL/extra selectors before observation', () => {
  const path=fileURLToPath(new URL('./protocol-document-operator.py',import.meta.url));
  const code='import runpy,json,sys\nm=runpy.run_path(sys.argv[1])\ntry: m["validate"](json.load(sys.stdin))\nexcept (ValueError,TypeError,KeyError): sys.exit(2)';
  for(const value of [good,...bad]){
    const result=spawnSync('python3',['-c',code,path],{input:JSON.stringify(value),encoding:'utf8',timeout:10000});
    assert.equal(result.status,value===good?0:2);
    assert.equal(result.stdout,'');
  }
});
