import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { isPapLoopbackRedirect, httpsUrl } from '../src/util.js';

test('F-T06 explicit account loopback matches the shared B/C positive and negative configuration vectors',async()=>{
  const fixture=JSON.parse(await readFile(new URL('./vectors/pap-account-redirects.json',import.meta.url),'utf8')) as {vectors:{uri:string;valid_v2_account:boolean;lane?:string}[]};
  for(const vector of fixture.vectors) {
    assert.equal(isPapLoopbackRedirect(vector.uri),vector.valid_v2_account&&vector.lane==='loopback',vector.uri);
    if(vector.lane==='loopback')assert.throws(()=>httpsUrl(vector.uri),{code:'unsafe_destination'});
  }
});
