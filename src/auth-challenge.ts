import type { PapAuthHint } from './errors.js';
import type { Company, HttpResponse } from './types.js';
import { responseHeader } from './cooldown.js';
import { httpsUrl, parseJson } from './util.js';
const token = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const allowedErrors = new Set(['invalid_request','invalid_client','invalid_grant','invalid_scope','invalid_target','invalid_token','insufficient_scope','unauthorized_client','invalid_dpop_proof','use_dpop_nonce','invalid_session','session_ended','access_denied','extension_required']);
const challengeErrors = new Set(['invalid_request','invalid_client','invalid_grant','invalid_scope','invalid_target','invalid_token','insufficient_scope','unauthorized_client','invalid_dpop_proof','use_dpop_nonce','access_denied']);
interface Challenge { scheme: 'Bearer' | 'DPoP'; error?: string; scope?: string; metadata?: string; invalid: boolean }
function parameter(value: string): [string,string] | undefined {
  const equals = value.indexOf('='); if (equals < 1) return undefined;
  const key = value.slice(0,equals).trim().toLowerCase(); const raw = value.slice(equals+1).trim(); if (!token.test(key)) return undefined;
  if (raw.startsWith('"')) {
    let decoded = ''; let at = 1;
    while (at < raw.length) {
      const char = raw[at++]!;
      if (char === '"') return raw.slice(at).trim() === '' ? [key,decoded] : undefined;
      if (char === '\\') { if (at === raw.length) return undefined; decoded += raw[at++]!; }
      else decoded += char;
    }
    return undefined;
  }
  return token.test(raw) ? [key,raw] : undefined;
}
export function parseAuthenticate(value: string | undefined): { challenges: Challenge[]; relevant: boolean } {
  if (!value || value.length > 16384 || /[\x00-\x08\x0a-\x1f\x7f]/.test(value)) return { challenges:[],relevant:false };
  const segments: string[] = []; let start = 0; let quoted = false; let escaped = false;
  for (let at=0;at<value.length;at++) { const char=value[at]; if (escaped) { escaped=false; continue; } if (quoted && char==='\\') { escaped=true;continue; } if (char==='"') quoted=!quoted; if(char===','&&!quoted){segments.push(value.slice(start,at).trim());start=at+1;} }
  if (quoted || escaped) return { challenges:[],relevant:/\b(?:Bearer|DPoP)\b/i.test(value) };
  segments.push(value.slice(start).trim());
  const challenges: Challenge[] = []; let current: Challenge | undefined; let seen = new Set<string>(); let relevant = false;
  const take = (part: string) => { const parsed=parameter(part); if (!current) return; if(!parsed||seen.has(parsed[0])){current.invalid=true;return;}seen.add(parsed[0]); const [key,content]=parsed; if(key==='error')current.error=content;else if(key==='scope')current.scope=content;else if(key==='resource_metadata')current.metadata=content; };
  for (const part of segments) {
    if (/^[!#$%&'*+.^_`|~0-9A-Za-z-]+[ \t]*=/.test(part)) { take(part); continue; }
    const match = part.match(/^([!#$%&'*+.^_`|~0-9A-Za-z-]+)(?:[ \t]+(.*))?$/); current=undefined;seen=new Set();
    if (!match) continue;
    const scheme=match[1]!.toLowerCase(); if(scheme!=='bearer'&&scheme!=='dpop')continue;
    relevant=true;current={scheme:scheme==='dpop'?'DPoP':'Bearer',invalid:false};challenges.push(current);if(match[2])take(match[2]);
  }
  return {challenges:challenges.filter(item=>!item.invalid),relevant};
}
function metadataUrl(resource: string): string { const url=httpsUrl(resource); return `${url.origin}/.well-known/oauth-protected-resource${url.pathname==='/'?'':url.pathname}`; }
function safeHint(challenge: Challenge, company: Company, resource: string): PapAuthHint {
  const hint: { scheme: 'Bearer'|'DPoP'; scope?: string[]; resourceMetadataUrl?: string } = { scheme: challenge.scheme };
  if(challenge.scope && challenge.scope.length<=2048){const scopes=[...new Set(challenge.scope.split(' '))].sort();if(scopes.length>0&&scopes.length<=64&&scopes.every(scope=>/^[\x21\x23-\x5b\x5d-\x7e]{1,128}$/.test(scope)&&company.scopes.includes(scope)))hint.scope=scopes;}
  if(challenge.metadata && challenge.metadata.length<=2048){try{const url=httpsUrl(challenge.metadata);const allowed=metadataUrl(resource);if(!url.search&&url.href===challenge.metadata&&url.href===allowed)hint.resourceMetadataUrl=url.href;}catch{/* An untrusted metadata hint is dropped; it is never fetched. */}}
  return hint;
}
export function protocolFailure(response: HttpResponse, company?: Company, resource?: string, preferred?: 'Bearer'|'DPoP'): { code?: string; hint?: PapAuthHint; challenge: boolean } {
  if(response.status===401||response.status===403){
    const parsed=parseAuthenticate(responseHeader(response,'www-authenticate'));
    const preferredItems=parsed.challenges.filter(item=>item.scheme===preferred); const candidates=preferredItems.length?preferredItems:parsed.challenges; const selected=candidates[0];
    if(selected&&candidates.filter(item=>item.scheme===selected.scheme).some(item=>item.error!==selected.error||item.scope!==selected.scope||item.metadata!==selected.metadata))return{code:'oauth_error',challenge:true};
    if(selected){const code=selected.error===undefined?(response.status===401?'invalid_token':'insufficient_scope'):challengeErrors.has(selected.error)?selected.error:'oauth_error';return {code,hint:company&&resource?safeHint(selected,company,resource):undefined,challenge:true};}
    if(parsed.relevant)return {code:'oauth_error',challenge:true};
  }
  try {const body=parseJson(response);if(typeof body.error==='string'&&allowedErrors.has(body.error))return{code:body.error,challenge:false};}catch{}
  return {challenge:false};
}
