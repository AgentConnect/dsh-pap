export type PapErrorCode =
  | 'identity_authorization_required' | 'identity_authorization_denied' | 'identity_authorization_expired'
  | 'discovery_failed' | 'unsupported_profile' | 'unsafe_destination' | 'namespace_changed'
  | 'permission_denied' | 'state_conflict' | 'state_corrupt' | 'credential_unavailable'
  | 'delegation_blocked' | 'invalid_session' | 'session_ended' | 'invalid_token'
  | 'reauthorization_required' | 'unsupported_sign_in' | 'invalid_authorization_response'
  | 'insufficient_scope' | 'unauthorized_client' | 'rate_limited' | 'request_uncertain'
  | 'redirect_blocked' | 'invalid_client' | 'invalid_dpop_proof' | 'invalid_scope' | 'invalid_target' | 'oauth_error' | 'disconnected' | 'revocation_pending' | 'not_configured' | 'credential_history_incomplete';

export interface PapAuthHint { readonly scheme: 'Bearer' | 'DPoP'; readonly scope?: readonly string[]; readonly resourceMetadataUrl?: string }

/** Errors are deliberately fixed text: no remote payloads or credentials. */
export class PapError extends Error {
  constructor(readonly code: PapErrorCode, readonly retryAfterSeconds?: number | string, readonly authHint?: PapAuthHint) {
    super(`PAP operation failed: ${code}`);
    this.name = 'PapError';
  }
}
export function requirePap(condition: unknown, code: PapErrorCode): asserts condition {
  if (!condition) throw new PapError(code);
}
