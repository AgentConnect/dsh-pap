# DSH PAP acceptance tests

System scenarios belong to `tests/system/`; real DSH + DeepSeek browser journeys belong to `tests/e2e/`.
The repository owns its runner, assertions and fixtures. These tests do not use
`awiki-system-test`, import sibling source modules, or change shared DSH profiles.

This suite is being implemented. `--list` distinguishes executable scenarios from
`not_implemented`. Selecting a missing case or running the incomplete full suite
returns a nonzero status; absence of tests is never a pass.

## Running

Use Node >=24.9, the current Harness CLI and the ordinary npm install prerequisites.
Run the following commands from `.`:

```sh
npm run test:acceptance-support
npm run test:system -- --list
npm run test:system -- --case PAP-S02
npm run test:e2e -- --list
```

The full/list output also names conditional account cases PAP-A01–PAP-A05.
They require an advertised AS, suitable protected accounts and callback cleanup;
they are currently unimplemented and never counted as passes. Selecting one
explicitly fails before starting a Host. PAP-S10 independently verifies NoAS
eligibility against the actual selected Company; NoAS does not establish account
login, DPoP, refresh, revoke or account-recovery acceptance.

`DSH_CLI` selects the built DSH CLI bin (default: the sibling independent Harness).
`AWIKI_IDENTITY_PACKAGE` selects an absolute identity-plugin candidate tarball or
an exact published identity-plugin version. When omitted, this repository uses
the exact published identity plugin `0.1.16`. Its actual installed version is
included in runtime evidence. The local identity source is a separate candidate
and is never substituted silently.
The subject candidate is built and packed into a protected temporary directory.

S01 records the subject tarball SHA-256, installed entry hashes, exact identity
version and npm integrity, plus the actual native platform package, binary path,
version and SHA-256. Native wrapper/platform versions must agree. The evidence
is a native node:test diagnostic on the current OS/architecture; it creates no
separate result archive and does not imply cross-platform acceptance.

Installation uses normal npm resolution with scripts disabled, preserving peer
dependency checks. A candidate/Host mismatch is a failure, not a reason to force
installation or change public version numbers.

The deterministic controller is a private fixture installed by the actual Loader.
Only its parent's IPC channel can request ordinary consumer or user manager actions.
It registers no model tools or network listener. This is system-test control,
not the browser actor required for E2E.

## Protected factors and fixed destinations

`AWIKI_TEST_FACTOR_FILE` selects the protected AWiki Me YAML (fields `otp.phone`
and `otp.code`) or an explicit dotenv (only `DEV_OTP_PHONE` and `DEV_OTP_CODE`).
The default is the existing `~/awiki-space/awiki-me/tests/e2e/configs/e2e.local.yaml`.
Files must be owned by the invoking user, have no group/other permissions, and
must not be symlinks. `AWIKI_E2E_OTP_PHONE` and `AWIKI_E2E_OTP_CODE` override
as a complete pair. Missing explicit input never falls back to another file.

Identity requests go to `https://awiki.me`. Discovery begins at
`https://agent-network-protocol.com`; discovered origins are checked by the
actual Host. Service URLs, DB configuration and unrelated credentials in the
factor file are never inherited. The configured phone, OTP, tokens and private
keys must not be printed, recorded in prompts, snapshots or command arguments.

## Planned coverage

Locations indicate implementation, not a passing full-run report. PAP-S07 has
exercised the actual one-hour boundary in full System verification; use the
current run result for candidate-specific acceptance. PAP-E05 operates the real
PAP Connections settings section; shared protocol permissions remain in Identity.

| Cases | Scenario | Location / gap |
|---|---|---|
| PAP-S01 | Installed, disabled client | `system/lifecycle.test.mjs` |
| PAP-S02 | Anonymous discovery, metadata target and byte/hop budgets | `system/discovery.test.mjs` |
| PAP-S10 | Actual NoAS/account boundary | `system/discovery.test.mjs` |
| PAP-S03 | Real signed-out Session | `system/session.test.mjs` |
| PAP-S04, PAP-S05 | Document and approved write/readback | `system/business.test.mjs` |
| PAP-S06 | Denial, cancellation, timeout, unload and actor failure | `system/consent.test.mjs` |
| PAP-S07 | Actual delegation expiry/renewal | `system/delegation-expiry.test.mjs`; actual default 3600-second lifetime |
| PAP-S08 | Proof-purpose isolation without fallback | `system/proof-isolation.test.mjs` |
| PAP-S09 | Persistent disconnect and actual restart | `system/disconnect.test.mjs`; public user-management API, not GUI evidence |
| PAP-S11 | Injected Session/rate errors, no write replay | `system/errors.test.mjs` |
| PAP-S12 | Lost receipt and exact cleanup | `system/lost-receipt.test.mjs` |
| PAP-E01, PAP-E02 | Actual model discovery/document reading | `e2e/read.spec.mjs` |
| PAP-E03 | Actual model write with UI approval | `e2e/post.spec.mjs` |
| PAP-E04 | UI refusal without alternate-channel bypass | `e2e/denial.spec.mjs` |
| PAP-E05 | Real UI disconnect/reconnect and restart | `e2e/restart.spec.mjs`; real PAP Connections page and persisted model session |
| PAP-A01–PAP-A05 | Account login, DPoP, refresh, revoke and restart | Conditional coverage unavailable: selected Company advertises NoAS; not counted as passes |

## Evidence boundary

PAP-S02 supplements real root-to-subdomain discovery with explicit bounded response
faults after actual HTTPS responses: a six-hop redirect loop, an HTTP target,
an HTTPS private-address target, an inconsistent Company, an oversized single
response and cumulative bytes above 4 MiB. The cumulative lane keeps every
individual document at 1 MiB minus one byte. Fault hits, zero private-probe sends,
anonymous headers, zero business/OAuth sends and continued use of the original
working Session are checked. Fault-expanded bodies are private test input, not
large responses naturally returned by the remote service. The controller gives
discovery 40 seconds so the production 30-second budget can finish; write/cancel
test deadlines remain explicit and bounded.

PAP-S04 checks the requested version/document/language and the real service's
404 `protocol_not_found` results for unknown values. The adapter exposes these
as HTTP business responses, not a successful document or a fabricated transport
exception. The observed negative operations are read-only and issue no POST.
S04 and E02 require the actual Markdown SHA-256 to match a separate read-only
observation of the running Service Agent's deployed public catalog. Its selector
cannot specify a file path or URL, and only public metadata/hash crosses SSH.
This detects a nonempty placeholder such as `[redacted]` being mistaken for the
requested document. Explicit angle-bracket authorization examples are preserved;
known sent/history secrets, private fields, ordinary credential values and full
compact assertions remain redacted, with owning unit and product regression tests.

PAP-S08 observes only header-presence booleans on actual PAP reads, probes two
fixed read URLs with the wrong proof placement, and checks that an injected
Session error produces no ANP/OAuth fallback. Proof bytes remain in private
controller memory. These probes are negative system evidence, not model journeys.

PAP-S11 applies explicit one-shot response faults after successful real HTTPS
requests. It covers `invalid_session`, `session_ended` and `rate_limited`, including
`Retry-After`. Its POSTs may already be committed before the injected error reaches
the client: each must have exactly one send and response, an independently queried
marker, and exact cleanup with quota restoration. This does not claim the remote
service naturally produced these errors or that an actual rate-limit response
commits a write. The client never retries those POSTs.

PAP-S07 uses the actual default 3600-second delegation lifetime and real wall
time. It can take slightly over one hour. It verifies the same live Host while
waiting, then checks old-proof rejection and a new delegated-key thumbprint.
Only times and public thumbprints leave the controller; compact proofs remain
in private process memory. No fake clock or replacement signer is used. This
long case is part of final full verification, not a fast development check.

Unit/fixture checks are separate from installed-Host system evidence and real-model
E2E evidence. The local custody scenarios do not claim remote registration or publication.
Each runtime has a private temporary DSH home and state. Restart tests stop and
reopen the same state with a new process. Teardown waits for the actual child to
exit before removing owned files; failure does not authorize killing other processes.

Live registration and writes require an exact cleanup route before creation.
Uncertain writes are queried, never replayed. Do not bulk-delete identities by phone.
Preserve only necessary private recovery input if cleanup remains unresolved.
The protected `post-recovery.json` contains `scope`, `quotaBaseline` and
write-count observations. Pass only `scope` to the exact operator; keep the
baseline for restoration checks. A business-recovery error includes a safe
cleanup-stage code. Remove this input after restoration, never archive it.

If the actor fails, owned-post teardown first drains and stops the actual Host
before locating or deleting remote objects. An unconfirmed stop preserves recovery
input. S06's runner-error branch verifies cancellation across restart and rejection
of late approval. Native diagnostics bind the branch and actual tool call ID to
the fixed POST method/origin/path and observed send count; model traces also carry
the real DSH tool call IDs. Credentials and signed headers are never included.

Use native runner output and concise failure diagnostics. Do not create
`verification-runs/`, replacement archives or execution indexes. Full acceptance
receives a concise final HTML report according to workspace rules after all
implementation is complete; focused checks are reported directly.

## Connection lifecycle UI

The PAP Connections settings section manages existing sessions only. It does not
restore the legacy discovery/account/permission form. Opening or refreshing the
page restores authorized local state without connecting a Company. Disconnected
sessions remain closed across Host restart until the user explicitly reconnects;
account reconnects retain their account-slot binding. Protocol access permissions
remain in the shared Identity Protocol Management section.
