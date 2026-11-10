# DSH PAP

Domain automatic access and exact-operation confirmation require `@agent-network-protocol/dsh-anp-identity >=0.1.14` in the same Host. The identity peer is optional for library-only use, but the domain plugin must have the new Host consent API. The supported policy is automatic discovered reads plus owner-approved one-shot writes; there is no full-write or chat-controlled global write setting in this release.

**A PAP 0.3 client for DeepSeek Harness (DSH), powered by a reusable, locally held agent identity.**

English | [简体中文](README.zh-CN.md)

[PAP 0.3 specification](https://github.com/personal-agent-protocol/personal-agent-protocol/blob/6fb46d381ac1b94265795132af13848ec442b6f6/content/versions/0.3/spec.mdx) · [Shared identity](https://github.com/agent-network-protocol/anp-identity) · [Service Agent demo](https://github.com/AgentConnect/service-agent) · [Apache-2.0](LICENSE)

## The problem

A personal agent should be able to connect to independent service agents without registering a fresh identity and handling another private key at every service. This plugin lets a DSH agent **reuse an existing, user-authorized identity** for PAP Company discovery, Delegation, signed Sessions and approved business operations.

PAP is one of three complementary paths in the shared-identity system:

| Protocol | Identity and authentication | Integration |
| --- | --- | --- |
| **ANP** | Published `did:wba` identity; per-request HTTP signatures | [dsh-anp](https://github.com/agent-network-protocol/dsh-anp) |
| **MCP** | CIMD/JWKS client metadata; `private_key_jwt` and policy-approved `client_credentials` OAuth | [DSH MCP Host](https://github.com/AgentConnect/dsh-harness-identity) |
| **PAP 0.3** | Identity-signed Delegation and per-request `Poppy-Session`, with optional separate account authorization | **This plugin** |

One local identity anchors these protocol-specific credentials. **A PAP Session is not an MCP access token, and neither bypasses Company policy or account permissions.** Private signing keys stay with the local [ANP Identity](https://github.com/agent-network-protocol/anp-identity) Host, not with dsh-pap or a remote Company.

## Features

- Discover PAP Companies and advertised OpenAPI operations over constrained HTTPS.
- Create regular or anonymous signed-out Sessions and generate fresh PAP Delegation/Session proofs through the local identity Host.
- Enable only explicitly user-approved operations; the agent cannot choose arbitrary endpoints, methods, headers, tokens or scopes.
- Support **Direct Sign-In** when a Company requires an account: user-initiated OAuth authorization, PKCE, optional DPoP, protected token storage, refresh and sign-out.
- Store per-identity/Company Session and account state in encrypted local storage, using a Host secret provider, OS keyring or an explicitly selected protected local-file key store.
- Expose a DSH settings interface and narrowly scoped model tools.

The reference [ANP website Service Agent](https://agent.agent-network-protocol.com/ready) supports **signed-out PAP Sessions without an account or browser login**. A separate Company (for example a suitably configured Frontvia integration) is required to test account sign-in. The plugin does not automatically grant account access.

## Architecture

```text
DSH user / settings UI          DSH Agent
  | identity + Company            | approved operation only
  | selection / consent           v
  v                            pap_status / pap_operations / pap_request
PAP management Remote ---------> dsh-pap Host plugin
                                      |
                            limited identity capability
                                      |
                         ANP Identity (same Host)
                         local Delegation / Session / DPoP signing
                                      |
                              signed HTTPS request
                                      v
                                PAP Company
                           OpenAPI / business resources
```

The shared identity can publish DID, CIMD and JWKS material through an identity service such as [AWiki](https://awiki.me); its private keys remain on the client. The PAP plugin owns protocol state and account-token handling, but **does not load or export the Agent/Delegation/DPoP private keys**.

## Requirements and installation

- Node.js **^22.19.0 or >=24.0.0**.
- Compatible DSH Host (current integration targets DSH `0.2.2-rc.1`, Cordis `4.1.0`).
- [ANP Identity](https://github.com/agent-network-protocol/anp-identity) in the same Host, with a previously created and published identity and approved PAP consumer policy.
- A writable, private absolute `stateRoot` and working secret backend. The default is the Linux Secret Service / keyring; an explicit `local-file` backend supports additional platforms.

Install the bundle when its package is available in your registry:

```sh
pnpm dsh plugin --profile <profile> add @awiki/dsh-pap@0.1.3
```

Build and run unit/component checks from source:

```sh
git clone https://github.com/AgentConnect/dsh-pap.git
cd dsh-pap
npm ci --ignore-scripts
npm run typecheck
npm run build
npm test
```

The package exposes separate Host service, management Remote, tool and web-client entries. The bundled [Cordis patch](cordis.patch.yml) registers them **disabled by default**; installing the bundle alone does not sign requests or discover Companies. Ensure the installed package version is compatible with your ANP Identity Host API. Source/component verification is not a claim of completed production end-to-end acceptance.

## Configure the Host

Configure the **exact** installed identity consumer `@awiki/dsh-pap/plugin` in ANP Identity. The Host must approve the selected identity, purpose/policy, Company targets and scopes. The model cannot change these bindings.

Example Host plugin row:

```yaml
- id: pap
  name: '@awiki/dsh-pap/plugin'
  config:
    enabled: true
    stateRoot: /absolute/private/dsh/profile/pap
    policyRef: approved-c-policy-id
    keyringService: org.agentconnect.dsh-pap
```

If the default keyring is unavailable, **explicitly** select file-backed key storage. The two directories must be distinct, non-overlapping absolute paths:

The keyring adapter uses Linux Secret Service. Windows and macOS return `credential_backend_unsupported`; retries cannot make that backend work. In domain mode the Identity Host owns storage selection: set `domainAccess.secretStore: local-file` on the identity plugin. Setting only the PAP plugin's `secretStore` is ineffective in domain mode. This is an explicit Host storage choice, never an automatic fallback; identity private-key custody and shared write permissions remain independent.

On Windows, file storage applies a DACL restricted to the current user. Its Windows PowerShell helper resolves the system module paths independently of an inherited PowerShell 7 `PSModulePath`; ACL failures still block key creation and never fall back to unprotected files.

```yaml
- id: pap
  name: '@awiki/dsh-pap/plugin'
  config:
    enabled: true
    stateRoot: /absolute/private/dsh/profile/pap
    policyRef: approved-c-policy-id
    secretStore: local-file
    secretsRoot: /absolute/private/dsh/secrets/pap
```

On Windows use appropriate absolute paths (for example `C:/Users/...`). Never point both settings at the same directory. There is **no automatic fallback or migration** between secret backends. Preserve state and its matching encryption keys during backups or migrations. Old unpublished `@agentconnect/dsh-pap` consumer approvals do not automatically authorize the current `@awiki/dsh-pap/plugin` consumer.

## Try the live three-protocol service

After installation, shared identity publication and Host approval:

1. Open the DSH **PAP Company** settings and select an existing published identity.
2. Discover the Company at `agent.agent-network-protocol.com`. Its public metadata is at `https://agent.agent-network-protocol.com/.well-known/poppy.json`.
3. Connect a **signed-out** Session. Explicitly enable the discovered read operation (`protocol_list` or `protocol_get`) for the agent; optionally enable `post_create` for a deliberate posting test.
4. Ask the DSH agent to invoke `pap_status` and `pap_operations`. Use the returned operation reference in `pap_request`:

```text
pap_status()
pap_operations()
pap_request({
  "operationRef": "<enabled post_create reference>",
  "body": { "content": "Hello from DSH via PAP" }
})
```

The placeholder must be replaced by the **actual enabled operationRef**; the model cannot manufacture one. Read the published result on the [ANP website posts page](https://agent-network-protocol.com/zh/posts). Documentation can be read using the appropriate discovered read operation and its declared parameters.

**No user-account OAuth login is needed for this signed-out demo.** For Companies requiring an account, a user must explicitly start Direct Sign-In through the management UI, complete the Company's authorization, and enable the relevant account-bound operation. The agent cannot initiate a browser login or collect authorization codes.

## Tools and user controls

| Interface | Available operations |
| --- | --- |
| **Agent tools** | `pap_status`, `pap_operations`, `pap_request` only |
| **User management** | `identity/select`, `company/discover`, `session/connect`, `session/disconnect`, `operation/enable`, `operation/disable` |
| **Account management** | `account/sign-in`, `account/collect`, `account/refresh`, `account/sign-out` |

The management Remote must be exposed only through an authenticated **user** gateway, never as a general model tool. Agent calls accept a previously authorized `operationRef` plus declared path/query fields and an optional JSON body; they do not accept arbitrary URL/method/headers, raw authorization tokens or resource changes.

## Service Agent example

https://agent-network-protocol.com is the project's example Service Agent for
MCP, ANP and PAP. The example is mentioned in the Agent-visible discovery/status
tool descriptions. To see ANP in action, discover `agent-network-protocol.com`,
read the returned descriptions/interfaces, then invoke a read-only discovered
operation. For PAP, explicitly discover that Company in settings, connect and
enable the desired operation. MCP uses a separately configured server connection.
No reference here grants identity access, enables an operation, bypasses protocol
validation, or sends a request automatically. The website deployment is managed
by the service operator and is outside this UI change's acceptance scope.

## Basic and advanced settings

The normal PAP page shows the active published identity, Company discovery,
one regular connection and explicit operation permission. Existing regular
connections are reused by the UI rather than creating duplicates. Connection
IDs/cleanup, per-operation connection changes, scopes and optional account
management are collapsed by default. NoAS companies do not show account-login
controls. Existing sessions are never deleted automatically, accounts/scopes are
never selected implicitly, and saving a different operation connection remains
an explicit user action.

## Security and current limits

- PAP state is AES-256-GCM encrypted and partitioned by identity/profile. Missing or mismatched secret keys fail closed.
- Local identity custody provides scoped, revocable signing capabilities; this plugin does not expose the private keys or a remote signing endpoint.
- Signed-out PAP makes no account-authority claim; account OAuth is explicit and separate from MCP machine tokens.
- Side-effecting requests are not blindly replayed after ambiguous failures. Token rotation, disconnect and sign-out enforce state and authorization fences.
- Browser Join, Mediated Sign-In, Device Sign-In, PS384, automatic account merging and a PAP-over-MCP transport are **not implemented** in this client.
- Existing legacy account state may require a controlled migration/revocation review; do not reset encrypted state or silently create replacement encryption keys.

For detailed API, storage, verification and recovery notes see the [Chinese technical README](README.zh-CN.md), [verification log](docs/verification.md) and [source code](src/).

## Related projects

[ANP Identity](https://github.com/agent-network-protocol/anp-identity) · [dsh-anp](https://github.com/agent-network-protocol/dsh-anp) · [service-agent](https://github.com/AgentConnect/service-agent) · [DSH Harness Identity](https://github.com/AgentConnect/dsh-harness-identity) · [AWiki User Service](https://github.com/AgentConnect/user-service)

## License

[Apache-2.0](LICENSE).

## Service examples and Agent guide

Below the Company field, `agent-network-protocol.com` is listed for visiting the
ANP community website and its multi-protocol example. Filling the example does
not discover, connect or grant anything automatically. Use `pap_status` first,
configure and approve operations in the owner UI, then `pap_operations` and
`pap_request`. URL path/query values are strings (e.g. `page: "1"`); JSON body
values retain their types. NoAS is not an account-login flow. The identity plugin's
`identity_connection_guide` remains available before PAP is configured.

## Domain-based automatic connections and shared permissions

Enable PAP and Host domain access once, then call `pap_connect({domain})`; do not configure a Company or permission for each domain. The candidate's Identity-owned **Protocol Management** page replaces the old PAP settings navigation. Its original browser component exports are no longer shipped by the client entry; encrypted legacy state and Host management diagnostics remain intact.

The original discovery origin is retained across validated redirects and refreshes. `pap_operations()` includes bounded inline `bodySchema` documentation and `operationId`; unavailable or external-reference schemas are explicitly marked and never fetched automatically. Unrelated legacy discoveries are marked for rediscovery without breaking a fresh domain connection. It returns every discovered operation with `effect`, `permission` (`allow`, `ask`, `deny`), `requiresApproval` and `blocked`. Every business call checks the shared read/write policy; the previously enabled read catalog cannot bypass a new denial. Allow executes without repeated confirmation but does not persist a route grant. Ask opens the global exact-operation dialog. Deny or explicit operation disable sends nothing. Account OAuth credentials remain separate and their scopes are never widened by these rules.

Classification uses the discovered method, body/security declarations and optional `x-agent-effect` / `x-agent-annotations` semantics; explicit read-only POST queries are supported. Unknown effects, declared payments and extra privileges still ask under all-write permission. Identity Host 0.1.15 or later is required; absence of its policy API fails closed, without a legacy permission fallback. Final dependency versions will be pinned before release.

`approvalWaitMs` defaults to 120000 (0–600000); `approvalPollMs` defaults to 1000 (10–10000). A timed-out pending request retains its original bound consent facade. Its key includes identity, Host policy, shared-policy version and exact request. Cancellation/unload cancels pending work. All relevant identity, policy, owner-denial, session and credential guards are rechecked before physical send; once-approved or policy-allowed mutations are never automatically replayed after session, token or nonce responses.

Failed `pap_request` results add `phase` and `businessRequest`: `not_sent` means no business transport call began, `unknown` means a transport attempt without a received response, and `response_received` retains `httpStatus` even when a later local permission check fails. These fields do not expose credentials, prove delivery of an attempted request, or justify retrying an uncertain write. The local candidate is jointly verified on both services through all three protocols; use Identity 0.1.15 with adapter 0.1.4.

Identity 0.1.15 provides `protocol_permissions` and `identity_settings` for owner-confirmed persistent settings changes from the Agent. A fresh explicit `pap_connect` adopts the saved default identity/epoch without deleting stored sessions or credentials; in-flight requests keep their old engine/identity fences. Configuration approval does not approve a business request or grant generic signing.
