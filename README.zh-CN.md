# DSH PAP：DeepSeek Harness 的 PAP 0.3 客户端

`0.1.5` 修复显式选用的 Windows `local-file` 后端，并在 keyring 平台不受支持时明确报错，不静默降级。状态密钥仍受仅当前所有者可访问的 DACL 保护，身份与签名密钥仍由 Native 保管。

域名自动接入和单次操作确认需要同一 Host 中的 `@agent-network-protocol/dsh-anp-identity >=0.1.15`。该 peer 对纯库用途是可选依赖。域名请求遵守共享的读写允许、询问与禁止规则；持续配置变更需要所有者确认，不开放通用签名权限。

[English](README.md) | 简体中文

本项目让 DSH 中的 Personal Agent 使用**一套可复用的本地身份**连接外部 PAP Company。用户创建并发布身份、授权插件和业务操作后，Agent 无需在每个服务重复创建自己的密钥和身份；但 Company 的准入策略、权限检查与需要账户时的用户授权仍然有效。

## 与 ANP、MCP 的关系

| 协议 | 采用的身份认证方式 | 组件 |
| --- | --- | --- |
| ANP | `did:wba` 身份 + 逐请求 HTTP 签名 | [dsh-anp](https://github.com/agent-network-protocol/dsh-anp) |
| MCP | CIMD/JWKS + `private_key_jwt` + `client_credentials` | [DSH MCP Host](https://github.com/AgentConnect/dsh-harness-identity) |
| **PAP 0.3** | 本地身份签发 Delegation，使用 `Poppy-Session`；账户授权单独处理 | **本仓库** |

共享的是本地身份和签名底座，**不是**同一个可在三种协议间复用的 Token。Agent／Delegation／DPoP 私钥由本地 [ANP Identity](https://github.com/agent-network-protocol/anp-identity) 管理，不托管在本插件或远端服务。

## 快速安装

要求 Node.js `^22.19.0 || >=24.0.0`、兼容 DSH Host、已发布的身份，以及在 ANP Identity 中批准 `@awiki/dsh-pap/plugin` 这一精确消费者。

```sh
pnpm dsh plugin --profile <profile> add @awiki/dsh-pap@0.1.3
```

源码构建：

```sh
git clone https://github.com/AgentConnect/dsh-pap.git
cd dsh-pap
npm ci --ignore-scripts
npm run typecheck
npm run build
npm test
```

安装后插件默认不启用。需要在 Host 的 Cordis 配置中显式开启并配置本地加密状态目录和身份政策：

```yaml
- id: pap
  name: '@awiki/dsh-pap/plugin'
  config:
    enabled: true
    stateRoot: /absolute/private/dsh/profile/pap
    policyRef: approved-c-policy-id
    keyringService: org.agentconnect.dsh-pap
```

Linux 默认使用 Secret Service；其他平台或没有可用 Keyring 时，可以显式使用 `secretStore: local-file` 和独立的绝对路径 `secretsRoot`。两种存储不会自动降级或迁移。配置细节见下方完整技术说明。

## 线上演示：不需要账户登录的 PAP Session

已部署示例：[Service Agent](https://agent.agent-network-protocol.com/ready)、[PAP Company 元数据](https://agent.agent-network-protocol.com/.well-known/poppy.json)、[官网公开帖子](https://agent-network-protocol.com/zh/posts)。

1. 打开 DSH 的 **PAP Company 连接**设置，选择已发布的共享身份。
2. 发现域名 `agent.agent-network-protocol.com`，连接 **signed-out Session**。
3. 由用户显式启用发现结果中的 `protocol_list`、`protocol_get` 或 `post_create` 操作。
4. 在 Agent 中通过 `pap_status`、`pap_operations` 查询已授权操作，再使用实际返回的操作引用调用：

```text
pap_request({
  "operationRef": "<已批准的 post_create 操作引用>",
  "body": { "content": "Hello from DSH via PAP" }
})
```

这是**无需浏览器、无需用户账户授权服务器的 Session 示例**；不等于获取了远端用户账户权限。若 Company 需要账户权限，必须由用户在管理界面主动发起 Direct Sign-In 并完成授权，Agent 不能自行打开授权页面或提取授权码。

下面保留本项目已有的详细实现、安全与测试记录，便于进一步集成和核验。

---

## 详细设计、接口与验证记录

### 原始技术 README（PAP 0.3）

Apache-2.0-licensed DSH Host plugin and PAP client. The protocol baseline is
[the fixed 0.3 spec](https://github.com/personal-agent-protocol/personal-agent-protocol/blob/6fb46d381ac1b94265795132af13848ec442b6f6/content/versions/0.3/spec.mdx),
Git blob `01e9dc34bacb73ef0a740cc3bae77d82f0be0d37`.

源码以 [Apache-2.0](LICENSE) 公开。包名为 `@awiki/dsh-pap`，声明 DSH bundle；发布必须经过显式授权和发布前验证。安装 bundle 默认不启用签名或网络请求，仍需配置身份、用途策略和秘密后端。

## 已实现路径

- Company discovery：HTTPS 受限重定向，DNS 解析与实际连接绑定，地址、大小、时间、请求数限制；根 PRM 与精确 issuer 双向关联；无 AS、账户和 disabled 分开。网络错误保留已知 issuer，Company Identifier 改变后隔离原命名空间。
- 随机且私有的 Company User/Agent ID、独立匿名身份、sid 和加密事务状态。匿名 Session 禁止账户 Token。Agent ID 不改变 User ID。新账户 slot 使用新 Session。
- 通过 C 的 `./protocol-client` 调用 A 本地 custody：临时 P-256 key、身份 Delegation、逐请求 Session、独立 DPoP key、客户端断言和重启后 handle 恢复。F 不打开 NativeStore，不持有或导出这些私钥，不调用远程 signer。
- 每个实际资源请求重新签 `Poppy-Session`，绑定实际 htm/htu，带账户 Token 时才有 ath。发现、描述和 OAuth 请求不携 Session；禁止调用者注入认证 Header；凭据重定向停止。
- Direct Sign-In：显式用户入口、state、issuer、43 字符 S256 PKCE verifier、已发布 callback 校验、标准账户 Token、可选 RFC 9449 DPoP 和按 AS/资源分离的 nonce。
- 独立 PAP account store：scope/resource 约束、refresh single-flight/CAS、轮换 Token 原子替换、丢回执标为 uncertain、退出撤销及 revocation_pending。持久 account slot epoch 同时约束登录事务、refresh 和发送前检查；退出取消 pending/exchanging 登录，迟到 Token 只保留撤销信息。并发资源调用会等待同一刷新代次。
- `invalid_session` 停止，`session_ended` 新 sid 后最多重发一次，仅 GET/HEAD/OPTIONS 的 Token 错误可刷新后最多重发一次；副作用 API 的认证 challenge 不自动重放。网络超时或丢回执不自动重发副作用请求。429 持久保存 Retry-After fence，原请求不重放，后续显式请求在窗口前不签名或发送。

Device 为后续独立阶段，当前返回 `unsupported_sign_in` 并且不广告。Browser Join、Mediated Sign-In、PS384、Web Bot Auth operator signature、自动账户合并均未实现。PAP 不复用 MCP machineToken、Mcp-Session-Id 或 0.2 Session grant。

## Host 接入

`@awiki/dsh-pap/plugin` 提供实际 Cordis `pap` 服务；bundle 同时挂载用户管理 `./management-remote`、模型工具 `./tools` 和根 package 的 client declaration marker。根 `@awiki/dsh-pap` 保留 Host 库 exports，作为 Cordis row 时仅是无能力 marker；不提供第二个 pap 服务、不注入 C 或 credentials。真实 consumer 始终是唯一的 `@awiki/dsh-pap/plugin`。默认 `enabled: false`，没有 Company、identity 或 policy 时不执行网络发现、创建凭据或签名。用户仍可读取 disabled/unconfigured 状态。启用需要 Host 的明确 profile 配置，不再读取 `DSH_PAP_*` 环境变量或接受自报 binding：

```yaml
- id: pap
  name: '@awiki/dsh-pap/plugin'
  config:
    enabled: true
    stateRoot: /absolute/profile/pap
    policyRef: approved-c-policy-id
    keyringService: org.agentconnect.dsh-pap
```

C 的真实 Loader consumer 必须是精确 `@awiki/dsh-pap/plugin`。Host 在 C 管理面预批准相应身份、profile、target 和 scopes；Remote 只选择 `{storeId, identityId, did}`，不能提交 owner、client_id、policy、verified metadata 或 targetRef。F 捕获插件构造时的真实 Context；不会将随 Cordis Service 调用关联变化的 `this.ctx` 当作签名调用者。

C 服务需实现 `bindProtocolConsumer(actualInstalledContext)` 与 `bindPapHostConsumer(actualInstalledContext)`。后者返回同进程 capability，`resolveBinding(identityRef, policyRef, profile)` 从当前已发布身份与政策得出 binding，`callbackManagementFor({identityRef,policyRef,targetRef})` 只返回 register/claim 两个受限操作。F 的 `ProtocolIdentityHost` 通过 C 真实 `registerValidatedTarget` 得到 opaque target，callback adapter 从加密事务重建相同 issuer/resource/scope 后取得该目标；不接受用户或模型提交的 opaque 引用。C factory 不可用时拒绝操作，不以组件 fixture 补位。失效 capability 永不复活；status/工具不会自动重绑，仅用户显式 identity/select 或插件重载从实际 Context 重新取得当前许可。

用户管理 namespace 为 `papManager`：`status()`、`operations()`、`manage(request)`。仅安装的 `@awiki/dsh-pap/management-remote` Context 可以取得管理 facade，部署必须把该 namespace 留在已认证的用户管理 Gateway，不接入 Agent 的 Remote/MCP 通用工具。闭合管理动作如下：

| action | 作用 |
|---|---|
| `identity/select` | 选择 C 已批准的已发布 identity reference |
| `company/discover` | 按用户指定域执行安全发现；Company 不由包预造 |
| `session/connect` / `session/disconnect` | 建立 signed-out 或明确 account slot 的 Session／断开 |
| `operation/enable` / `operation/disable` | 将已发现 operation 绑定到用户选定的 Session 与 scope，或撤销 |
| `account/sign-in` | 选定 operation/resource 和 scopes，使用实际已发布的 HTTPS callback 发起 Direct |
| `account/collect` / `account/refresh` / `account/sign-out` | 原设备一次领取后换码／显式刷新或退出指定账户 slot；不接受 grantRef、resource、scope 或 Token |

`account/sign-in` 的授权 URL 只返回给上述用户管理调用，需由真实用户 UI 打开。state、code、PKCE、callbackRef、claim secret、Token、key handle 不进入模型工具。包内 `./client` 现提供最小 settings.section“PAP 连接”：只从 C 的公开 listIdentities/publicationStatus 选择已发布且支持 PAP Session 的 reference，发现 Company、建立连接、明确批准操作及其账户权限、显式发起浏览器登录/领取、刷新、退出和断开。登录链接只由用户点击，带 noopener/noreferrer，不由模型自动打开。默认 disabled、C 未 ready、缺秘密后端和 legacy history 门禁均有安全状态，不切 fallback。UI 只调用用户 Remote，不持有 Host secret、C signer capability、DeviceAccess 或 callback proof。Desktop owner 负责最终正式 profile/renderer 装入和产品验证。

`package.dsh.client` 使用现有 Web/Settings/Remote 依赖，`./client` 指向独立 `lib/browser-client.js`。Host 核心仍在 `lib/client.js`，不被 browser build 覆盖；实际 client-modules 通过根 marker 找到并服务 browser export。

模型只有 `pap_status`、`pap_operations`、`pap_request` 三个工具。`pap_request` 输入只含本地 `operationRef`、已声明 path/query 参数及可选 JSON body，不接受 URL、method、Header、resource、scopes、account slot 或认证 metadata。method/destination/resource/session 来自本地已发现描述与用户授权。每次启用产生新的持久授权 generation，撤销后重新启用也不能让旧的在途调用越过发送前 fence。操作输出只给有界业务 JSON／状态，不透传响应 Header。除凭据字段和 JWT 模式外，实际发送前只在 Host 内存捕获本次 Session/DPoP/access/refresh 等值，任意 JSON key/value 或嵌入消息中的同值也遮盖；自动 refresh 后即使 sign-out 清空 Store，迟到 response 也不能回显新凭据。当前工具是 HTTP operation adapter；MCP 描述不会被当成已经实现的 PAP MCP transport，机器 MCP 不作 PAP 回退。

状态 key 的 namespace 包含 PAP purpose、规范化 profile stateRoot 摘要以及 identity/owner/client binding 摘要；不同 profile 不复用同一 item。移动 profile 目录需要受控迁移其 protected item，不能只拷密文后创建新 key。状态根密钥默认使用 Linux Secret Service，也可显式选择下面的跨平台文件存储。受信 Host 仍可通过同进程 `papHost.secrets` 提供 `HostSecretStore`；显式指定 `secretStore` 时，以插件配置为准。密钥后端之间不会自动回退或迁移。

### 跨平台文件密钥存储

```yaml
- id: pap
  name: '@awiki/dsh-pap/plugin'
  config:
    enabled: true
    stateRoot: /Users/your-name/.dsh/profiles/pap-test/pap
    policyRef: approved-c-policy-id
    secretStore: local-file
    secretsRoot: /Users/your-name/.dsh/secrets/pap
```

两个路径都使用本机绝对路径；Windows 可用 `C:/Users/your-name/...`。`secretsRoot` 与 `stateRoot` 必须是彼此独立、互不包含的目录。不同 profile 和身份通过 namespace 派生各自的密钥文件名。

文件后端保存随机 32 字节的 PAP 状态加密密钥：macOS/Linux 设置目录 `0700`、文件 `0600` 并检查当前用户所有权；Windows 使用系统 PowerShell 设置当前用户 SID 的 DACL、移除继承权限，不依赖 chmod。临时文件写入并刷盘后，通过不覆盖已有目标的原子 hard link 发布；并发创建复用胜出的文件。需要支持这些文件权限和 hard link 的本地文件系统（例如 APFS、NTFS）。Windows 刷新文件，不尝试打开目录执行 fsync。

PAP 状态继续加密保存，Agent/Delegation/DPoP 私钥仍由 ANP Identity 托管。文件权限保护边界是当前 OS 用户账户；同用户进程和管理员仍可能访问。已有密文找不到对应密钥或密钥文件损坏时返回 `credential_unavailable`，不会为已有密文生成替代密钥。备份及迁移需同时保留匹配的状态与密钥，并在目标系统重设权限。

独立 Host 集成也可从根包或 `./file-secrets` 导入 `FileSecretStore`；`./host-secrets` provider 同样接受 `secretStore: local-file` 和 `secretsRoot`。保留 keyring 时，Linux 仍需要可用的 `secret-tool`。本次未改变默认后端。


生产网络默认 `SafeHttpsTransport`。受信 Host 的 `papHost.transport` 仅用于显式部署连接策略和组件验证，Remote/Tools 不能覆盖。`privateOrigins`、`portOverrides` 和自定义 DNS 仅适用于明确配置的隔离部署/组件；TLS 始终验证，连接映射只改变 TCP 端口，Host 与 Session htu 保持逻辑 URL。

账户 callback 固定为当前实际发布 CIMD 中的 HTTPS URI。F 不取得管理 DeviceAccess，C 保留 exact-device credential/checkpoint/proof；只提交 state/claim 的独立 SHA-256 摘要与一次领取 secret。verifier、PAP User/Agent ID、sid、第三方 Token 均不交给 callback 服务，完整领取引用只在加密 Store。C 逐次检查当前调用者、政策、publication、provider、manager 以及目标 issuer/resource。

底层 Host engine 保留显式独立 loopback lane（127.0.0.1 或 [::1] literal、合法显式 port、固定 path、无 query/fragment/userinfo/dot segment），它与默认 HTTPS handoff 分开，不能作为后者失败后的回退。本产品管理 adapter 首先只提供默认 HTTPS handoff，其他 lane 不广告为可用 UI。

## 本地状态与生命周期

产品将 Company/Session/operation 授权保存在每个 identity binding 独立目录；`selected-identity.json` 仅保存三字段公开 reference（0600、原子替换），每次恢复仍需 C 重新批准 binding。`pap-state.enc` 以 AES-256-GCM 加密，AAD 绑定 schema 和 identity/owner/client 命名空间；目录 0700、文件 0600。跨进程锁内使用 fsync + rename 原子提交；公开映射、Delegation、Token、PKCE 和 callback 领取状态均不明文落盘。状态目录备份与 Host secret store 备份应分别保管。Cordis Context disposer 会关闭 engine、取消在途资源请求并 dispose C facade；输出前仍检查原 engine/selection 与调用 Context，忽略 abort 的旧 transport 也不能交出迟到结果。Keyring provider 的 locksRoot 须使用独立目录，不能与 PAP stateRoot 使用同一个锁目录。

恢复后重新经 C 获取目标许可并复核 key handle；持久 handle 本身不授予签名权。中断的 refresh 标为 uncertain，换码中断要求重新授权。委托默认一小时且校验最大二十四小时；自动/显式轮换保持 User ID/sid，并保存旧 key 的停用重试引用。每次 key 创建先持久预留 attempt；创建回执未知时复用原幂等 operation，已停用的失败 attempt 则不会再用；退休未确认时先完成清理再创建下一把 key。外部 Company 可缓存 Delegation 到 exp，本地停止签名不等于立即全网撤销。

元数据五分钟过期后自动重新发现；发现失败直接停止，不降级无 AS。没有 expires_in 的 Token 保持未知远端寿命，仅施加本地二十四小时使用上限，不猜测 opaque Token 内容。账户 sign-out 停止本地 Token 使用；未确认撤销保留最小加密重试信息。普通 `disconnectPap` 停止该连接，不隐式退出其他共用账户 Session。

## 构建、测试和依赖来源

当前插件面向 Harness `0.2.2-rc.1`，使用 Cordis `4.1.0` 与 Loader `1.1.0`。Remote 描述符使用该版本的延迟 `create()` codec 接口；不再声明兼容 Harness `0.1.5`。

```bash
npm ci --ignore-scripts
npm run typecheck
npm test
npm run build
npm pack --ignore-scripts --pack-destination .artifacts
```

生产依赖固定 `proper-lockfile@4.1.2` 和 `zod@4.6.2`（严格管理 DTO）；JOSE 验证使用 Node crypto。Cordis 固定 `4.1.0`，可选 Host peer 为 typert/tools `0.2.2-rc.1`；依赖 integrity 在 package-lock.json 固定。原生 SDK 依赖由 Identity Host 固定为 @agent-network-protocol/anp-identity@0.2.6；适配器继续通过实际 Host capability 结构绑定，并在缺少必需方法时失败关闭。

`npm test` 是本仓库单位/隔离组件检查，不启动产品 E2E、System Test 或远程部署。`tests/fixture.ts` 的 in-memory ECDSA custody 仅供测试，和生产 C/A 路径分开。`tests/vectors/local-signer-v2.json` 来自 A 的真实本地 native 公有测试向量，独立 Node 验签；没有私钥。它证明 wire 兼容，不替代实际 C/A Host 接入。

G 在隔离 HTTPS/PG 环境提供合成用户和 fixture CIMD 时，可执行：

```bash
npx tsx scripts/frontvia-component.ts /absolute/path/to/handoff.json --account
```

此 driver 验证 F→G 的真实 Rust Session/对象/账户路径，显式读取 G 的合成 fixture identity key；不用于运行时，不打包进产品，不把该 custody 计为 A/C 原生验收。`--account` 仅在 G 明确开启测试 OTP/consent 模式时运行，受其 OTP 冷却限制。

详细边界和本轮实际证据见 [安全与验收记录](docs/verification.md)。

## 新增真实模块链入口

默认 fixed HTTPS relay 的 F/C/B 链：

```bash
npm run test:callback-component -- /absolute/C/test/helpers/managed-callback-fixture.ts /absolute/user-service /absolute/venv/bin/python
```

该入口使用 C 的真实批准创建/A native 设备 proof、B 实际 factor 注册/Registry/SQL/PAP 发布和生产 ASGI callback handlers，验证 F handoff 登记、公共 callback、原设备一次领取及拒绝路径。B 使用隔离临时 MySQL，邮件投递是 capture；URL 是逻辑 HTTPS 的 ASGI 模块调用，不计远程 TLS 部署。

C/A 本地 custody 与 G 实际账户组合链：

```bash
npm run test:native-account-component -- /absolute/C/test/helpers/native-protocol-fixture.ts /absolute/public-materials.json https://agent.test:29443
```

进程打印 `public_materials_ready` 后保持存活；将文件交给 G 的 `--materials-file` public-only fixture，用同一端口开启 fresh OTP 窗口，再在该进程 stdin 输入 G handoff.json 的绝对路径。输入通道应保持打开。它只导出 C 确认的原始 CIMD/JWKS 字节，G 不接收 Agent private key；F 不读 `identity_key`，不使用 FixtureHost，所有 Agent identity/delegated/DPoP 签名均通过真实 C/A。实际 loopback listener 接收 callback，并验证 Direct、DPoP 重启恢复、委托轮换、refresh、revoke 与 signed-out。完成后双方精确清理。

上述两条独立链保留其历史边界；后续默认 HTTPS relay 与同一 native 账户已通过下面的新联合入口。宿主 keyring 配置、产品 UI/E2E、System Test 和 registry 发行仍不因此自动通过。

## 实际 Secret Service 模块验证

`npm run test:keyring-container` 在唯一任务镜像中安装 libsecret-tools/gnome-keyring/dbus，使用真实 F 私有包，不安装宿主软件。运行阶段 network none、根文件系统只读、非 root、有限 tmpfs/资源和独立 DBus/XDG/control；密码只在 stdin/内存。已验证创建/读取、PapStore 加密、新 Node 进程恢复、daemon 重启、锁定拒绝、删除 item 后不重建/不改写既有密文，以及无明文回退。详见 `scripts/keyring-container/README.md`（源码内） 和 [验证记录](docs/verification.md)。

这关闭了隔离容器内真实 Secret Service 的模块证据缺口；宿主仍没有配置该后端，原 `real_missing_backend_only` 结果保持。它不代表宿主 keyring 部署就绪，也不补齐产品 UI/E2E 或 registry 门槛。

## HTTP 认证错误与持久冷却

资源冷却按当前本地身份/owner Store 内的 Company+resource 隔离，OAuth endpoint 冷却按 Company+精确 AS issuer 隔离，二者即使同 origin 也不共用窗口。Retry-After 支持 delta-seconds 和 HTTP-date；绝对截止时间以精确整数字符串保存在加密状态中，不截短到 300 秒。缺失/非法值使用本地一秒 fence，不伪造远端 TTL。较短窗口可等待，较长窗口返回 `PapError.retryAfterSeconds` 并保持 fence；超大整数用十进制字符串返回。Host engine 的 `inlineCooldownWaitMs` 为 0–5000ms，默认1500ms，只约束本次愿意等待多久，不缩短服务器窗口。

close、断开和账户退出可取消等待；这些动作不清除共享 fence。等待后重新检查当前 scope、账户 epoch、连接、generation 和 C lease。实际发送的持锁 callback 在等待 Store 锁/secret resolver 后再次检查真实 C Session/DPoP lease，随后同步完成本地 CAS 并启动 HTTP，不能使用撤销后的旧签名发出请求。

401/403 优先解析标准 Bearer/DPoP WWW-Authenticate，支持多 challenge、quoted comma/escape，重复或歧义参数拒绝。`PapError.authHint` 只可能包含固定 scheme、当前 Company 已广告的合法 scope 和当前 resource 的精确标准 PRM URL；realm、error_description、任意 URL/query 或远端秘密不会进入提示/日志。提示不触发 metadata fetch、resource 切换、Token 请求或扩权。非标准 Session/旧登录错误不能通过 OAuth challenge 触发新 sid 或副作用重放。

定向回归入口：`npm run test:p22`。该入口仅 owning client/storage/HTTP 检查，不运行 System Test 或产品 E2E。

## 默认 HTTPS relay 与同一 native 账户联合入口

```bash
npm run test:relay-native-account-component -- /absolute/C/test/helpers/managed-callback-fixture.ts /absolute/user-service /absolute/venv/bin/python /absolute/public-materials.json https://agent.test:29443
```

脚本以真实 C 批准/A native/B 注册、Registry 和 PAP 发布建立同一身份，重新打开相同 native Store 安装显式 PAP consumer policy，导出原始 B CIMD/JWKS 公材料；不导出 provider、lease、Token 或 Agent private key。它打印 `public_materials_ready` 和精确的 `callbackForward` 后等待 stdin。G 使用 `--materials-file <file> --fixture-port 29443 --callback-forward <listener URL> --handoff-only` 开启独立 fresh 账户窗口，再将其 handoff.json 的绝对路径输入该进程。

该 lane 始终注册 `https://agent.test:29443/user-service/v1/pap-callback` 并使用显式 `handoff`。G 只对这个精确 HTTPS GET 转发原 query 到 Node 的 127 listener，不转 caller auth/cookie/DPoP/Session，也不记录 query/code；Node 只转发到 `helper.fetch` 的真实 B public callback，不自行保存或领取 code。随后 F `DeviceCallbackHandoff` 经真实 C 原设备 proof 领取，由原本地 PKCE verifier 兑换 G 的实际 code。没有 fake callback、没有以 RFC8252 loopback URI 替代默认 relay。内部 127 HTTP 仅为隔离 HTTPS publisher 到 B ASGI 的测试转发路径。

实际同一链已通过真实 HTTPS 公材料/AS code→B receive→C device claim→PKCE/DPoP account→restart key restore→delegation rotation→refresh→revoke→signed-out。生产执行 lineage 为 `7325b80`，测试脚本之后单独入库；双方精确清理，只有隔离 master 和外部邮件投递 capture 的已声明边界。它是源级真实模块证据，不是已安装 DSH 产品、外部短信/邮件投递、宿主 keyring 配置或 registry 发布 gate。

## S15 凭据历史与 legacy 门禁

AT/RT 的脱敏不限于一次请求或当前 grant：有效 AS response 在返回解析前先归档到现有 AES-GCM PapStore 的私有 credentialVault，替换、刷新和清除前也在同一事务保存旧值。vault 与协议授权分离，只用于防止已知凭据从任意业务 JSON key/value、Company 名称、operation 路径、公开状态或错误字段回显；它不构成 grant 或恢复签名权。运行内已知寿命使用单调时钟并 pin 在途响应；重启后的私有 tombstone 保守按未知剩余寿命保留，不凭本地24h使用上限猜测 AS/RT 期限。上限4096值/4MiB，容量不足锁闭输出，不驱逐仍可能有效值。不能把旧 AT 从当前 grant 消失当作脱敏完成。

当前 state/verifier/claim/sid 等映射与本次真正发送的材料也会过滤；只有明确用户 account/sign-in 的 authorizationUrl 字段保留正常 OAuth state/challenge。跨请求及跨重启的持久历史承诺专指已观察 AT/RT，不宣称无限重构已删除的旧协议 nonce 或未知过去值。

新 vault 有完整性标记。老加密状态没有 vault，但存在任意 grant、account slot、登录事务（包括 cancelled/failed）、AS nonce 或 DPoP retirement 迹象时，迁移为 legacy_incomplete；seed 当前已知 Token 不等于补全历史。Agent 请求及动态 Company/catalog/status 输出停止，只有固定迁移码。用户只见 Host 产生的账户引用与封闭状态，可尝试正常撤销当前账户；退出/latest revoke 不会自动把历史标为完整。旧纯 NoAS 状态仅在无账户处理迹象时可迁移 complete。加密数据、epoch、cooldown fence 都保留，不自动 wipe、新建 key 或放开权限。

本轮没有“confirmed:true”、重置按钮或普通 Remote 恢复入口。处理 legacy 需要独立受信 Host 运维证据：对应 issuer/client/resource 的全部旧凭据已撤销事实，并保留审计来源；不能让模型或普通业务请求声明已确认。既有未知旧值无法重构，不把它们写成已覆盖。

## 实际产品模块与默认秘密后端组件

`scripts/product-native-component.ts` 使用真实 fresh C approval/B strict 注册发布→同 store C Host 重开→实际 F plugin/manager/tools 与实际 DSH ToolRuntime，向独立 HTTPS NoAS verifier 发送2条实际 Delegation/Session；批准前0请求、卸载后0后续请求、Company Token0。F 只注入隔离网络 transport，秘密存储走默认 KeyringSecretStore。Host 进程中的私有 secret-tool shim 固定本地 Docker socket 和 inspected container ID，访问任务专属容器真实 DBus/gnome-keyring；不装宿主软件、不读用户 keyring、不改 HOME，所有 key/password 仅 stdin/内存。此为实际 factory/default backend 模块证据，不是 GUI 产品 E2E。

侧车入口 `scripts/secret-service-sidecar-component.ts` 单独验证当前加密 vault 的真实 backend create/get、daemon 重启、新 Host Node 进程恢复和无明文；镜像复用已核验 fea7c2…，不是把整个 C/Python 仓库搬入容器。原始宿主缺后端记录仍成立，容器后端不代表宿主已配置。

新实际账户入口 `scripts/product-account-component.ts` 已实际通过：使用新 C factory 与 user Remote、固定 B HTTPS relay、G 实际 OAuth/DPoP 及默认 backend；显式当前 A runtime aliases，并核实际加载冻结 native FFB。它不是旧直接 PapClient/managed-callback helper 的替代计数，完整来源见验证记录。

## npm scope and existing source profiles

The published package is `@awiki/dsh-pap`. Its identity consumer is
`@awiki/dsh-pap/plugin`; manager and tool entries use the same package scope.
Install with `pnpm dsh plugin --profile <profile> add @awiki/dsh-pap@0.1.3`.

Earlier unpublished source profiles used `@agentconnect/dsh-pap`. They are not
silently aliased or granted access under the new consumer. Configure the new
installed consumer explicitly in ANP Identity's allow list and protocol policy,
then approve it. Keep the existing identity Store and keys unchanged. Start the
new PAP consumer with its own empty state root and matching secret namespace;
retain old encrypted PAP state and its keys separately rather than editing its
binding, overwriting keys, or attempting an unauthenticated in-place migration.

## 域名自动连接与统一权限

一次性启用 PAP 和 Host 全局域名接入后，只需 `pap_connect({domain})`，不再每个站点配置 Company 和许可。本版本由 Identity 的共享“协议管理”替代旧 PAP 设置导航；浏览器入口也不再导出旧手工表单，但保留原加密连接、凭据与 Host 诊断接口，不迁移或删除用户数据。

发现记录保留最初域名及已验证的重定向绑定，刷新仍从该源开始。`pap_operations()` 返回 `effect`、`permission`（allow/ask/deny）、`requiresApproval`、`blocked`。每次业务请求都检查统一读写规则，已有只读启用记录不能绕过新禁止。允许直接执行，不重复确认，也不持久写入操作许可；询问自动弹出本次操作确认框；禁止或明确禁用不发送。账户 OAuth 登录及其 scope 仍独立管理。

分类结合方法、请求正文与安全声明，以及可选的 `x-agent-effect`、`x-agent-annotations`；支持明确声明的 POST 只读查询。未知、明确支付及额外权限即使在全写允许时仍单独确认。需要 Identity 0.1.15 或更高版本的 Host API，缺少时失败关闭，不退回旧授权路径；本适配器 0.1.4 要求 Identity >=0.1.15。

等待确认默认 120 秒，可用 `approvalWaitMs`、`approvalPollMs` 配置。超时后保留原授权对象，缓存绑定身份、Host 策略、统一策略版本和完整请求。取消、卸载、身份变化、既有拒绝、断开和撤权都会阻止后续执行；已批准或规则允许的变更操作也不因 Session、token 或 nonce 响应自动重放。

失败结果的 `phase` 和 `businessRequest` 区分未开始业务传输、传输结果未知、已收到响应。已收到响应时保留 `httpStatus`，不能仅凭本地错误认定未发送，也不能把传输尝试当作已送达。不确定写入不得自动重试。本版本已完成两站三协议真实读写，版本组合为适配器 0.1.4 与 Identity 0.1.15。

Identity 0.1.15 提供 `protocol_permissions`、`identity_settings`，让 Agent 在会话内确认后修改持续配置。新的显式 `pap_connect` 会采用已保存的默认身份及准入版本，不删除旧会话或凭据；在途请求仍受原引擎／身份边界约束。配置确认不等于业务请求审批，也不开放通用签名。
