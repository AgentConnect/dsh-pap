# DSH PAP 0.3

Private DSH Host plugin and PAP client. The protocol baseline is
[the fixed 0.3 spec](https://github.com/personal-agent-protocol/personal-agent-protocol/blob/6fb46d381ac1b94265795132af13848ec442b6f6/content/versions/0.3/spec.mdx),
Git blob `01e9dc34bacb73ef0a740cc3bae77d82f0be0d37`.

源码、包和镜像均为私有交付。`private: true` 禁止误发布 npm；本仓库不包含发布入口。

## 已实现路径

- Company discovery：HTTPS 受限重定向，DNS 解析与实际连接绑定，地址、大小、时间、请求数限制；根 PRM 与精确 issuer 双向关联；无 AS、账户和 disabled 分开。网络错误保留已知 issuer，Company Identifier 改变后隔离原命名空间。
- 随机且私有的 Company User/Agent ID、独立匿名身份、sid 和加密事务状态。匿名 Session 禁止账户 Token。Agent ID 不改变 User ID。新账户 slot 使用新 Session。
- 通过 C 的 `./protocol-client` 调用 A 本地 custody：临时 P-256 key、身份 Delegation、逐请求 Session、独立 DPoP key、客户端断言和重启后 handle 恢复。F 不打开 NativeStore，不持有或导出这些私钥，不调用远程 signer。
- 每个实际资源请求重新签 `Poppy-Session`，绑定实际 htm/htu，带账户 Token 时才有 ath。发现、描述和 OAuth 请求不携 Session；禁止调用者注入认证 Header；凭据重定向停止。
- Direct Sign-In：显式用户入口、state、issuer、43 字符 S256 PKCE verifier、已发布 callback 校验、标准账户 Token、可选 RFC 9449 DPoP 和按 AS/资源分离的 nonce。
- 独立 PAP account store：scope/resource 约束、refresh single-flight/CAS、轮换 Token 原子替换、丢回执标为 uncertain、退出撤销及 revocation_pending。持久 account slot epoch 同时约束登录事务、refresh 和发送前检查；退出取消 pending/exchanging 登录，迟到 Token 只保留撤销信息。并发资源调用会等待同一刷新代次。
- `invalid_session` 停止，`session_ended` 新 sid 后最多重发一次，Token 错误最多刷新重发一次。网络超时或丢回执不自动重发副作用请求。429 保留有界 Retry-After 摘要。

Device 为后续独立阶段，当前返回 `unsupported_sign_in` 并且不广告。Browser Join、Mediated Sign-In、PS384、Web Bot Auth operator signature、自动账户合并均未实现。PAP 不复用 MCP machineToken、Mcp-Session-Id 或 0.2 Session grant。

## Host 接入

`@agentconnect/dsh-pap/plugin` 提供 Cordis `pap` 服务。依赖当前任务 C 真实实现的 `anpIdentity.bindProtocolConsumer(ctx)` 和 Host 的 `papHost` 服务。`ProtocolIdentityHost` 直接调用 C 的 `registerValidatedTarget`、opaque scope/key API 和 `restorePapKey`，不提供 native 绕行。

```ts
import { PapUserManagement } from '@agentconnect/dsh-pap/plugin';

// Run only inside an installed, trusted Host plugin Context.
const manager = new PapUserManagement(ctx.pap.engine, {
  assertAuthorizedUserAction() {
    authenticatedManagementSession.assertUserInitiated();
  },
});
const company = await manager.discover('company.example');
const subject = await manager.createUser(company.companyRef);
const session = await manager.openSession(subject.subjectRef);
```

Host 配置需明确指定：绝对 `stateRoot`、`binding={identityRef,ownerRef,clientId}` 和管理端预批准的 `policyRef`。`cordis.patch.yml` 从 `DSH_PAP_STATE_ROOT`、`DSH_PAP_IDENTITY_BINDING` 和 `DSH_PAP_POLICY_REF` 读取这些非秘密配置。应先安装 C 身份服务、A native provider 和 `papHost`，再安装本插件。

`papHost.secrets` 必须实现 `HostSecretStore`，将 32-byte 状态加密根密钥保留在 Host secret store。仓库提供 Linux Secret Service 的 `KeyringSecretStore` 与可选 `./host-secrets` Cordis provider；使用 `secret-tool`，不写明文回退，不修改共享身份配置。其他系统由 Host 注入合规 secret store。既有加密文件对应的 secret 丢失时返回 `credential_unavailable`，不创建替代密钥。

默认生产网络使用 `SafeHttpsTransport`。`privateOrigins`、`portOverrides` 和自定义 DNS 仅供明确配置的隔离部署/组件测试；TLS 验证始终启用。映射仅改变 TCP 端口，Host 与 Session htu 保持逻辑 HTTPS URL。

`papHost.callbackHandoff` 可以使用 `DeviceCallbackHandoff`。其管理 driver 必须通过 B 的 exact-device API 添加当前 checkpoint 和受限 device proof，固定调用 `/user-service/v1/agent-clients/device/pap-callback-register` 或 `pap-callback-claim`。F 只提交 state/claim 的独立 SHA-256 hex 摘要，领取时提交独立 claim secret；verifier、PAP User/Agent ID、sid 和第三方 Token 均不交给 callback 服务。`callbackRef` 含领取秘密，只进入加密 Store。B 固定 callback URI 为 `/user-service/v1/pap-callback`，须先出现在实际已发布 CIMD。重定向地址不随交易变化。C 的 `configureManagedPublicationBackend(...)` 现在返回受限 `callbackManagement`，可直接传给 `new DeviceCallbackHandoff(configured.callbackManagement)`；其 `execute` 只有 register/claim 两个闭合 DTO overload，由 C 逐次核验真实 manager Context/device/identity，F 不提交 method、purpose 或 route。

独立 loopback lane 必须显式配置并发布：仅 PAP account 的 `http://127.0.0.1:<port>/<path>` 或 `http://[::1]:<port>/<path>`，端口为显式 1–65535 十进制且无前导零；禁止 localhost、其他 127 地址、userinfo、query、fragment 和路径 dot segment。Host 持有实际本机 listener，运行时仅按 RFC 8252 忽略已发布 loopback URI 的端口差异。它不能进入 B 的 HTTPS relay register，不是 relay 失败后的回退；公开 CIMD/JWKS/发现/业务 URL 仍只接受 HTTPS。共同正负向向量位于 `tests/vectors/pap-account-redirects.json`。

`PapUserManagement` 是 Host 用户管理适配器，调用方必须检查真实用户会话。其授权 URL 只交给用户 UI。不要将 `engine`、`store`、signer lease、callbackRef 或管理方法注册成可由模型任意调用的 Remote。此包尚未包含产品 Web 界面或其 E2E。

## 本地状态与生命周期

`pap-state.enc` 以 AES-256-GCM 加密，AAD 绑定 schema 和 identity/owner/client 命名空间；目录 0700、文件 0600。跨进程锁内使用 fsync + rename 原子提交；公开映射、Delegation、Token、PKCE 和 callback 领取状态均不明文落盘。状态目录备份与 Host secret store 备份应分别保管。Keyring provider 的 locksRoot 须使用独立目录，不能与 PAP stateRoot 使用同一个锁目录。

恢复后重新经 C 获取目标许可并复核 key handle；持久 handle 本身不授予签名权。中断的 refresh 标为 uncertain，换码中断要求重新授权。委托默认一小时且校验最大二十四小时；自动/显式轮换保持 User ID/sid，并保存旧 key 的停用重试引用。每次 key 创建先持久预留 attempt；创建回执未知时复用原幂等 operation，已停用的失败 attempt 则不会再用；退休未确认时先完成清理再创建下一把 key。外部 Company 可缓存 Delegation 到 exp，本地停止签名不等于立即全网撤销。

元数据五分钟过期后自动重新发现；发现失败直接停止，不降级无 AS。没有 expires_in 的 Token 保持未知远端寿命，仅施加本地二十四小时使用上限，不猜测 opaque Token 内容。账户 sign-out 停止本地 Token 使用；未确认撤销保留最小加密重试信息。普通 `disconnectPap` 停止该连接，不隐式退出其他共用账户 Session。

## 构建、测试和依赖来源

```bash
npm ci --ignore-scripts
npm run typecheck
npm test
npm run build
npm pack --ignore-scripts --pack-destination .artifacts
```

生产依赖只含固定 `proper-lockfile@4.1.2`；JOSE 验证使用 Node crypto。Cordis 固定 `4.0.2`；工具版本与 registry integrity 在 package-lock.json 固定。C/A 的新 PAP API 尚未发布到 registry，因此本阶段依赖实际 Host capability 结构绑定，不能宣称已通过新 API 的 registry 安装验证或正式发行门槛。此阶段不将未发布本地源码写作正式 SDK lock 来源。

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

两条链分别出具证据：账户链仍允许明确的 C publication acceptance fixture 和隔离 master；默认 HTTPS relay 的完整同一账户链组合、系统 keyring 正向、产品 UI/E2E、System Test 和 registry 发行验证没有因此自动通过。

## 实际 Secret Service 模块验证

`npm run test:keyring-container` 在唯一任务镜像中安装 libsecret-tools/gnome-keyring/dbus，使用真实 F 私有包，不安装宿主软件。运行阶段 network none、根文件系统只读、非 root、有限 tmpfs/资源和独立 DBus/XDG/control；密码只在 stdin/内存。已验证创建/读取、PapStore 加密、新 Node 进程恢复、daemon 重启、锁定拒绝、删除 item 后不重建/不改写既有密文，以及无明文回退。详见 `scripts/keyring-container/README.md`（源码内） 和 [验证记录](docs/verification.md)。

这关闭了隔离容器内真实 Secret Service 的模块证据缺口；宿主仍没有配置该后端，原 `real_missing_backend_only` 结果保持。它不代表宿主 keyring 部署就绪，也不补齐产品 UI/E2E 或 registry 门槛。
