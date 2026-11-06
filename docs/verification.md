# F 模块验证与安全边界

本仓库为私有源码，当前没有 push、发布、产品 E2E、System Test 或远程服务部署。

本轮通过的 owner 检查：`npm run typecheck`、`npm test`。测试覆盖发现分类/issuer 失效保留、disabled、协议版本、私有与匿名身份、重启、加密与损坏拒绝、委托/Session 独立 ECDSA 验签、逐请求 method/URL/ath、轮换、Direct state/issuer/PKCE/标准 Token、DPoP、refresh single-flight/丢回执/退出竞态、Session 错误、429/redirect/撤销/断开，以及 Device 不广告。具体最终数量和最终组件命令见文档末尾执行记录。

`tests/native-vector.test.ts` 消费 A 生成的 `local-signer-v2-vector.json` 公有向量并用 Node crypto 独立验证四种 JWT，字段与协议基线一致。向量来自本轮 A worktree `bindings/node/test/fixtures/`，未包含私钥。实际 A 最终 native 候选 `anp-identity.linux-x64-gnu.node` 的提供方 SHA-256 为 `e2c4b86a0b3622aaefa70b44d3dc31cdab579b1237a4418d349bd294c52663ef`。静态向量不替代运行证据；本轮后续真实 C/A→F→HTTPS 结果见执行记录。

安全检查的主要信任边界如下：

| 边界 | 约束与证据 |
| --- | --- |
| Company 网络输入 | HTTPS、DNS pin、地址过滤、精确私网例外、五次 discovery redirect、64 次请求/30s/4MiB 总预算；携凭据的请求不转发 redirect |
| 目标许可 | F 仅从验证过的路由构造实际 URL，C Context/管理 policy 授权，注册精确 allowedEndpoints；普通 consumer JSON 不充当 targetRef |
| 本地持钥 | F 仅保存 A key handle、公钥与 generation；C 重新授权/restore；无 NativeStore 或远程 signer 调用 |
| 本地状态 | Host secret store 根密钥、AES-GCM、AAD、0700/0600、进程锁、fsync/rename；秘密缺失时不创建替代根密钥 |
| 签名用途 | 身份→Delegation，委托→Session，独立 DPoP key；ES256、typ、thumbprint、请求绑定、ath 分开核验 |
| OAuth | 非空且不提升 scope、精确 issuer、独立 state/43字符PKCE、固定已发布 callback；token endpoint 不接收 Session/User/sid |
| 并发与退出 | refresh single-flight/CAS；丢回执 uncertain；退出立即停止账户请求；迟到 refresh 仅保留待撤销秘密而不复活登录态 |
| 用户与模型 | 管理状态不含Token/JWT/key；授权链接仅用户UI；没有模型tool/Remote通用签名入口 |
| MCP 隔离 | 独立 PAP schema 与 OAuth account grants；没有machineToken导入、client_credentials或协议回退 |

当前剩余发行/启用门槛：实际 Host Secret Service 配置与恢复（隔离容器正向已补证）；产品管理 UI、产品 E2E 和受影响 System Test；发布后的 registry SDK pin/lock 验证。真实 C/A native 账户组合和 F/C/B exact-device callback 模块链已补证，边界见末节。Device 为另阶段，当前不广告。测试 custody 的成功不能抵消这些未验证范围。

## 执行记录

- 2026-11-06：初始 15 项 owner 检查与真实本仓库隔离 HTTPS Session 组件通过；增加 refresh 竞态、B relay mapper、A 公有向量及秘密丢失检查后，20 项 owner 检查通过。
- F→G `pap03_d4f27aa3b9e5`：真实 HTTPS discovery、同 sid Session、委托轮换通过。测试 custody；账户未执行。
- F→G `pap03_5e01b509d095`：`npx tsx scripts/frontvia-component.ts <该隔离 handoff.json> --account` 通过 Session/委托轮换、对象 create/read、真实合成用户 OTP/consent、F Direct PKCE/state/issuer、标准 Token、DPoP account、refresh、revoke 和退出后 signed-out。该窗口 binary 的 discovery 仍有 G 随后修正的旧未知字段；F 使用标准 AS scopes_supported，不按旧字段解释。最终 0.3 discovery 证据以修订 binary 重跑为准。
- 实际联调发现 F 早期 PKCE verifier 长度为 37，已改为 32 随机字节 base64url（43 字符），补 owner 回归并在真实账户组件成功。初始生成向量的 access_token=null，独立验签测试已按 signed-out 规则检查 ath 缺失；该失败属于测试断言修正。

- 最终 owner 检查：`npm run typecheck && npm test`，26/26 通过。新增 fatal UTF-8、BOM、重复 JSON（含转义等价 key）、深度/大小、JWT canonical base64url、JSON media type、IPv6 `2001::/23`/文档地址，以及 OAuth 路由即使被 API 声明也不发 Session、DPoP key 丢失不降 Bearer。
- 最终 G binary：`npx tsx scripts/frontvia-component.ts /home/ecs-user/awiki-space/worktrees/20261104-dsh-shared-agent-identity/frontvia-pap/platform/.local/pap03/pap03_51205459476f/handoff.json --account` 通过。该候选已修正 auth.scopes、HTTP 400 Session 错误、登录路由范围和 code/refresh 最终事务到期检查。测试 custody；没有冒充 A/C 的账户持钥证据。
- 真实 C/A native：`npx tsx scripts/native-component.ts /home/ecs-user/awiki-space/worktrees/20261104-dsh-shared-agent-identity/anp-identity/packages/dsh-anp-identity/test/helpers/native-protocol-fixture.ts` 通过。三次真实 HTTPS Session 请求、C Context/target/scope 许可、A native 持钥和委托签名、F dispatcher、独立 Node 验签、委托轮换、重启后 restorePapKey 与 sid 连续。C publication 仍为显式 accepted fixture，状态根密钥为隔离测试 master；不提供 B 设备注册或系统 keyring 证据。
- A native 早期 ef32 候选在最终格式化/能力广告重编译后被 f123 候选替换；先执行哈希检查并暂停消费，A/H 核对完整候选 manifest 后固定 f123 继续。该制品不是 registry 包。
- 安全复核已关闭本轮发现的 PKCE 长度、UTF-8/重复 JSON/BOM/media type、IPv6 special-use、OAuth 目的地重叠和 refresh/sign-out 竞态问题。正式发行/启用仍受上面的未验证范围约束。
- 最终 G component manifest 的 binary SHA-256：`35f6265876ef98daa69e8780f055ed2e6f164468494f1241b711dd2e7be09444`。
- 最终补充匿名结束清除映射、可选 Agent 共享相同 Company User/account slot 的 owner 回归；`npm run typecheck && npm test` 最终 26/26。

## 交叉审查后的最终修订

G 只读交叉审查实复现了三项缺口：登录换码与退出竞态可能恢复账户；第二个资源调用未等待正在进行的 refresh；首次委托签发失败并退休 key 后复用了原幂等 key 创建 operation，导致恢复永久失败。初始提交及 26 项通过记录不能证明这三条边界。

本轮修复增加持久 account slot epoch，退出原子取消 pending/exchanging 事务并清除 verifier/领取引用。Token HTTP 启动前再次检查该 epoch；已经发出的换码响应迟到时只保留空 accessToken 的 revocation_pending grant，不恢复账户。资源 dispatcher 对 refreshing grant 合并等待，并在同一 account epoch 与后续 grant generation 重读；退出或刷新失败后停止本次账户调用，不改成 signed-out 重发。

Delegation 创建改为先持久预留 attempt，再执行幂等创建/签发。失败 key 已退休后下一尝试使用新序号；创建回执未知时保留原操作恢复；退休失败保留加密清理引用，完成清理后才创建下一把 key。自动轮换失败仍可使用尚有效且获准的旧委托，sid/User ID 不变。

- `npm run typecheck && npm test`：最终 **35/35** 通过，新增跨客户端 pending/exchanging 退出、迟到换码、等待刷新、等待期间退出、signer 挂起后取消、委托失败后重启恢复、自动轮换恢复、create 丢回执和退休失败边界。
- G 原复现脚本 `node --import tsx <G .local/review/f-races.mjs>`：P1 返回 revocation_pending，迟到换码后 activeGrants=0；P2 第二请求成功且只进行同一轮刷新；P3 `[delegation_blocked, ok, ok]`，创建两把 key、只剩一把 active。G 独立只读复测也确认三项关闭。
- 真实 C/A 组件 fresh Node 进程再次通过，native pin 更新为 e2c4 候选，三请求、轮换与重启恢复均通过。A 的该次改动为 publication candidate 的冻结 baseEvidence，PAP 签名契约未改；f123 是被其替换的历史候选，不是最终包或 registry 依赖。

截至该次并发修复提交，B callback、系统 keyring、native 账户组合、产品 E2E/System Test 和 registry 门槛仍未执行；后续模块补证见下节。

## 真实 callback 与 native 账户组合补证

本轮不再以 mapper mock 或 FixtureHost 代替这两条链。F 的 callback Host seam 已缩为闭合 register/claim DTO 与两个 execute overload，实际兼容 C 的受限 driver。F 同步 B/C 独立 loopback 正负向配置向量，公开材料/资源 URL 的 HTTPS 限制没有放宽。

1. `npx tsx scripts/callback-component.ts <C test/helpers/managed-callback-fixture.ts> <B source> <Python>` 通过。真实 C 批准 E1 创建、A native 设备签名、B factor 注册/owner/ready-admin Registry 与实际 PAP account 发布后，经 `DeviceCallbackHandoff` 完成 register、公共 callback 和原设备一次领取；未 ready、state 伪装领取秘密、issuer 不匹配、重复领取均拒绝；access_denied 的 state/iss 保留。该检查只替代邮件投递和隔离 master，B 为生产 ASGI handlers + 临时真实 MySQL；逻辑 fixed HTTPS relay，不是远程 TLS 部署。未冒称 Web native 管理全链。
2. `scripts/native-frontvia-component.ts` 与 G `pap03_0c7c24406ada` 窗口通过。所有 Agent identity/delegated/DPoP key 由 A 本地 custody 经真实 C Context 使用，F 与 G 不读取/接收 Agent private key。C 的公材料以原始字节挂接 G，实际 HTTPS GET 与 C 确认字符串逐字节相等；metadata SHA-256 `5fe653513cc2180e5ad1043b10f27819910851ba936c8c92990cebd7f4a40c71`，JWKS `3f66193cf6011226c349179644338792a2e0b23d16f8b00ad4f21f345945e7a0`，G 独立计数两份材料各 GET 11 次并核对相同摘要。
3. 上述 native 账户链包含真实 127.0.0.1 HTTP listener、Direct/PKCE、state/issuer 负例、标准 Token、DPoP 资源调用、重启后 native key restore、委托轮换不触发账户刷新、显式 refresh、revoke 与退出后 signed-out。Token endpoint 仅两次（code + refresh），revocation 一次。仍明确保留 C publication acceptance fixture 和隔离状态 master；它与第 1 条默认 HTTPS relay 是分别验证的模块链。
4. `npm run typecheck && npm test`：**36/36 通过**，包含新增 B/C 共同 loopback 正负向向量。A native pin 仍为 `e2c4b86a0b3622aaefa70b44d3dc31cdab579b1237a4418d349bd294c52663ef`；G binary 仍为 `35f6265876ef98daa69e8780f055ed2e6f164468494f1241b711dd2e7be09444`。

首个 native 账户编排在进入任何网络前因 stdin/TTY 与 readline close 顺序失败，已修复后重新生成 native fixture/public materials 并执行成功窗口；失败不计作通过。两次 G 窗口均已核对 DB/role=0、进程停止，独占 PG 27432 停止；F listener、C native 临时状态、PAP 状态 master、公材料文件和 callback 管理 fixture 已精确清理。没有 Token、code、JWT、claim secret 或私钥进入日志/结果。

A owner 另对当前 host 做真实缺后端 keyring 检查：缺少 secret-tool/gnome-keyring-daemon，独立无 activation DBus/private XDG 中 F KeyringSecretStore get/create/PapStore.transaction 均 credential_unavailable、无文件 fallback。此项只能记为 real_missing_backend_only；Secret Service 正向 create/restart/locked/missing-item 未执行。

## 隔离容器真实 Secret Service 正向补证

2026-11-06 在任务专用 Docker 镜像/容器内直接导入 F 实际私有包的 KeyringSecretStore/PapStore，9 项检查全部通过；没有替代 secret-tool/Secret Service，没有 Agent private key，也没有修改生产实现。输入私有包为 aa4241089027bc003d18b2a36080d4780a7fccff 的候选，SHA-256 `1db4804f23af43ffcad4a094ded981e2f7f8a5b8df624a28ee9f6eed2db2b30b`；三份相关源文件 SHA 在结果中记录且与运行后仓库完全相同。

实际检查：真实 create/get、PapStore 加密事务、新 Node 进程取 key/恢复状态、gnome-keyring-daemon 重启、Lock 后 get 不返回 key/create 和 PapStore read 拒绝且密文不变、带 stdin 密码启动新 daemon 后恢复同一 key/state、clear item 后既有状态 read/transaction 均 credential_unavailable 且不重建/不改写，以及私有普通文件中没有明文 key/password/marker 或 fallback。

- 入口：`node scripts/keyring-container/run.mjs`，只运行该真实模块验证，没有重跑完整 owner/System/E2E 套件。
- 成功 run：`worktrees/20261104-dsh-shared-agent-identity/.artifacts/keyring-verification/secret-service-container/run-20261105t185044615-a3063167/`。
- 基镜像：`node:22.23.1-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3`，实际 Node v22.23.1。
- 最终任务镜像 digest：`sha256:8a56b828b5f50bae4eaac282304a223653f40d2c9a8ca19a4b3b2f478b4020e5`；tag `dsh-pap-secretservice-check:run-20261105t185044615-a3063167`，没有 push。
- 实际包版本：libsecret-tools `0.20.5-3`、gnome-keyring `42.1-1+b2`、dbus `1.14.10-1~deb12u1`；完整依赖版本在 result.json。
- 结果 `output/result.json` SHA-256：`56bdaaea832b17129c3ad901dfc36a671e9e9caac964b1dcf7f59df2bcfb56d4`。

运行时使用 --rm/network none/read-only root、非 root、cap-drop ALL/no-new-privileges、有限 pids/memory/CPU、私有 tmpfs、仅任务 evidence 可写路径。私有 DBus 不配置 activation 服务目录，XDG/control/state 独立，不改 HOME、不接宿主 DBus/keyring。Secret Service、DBus、私有状态清理均核实 true，容器无残留；失败尝试的专属 image tag 已删除，只保留最终镜像供核对。

前期 harness 断言曾误用成功 read 之前的密文摘要（read 会推进 generation），另有 host log stream 收尾和运行中 CLI unlock 假设的问题；修正验证编排后重新执行，旧失败结果保留且不计通过。锁定后的恢复采用真实 daemon 重启并从 stdin 提供同一密码，不冒称 headless in-place CLI unlock 成功。

原宿主 negative result 完整保留。结论是 isolated_container_real_secret_service，不是“宿主已配置 keyring”。另已核对 C clean `481ac1707b2287b03a08725141ce81d983dcda6a` 与前述两真实组件执行时的 7 个关键源文件完全同字节；可绑定 C481/Bf2/G242 的已测来源，不再只停在 dirty source 描述。

## P22 实际客户端缺口修复与 P06 fixture 回归

只读 P01–P28 快照位于统一 `.artifacts/completion-audit/pap.json`，保留当时 P22 partial 的事实；后续最新总审计由 H 合并，未把其他缺口静默改成通过。本轮增加持久加密 resource/AS 冷却命名空间，Retry-After 精确 deadline（delta 与三种 HTTP-date）、跨实例/新进程恢复、短窗等待/长窗剩余提示、取消与重新授权检查；429 不自动重放原请求，也不以 cap300 提前发出。标准 Bearer/DPoP challenge 优先于 JSON，并只提供严格校验后的 scope/PRM 管理提示；无 metadata fetch 或 Token/resource 自动跳转，不记录远端描述。

H 指出的发送窗口也已关闭：签名后若因 Store 锁/secret resolver 挂起，恢复后的持锁 callback 会重新 await 实际 C Session/DPoP lease.assertActive，再同步复核本地 generation/epoch 到 HTTP start。受控 resolver 挂起→撤销 fixture lease→恢复的直接回归观察到一条签名、**零 physical request**，没有输出 JWT。

实际命令：`npm run typecheck && npx tsx --test tests/cooldown-challenge.test.ts tests/client.test.ts tests/network-store.test.ts`，最终 **48/48** 通过；原生 TAP 为 ignored `.artifacts/p22-owner.tap`。其中新文件18项（含 P06 fixture），client26项和storage/network4项。没有跑 System Test、产品 E2E 或其他全量套件。

直接证据包括：真实 HTTPS 的一秒窗口与两个显式并发 client、签名/物理请求零提前；HTTP-date fence 在新 Node 进程恢复且 signer/network 均0；3601秒窗口不截短；disconnect/signout/close 取消且保留fence；scope/epoch/lease复查；同origin AS/resource互不阻塞；AS429并发等待一致返回rate_limited而不误报reauth；challenge-only/空JSON、header优先、quoted challenge、多scheme、重复参数、unsafe URL/scope丢弃、无副作用重放、非标准Session错误不能触发OAuth重试。AS时间/错误矩阵使用明确FixtureTransport边界，不冒充新真实G限流运行。

新增 P06 client unit/fixture：已持有效标准grant后重新发现disabled=true、issuer不变，即使scope广告省略也允许按本地grant/C许可向AS实际refresh；new sign-in拒绝；AS返回invalid_grant后本地reauthorization_required，Company仍disabled/issuer，不降无AS、不转CC/JWT Session grant。此项不替代 H/G 的真实disabled服务专项。

旧 client 回归原来在429后立即检查许可撤销，现因持久fence先返回rate_limited，已用显式测试时钟走过该窗口再隔离检查permission_denied；不是清除生产fence。

此前容器SecretService正向测试仍绑定旧输入包/Store源码；本轮Store只加cooldowns的加密schema默认值/迁移，cipher/atomic/key逻辑未改，keyring实现未改。最新focused storage regression通过，但不把旧container Store整文件hash称为当前相同；宿主未配置的边界不变。

P22 收尾补充：AS 冷却期间也复查本地 code transaction.expiresAt；窗口尚未结束但交易已到期时，不签新的客户端断言、不发送 code。追加真实短时间窗回归，并重跑 P06 与 delayed-signer 取消用例：`npx tsx --test --test-name-pattern='P22 an expiring|P06 fixture|cancelled code exchange' tests/cooldown-challenge.test.ts tests/client.test.ts`，**3/3** 通过。此为前述48项之外一项新expiry场景及两项复验，不把重叠用例重复累加为一轮全量结果。

## 最终 production 7325 的最小真实重绑与默认 relay 联合链

生产保持 `7325b80a2b5c4b4b5e5e80d1ff1304921c9d1bb7`，没有修改 src 或 package-lock；此前更旧源码的 positive 没有直接冒充本轮。

- 当前 7325 私有包 `5fcaca0d98fa857433a1af0e8786f33ce545595136fcd4763a46fcc98cb7a255` 输入新 Secret Service source layer，真实 **9/9** 通过；source 三文件及 compiled JS 与当前文件逐SHA一致。新镜像 `sha256:fea7c2a0f03570a8bc636c1d3c19505a79964bb0b7f573363d7473fe039aa72c`；结果 `run-20261105t200941309-2cad8afb/output/result.json` SHA `6b764c884c6c57689211c580b85afda8496ce7ce9ff9abda58a3a60bfa7c9350`，daemon/DBus/private state清理均true、--rm无容器。该结论仍是隔离容器，不是宿主已配。
- 旧 callback component 以 C95c5f5/B04fe 重新通过一次。C当时全仓dirty仅无关test helper，31个 production src+managed helper实际执行文件全部匹配HEAD blob且pre/post无变，未虚写全仓clean；B clean且pre/post无变。F `.artifacts/rebind-7325/summary.json` SHA `37fc0078f14e5ccf02b201bc8ecd939ddc040e7ed12cbe38152c2c4008aa6d8e`。

默认 HTTPS relay + same-native 账户联合新入口 `scripts/relay-native-frontvia-component.ts` 已在 G `pap03_9ba25075199a` 实际通过。它直接使用 B 扩展的 `createManagedCallbackFixture` 完整显式 policy tuple，实际 C 批准/E1 native/B factor 注册/Registry/PAP publication，C public material 是 B 原始 GET bytes。所有 Agent identity/delegated/DPoP key 仅经 C/A 本地 custody；不是 FixtureHost，也不是 publication acceptance mock。隔离 master、测试邮件投递 capture 与 G 保留 OTP身份范围仍明确。

实际请求次序为：F startSignIn真实登记→G AS真实consent/code→真实TLS `https://agent.test:29443/user-service/v1/pap-callback`→G精确路径代理→Node只`helper.fetch`实际B callback→F DeviceCallbackHandoff 原设备一次领取→本地PKCE换标准Token→DPoP账户→重启DPoP restore→委托轮换（Token请求数不变）→显式refresh→revoke→signed-out。callback forwarded/received=1，Token endpoint仅2次（code+refresh）。Node proxy没有parse/store/claim code，G ledger只固定path不含query；不能把内部127转发称为AS loopback callback lane。

原生consumer结构stdout保存 `.artifacts/default-relay-native-7325/consumer-result.json`，SHA `fe02de620a06de33c7d0c88a51e8bb519550d6ae65e3d31f999d025d7bec981c`；与 G 原生 `pap03_9ba25075199a/result.json`（SHA `f601ccef6c5711e5512af342f08f4911399e84ca6738143898808dea143c241c`）配对。最终 summary SHA `23b97c3feb4e2e79543cf1838514aa34225a46388089f594753c3d84dd5b7b98` 是初始 summary27d 加最终 producer blob绑定后的版本，consumer/G结果没有改动。

G独立核对 metadata/JWKS各11GET，原始bytes SHA分别 `1ca906fee0216195d57244b35f7108f1b27a4acd8f0a553cf1e421e1a19a6fcd` / `ad5c33829caba2ee7a4bb371aefc7df9fffa339b17a433f1c59be23fb5f6fcaa`，固定callback forwarded1/non-success0，DB/roles0、process stopped、PG27432停止。F listener、native/PAP临时状态、master、公材料与B临时MySQL fixture清理完成，process exit0。

执行时 C managed helper17d737/B bridgec857 pre/post逐SHA相同，并分别与最终 C commit `fddc8a3e1bb81409ef9eb06ed5e6bbdda8bdd735` / B commit `6dcf839c0d2eff1f63d881695c20cc80445cc7ac` 的blob逐字节匹配。实际生产仍native e2c4、G binary35f626；H/G/E在同一生产7325上另行运行P01/P28，不以此账户链代替MCP回归，也未让此test-only入库改动抢占其HEAD guard。

本轮没有重复 full owner suite、System Test、产品E2E或依赖发布检查。测试脚本已typecheck并实际运行，后续只提交脚本/说明，生产src/lock继续与7325同字节。

H/G/E 的 P01/P28 联合已完成并释放 F HEAD guard：原生工具结果结构化归档为 `cimd-oauth-server/ts/.local/verification/shared-protocol-final-20261106.json`，SHA `fcd4f93190bf787a1e7e93caf4455b0bc3b71f99b2c6a64cce74fa3fc2392ea9`。实际绑定 F7325/Daf6/C helperd193/nativee2：PAP NoAS真实C/A→HTTPS、Token0，关闭engine/实际PAP Context/lease/server，随后同DID/CIMD在新独立MCP Context完成陌生client CC双工具、真实等待8.5s DB expiry后再次CC双工具，Token2且均CC、无callback/authorize/refresh。PG owner与私有/tmp/cimd-pg.rvezGbFr已EXIT删除。该结果来自已完成tool25276 stdout归档与guard后source复核，不是本轮F另跑，也不是新test-only HEAD的执行来源。

## PAP installed Host 管理与受限工具（新增候选）

本轮针对只读产品接入审计发现的缺口，仅修改 F 仓库。bundle 默认 disabled，不再隐式从 DSH_PAP_* 环境变量取得 binding；enabled 但配置不全时返回 unconfigured，正常装载且没有网络或 key 创建。实际插件 Context 固定为 `@agentconnect/dsh-pap/plugin`；独立用户 Remote 与工具 row 分别为 `@agentconnect/dsh-pap/management-remote`、`@agentconnect/dsh-pap/tools`，通过真实 Loader entry/fiber 校验。用户管理不再依赖调用者提供的 `assertAuthorizedUserAction` 空泛回调。产品 Host 必须将 Typert 管理 namespace 限定在真实已认证用户 Gateway；本模块没有新建公开 HTTP listener 或把管理能力注册成模型工具。

新增 `PapHostConsumer` 是 C 真实安全 factory 的结构合同，不是 F 自实现授权：F 仅给出实际 installed Context、三字段身份 reference 和 Host 固定 policyRef；binding/HTTPS redirect 从当前 C publication/policy 得出。callback 逐次从加密事务还原 Company/resource/scope，先走真实 ProtocolIdentityHost 获取 C opaque target，再索取 register/claim 闭合 capability 并在 finally dispose。F 没有 DeviceAccess、NativeStore 或 generic HTTP/signer 入口。C factory 在本轮 F 单位测试中是明确替身；未把此前直接 new PapClient 的真实 native 结果当成此新入口的 C/A 集成通过。真实 C factory owner 通知 ready 后才补必要模块验证。

模型只注册 `pap_status`、`pap_operations`、`pap_request`。用户先通过管理 Remote 选择 identity、发现 Company、创建 Session、显式启用本地 operation；工具只提交 operationRef 与已声明 path/query/JSON body，不能自报 URL/method/Header/resource/scopes/account/verified metadata。权限存入加密 Store，每次启用有新 generation；签名期间撤销再启用同一操作，旧调用在最终持锁 guard 拒绝，实际 HTTP 为零。工具不自动发起账户登录或 browser/callback action。标准 challenge 的安全 PRM/scope 提示仅在用户 status 出现，不把 URL/远端描述送给工具。

Secret Store 复用真实 KeyringSecretStore；namespace 额外隔离 PAP purpose 与规范化 profile stateRoot 摘要。实际状态 key 仍为 OS secret store 产生的独立随机32bytes，不从身份私钥或普通 credentials/env 派生。可选受信 papHost.secrets 支持其他平台；后端不可用/锁定/既有 item 丢失继续 credential_unavailable，没有明文、RootKey 或 env fallback。既有 SecretService 容器9项仍只证明其对应源码和容器平台，不能宣称宿主已配；此次 keyring.ts/store.ts/host-secrets.ts 的生产密钥/密文实现未改。

实际定向验证：

- `npm run typecheck && npm run build && npx tsx --test tests/product.test.ts`：12/12。正式 registry `@deepseek-ai/cordis-plugin-loader@1.0.3` 入口与真实 Cordis 生命周期；C/publication/callback backend 和加密 root key 为单位替身。覆盖 disabled/unconfigured、精确 installed caller、仅用户管理、NoAS Token0、路径/URL/Header/query 拒绝、Direct target handoff、秘密不进工具、错误脱敏、权限 ABA race、Loader 重启恢复、工具禁用、profile namespace、blocked secrets、challenge 提示分离。
- 较早受影响回归 `npx tsx --test tests/product.test.ts tests/client.test.ts tests/cooldown-challenge.test.ts`：55/55（当时 product10项）；新增2项后仅复跑 product12，不将重叠次数累加成新整轮57。没有跑其他全量或 System/E2E。
- `npx tsx scripts/tools-registry-component.ts <Desktop已安装dsh-tools/lib/index.js>`：真实 `@deepseek-ai/dsh-tools@0.1.5-rc.2` 注册三工具并经 ToolRuntime.execute 执行 disabled status、拒绝任意URL、未配置 operations。实际入口 SHA-256 `aaba52bf5d0149355407642b3965c06977d1e9143f5c61bc19429abbe6a11c5d` 前后相同；systemPrompt 仅替代注册 seam，无 LLM、Company、credentials 或 native 验收声明。

依赖诊断纠正：起初误读 `lib/index.d.ts` 路径（实际为 `lib/types/index.d.ts`）并被 rg 默认忽略 lib 的结果误导，曾误报 registry Loader 缺入口。Root 与 owner 重新核对正式包 lib/index.js 存在、SRI一致；测试已完全改为正式包入口，删除源码编译辅助与所有 NoCheck 绕行。lock 虽来自 mirror，SRI `sha512-YNcHiH7TRFrgnRbQU7qdS1spABUFFHg04QpB9DdboPEjgKLTFfeEAvr6Y7qll3/nGgqywDQdk1tYshqKO0p1WQ==` 与 primary 制品逐字节相符。安装 dsh-tools dev 依赖曾因 ^rc2 解析到 rc3 的 peer 冲突停止，没有 force；运行时 peer仍固定rc2，实际 registry检查复用 Desktop 安装产物，不修改其依赖。

此候选补齐 F 管理/工具 Host 源码，不代表 Desktop 默认 bundle/vendor/settings 已接入。Desktop/C/D 由对应 owner 修改；实际 Company 业务目标尚未决定时保留配置，不新造默认 Company。C factory 全链、真实产品 UI/启用流程、宿主 keyring 配置、System/E2E 和发行门槛分别保留其待验范围。

### 产品入口安全复核 follow-up

A/H 只读 source review 在 7bd 候选发现实际生命周期缺口：仅定义 stop 不会触发 Cordis disposer。现 constructor 显式注册 ctx.effect cleanup，stop 幂等关闭 engine/abort resource HTTP/dispose C facade；工具响应后与 post-Store 公开结果前再次检查 installed tool Context、真实 C active capability 和原始 engine/selection。显式重选同一 identity 也会产生新 engine，旧结果不得借用新 active facade 返回。select 在 persistSelection 的 fsync/rename await 后再次检查 C active/stopped，不能在卸载之后发布新 client。

同批关闭 opaque credential 回显空洞：不只按字段/JWT pattern 遮盖，还在实际 HTTP send 前持锁同步 capture 本次真正发送的 Session/DPoP/Authorization/access/refresh 值，仅供同进程 redaction set，不是 wire DTO/日志。合并调用前后私有值集，任意 JSON key/value/message 包含该值都遮盖，包含自动 refresh 的中间新 Token，不能假设响应后 Store 还留着它。输入 URI 经编码后的8KiB上限在签名前检查。C disposed generation 只在真实用户 identity/select 或插件重载时重获，工具/status 保持 fail-closed，不复活旧 target。

当前 `npm run typecheck && npx tsx --test tests/product.test.ts`：18/18。新增直接断言包括实际 Loader unload 的 transport abort（honor/ignore两模式）、迟到结果不返、selection 持久化挂起时卸载后 next.close、自动 refresh→实际资源响应→dispatch返回挂起→用户 sign-out 清空新 Token→恢复后的未知 key/value/message 回显仍脱敏，以及同 identity/operation approval 不变时重选仍拒旧 engine 结果。C/protocol/callback 仍是明确单位替身；这些用例不冒充新 C factory/native 或产品 E2E。

只读复核再收口同族只读入口：getStatus/catalog 在 protected-key/Store await 后也检查当前 engine/selection、真实 C active 与调用 Context；user/tool status facade 在 await 后复查，manager.execute 通用尾检避免慢管理动作返回卸载前结果。受控 key resolver 挂起期间实际 Loader 卸载，四种 user/tool status/operations 均拒返回旧 ready/catalog；另一次 provider generation 在挂起期间变化，恢复后拒绝旧 status。当前 `npm run typecheck && npx tsx --test tests/product.test.ts` 为 **23/23**。A 对最终源码只读安全复核未发现剩余确定阻塞，测试归 F owner 执行；不将其称为 C factory/产品全链审计通过。

## 产品入口后续：S15 持久闭环、用户 settings 与真实默认 backend

后续 Root 实际复核发现两个历史边界，均先复现：旧 AT 首请求401引发 refresh，下一请求 echo 仍有效旧 AT 时单请求 redaction set 不足；加 service 内历史后，实际 Loader disable/enable 创建新 engine 仍会漏旧值。两个失败结果不计通过。并纠正早先 owner“重启”用例只 update 相同 config 的不足：Loader 不会因此重启；现明确 disable/enable，assert 旧 stopped、新 engine 引用不同，才计恢复证明。旧2113与23项记录保留其当时范围。

现在私有 AT/RT 历史在既有 AES-GCM PapStore credentialVault 内，不另建密钥服务或明文 vault。新AS response 在解析/提交 grant 前先持锁归档；发送 refresh/revoke、替换及清 Token 前也原子保留旧值。运行内已知寿命使用单调时间与所有在途响应 pin；跨重启剩余寿命无法证明的 tombstone 保守保留，不伪造24h AS/RT期限。4096值/4MiB预算满即持续 fail-closed，不驱逐仍可能有效项，也不因用户重选同identity清历史。所有 tool/user 动态状态、Company名称、operation路径和业务输出都做已知秘密过滤；当前pending state默认过滤，只有明确User account/sign-in的authorizationUrl字段局部保留正常state/challenge。AT/RT是持久历史范围，已删除的旧nonce/verifier/claim/sid不宣称无限追踪或重构。

Legacy规则由Root明确确认：无vault却有grant/slot、任意已处理或取消的账号tx、AS nonce/DPoP迹象，保守 legacy_incomplete；只 seed当前已知不等于补全未知。Agent请求和动态Company/catalog/status停止；user仅固定迁移状态、Host生成的account refs/闭合状态并可正常尝试revoke。最新logout/revoke不自动证明全部旧RT失效。无账号迹象的旧纯NoAS才迁移complete；fresh在首次AS请求前有complete marker。保留加密数据/epoch/cooldown，不wipe/newkey/弱confirmed参数；只记录独立受信Host运维的完整issuer/client/resource撤销事实前置，本轮没有新恢复UI或通用扫描器。

用户明确的 account/refresh{accountSlot} 也已纳入闭合管理动作，输入无grantRef/URL/resource/scope/Token；核对当前binding/subject/Company/slot epoch/已有连接代次，调用既有真实refresh，再检查原Context、engine与C active。无RT或not-active拒绝，不自动重新授权；slow refresh期间实际Loader卸载不返回active。callback在Company discovery过期后先安全重新发现、检查namespace/tx，再重新获取真实C目标，不复活过期target。

实际验证：

- 最后一次受影响 owner 合计 **94/94**（client26、P22 19、storage4、history5、product32、UI8）；原生 `.artifacts/product-final-owner.tap`。此后新增hint一项仅复跑UI，不能把不同重叠轮次累加成整轮95。typecheck/build均通过，未执行fullsuite/System/E2E。
- settings DOM与browser制品：明确identity选择、Company发现、Session、operation批准/撤销、浏览器点击/collect、refresh/logout、disabled/Cwaiting/legacy/error安全提示、实际settings.section注册；C身份只能经公开list+publicationStatus得到published且papSession=true的refs，无C审批/Native/DeviceAccess。浏览器bundle与输入图不含Host/Node模块，Host `lib/client.js`不被覆盖；浏览器入口是`lib/browser-client.js`。
- 实际Desktop所装ClientModuleRegistry（entry SHA `a178c4b2d8adfb18d21e66337638aa66d08b57cc0f6325981678045aca380510`）完成root marker→locatePkgJson→browser export→serveBundle。marker没有pap/C/credentials能力；DOM与此gate分别记录，不当Desktop GUI已启动。
- `scripts/product-native-component.ts` 新真正入口 `.artifacts/product-native-entry/second-run.json`（SHA `5113b33c85a1c723d2b150bf61cfcaa6685332f92c613b14ba6e5c459ea9f44b`）exit0：fresh实际C批准/Bstrict注册发布→同store真实C/Native/credentials/manager重开→实际F三entry+真实ToolRuntime→独立实际TLS Nodecrypto NoAS verifier，2条Delegation/Session验签、jti2、Token0、公发现无auth、批准前physical0、卸载后0。F仅提供网络transport，默认Keyring实item32bytes已查证，无memorySecret。F Host与C src pre/post一致，实际加载native e2c；对应helper为旧49.../strict c74...，后继test-onlyoptional origin/profile不反标为本次来源。该结果早于M12 availability新native，保持历史。
- 上项首轮未显式A runtime aliases，freshpublication失败；原生结构输出保留first-run-failed.json且全清理。第二轮fresh Node用明确main/provider aliases→A bindings/node，Cordis/credentials仍official registry，唯一加载e2c。不是新API registry安装或署名remoteSigner。
- 默认backend sidecar复用image `sha256:fea7c2a0f03570a8bc636c1d3c19505a79964bb0b7f573363d7473fe039aa72c`；固定本机`unix:///var/run/docker.sock`，CLI最小env，shim固化inspected containerId+privateDBus+closedargv，无Host HOME/DBus/keyring mount。current Keyring/PapStore/vault real create/get、密文、daemon restart、新Host Node与vault恢复4项过；预取消/启动中取消也清理且task container inventory不变。该后端容器不是宿主已配置。所有key/pass只stdin/内存/捕获stdout，无日志。

上述native默认backend链结束已核C/F state、TLS server、SecretService/DBus/private state/container/shim全清理，HOME不变。新actual account产品链另由 `scripts/product-account-component.ts` 准备，严格使用fresh C factory与实际user Remote、defaultbackend、B固定HTTPS relay、G真实OAuth/DPoP，不使用旧直接new PapClient/managed callback helper。其新C/A M12候选及运行结果尚需单独绑定；不以NoAS或旧账户组件冒充此层通过。Desktop profile/renderer最终产品gate仍由Root执行。

## 最终 actual product-account：F43 / C M12 / A FFB / G35

实际执行F源码为 clean `43aac767fa1c73ecdb7a60e1f263c1ec06155d8f`。命令为 `npx tsx --tsconfig .local/tsconfig.product-native.json scripts/product-account-component.ts <C test/helpers/product-host-fixture.ts> <B source> <Python> <public-only-materials.json> <Desktop installed dsh-tools/lib/index.js> ffb6c3a6ee7bcd5592184db57c865d0a90748a6379636ca203a5ad42012718b9`；TTY99220只输入G handoff绝对路径，stdout只有ready/public hash与最终脱敏结构。source aliases明确指A bindings/node主包与provider，C/Harness peers保持当前正式registry，不伪称同号NPM已具新native接口。

这一次不再直接new PapClient或传旧managed-callback helper：真实C创建批准→strict B独立用户确认/注册/Registry/PAP all3发布→同store按真实ref装入一次性PAP policy→实际Loader根marker、Fplugin、Fmanager、Ftools与真实ToolRuntime。F只收到C真实factory/config；测试用户control和个人Company登录actor留在controller外，插件没有Native/DeviceAccess/邮箱control。papHost仅提供明确fixture网络transport，不提供secrets，F走默认KeyringSecretStore与真实私有SecretService后端。

实际路径：signed-out Session请求/Token0→用户Remote startSignIn→C目标绑定callback登记→G真实个人OTP/consent/code→真实TLS固定HTTPS callback→G唯一GET代理→Node只forward原query到B实际public callback→F用户collect经C真实原设备claim+本地PKCE换码→DPoP账户GET→实际Loader disable/enable F→DPoP key恢复→用户account/refresh→DPoP账户GET→account/sign-out/revoke→signed-out调用继续。callback forwarded/received各1；Token endpoint恰2次，grant_type只有authorization_code和refresh_token；revoke1。重启后记录 **userReselectedAfterRestart=true**，即复核状态后执行了一次显式用户重选，不能描述成全自动恢复无需用户动作；没有重新账户授权/新增code请求，原DPoP/账户恢复仍实际通过。

实际唯一加载native为 `ffb6c3a6ee7bcd5592184db57c865d0a90748a6379636ca203a5ad42012718b9`，C production index `fd24642860074a964be7116ab7a045cdba16d0a474220a90f5b4c8e35c6a95fc` / target-policy `5dfa70b0f0b1dd3ac8c64a44c62b35fbdf13d7f857d43e7fddaed92aad91cb7b`。全部F src（含browser）与C src pre/post逐SHA相同，F源与执行43 commit blobs逐项绑定。G生产binary仍 `35f6265876ef98daa69e8780f055ed2e6f164468494f1241b711dd2e7be09444`，helper e564/strict bridge b89。主体仍本地AES-GCM文件；主key当前为已实现OS backend，sidecar只用于隔离模块验证，不新增运行时服务/文件fallback，不把这次计成宿主OS已配置。C Native root在fixture明确使用A任务local-file custody，非A OS keyring产品gate替代。

消费者结构归档 `.artifacts/product-account-43/consumer-result.json` SHA `de0f2fd8c161df93adcce17c32a76cf07ff65b1e2dc8a24f302354e3e29337cd`，archiveProvenance明确：已完成PTY99220最后JSON stdout的结构化归档+postexit source重新hash/F43blob绑定，不是重新运行，不冒称runner直接原生落盘。对应G原生 `platform/.local/pap03/pap03_1b87dd6acaab/result.json` SHA `91bd206da87a009022650129f0e3ed286feea490712ad81de7ca219522574159`。

G独立核验真实公开metadata/JWKS各GET10，served字节SHA与实际B公开raw strings完全一致：`d67223640067a86017ee7e32afe4333adfb3792295f2d7d6266a857613b0ca20` / `796035da6c8f2a587ac8faa3b4046dda9251d8b4224af28ece484f82b9c8583a`；callback仅固定path1/error0，result/ledger无code/state/iss query或Token。G是handoff-only窗口owner checks0，不把历史16suite算本次重跑。

消费者exit0后C/F临时state/SQL、Node relay、公开材料、SecretService/DBus/private tmpfs/container/shim全精确清理，HOME不变。G确认DB0/role0/process stopped，27432/29443无监听且ownedPG停止，guard已释放。B为实际production ASGI/fullmiddleware的逻辑HTTPS模块调用，Company为真实TLS/Rust/PG；没有GUI产品E2E、System Test、LLM runtime、共享部署、push或发布。Desktop正式profile/renderer最终验收另由Root owning。

## 冻结 production43 后的 test-only 模块差额

后继879eb4b与045ebf7仅新增测试，e65现有安装tar不重打。P19/P20/P21/P23/P24沿原fixture五组focused分别1/4/2/1/1通过，补same-grant双sid刷新、scope返回子集/empty/extra与unauthorized_client、第二次ended停止/validgrant保留、只选账号枚举全部RT、Company namespace旧身份/Token不迁移。P23第二resource行明确direct encrypted-storage fixture，不是实际AS多resource签发或Commerce隔离。G另补discovery/session差额5/5，B只读审过；执行命令、类型检查与G stdout provenance见 `.artifacts/pap-module-gap-final-summary.json`，不把不同轮次拼为新全套。

P18后继script `p18-native-wire-component.ts`（SHA `4d636239a1549cf108a3946d2790b0dc754bf485cca2fba78d22be68a9add55d`）在C clean46bf/AFFB上实际exit0。直接输出原生 `.artifacts/p18-native-wire/result.json` SHA `e5c910d002f5355f5f87e502dc70d63ae459b7153d471b997da6ceed2c5ab294`；69个相关production/script/helpers/Awrapper前后相同。Bearer无DPoP广告、create/sign/header各0，AS2post/RS2get；DPoP ASnonce challenge2、RSnonce1、code2post/refresh2post/RS3get，独立Nodecrypto核7proof/4assertion/3Session及jti/htm/htu/iat/ath/同origin nonce隔离。pass-through只计数不改真实C/A结果。回调明确published loopback，AS/RS为scripted HTTPS fixture，非独立第三方AS/GUI/System。B只读核源码/结果/69files无阻塞，全部listener/state/SQL/SS/container清理。

NoAS handler机械提取后继3961059只移到 `scripts/helpers/no-as-product-verifier.ts`（a74586…23817e），原product-native仅改调用（91f5aaa…a0048）。D只读确认默认company.test语义和原Nodecrypto验证未削弱；不重跑旧NoAS脚本，也不重标旧5113来源。新current P01/P28复用了此单一helper：C46bf/AFFB/D a8/F43同Host/provider/ref/mixedCIMD，真实FNoAS1/Token0→Context仍installed时F.stop且实际rawCtargets已dispose/assertActive拒→卸F三rows/关闭NoAS与SS→同一Host再MCP首次CC双工具→真8500ms SQL到期后CC2双工具，无authorize/callback/refresh。G实际1case pass，原生C `.local/verification/shared-product-current-host-20261106.json` SHA `00cc6b086d50ec09d9cccaac36d566ffaed86814befa60b2f982db368b1d7a66`，MySQL/Redis/Croot/TLS/PG/SS全清；D只读复审无阻塞，F不在此重复执行或提交C spec。首轮新case缺actualAgent被合法门禁拒，修test actor后成功，不算prodBug。

以上新增仅test/script/docs，runtime仍43、安装文档制品仍e65；source/test后继与二者分开。没有改变存储、production、依赖或现有tar，未跑fullsuite/System/GUI/共享部署。
