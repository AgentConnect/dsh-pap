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

当前剩余发行/启用门槛：实际 Host Secret Service 配置与恢复（隔离容器正向已补证）；默认 HTTPS relay 与真实账户的同一链路组合；产品管理 UI、产品 E2E 和受影响 System Test；发布后的 registry SDK pin/lock 验证。真实 C/A native 账户组合和 F/C/B exact-device callback 模块链已补证，边界见末节。Device 为另阶段，当前不广告。测试 custody 的成功不能抵消这些未验证范围。

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
