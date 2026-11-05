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

当前剩余发行/启用门槛：实际账户路径组合 C/A 原生 custody 的同链路验收；B exact-device callback driver 的真实注册/一次领取联调；实际 Host Secret Service 可用性与恢复；产品管理 UI、产品 E2E 和受影响 System Test；发布后的 registry SDK pin/lock 验证。Device 为另阶段，当前不广告。测试 custody 的成功不能抵消这些未验证范围。

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

原来列出的 B callback、系统 keyring、native 账户组合、产品 E2E/System Test 和 registry 发行门槛仍未执行；本次并发修复不改变其状态。
