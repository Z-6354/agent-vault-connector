[English](README_EN.md) | [中文](README.md)

# Agent Vault Connector — 本地 V1

单用户凭据中心，提供回环管理界面、加密 SQLite 存储和标准 MCP stdio 执行桥。核心无需模型或 ASR 即可启动运行。当前实现遵循 [V1-IMPLEMENTATION-PLAN.md](V1-IMPLEMENTATION-PLAN.md) 与 [PROJECT-DESIGN.md §8A](PROJECT-DESIGN.md)；历史上的暂停/范围文档不构成当前授权。

默认 CLI/服务/界面与 stdio MCP 现已按[产品集成补充说明](V1-PRODUCT-INTEGRATION-ADDENDUM.md)的要求，接入受控浏览器批准，以及 GitHub/Google OAuth 的配置、授权、回调、执行期刷新与撤销。验证已通过**构建、88/88 项聚焦测试、最后一轮 13/13 的重叠锁定/浏览器检查，以及针对两个独立 GitHub/Google 回环提供方的实际 CLI + Chromium 界面 + 官方 stdio MCP 产品验收**。确切命令、证据以及两处已修正的验收失败记录在[验收报告](docs/acceptance.md)中。历史上的 **134/134** 套件与库演示对其早先快照仍是有效证据，但不构成针对当前已变更代码的全套件结果。内部实现评审与指定的 Hermes `@reviewer` 相互独立。[指定评审](docs/evidence/v1-designated-review.md)现对本可运行的本地产品 V1 给出有条件通过，并关闭了 OAuth 范围 P2；该评审独立检查了源码与既有执行证据，未重新运行测试。评审意见由开发者带署名转录，并非评审者直接撰写。[五智能体兼容性矩阵](docs/compatibility.md)在实际任务上仍未验证。本次未使用真实密钥、既有智能体配置、真实提供方/账户调用、隧道、部署或提交。

## 安装与构建

使用 Linux、Node **22 系列内 22.13 或更高版本**以及 npm。若 `better-sqlite3` 的原生预构建不可用，可能需要 C++ 工具链与 Python。浏览器验收需要 `/usr/bin/chromium` 以及用于 PTY 初始化的 Python 3。请在项目目录下执行命令。

```sh
npm ci --no-audit --no-fund
npm run build
```

若需隔离安装以避免使用个人 npm 配置，可在私有临时目录中创建两个空的 user/global npmrc 文件，并通过 `npm_config_userconfig` / `npm_config_globalconfig` 传入。不要将既有智能体配置或 `.env` 复制进本项目。`package-lock.json` 记录依赖解析结果。依赖漏洞审计不属于已记录的验收范围。

## 初始化与启动

```sh
node dist/src/cli.js init --data-dir ./data
node dist/src/cli.js serve --data-dir ./data --port 43120
```

`init` 需要真实的交互式终端，并以无回显方式两次提示输入 12–1024 字符的口令。它不接受任何口令命令行参数或环境变量。它会拒绝非空数据目录。数据目录必须归当前用户所有且权限为 `0700`；文件为 `0600`、普通文件且非符号链接。初始化会创建加密数据库、一个执行访问密钥，以及一个独立的持久请求签名密钥。切勿将这些密钥放入提示词、命令参数或日志。

在同一台机器上打开 **http://127.0.0.1:43120**，必须使用完全一致的 IP 与端口。默认情况下服务绑定 `127.0.0.1`，且只接受该精确 Host 与 Origin；`localhost` 及其他 Host 取值均会失败。如需从外部浏览器访问，请使用下方显式的 TLS 代理配置。每次重启后都处于锁定状态。管理流程为：

1. 使用初始化口令登录：S0 → S1（已认证，仍锁定）。
2. 使用口令解锁：S1 → S2（已认证且已解锁）。
3. 填写类型、已注册服务/Origin、账户与操作授权。保存前复核不含密钥的确认卡片。替换操作会绑定目标当前的 `record_version`；发生冲突时必须重新复核。
4. 暂停/撤销使用当前的 `status_version`，替换/删除使用当前的 `record_version`，完成后显式锁定或登出。

管理界面包含近期审计事件和 **Recover save result**（恢复保存结果）面板。它仅在标签页的 `sessionStorage` 中保存不透明的签名保存请求 ID，绝不保存密钥、草稿、转写文本或批准。若保存响应丢失或服务重启，请登录/解锁后用该请求 ID 执行恢复：服务会返回已保留的完成元数据，不会再次保存，也不要求提供旧的批准。恢复仅限稳定的已认证管理员，且在保留期结束/清除后返回不可用；未提交的草稿在重启后无法恢复。

锁定会将当前管理员退回受限的 S1 会话，并轮换 cookie/CSRF 令牌；旧的 cookie、草稿与批准均失效。登出、管理员 15 分钟空闲超时或进程重启都会进入 S0 并全局锁定执行。MCP 流量不会延长管理员空闲时间。关闭标签页不会立即登出。同一时间最多只有一个活动管理员会话。口令尝试失败与请求频率限制均返回受控错误。

注册表将固定的合成 HTTP 测试装置与受源码管控的生产 HTTPS 目标分开。API 密钥与密码无需模型即可使用。`external_reference` 仅存储元数据、不含密钥信封，且始终 `can_execute=false`。

### 通过 TLS 代理提供外部浏览器界面

只配置一个规范公共 Origin：不得含尾部斜杠、路径、查询串、片段、用户信息、通配符或列表。除显式的 `http://127.0.0.1:<port>` 开发 Origin 外，必须使用 HTTPS。大写/非规范的 URL 写法以及冗余的默认端口会被拒绝，而不会被静默规范化。`--allowed-origin` 是校验规则完全相同的兼容别名；同时提供两个标志会报错。非法的网络配置会在打开保险库或开始监听之前失败。

```sh
# Same-host proxy: application upstream stays on loopback.
node dist/src/cli.js serve --data-dir ./data --port 43120 \
  --public-origin https://vault.example.com

# Container/private mapping: explicitly opt into an IPv4 bind.
node dist/src/cli.js serve --data-dir ./data --port 43120 \
  --bind-host 0.0.0.0 --public-origin https://vault.example.com
```

默认绑定 `127.0.0.1`；`--bind-host` 只接受 `127.0.0.1` 或 `0.0.0.0`，以保证本地桥可达。通配绑定必须显式提供 HTTPS 公共 Origin。**非回环的 HTTP 上游必须通过防火墙限制为仅 TLS 代理可访问。**只发布代理的 TLS 监听端口；绝不直接暴露应用的明文套接字。对同主机容器代理，形如 `127.0.0.1:43120:43120` 的映射可使宿主侧上游保持私有。网络隔离与 TLS 属于部署方责任；应用无法从请求头推断这些信息。

同主机代理的 nginx 配置示例（请将示例域名与证书路径替换为实际签发的值）：

```nginx
server {
    listen 443 ssl;
    server_name vault.example.com;
    ssl_certificate /etc/nginx/tls/vault.example.com.crt;
    ssl_certificate_key /etc/nginx/tls/vault.example.com.key;

    location /execution/ { return 403; }
    location / {
        proxy_pass http://127.0.0.1:43120;
        proxy_set_header Host vault.example.com;
        proxy_set_header Origin $http_origin;
        proxy_set_header Forwarded "";
        proxy_set_header X-Forwarded-Host "";
        proxy_set_header X-Forwarded-Proto "";
        proxy_set_header X-Forwarded-For "";
    }
}
```

若使用非默认的公共 TLS 端口，需在 `--public-origin` 与保留的 `Host` 中同时包含该端口。浏览器原始 `Origin` 必须原样透传；不要伪造它，也不要用上游 Origin 替换它。默认情况下，映射服务必须保留配置的公共 Host 和浏览器 Origin，并提供 TLS。Fastify 的代理信任保持禁用。仅凭管理 cookie 无法绕过同源 CSRF 校验。

对于会将 Host 改写为回环地址的边缘网关，请在下次由运维控制的启动中显式启用固定回环代理模式（沿用现有的数据目录与产品配置参数）：

```sh
node dist/src/cli.js serve --data-dir <existing-data-directory> --port <port> \
  --public-origin https://vault.example.com \
  --trusted-proxy loopback --diagnose-proxy-headers false
```

`--trusted-proxy loopback` 默认关闭，且要求已配置 HTTPS 公共 Origin。仅当改写后的 Host 等于 `127.0.0.1:<actual-listening-port>`、且实际套接字对端恰为 `127.0.0.1`、`::ffff:127.0.0.1` 或 `::ffff:7f00:1` 时，才接受该 Host。以上是可接受对端字符串全集；`::1`、其他 `127/8` 地址以及其他 IPv6 文本写法一律拒绝。必须恰有一个原始 Host、恰有一个原始 X-Forwarded-Host 且等于所配置公共 Origin 的主机名（含任何非默认端口）、恰有一个原始 X-Forwarded-Proto 且等于 `https`。重复、逗号/列表、冲突或缺失的转发字段一律失败关闭。该模式下拒绝 RFC Forwarded。既有的直接公共 Host 路径在无转发字段时仍被允许；若该路径上存在转发字段，则必须满足同样的精确元组与对端校验。转发值从不用于选择新的 Origin。静态资源、OAuth 重定向/回调以及管理端 Origin/CSRF 校验始终使用配置的公共 Origin。请保持浏览器原始 Origin 不变。

**回环对端并不能证明网关来源。**部署方必须限制对上游的访问，并要求网关覆盖这些转发字段、剥离冲突的或客户端自带的取值（包括 Forwarded）；请求头本身不是认证手段。本机进程可以伪造该元组。启用该模式时 CLI 会打印这条警告。执行路径会拒绝任何 X-Forwarded-Host 或 X-Forwarded-Proto，即使其取值看似合法的网关值，并且仍要求精确的本地 Host、可接受的实际套接字对端与执行 bearer。作为额外的部署限制，请在公共网关上屏蔽 `/execution/`。

代理诊断默认关闭。若使用 `--diagnose-proxy-headers true` 临时采样，采样结束后应关闭（`--diagnose-proxy-headers false`，或在下次运维控制的启动中省略该选项）。诊断白名单仅含长度受限的 Host/计数、Origin、X-Forwarded-Host、X-Forwarded-Proto 与实际对端；绝不记录 cookie、authorization、URL/查询串或请求体。参见[可信代理证据与验证状态](docs/evidence/trusted-proxy.md)。上述说明不会重启现有服务。

启动时会分别打印实际监听的 HTTP 套接字、公共管理 URL 和本地执行 Origin。在公共模式下，所有会话签发、续期、锁定与登出清除的 cookie 都带 `Secure`、`HttpOnly` 和 `SameSite=Strict`。登录与解锁仍为两个独立步骤。请将 OAuth 回调注册为 `https://vault.example.com/management/oauth/callback/github` 和 `/google`（若配置了端口则包含该端口）；界面与已存储的客户端配置都使用这个经过精确校验的 Origin。变更该 Origin 需先更新提供方已注册的回调，再重新配置本地客户端（递增其版本）；绑定到旧客户端配置的旧令牌材料无法复用。重启会使先前的会话与状态失效，因此需在新的已认证会话中重新发起授权。Origin 不匹配会以 `redirect_uri_changed` 失败关闭，并禁用该不匹配的提供方。仅重新登录并不能恢复旧回调。该 Origin 迁移/重配置场景已在源码层面检查，但未直接做动态演练。

即使管理端使用公共 URL，标准 stdio 桥仍使用**服务所在网络命名空间内**的 `http://127.0.0.1:<application-port>`。执行路径接受其精确的本地 Host、实际的回环对端和执行凭据，不需要浏览器 cookie 或 Origin。当服务配置了不同的公共 Host 时，本地执行 Host 无法管理该服务，除非通过显式可信回环模式校验上文所述的完整固定网关元组。通配的容器绑定会使容器内的回环套接字仍然可达；请在同一容器/网络命名空间中运行该桥。这不提供远程 MCP 访问能力。

本地验证已通过：构建与全部 7 项聚焦的代理/服务认证/CLI 测试均成功，其中包括任务创建的保险库和真实的本地 TLS 反向代理。指定的 Hermes 评审者在检查源码与既有执行证据后，对本增量给出有条件通过；评审者未亲自重跑测试。参见[反向代理证据](docs/evidence/reverse-proxy.md)。公共部署、真实 DNS/证书、nginx/防火墙操作以及任何外部映射服务仍未验证。这些改动不执行任何部署。

### 受控浏览器配置

浏览器宿主默认禁用，除非显式启用。请在保险库目录之外保存一个归当前用户所有的普通 `0600` JSON 文件，例如：

```json
{"mode":"production","browser":{"enabled":true,"executablePath":"/usr/bin/chromium","headless":true}}
```

使用 `node dist/src/cli.js serve --data-dir ./data --port 43120 --product-config /absolute/private/product.json` 启动。唯一注册的浏览器站点是位于 **http://127.0.0.1:43122** 的已知合成登录测试装置；这并不增加对任意网站的支持。验收脚本会自动启动该测试装置。未配置的宿主会报告 `unsupported`。

MCP 会请求一个会话以及一个待处理的 `browser_fill` 或 `login_submit` 批准。在管理界面选择 **Refresh approvals**（刷新批准），核对已认证的执行主体、精确的固定站点、记录/版本、动作与有效期，然后批准该动作。填充与提交需要各自独立的单次批准；MCP 没有批准工具。填充不会提交。在批准登录之后，安全的会话状态会在固定账户页验证宿主自有的 cookie 复用。原始文档标识、五分钟句柄 TTL、60 秒批准有效期、记录/状态/规则版本与 epoch 校验仍全部生效。系统不暴露任何 URL、选择器、脚本、cookie 或密钥 DOM 接口。

### GitHub 与 Google OAuth

未保存客户端时，每个提供方以 `client_not_configured` 禁用。在 **OAuth provider setup**（OAuth 提供方设置）中，使用界面显示的精确回调手动注册相应的提供方应用，然后输入其 client ID 与 secret。本产品只在本地配置该已注册客户端，不会注册远程应用。客户端配置以版本 CAS 加密存储于 SQLite；secret 为密码输入框，提交后清空且永不回读。固定的生产上游端点无法通过管理界面或启动配置更改。本地回调为 `http://127.0.0.1:<port>/management/oauth/callback/github` 和 `/google`；更改 serve 端口需同时更新提供方注册信息与本地客户端配置。

通过普通保存流程创建并复核 OAuth 连接。其固定的最小 scope 为 GitHub 的 `read:user`，或 Google 的 `openid email`。保存后的占位记录初始状态为 `needs_user_action`。选择 **Authorize**（授权），复核可选的同意屏幕勾选项，并点击会过期的提供方链接。受保护的回调会绑定发起时的管理会话、所有者、连接/版本、state、PKCE、epoch 与有效期。静态导航中转会从地址中剥离 code/state，并通过已认证的同源 CSRF POST 完成授权，同时保持严格 cookie。锁定/登出/重启会使待处理的授权失效。

真实的 stdio `execute_operation` 会为固定的 `github.current_user` 或 `google.userinfo` 使用加密材料。已过期的访问材料在派发前通过持久租约/CAS 刷新；针对同一连接的并发请求共享一次刷新。令牌材料绑定精确的客户端代次以及提供方/模式/端点；替换已配置客户端需要重新授权，且不能复用旧的 refresh token。资源授权被拒会将当前匹配材料置为 `needs_user_action`，且不会自动重试。缺少刷新材料需要重新授权。结果未知的轮换刷新会被阻止并保持 `needs_user_action`；**Reconcile OAuth material**（核对 OAuth 材料）在带有复核证据的前提下放弃旧材料，随后 **Reauthorize**（重新授权）从头开始。它绝不会重试不确定的 refresh token。**Revoke OAuth**（撤销 OAuth）会调用提供方的撤销流程并删除本地令牌材料。仅靠本地通用记录的撤销/删除并不等于提供方侧撤销。在本次获授权的合成运行中，生产注册、账户同意与提供方互操作性仍未测试；参见 [OAuth 要求](docs/oauth-v1.md)。

## 合成操作与 MCP

在另一个终端启动固定的本地 mock：

```sh
node dist/src/cli.js mock
```

它只绑定 **http://127.0.0.1:43121**。在界面中选择 `synthetic-mock`，输入账户别名和一个形如 `synthetic_example_token_123456` 的令牌，并授予 `mock.account_summary`。合成令牌格式被刻意限制为 `synthetic_[A-Za-z0-9_-]+`（16–512 字符）。mock 的反射/重定向/超大/超时行为用于测试过滤与拒绝；切勿在其中放入真实凭据。

本地 MCP 宿主应直接启动 Node，以确保 stdout 只包含 MCP 协议内容：

```json
{
  "mcpServers": {
    "local-vault": {
      "command": "node",
      "args": [
        "/absolute/project/path/dist/src/cli.js", "bridge",
        "--origin", "http://127.0.0.1:43120",
        "--credential-file", "/absolute/project/path/data/execution.key"
      ]
    }
  }
}
```

该桥只读取显式提供的受保护执行凭据文件。服务会将其映射到稳定的执行主体；请求参数无法选择其他身份。该凭据只授予中心执行访问权，不授予上游提供方访问权或管理权限，也无法解锁保险库。

执行客户端可发现 `list_connections`、`list_operations`、`get_connection_status`、`prepare_request`、`execute_operation` 和 `get_operation_status`，以及 `browser_sites`、`browser_open_session`、`browser_session_status`、`browser_request_approval`、`browser_approval_status`、`browser_fill` 和 `browser_submit`。先用 `prepare_request({"operation_name":"mock.account_summary"})` 获取服务端签发的 ticket，然后调用：

```json
{
  "connection_id": "<connection UUID>",
  "operation_id": "mock.account_summary",
  "expected_record_version": 1,
  "request_id": "<server-issued ticket>",
  "args": {}
}
```

中心只在固定执行器内部注入认证，并返回经复核的字段。系统不提供任意 URL/请求头/路径/脚本、shell、密钥读取、解锁或管理类工具。重试/查询状态时复用同一 ticket；它会返回已持久化的状态/结果，不会再次派发。派发后发生超时/断连时，`outcome_unknown` 表示**可能已执行，需要核对**。它不是安全的自动重试，更改 request ID 也不能证明重复副作用是安全的。管理端的操作历史允许已认证管理员将经复核的上游证据记录为确认成功/失败，或在接受重复风险的前提下显式授权新的一次尝试。核对使用当前操作状态版本；核对本身不派发操作。

这些内部已认证 HTTP 路由不是 Streamable HTTP MCP 服务，也不是 MCP OAuth 授权服务器。远程云端客户端无法通过写 localhost 访问本机。系统不提供远程端点、隧道、公共端口或 TLS 部署。仅支持 OAuth 的远程客户端仍不受支持。

## 可选组件与明确限制

`src/delegation.ts` 使外部引用保持不可执行，并定义独立的 `TrustedDelegationHost`/`DelegationExecutor`。正式授权会绑定所有者、中心与上游的身份/账户、授权来源/证据、受众、资源、scope、操作、端点、有效期与撤销状态。每次调用都会检查其与本地策略的交集，并核验当前宿主状态。实际用于验证的 HTTP 回环测试装置对两个方向都做认证并测试拒绝；它是显式声明的合成协议，并非虚构的平台 API。生产委派尚未接入 MCP，也未接入五个智能体中的任何一个。真实适配器必须获得正式授权并使用核心的持久 A3 派发状态机；不支持任何令牌导出或 shell 变通做法。

`src/local-draft.ts` 是可选的、可注入组件。`LocalDraftSession` 需要显式的数值型回环推理接口；ASR 另行注入。`bindVaultLocalDraftCore` 调用真实的不可变草稿/批准 API，并要求可信的会话/CSRF 校验器。`src/enrollment-mcp.ts` 提供一个独立的、基于官方 SDK 的可信内存 MCP 通道，仅暴露 `save_credential`；真实核心以原子方式消费该批准。测试覆盖草稿 → 确认 → 真实 MCP 保存与重放。该录入通道不向推理或普通执行客户端暴露。推理无法自行批准。确认使用所保留的精确密钥；取消、超时、编辑与锁定都会使待处理草稿失效。该组件不存储转写文本/音频/历史。它是库级集成点，不是已配置的模型服务，也不是已启用的界面/CLI 语音流程。测试注入确定性的**合成测试装置**；未运行任何模型或 ASR 推理。不存在已批准的模型/ASR 端点，未猜测任何端点，也未提供云端回退。仅有回环 URL 并不能证明后端从不外发数据；完全本地运行**未经验证**。

## 存储、迁移与保留

密钥使用 AES-256-GCM，配以独立的随机 nonce 和带认证的记录/请求上下文。Scrypt 从口令派生加密材料；管理员认证使用独立的 salt/域。主密钥材料仅驻留进程内存，销毁时保留的 key Buffer 会被清零。JavaScript 字符串、浏览器输入、原生缓冲区、操作系统交换区/core dump 以及同 UID 的进程不在任何可保证的内存擦除边界内。元数据、记录/账户标签、Origin、操作授权、时间戳与审计标识均不加密；请勿在元数据中放置密钥。

启动时以事务方式将迁移应用到 schema v4。新增的 `oauth_clients` 表将客户端配置与凭据材料分开加密保存。在升级 v3 数据库之前，会创建私有备份 `vault.pre-v3-to-v4.sqlite`。既有的 v1/v2 升级会保留其 `vault.pre-v1-to-v3.sqlite` 或 `vault.pre-v2-to-v3.sqlite` 原始备份，并继续升级到 v4。既有备份永远不会被覆盖。遗留记录会被暂停且不授予任何操作权限；请显式复核并重新授权。既有 v2 审计历史保留在 `legacy_audit_events_v2` 中，同时在当前审计表内记录经脱敏的标识/时间保留事件。更新或未知的 schema 版本会失败关闭。不要通过修改 version pragma 或迁移 SQL 来强行打开数据库。初始化失败可能留下部分目录，该目录被有意保留而不覆盖；删除任务产生的部分数据前请先检查。

请求 ticket 的作用域限定为所有者、稳定主体和操作。新注册会在 24 小时后过期。已完成结果和加密的规范化比对副本共有 7 天可用/保留边界；清理在启动时及服务运行期间每分钟执行。请求墓碑可防止在比对副本被移除后再次执行。未解决的外部操作记录不会被自动丢弃。删除当前凭据**不会**立即擦除已保留的加密请求比对副本、备份或上游令牌。管理员的 **Purge retained copies**（清除保留副本）操作会删除该连接保留的请求比对副本/结果，同时保留墓碑；后续重试会返回 `result_unavailable`。该操作不会删除备份副本，也不是普通 MCP 工具。审计事件包含标识/动作/版本/结果，不含请求体或密钥摘要；未配置审计自动过期。关于实际的清理集成方式与仍存在的限制，参见[验收](docs/acceptance.md)。

## 备份与恢复

复制或恢复前请先停止服务与所有桥。为获得一致的冷备份，请将**整个私有数据目录**复制到可信本地存储，同时保持 `0700`/`0600` 权限，其中须包含 `vault.sqlite`、`execution.key` 与 **`request-signing.key`**。口令另行保管。数据库包含加密的当前密钥、保留的比对材料，以及未加密的元数据；数据库与访问密钥均属敏感信息。任何备份或恢复命令都不上传文件，也不绕过加密。

恢复时，将冷备份复制到一个新的空目录（归当前用户所有，模式 `0700`），保持文件模式（`0600`），然后运行 `serve --data-dir /absolute/restored-directory --port 43120`，并用原口令登录/解锁。schema v3 的签名密钥是必需的；一旦丢失，中心会拒绝运行，而不会重新生成密钥并允许含义不明的重试。执行密钥必须与数据库匹配。在依赖某份备份之前，请先用合成数据在独立目录上演练恢复；除非验收证据中列出，冷备份恢复不声称已验证。

如需迁移回滚，请停止所有进程，并在独立目录中使用匹配的旧版应用，恢复私有的迁移前数据库及其匹配的原始密钥。本 V1 在打开时会再次自动迁移较旧数据，因此仅用 pre-v3 或 pre-v4 备份启动它便已执行升级。请保持原始备份不变。恢复较旧快照可能丢失近期的请求结果，且无法撤销已完成的上游操作；在进行任何新尝试之前，请先核对未解决的操作。已遗忘的口令无法重置以恢复密文。本地删除/撤销不等于提供方侧的令牌撤销。

## 验证与许可

```sh
# The full test command is available; the current report records focused checks.
npm run acceptance

# Integrated product paths use fresh short private scratch directories automatically.
node scripts/v1-product-acceptance.mjs
```

构建完成后执行集成产品验收，请运行 `node scripts/v1-product-acceptance.mjs`。它会通过 PTY 用真实 CLI 初始化一个全新的合成保险库，启动默认 CLI 服务，驱动 Chromium 执行管理操作，并使用真实的 stdio MCP 桥。独立的 GitHub/Google 回环模拟器覆盖配置 → 授权/回调 → 固定操作 → 真实过期/并发刷新 → 撤销；受控浏览器路径覆盖经复核的密码保存 → 人工分别批准填充/提交 → cookie 复用 → 锁定拒绝。它会写出脱敏 JSON 和一张截图，然后停止子进程并删除临时数据。必须已安装 Chromium 与 Python；固定端口 43122 必须空闲。

仅在 `mode:"synthetic"` 且保险库是用 `init --synthetic true` 全新初始化的情况下，才接受合成端点注入；受保护的 `.synthetic-product` 标记可防止把已有的普通保险库当作该测试装置。带标记的保险库在每次 serve 时都必须使用合成启动配置；不能回退到生产/默认模式。合成执行还会阻止生产 API 密钥目标。合成配置需要 `github` 与 `google` 各自独立的端点集合（`authorize`、`token`、`identity`、`revoke`），全部为字面量 `127.0.0.1` HTTP 且带显式端口。验收脚本会自动创建该私有配置。生产配置会拒绝提供方端点字段。

`node scripts/v1-app-smoke.mjs` 仍是较早的 CLI/CRUD 冒烟脚本；`node dist/src/browser-demo-run.js` 仍是库宿主的演示。两者都不能替代产品验收。

测试使用任务创建的合成保险库与本地测试装置。测试套件包含真实 CLI PTY、通过 Chromium 的管理界面、官方 SDK stdio MCP、核心事务/重放以及本地适配器测试；结果仅属于当次确切记录的运行。缺少浏览器/PTY 前置条件即为失败或显式跳过，不能作为覆盖已通过的证据。[docs/acceptance.md](docs/acceptance.md) 与 `docs/evidence/v1-delivery*` 包含当前命令、结果与阻塞项；较早的验收日志仍属历史证据。

项目源码基于 [MIT](LICENSE) 许可发布。依赖保留各自的许可证。本次为本地源码交付，并非仓库发布或远程发布。
