# Embedded Form Matrix：实施方案与宿主边界

> 历史阶段方案；最终交互规范以 [INLINE-STANDARD.md](INLINE-STANDARD.md) 为准。公开安全输入入口已移除外部桌面/浏览器/GUI模式。

## 目标与当前范围

统一 `request_secure_input(service, account, prompt, mode="auto")` 的凭据输入体验：优先宿主内部安全卡片；无适配宿主时使用已验证的桌面/TTY通道。中央 Vault 继续负责集中存储，不新增每宿主密码数据库。

本轮新增 `integrations/embedded/`，提供 broker、沙箱卡片、宿主挂载 SDK、原生 broker client 与可独立运行的 MCP stdio 入口。现有共享 MCP/profile 配置没有切换；此目录不是声称所有宿主已经安装的插件。

## 已查证的 Hermes 接口

源码位置：`apps/desktop/src/components/assistant-ui/inline-preview-directive.tsx`。
普通 `::preview` 的 `window.hermes.send()` 会经 composer 发送隐藏用户消息并持久化，禁止用它传密码。Widget 内容由文件读入，也不能把用户输入写回该文件。

`components/ui/sandboxed-frame.tsx` 的允许列表保留不透明源 `allow-scripts`，主动排除 `allow-same-origin`。方案不修改这一全局防护。专用卡片使用URL iframe、能力令牌和 `Origin:null` 请求，不走聊天发送。

## 数据流

1. MCP 请求发送元数据给本机 broker；标准工具输入参数从不包含秘密。
2. 原生宿主插件从受保护 discovery 文件取得 broker 管理令牌，经本机 native/preload 查询待处理请求。此令牌不进入 renderer/model/history。
3. 宿主仅收到单次 `frame_url` 与服务/账号/提示，将卡片挂在当前聊天槽、模态槽或字段旁容器。
4. 卡片位于不透明源 iframe，父页面不能通过 DOM 读取输入。卡片脚本 POST 直接送 broker；broker 通过固定 HTTPS 端点保存到中央 Vault。
5. 卡片向父宿主 postMessage 仅发送 `{type,request_id,status,ref?}`；父宿主验证 `event.source`、`event.origin=="null"`、请求ID并重新构造白名单结果，随后销毁iframe。MCP独立GET结果只获得captured/ref，不读取secret。

此边界防止普通消息抓取和父页面脚本误读；不承诺抵御被完全控制的宿主、浏览器扩展、调试器或操作系统。密码掩码和 iframe 不能建立针对恶意本机管理员的安全边界。

## 适配矩阵与落地顺序

| 宿主 | 组件 | 实际接入条件 |
|---|---|---|
| Hermes 聊天 Widget | `mountSecureInput(...,{presentation:"inline"})` | 由可信 runtime plugin 注册独立directive或工具UI；元数据由native读取，禁止模型生成capability URL，禁止hermes.send(secret) |
| Electron / DSH | `native-client.mjs` + `host-adapter.mjs` 的overlay | main/preload持有管理token，仅暴露pending元数据和结果；contextIsolation开启、nodeIntegration关闭，宿主CSP允许固定loopbackframe |
| VS Code / Cursor | 原生extension端broker client +受控Webview mount | 需要正式extension和宿主CSP/资源声明；不能任意往编辑器自身DOM注入 |
| Browser | `presentation:"anchored"`，由扩展拥有定位容器 | 内容脚本只挂隔离iframe；须扩展权限与frame/CSP/local-network策略支持。HTTPS网页不保证允许HTTP loopback，不能关闭安全策略来“适配” |
| 不支持的宿主 | 现有400×260桌面卡片 | 本轮不再次重写原生兜底；compact E2E原始证据保留 |
| CLI/Linux/SSH | 现有/dev/tty与CONIN$无回显 | 非图形能力缺失不等于静默降级成功；通道失败必须明确反馈 |

阶段1实现并验证可移植组件和协议；阶段2接实际Hermes trusted plugin；阶段3在已取得源码/扩展接口的DSH、VSCode、Cursor和浏览器逐项安装验证。不能只靠标准MCP工具定义强迫任意宿主显示原生界面；宿主必须有工具UI/elicitation或自有插件支持。

## 文件职责

- `broker.py`：loopback注册/请求级能力令牌/一次提交/固定HTTPS保存/只返回引用。
- `mcp_adapter.py`、`mcp_stdio.py`：独立可运行的标准MCP边界，显式discovery配置；不改用户已有profile或共享servers.json。
- `native-client.mjs`：trusted main/extension进程持有broker管理token，renderer不得导入。
- `host-adapter.mjs`：inline/overlay/anchored 三种挂载，opaque sandbox，完成仅白名单事件。
- `web/card.*`：密码框和操作，秘密仅用于当前POST，清空后不回填，不写storage或日志。

## 验收要求

分别验收 broker HTTP、MCP stdio、真实浏览器沙箱iframe与实际宿主。浏览器参考页通过不等于Hermes发布包通过，stub保存回调通过不等于生产Vault业务成功。审阅状态必须单独标识。

当前已有MCP边界Windows4/4、WSL4/4；其他结果在集成完成后更新。broker子任务进行中，尚不能宣布全矩阵完成。
