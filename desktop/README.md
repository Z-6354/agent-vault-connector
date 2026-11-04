# Agent Vault 安全输入浮窗

> 历史独立客户端。最终方案为聊天内置卡片，request_secure_input 不再暴露桌面弹窗模式；见 ../integrations/embedded/INLINE-STANDARD.md。此目录保留以便审计历史产物，不作为新安全输入入口。

客户端是 420×260 CSS 像素的无边框卡片，置顶、跳过任务栏，后台只驻留托盘，不创建管理主窗口。收到 MCP 安全输入请求后，为该请求创建独立窗口，监听就绪后居中显示，内容仅有服务/账号、提示、掩码输入、授权与取消。

Enter 或点击“授权并存入”将输入交给原生端并销毁窗口；ESC、关闭按钮或“取消”将请求标为 declined 并销毁。输入不写入浏览器存储或日志。中央 Vault 的认证由现有 MCP 会话负责；卡片不承载账号管理或数据库。

## 构建

Windows x64 需要 Rust MSVC 工具链、C++ Build Tools 和系统 WebView2 Runtime。在 `src-tauri` 目录运行：

```text
cargo test --locked
cargo build --release --locked
```

应用文件为 `src-tauri/target/release/agent-vault-desktop.exe`，前端内嵌，无 Node 或 SQLite sidecar。EXE 未签名，WebView2 是系统依赖。

## MCP 对接

应用绑定随机 loopback 端口，使用每进程随机 token。交换文件 `agent-vault-secure-input.env` 默认写入当前用户临时目录，可用绝对路径 `VAULT_SECURE_INPUT_ENV_FILE` 指定。客户端与 MCP 应共享此路径；它含本机通道令牌，不能提交到仓库或回传模型。

POST 注册返回 pending；MCP 带鉴权头轮询 GET，请求完成才取回一次性结果，再通过中央 Vault API 存储。模型只接收安全引用及状态。不要用“收到 pending”或“返回 declined”作为完成验收。

窗口只显示请求元数据和用户输入。秘密存在于临时 JS/原生/传输缓冲中；Rust 使用 Zeroizing 清理其持有的缓冲，但不承诺操作系统及 JS 的全部临时副本物理销毁。

## 本轮验证

真实 EXE/MCP/WebView 测试使用合成秘密与本地 HTTP Vault 替身，检查实际尺寸、窗口样式、自动聚焦、Enter 保存、ESC/按钮拒绝以及窗口销毁行为；不代表真实生产账号业务验收。
