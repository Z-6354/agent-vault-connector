# Inline Embedded Card 最终规范

此规范取代此前“独立原生小卡片/桌面回退”交互决策。安全输入的公开入口只接受 `auto`、`inline`、`console`；不再接受 `desktop`、`web` 或 `gui`，不唤起浏览器、Tauri外窗或zenity。

## 使用与宿主链路

1. 已连接中央Vault的同一用户启动无窗口服务：`python integrations/embedded/run_broker.py`。默认 discovery 为用户临时目录的 `agent-vault-embedded.json`；显式 `EMBEDDED_VAULT_DISCOVERY` 可统一native宿主和MCP的路径。此文件含本机管理令牌，不能传模型、提交仓库或放在公共共享目录。Linux必须是支持0600权限的本地文件系统，WSL /mnt/c不适用。
2. Agent调用共享 `vault_mcp.py` 的 `request_secure_input(service, account, prompt, mode="inline")`，立即得到pending、request_id与next_action，能力令牌不会返回模型。
3. Agent将返回的 `::vault-input{request_id="..."}` 放入当前对话。Hermes核心贡献区已注册 `vault-input`，无需修改任何Bot profile或SOUL。
4. 新Electron main/preload原生桥读取管理令牌，只向当前可信主渲染框架返回该ID对应的单次卡片URL。iframe只授予allow-scripts，保持不透明源；模型不能用directive指定任意URL。
5. 用户在聊天气泡内输入并按授权/Enter。隔离卡片经请求级能力令牌直接POST本机broker，broker单次HTTPS调用固定中央Vault地址，确认saved+UUID后记录captured。父页面仅接收状态通知，再经native重新查询权威元数据，销毁输入iframe并显示“已安全存入 · vault://...”。
6. Agent调用 `vault_input_result(request_id)` 取得captured/ref或pending/declined/expired，无需接触秘密。重载聊天也会查询原请求状态，不重新弹输入。

MCP工具调用不能一边阻塞等输入、一边依赖其结束后才显示的卡片。因此inline是明确的请求/结果两阶段；pending绝不算成功，只有Vault确认后才captured。CLI无broker的auto仅尝试已有无回显终端通道；有broker却配置错误时返回error，不跳外部窗口。

## 安全边界

- 不使用普通Widget的hermes.send(secret)，不写聊天历史、localStorage、文件或工具结果中的明文。
- 父页面受SOP和opaque sandbox限制，不能读取iframe输入DOM；postMessage结果按source/request_id校验且再查broker，不信任子页自报的saved状态。
- 管理令牌留在native进程，renderer只得请求级capability；MCP只得请求ID。拒绝重定向、远端broker地址、异常返回正文透传。
- `allow-forms`也不开放：按钮和Enter由脚本触发受控POST，避免依赖浏览器原生form提交。禁用Edge默认密码显示眼睛图标。
- Python/JS不可变字符串无法保证所有内存副本物理zeroize，DevTools/CDP和被控制的宿主具有更高权限。因此本实现验证的是正常模型消息/工具协议和父DOM不暴露秘密，不能承诺恶意调试器/本机管理员“物理永远不可读”。这项绝对安全要求仍需宿主工具权限隔离层另行审计，不能仅靠HTML密码框兑现。

## 实际集成状态

Hermes源码已实现内置directive、原生IPC、preload和类型定义，build及UI/Electron typecheck通过。没有替换当前运行中的Hermes包或重启用户应用，因此实际聊天中的激活验收仍待主控在审签后切换新产物。

浏览器实际E2E运行的是明确标识的参考宿主，使用真实MCP+真实broker+真实opaque iframe和测试保存回调。它证明协议/浏览器隔离链路，不代表已把DSH、VSCode、Cursor或任意Web产品安装成可用插件。其他宿主必须提供等价的可信桥与聊天挂载槽，否则应明确提示不支持；禁止自动弹外部窗口。

Windows CONIN$底层未改；本轮没有让真实用户录入生产凭据。Linux /dev/tty实际PTY回归7/7。老desktop/web/gui测试的预期已不适用新规范，用公开schema拒绝和inline闭环代替；不将旧原生窗口14/14计入本轮。
