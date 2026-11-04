# AGENTS.md — Agent Vault Connector 指南 (专门面向 AI Agent)

> 本文档专为 **Claude Code、Cursor、Windsurf、Hermes、DSH、DeepSeek 及各类 AI Coding Agent** 编写。  
> 当用户指示你为他们配置、启动、测试或接入 Agent Vault 安全凭据中心时，请严格遵守以下工业级规范。

---

## 一、 核心铁律（前置拦截，一发出去就算泄露）

1. **绝对禁止在对话框索要明文凭据**：  
   严禁以任何理由向用户索要明文密码、API Key、Token 或私钥并让其发在聊天框里！用户在聊天框敲下回车的一瞬间，密钥就已经泄露进了大模型的云端日志和上下文数据库。
2. **强制走受控原生安全卡片通道**：  
   当需要凭据时，必须引导用户走本地安全卡片录入，或调用本连接器提供的标准 MCP 工具。大模型可见的永远只有脱敏引用（如 `vault://service/account`），真实密钥在本地 AES-256-GCM 加密，绝不上云！

---

## 二、 Agent 自动化一键启动与初始化指令 (Single Command)

作为 Agent，当你需要为用户在本地机器上拉起或初始化 Agent Vault 服务时，请根据当前操作系统执行对应的单一后台命令：

### Windows 环境：
```powershell
cmd /c "cd /d integrations\embedded && install-and-start.cmd"
```
*或者直接通过 Python 启动：*
```powershell
python integrations/embedded/vault_server_local.py 3210
```

### Linux / macOS 环境：
```bash
python3 integrations/embedded/vault_server_local.py 3210
```

*执行后，本地服务将在 `http://127.0.0.1:3210` 纯回环监听，自动在 `~/.hermes/vault/vault.db` 完成 SQLite 密文建库与表结构初始化（零外部笨重依赖）。*

---

## 三、 四阶段完整用户生命周期规范 (Lifecycle Spec)

当你与用户交互时，必须严格执行以下四阶段状态机：

### 阶段 1：前置探测与自然语言引导 (Probe & Guide)
- 检查本地数据库 `~/.hermes/vault/vault.db` 是否存在；
- 若未检测到就绪数据，**首先自然询问用户**：
  > “请问您的密码库希望保存在【本地单机】还是【云端服务器】？”
- **用户选本地**：检测本地若无库，询问：“检测到本地尚未初始化密码库，是否立即创建？”用户确认后触发创建；
- **用户选云端**：探活目标端口，若连接超时或被挡，明确提示：“目标服务器连接超时，请检查公网安全组/防火墙是否放行 3210 端口”。

### 阶段 2：原生安全卡片呈现 (Creation & Login)
- **创建模式**：预填已知参数（如存储目标为本地），未知项留白，用户在带黑点遮罩的卡片里输入管理员账户和主密码，原地完成 PBKDF2 盐值派生与库初始化；
- **登录模式**：检测到已有库时引导登录，登录成功后永久保存本地 Session（`vault_client.json`）；
- 登录后给用户明确安全指引：
  > “保险库初始化已就绪！后续若需存密码，请直接告诉我密码类型（如 DeepSeek API Key），切勿在聊天框贴出明文！”

### 阶段 3：凭据录入与存后即测 (Post-Save Verify & Auto-Purge)
- 用户表达录入意图后，唤起录入卡片；
- 用户敲入密钥后，系统**自动发起真实探针测试**（格式与连接探活）；
- **验错自毁机制**：
  * 若测试失败（密码错误或 Key 无效）：界面明确红字报警，并**立即物理清空刚才写入的错误记录，数据库绝不留脏数据**，等待用户二次输入；
  * 若测试通过：确认转正，落盘为 AES-256-GCM 密文并返回引用 `vault://<service>/<account>`。

### 阶段 4：换号与换服重弹登录页 (Re-Login)
- 彻底废除卡片右上角下拉切换菜单；
- 当用户表示“我要换账户”或“我要切换服务器/切换到云端”时，Agent 重新为用户唤起对应的原生登录卡片。

---

## 四、 宿主 MCP 客户端配置挂载 (MCP Servers Config)

将本连接器挂接到用户的 Claude Desktop、Cursor 或 Hermes 中：

```json
{
  "mcpServers": {
    "agent-vault": {
      "command": "python",
      "args": ["integrations/embedded/mcp_stdio.py"]
    }
  }
}
```

---

## 五、 常用诊断探针 (Agent Self-Check)

当需要检查本地保险库是否健康时，运行以下探针：
```bash
python -c "import urllib.request, json; print(json.loads(urllib.request.urlopen('http://127.0.0.1:3210/vault/status').read()))"
```
预期健康返回：
```json
{
  "status": "connected",
  "mode": "pure_local_standalone",
  "database": ".../vault.db"
}
```
