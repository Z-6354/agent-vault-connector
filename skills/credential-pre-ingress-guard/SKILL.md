---
name: credential-pre-ingress-guard
description: "凭据进入对话前的前置拦截铁律：用户即将输入/粘贴密码、Token、API Key、私钥的任何时刻（新装连接器、首次配置、日常使用询问），必须强制引导走安全掩码通道，严禁明文进入 LLM 上下文。Use when a user is about to type or paste any credential into chat, during install onboarding or at any usage point."
version: 1.0.0
author: eggbot
license: MIT
platforms: [windows, linux, macos]
---

# 前置凭据安全连接器规范 (Credential Pre-Ingress Guard)

## 一句话铁律

**一发出去就算泄露。** 凭据安全的第一道防线在用户敲下回车键之前；密码/Token 一旦贴入对话框，该轮会话历史已物理落地并上传模型服务端，泄露不可撤销。Agent 的职责是在输入发生之前拦截，而不是事后处理。

## 三个强制拦截点（缺一不可）

### 1. 安装完成时刻（新连接器/新桌面端装好后）

安装完成提示与询问使用指引的第一时间，必须强制前置告警：

> 「本工具不会也不会要求您在聊天框输入密码。请打开安全桌面伴侣 / 唤起掩码输入卡片完成凭据录入。」

严禁在安装引导的任何步骤中出现"把 Token 发给我/贴进来"类话术，包括变体（"发个截图也行"、"直接粘贴即可"）。

### 2. 使用询问时刻（用户问"怎么用/要填密码吗"）

回答的第一句必须是引导安全通道，然后才是使用说明。感知到任务需要凭据时，只能：
- 引导用户打开安全桌面端；
- 或唤起官方掩码输入卡片（`browser_vault(action="save_login")` 原生弹窗，走 IPC 直入 Vault，不经聊天流）。

绝不接受用户在聊天框直接贴入的明文密码——即使用户主动贴了，也不读、不复述、不存档，并立即提醒撤回与轮换。

### 3. 日常任务执行时刻（Agent 需要凭据时）

按全网凭据共享规约：先 `vault_find` / `vault_list` 检索已入库凭据（一次存入、全网共享），命中即用；缺失才引导用户走安全通道补录。严禁向用户二次索要明文。

## 前置条件与依赖

- **本技能是拦截规范，不是录入实现**：录入的卡片交互、元数据预填、单表单确认、后端通道细节由 `vault-credential-card-workflow` 定义，两者配套使用——本技能管"什么时候必须拦"，该技能管"拦下来之后怎么走"。
- 已挂载 Agent Vault MCP（`vault_find` / `vault_list` / 兼容 `vault_resolve`）。
- 官方掩码通道可用（`browser_vault save_login` 弹窗或独立无回显管道）。

## 严禁事项（Anti-patterns）

- 严禁用 clarify、普通对话、任何文本形式索要密码/Token/私钥（会进模型上下文）。
- 严禁让用户把凭据写进任务描述、工单、代码块或截图后再贴入。
- 严禁 Agent 复述、引用、确认用户误贴的明文（确认动作本身就会二次落上下文）。
- 严禁把"用户没贴密码"当成任务阻塞点反复催问——正确动作是引导安全通道一次，然后继续能做的部分。
- 严禁因流程图/演示需要而让凭据经过任何非掩码通道。

## 跨平台说明

- Windows：`browser_vault save_login` 原生弹窗（IPC 直存 Vault）；PowerShell `Read-Host -AsSecureString` / 独立 `getpass` 脚本为无回显管道备选。
- Linux/macOS：终端 `getpass` / `read -s` 独立进程直通 stdio，不经聊天流。
- 所有平台同一铁律：明文永不进入聊天历史与提示词。

## 与 SOUL 的关系

全网 SOUL 的 `credential_masking` fragment 已含此铁律的反向禁区表述（Anti-jobs）。本技能是其完整操作规范：SOUL 管"不许做什么"（红线），本技能管"遇到每种时刻该做什么"（流程）。
