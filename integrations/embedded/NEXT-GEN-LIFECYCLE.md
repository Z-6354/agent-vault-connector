# 下一代生命周期适配器（待独立终审）

本实现与已封盘的共享生产 MCP/旧 ZIP 分开发布，不会自动修改宿主配置或重启用户应用。

## 调用链与启动

Agent/宿主先启动 `python integrations/embedded/lifecycle_http.py`（默认仅监听 127.0.0.1:3210）；探测和启动不创建数据库。控制器将管理 discovery 写入受保护的 `~/.hermes/vault-lifecycle.json`。随后通过 `python integrations/embedded/lifecycle_mcp.py` 接入支持 MCP Apps 的宿主。依赖 Python 和 cryptography；浏览器验收另需 Node、已安装的 playwright-core 与 Edge。这些依赖不会自动下载。

此处是接入说明，不要求用户手动执行命令；安装/启动由 Agent 在用户授权范围内完成。实际宿主挂载与切包需主控另行安排。

MCP 工具不接受密码/Token 参数：

- `vault_guide`：start、switch_account、switch_server；target=local/cloud；已知账号/名称预填，未知留白。无库先返回询问创建，明确 consent=true 后才发 create 卡片；已有库走 login。
- `vault_credential`：已登录后申请指定服务的安全录入卡。
- `vault_lifecycle_frame`：仅 app 可见，返回能力限定的 iframe URL。
- `vault_lifecycle_result`：只读 pending/ready/valid/rejected/待验证等状态及安全引用，不返回会话 Token 或 secret。

create/login/credential 都复用白色半透明内嵌卡，无右上角切换下拉菜单。卡片完成通知不包含秘密；宿主按帧来源与不透明源校验并销毁卡片。自然语言由调用 Agent 映射为明确 intent；没有新增自由文本密码入口。

## 本地密文与持久会话

创建后复用 credentials/meta 表，增加 lifecycle_sessions 和 lifecycle_validation。PBKDF2-SHA256 派生主密钥，凭据由 AES-256-GCM 加密；nonce 12 字节，tag 为真实 encrypt 输出最后16字节。不会生成或保存明文主密码兜底。旧库不能静默覆盖；不带新认证元数据的历史库明确要求迁移，迁移工具不在本次发布范围。

vault_client.json 在 Windows 使用当前用户 DPAPI 保护，POSIX 使用0600文件权限。数据库只保存域分离的会话 lookup 哈希和受 token 派生密钥包装的主密钥；lookup 哈希不是包装密钥。可跨实例恢复与撤销。持久会话不抵御同用户高权限工具或已控制宿主的调试器。

凭据先加密落库为 pending_validation，然后发送固定目的地只读认证探针：GitHub `/user`、DeepSeek `/models`。401 确认拒绝时，仅删除本次候选；已有有效记录保持。403/429/5xx/网络失败保持待验证，不报密码错误。未知服务可加密存储但返回 validation_unsupported，不伪造有效结论。尚未实现未知服务的自动验证器。

secure_delete 配合原子 DELETE 清理本次候选；不宣传备份、操作系统快照或历史 WAL 的取证级擦除。相同卡片的重复提交幂等；换库/重新登录后旧卡被 generation 拒绝。服务返回错误采用固定脱敏代码，不透传上游错误正文。

## 云端协议与运维边界

`lifecycle_remote.py` 是配套 TLS 协议服务，只绑定 loopback，需由已授权运维配置 TLS/tunnel；本次不开放防火墙、不部署任何公网服务。公开探测只返回库存在性；已有库登录使用账号和主密码。首次建库额外要求运维 bootstrap token，不允许互联网上任意调用者抢先创建。

云端 bootstrap 保存在本机受保护的 `vault_targets.json`（origin→token）；需由安全的本机/运维通道配置，不能写入模型工具参数或聊天。未配置时明确报 cloud_create_requires_provisioning。服务端 bootstrap 配置通过 `--bootstrap-file` 提供，服务 CLI 要求 TLS cert/key 路径，绝不接收命令行明文密钥。

RemoteClient 只接受 HTTPS origin、正常证书验证、禁止重定向，Token 不跟随跳转。登录成功返回的 Token 只在原生 HTTP 客户端内部落入受保护 session，不进入 MCP 输出。云端结果只投影已知状态与固定文案，忽略上游消息中可能回显的内容。

本次云端集成使用本机生成且显式信任的测试证书、真实 TLS 请求及另一份真实 SQLite，不等同真实服务器部署验收。现有远端 Vault 若不支持新 /lifecycle/* 协议，需要配套部署/兼容层，不能直接宣称接通。

## 验收与剩余事项

`tests/test_lifecycle.py`：真实SQLite、Windows DPAPI、HTTP/MCP子进程、探测/授权/清理/切换。
`tests/test_lifecycle_remote.py`：真实TLS与独立数据库、建库授权、重启恢复、本地到云端登录失败保留旧会话。
`tests/test_lifecycle_browser.py`：22个受控卡片反馈场景及5条真实浏览器→控制器→SQLite流程；其中第三方认证服务器是明确的受控HTTP替身。

公网仅使用合成无效凭据实测了 GitHub/DeepSeek 拒绝路径。尚无有效真实凭据成功路径验收；不会向用户索要聊天明文补测。旧 TS registry 套件未在缺少依赖的本机实跑，本次不将其算为通过。真实产品宿主安装/升级、真实云端部署、旧库迁移和独立安全终签仍需单独闭环。

单元测试通过不等于已发布。最终测试数字、源码原始字节SHA、包内MANIFEST及未跑范围以新任务 evidence.json 为准。
