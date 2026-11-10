# AgentGate

基于 **Rust + GPUI + russh** 构建的跨平台菜单栏 SSH 安全隔离中转工作台（支持 **macOS / Windows / Linux**）。

AgentGate 专为与 AI Agent（如 Codex、Claude Code、Cursor 等）协同运维远端服务器设计：**对外仅向 AI Agent 暴露机器唯一代号（`codename`）、本地回环地址 `127.0.0.1:<随机未占用端口>` 以及临时密码或本机专用 Ed25519 密钥**；真实远端 IP、端口、登录用户名、真实密码/私钥与代理凭据全部加密保存在本机，永不进入 Agent 配置文件、终端命令行或对话上下文。

---

## 架构与隔离原理

```text
+-------------------+        SSH (仅限本机回环)         +-----------------------------------+
|     AI Agent      | ------------------------------> |             AgentGate             |
| (仅知晓代号与本地端口) |   Host: 127.0.0.1:<随机端口>      |  - 校验唯一代号 (codename)         |
|                   |   User: <codename>              |  - 恒定时间校验临时密码 / 专用公钥   |
|                   |   Auth: 24位临时密码 / 专用密钥    |  - 双向桥接 exec/shell/pty/sftp   |
+-------------------+                                 +-----------------+-----------------+
                                                                        |
                                                                        | 直连 / SOCKS5 / HTTP CONNECT
                                                                        | + TOFU 主机公钥指纹强校验
                                                                        v
                                                      +-----------------------------------+
                                                      |         真实远端 SSH 服务器         |
                                                      |  Real IP / Port / User / Secret   |
                                                      |  (AES-256-GCM 加密存储于本机仓库)   |
                                                      +-----------------------------------+
```

---

## 核心安全特性

1. **零真实凭据暴露**：
   - 每次开启单条主机中转时，自动绑定 `127.0.0.1:0` 分配未占用的随机本地端口，杜绝局域网或公网扫描访问。
   - 强制校验本地登录用户名必须等于该机器的唯一 `codename`，且禁止 `codename` 与真实远端用户名相同。
   - 生成发给 Agent 的提示词卡片或 SSH 命令时，仅包含 `codename`、`127.0.0.1`、本地随机端口及临时密码/专用密钥路径。
2. **本机 `AES-256-GCM` 加密仓库与内存擦除**：
   - 真实主机配置通过 256-bit 主密钥（`master.key`）与每次写入随机生成的 96-bit Nonce 加密持久化至 `vault.enc`。
   - 主密钥、加解密明文缓冲区及轮换/停止后的临时密码均通过 `write_volatile` + 编译器屏障在内存中立即覆写清零。
   - 类 Unix 系统强制设置目录 `0700`、密钥文件 `0600` 权限；Windows 系统通过 `icacls` 仅授予当前用户与系统管理员访问权限。
3. **上游主机密钥 TOFU 绑定与防中间人攻击**：
   - 首次连接远端真实 SSH 主机时自动记录并加密持久化其公钥指纹（Trust On First Use）。
   - 后续每次连接均采用恒定时间比对校验远端主机公钥；一旦指纹异常立即阻断连接并写入安全审计日志。
4. **独立出站代理与全阶段超时保护**：
   - 每条主机可独立配置 **直连**、**SOCKS5 代理**（支持用户名/密码认证）或 **HTTP CONNECT 隧道代理**（支持 Basic 认证）。
   - 代理握手与上游 SSH 协议握手全程受超时保护，且任何上游报错均自动脱敏真实主机 IP、真实账号、密码与代理凭据。
5. **全操作内置模态二次确认**：
   - 启动中转、停止中转、全部停止、新建/保存主机、删除主机、轮换临时密码/重置专用密钥、切换认证模式、复制 Agent 配置，所有操作均需经过 GPUI 内置二次确认弹窗确认（支持 `Enter` 确认 / `Esc` 取消）。
6. **三端菜单栏常驻（无 Dock / 任务栏图标）**：
   - macOS 采用 `LSUIElement` / `NSApplicationActivationPolicyAccessory` 驻留系统右上角菜单栏；
   - Windows 采用 `Shell_NotifyIconW` 驻留系统托盘并隐藏任务栏按钮；
   - Linux 采用 `StatusNotifierItem` (`ksni`) 驻留系统状态栏。

---

## 安装包说明

可在 [GitHub Releases](https://github.com/aurorax-neo/AgentGate/releases) 页面获取对应平台的原生安装包：

| 平台 | 架构 | 发布包格式 | 说明 |
| :--- | :--- | :--- | :--- |
| **macOS** | Apple Silicon (`aarch64`) / Intel (`x86_64`) | `.dmg` | 内含签名的 `AgentGate.app`，拖拽至 `Applications` 即可运行 |
| **Windows** | `x86_64-pc-windows-msvc` | `-setup.exe` / `.zip` | NSIS 图形安装程序（自动创建开始菜单与桌面快捷方式）及免安装便携包 |
| **Linux** | `x86_64` / `aarch64` | `.deb` / `.tar.gz` | 标准 Debian/Ubuntu 软件包（含 `.desktop` 与多尺寸图标）及归档包 |

---

## 快速使用流程

1. **新建受保护机器**：
   打开 AgentGate 工作台，点击右上角 **「+ 新建主机」**，设定唯一代号（如 `cobalt-nexus-01`），填入真实远端 IP、端口、用户名、密码或 OpenSSH 私钥，按需配置 SOCKS5 / HTTP CONNECT 代理，选择对 Agent 暴露的认证方式（**临时随机密码** 或 **专用本地密钥 Ed25519**），点击保存并在模态框中二次确认。
2. **开启本地随机端口中转**：
   在左侧机器列表中点击目标代号的 **「开启中转」** 并二次确认，AgentGate 将在 `127.0.0.1` 分配未占用端口并启动本地 SSH 服务。
3. **一键复制配置发给 Agent**：
   点击 **「复制发给 Agent」** 并二次确认，直接粘贴至 AI Agent 对话框。

### 复制给 AI Agent 的配置卡片示例

- **临时密码模式**：
  ```text
  [SSH 目标代号: cobalt-nexus-01]
  Host: 127.0.0.1
  Port: 54918
  User: cobalt-nexus-01
  AuthMode: EphemeralPassword (24-char)
  Password: <24位高熵随机临时密码>
  Command: ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 54918 cobalt-nexus-01@127.0.0.1
  ```

- **专用本地密钥模式（支持免交互 `BatchMode=yes`）**：
  ```text
  [SSH 目标代号: jade-sentry-02]
  Host: 127.0.0.1
  Port: 55102
  User: jade-sentry-02
  AuthMode: DedicatedKey (Ed25519)
  IdentityFile: "/Users/<you>/Library/Application Support/AgentGate/agent_keys/jade-sentry-02_id_ed25519"
  Command: ssh -i "/Users/<you>/Library/Application Support/AgentGate/agent_keys/jade-sentry-02_id_ed25519" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 55102 jade-sentry-02@127.0.0.1
  ```

---

## 本机加密存储目录结构

| 平台 | 默认应用数据目录 |
| :--- | :--- |
| **macOS** | `~/Library/Application Support/AgentGate/` |
| **Windows** | `%APPDATA%\AgentGate\` |
| **Linux** | `~/.local/share/AgentGate/` |

目录内文件说明：
- `master.key`：本机随机生成的 256-bit 主密钥（权限 `0600`）。
- `vault.enc`：`AES-256-GCM` 认证加密的主机与代理配置密文仓库（权限 `0600`）。
- `agent_keys/<codename>_id_ed25519`：专为对应代号生成的本地 Ed25519 私钥（权限 `0600`）。
- `ui_state.json`：界面深浅色主题与面板视图偏好状态。

---

## 本地开发与测试

```bash
# 运行全量单元测试与本地 SSH 回环/代理端到端测试
cargo test

# 编译并启动桌面端工作台
cargo run --release
```

## 许可证

[MIT License](LICENSE)
