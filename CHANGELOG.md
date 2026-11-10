# Changelog

本项目所有重要变更均记录于此文件。
格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [0.1.1] - 2026-11-11

### 🛡️ Security
- 新增上游真实 SSH 主机公钥 TOFU（首次连接绑定）与恒定时间指纹校验，公钥变更时自动阻断连接并记录安全审计日志，防范中间人攻击
- 强化代号与真实身份隔离：仅允许唯一 `codename` 登录本地中转端口，禁止使用保留名 `agent` 或与真实远端用户名同名
- 扩展错误与断开消息脱敏：全量过滤真实主机地址、真实用户名、真实密码、私钥口令及代理服务器地址与账号密码，向 Agent 返回固定断开提示
- 新增主密钥、加解密缓冲区与轮换后临时密码的内存安全擦除（`write_volatile` + 编译器屏障），并加固 Windows `icacls` 权限设置的参数校验与生产环境演示种子隔离

### 🐛 Bug Fixes
- 修复编辑运行中主机配置时新代号/新地址/新代理未实时同步至监听实例的问题，并在修改代号时自动清理旧代号遗留私钥文件
- 修复快速重启单条中转时旧监听协程异步退出事件覆盖新实例运行状态的竞争问题
- 为 SOCKS5 / HTTP CONNECT 代理握手与上游 SSH 协议握手补充全阶段整体超时控制，并在远端通道关闭时主动清理本地通道写句柄
- 修复掩码密码输入框在包含多字节 UTF-8 字符时鼠标定位与切片边界未对齐的问题，修正 IME 预编辑选区偏移计算
- 修复 Windows 系统托盘通过 `GetForegroundWindow` 可能误绑定其它窗口的问题（改为按当前进程 PID 精确枚举主窗口），并补齐 Linux 状态栏窗口显隐控制

### 📝 Documentation
- 全面重构 `README.md`，补充隔离架构图、核心安全机制、三端安装包说明、快速使用流程、Agent 配置卡片示例与加密存储目录文档

### 🧰 Maintenance
- 将 GitHub Actions 发布流水线中的第三方 Action 全部固定至完整 Commit SHA，并使用单调递增序号保证跨午夜与同秒审计日志严格按发生顺序排列

## [0.1.0] - 2026-11-10

### 🚀 Features
- 基于 Rust + GPUI + russh 实现本地 SSH 安全隔离中转工作台，对外仅暴露机器代号、`127.0.0.1:<随机未占用端口>` 与临时密码或专用 Ed25519 密钥
- 支持真实主机地址、端口、账号与密钥经 `AES-256-GCM` (`vault.enc` + `0600` 权限) 本机加密持久化，永不进入 AI Agent 配置或剪贴板
- 支持上游直连、SOCKS5 代理与 HTTP CONNECT 隧道代理转发，完整透传 `exec`、`shell`、`pty`、`env`、`sftp` 通道
- 支持 macOS / Windows / Linux 三端菜单栏或系统托盘常驻运行，隐藏 Dock 与任务栏图标，全操作强制内置模态框二次确认

### 🧰 Maintenance
- 接入符合工程规范的多架构桌面安装包构建与 GitHub Release 自动化发布流水线（产出 macOS `.dmg` / `AgentGate.app`、Windows `-setup.exe` / `.zip`、Linux `.deb` / `.tar.gz`，含 SemVer Tag、Cargo.toml 版本与 CHANGELOG 强一致校验）
