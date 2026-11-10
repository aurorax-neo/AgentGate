# Changelog

本项目所有重要变更均记录于此文件。
格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [0.1.0] - 2026-11-10

### 🚀 Features
- 基于 Rust + GPUI + russh 实现本地 SSH 安全隔离中转工作台，对外仅暴露机器代号、`127.0.0.1:<随机未占用端口>` 与临时密码或专用 Ed25519 密钥
- 支持真实主机地址、端口、账号与密钥经 `AES-256-GCM` (`vault.enc` + `0600` 权限) 本机加密持久化，永不进入 AI Agent 配置或剪贴板
- 支持上游直连、SOCKS5 代理与 HTTP CONNECT 隧道代理转发，完整透传 `exec`、`shell`、`pty`、`env`、`sftp` 通道
- 支持 macOS / Windows / Linux 三端菜单栏或系统托盘常驻运行，隐藏 Dock 与任务栏图标，全操作强制内置模态框二次确认

### 🧰 Maintenance
- 接入符合工程规范的多架构二进制构建与 GitHub Release 自动化发布流水线（SemVer Tag、Cargo.toml 版本与 CHANGELOG 强一致校验）
