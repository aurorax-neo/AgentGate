# Changelog

本项目所有重要变更均记录于此文件。
格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [0.1.6] - 2026-11-12

### 🐛 Bug Fixes
- 修复连接 MikroTik RouterOS (`ROSSSH`) 等通告 `cipher = none` 的设备时返回 `MethodSet([])` 拒绝认证的问题：彻底移除上游 `Preferred` 中的 `russh::cipher::NONE` 与 `CLEAR`，按现代 AEAD/CTR 优先、传统 CBC 兜底顺序排列算法，并补齐 `ext-info-c` 与 `kex-strict-c-v00@openssh.com` 扩展协商

## [0.1.5] - 2026-11-12

### 🚀 Features
- 重绘密码显隐矢量小眼睛图标：采用标准 Lucide `24x24` 饱满杏仁眼比例（眼宽 `20`、眼高 `14.4`、空心圆瞳孔半径 `3.3`），闭眼态自动按斜线走廊裁切分段缺口并绘制左上至右下贯穿斜杠

### 🐛 Bug Fixes
- 修复交互式 SSH 终端连接后卡死的问题：在 `pty_request`、`env_request`、`shell_request`、`exec_request`、`subsystem_request`、`window_change_request` 中向远端转发后立即同步调用 `session.channel_success(channel)`，并将通道写半部升级为无跨 `.await` 锁持有的 `Arc<ChannelWriteHalf>`，解决客户端连续发送 `pty-req + env + shell` 时 `CHANNEL_SUCCESS` 被覆盖丢失的问题
- 修复 macOS 与 Windows 端窗口最大化与还原问题：macOS 端为绿色缩放按钮挂载 `NSClickGestureRecognizer` 绕过 `Accessory` 模式下失效的私有 handoff 追踪；Windows 端改用主线程隐藏 Owner 窗口移除任务栏图标并全量使用 `ShowWindowAsync` 异步投递，避免在 `on_input` 持有 GPUI `Window` 借用期间同步重入 `WM_SIZE` 导致布局不刷新或最大化遮挡任务栏
- 修复菜单栏右键「显示 / 隐藏工作台」失效及窗口过度置顶问题：右键菜单按 `is_window_currently_shown()` 确定性切换显隐，拉起时脉冲置顶并在同一事件帧末尾立即恢复 `NSNormalWindowLevel (0)`，确保其他窗口获得焦点时正常覆盖在本程序上方

## [0.1.4] - 2026-11-11

### 🐛 Bug Fixes
- 修复 Windows 端出现内外两套窗口控制按钮的问题：开启 `TitlebarOptions::appears_transparent` 隐藏 Windows 外层原生标题栏，仅保留内部工作台顶栏控制按钮，并为顶栏空白区域绑定 `WindowControlArea::Drag` 原生拖拽与双击最大化/还原
- 修复 Windows 端内部顶栏关闭（`×`）、最小化（`—`）、最大化/还原（`□`）及系统托盘「显示 / 隐藏工作台」点击无效的问题：按 `Zed::Window` 类名 + `AgentGate` 标题 + 当前进程 PID 精确查找主窗口（彻底排除系统 `Default IME` 隐藏窗口干扰），并使用 `IsZoomed` 支持最大化与还原双向切换
- 修复 macOS 与 Windows 端菜单栏 / 托盘「显示 / 隐藏工作台」在多显示器或窗口被同屏其他应用遮挡时切换失效的问题：基于 `CGWindowListCopyWindowInfo` 计算同屏上层窗口实际遮挡面积，并在模态右键菜单关闭前后同步执行窗口显隐与激活
- 增强上游 `root` 账号密码被拒时的诊断提示，明确提示排查远端 `/etc/ssh/sshd_config` 的 `PermitRootLogin yes` 配置

## [0.1.3] - 2026-11-11

### 🚀 Features
- 全界面按钮名称精简（`+ 新建`、`全停`、`启动`/`停止`、`编辑`、`删除`、`密码`/`密钥`、`复制`、`轮换`/`重置`、`复制卡片`、`复制命令`、`当前`/`全部`）
- 为主工作台「本地隔离凭证」与新建/编辑弹窗内的密码项新增纯几何小眼睛显隐切换图标按钮及一键「复制」按钮
- 将底部面板精简更名为「日志」，完整输出故障阶段（TCP直连/代理握手/SSH协商/身份认证）、毫秒耗时与远端允许认证方式，并支持单条日志一键复制与顶部「复制全部」
- 为上游 SSH 客户端开启全量 KEX、HostKey（含 `Ed25519`、`ECDSA P256/P384/P521`、`RSA SHA512/SHA256/SHA1`）、Cipher 与 MAC 算法兼容，并在 `password` 认证未通过时自动回退尝试 PAM `keyboard-interactive` 交互式认证

### 🐛 Bug Fixes
- 修复 Windows 与 Linux 平台缺失最小化、最大化、关闭窗口控制按钮的问题：全平台统一采用 `WindowKind::Normal`，Windows 端补齐 `WS_OVERLAPPEDWINDOW` 样式并通过隐藏托盘宿主窗口 `GWLP_HWNDPARENT` 隐藏任务栏图标（同时在非 macOS 顶栏右侧提供最小化/最大化/关闭图标按钮）
- 修复 macOS `Accessory` 模式下绿色最大化按钮点击无响应的问题（配置 `NSWindowCollectionBehaviorFullScreenNone` 并绑定 `zoom:`）
- 修复 macOS 多显示器下右键点击菜单栏图标时菜单跳回主窗口所在屏幕的问题（改为按鼠标全局坐标 `[NSEvent mouseLocation]` 在当前屏幕弹出），并修复右键菜单「显示 / 隐藏工作台」因菜单自身焦点导致无法隐藏窗口的问题
- 修复单行输入框粘贴文本时可能带入隐藏换行符（`\r` / `\n`）导致上游密码认证失败的问题

## [0.1.2] - 2026-11-11

### 🚀 Features
- 重构主工作台界面为左侧紧凑代号导航栏 + 右侧连续三段式详情工作台（主机状态顶栏、本地隔离凭证与 AI Agent 配置双栏并排、底部常驻实时审计流），新建与编辑主机改为独立居中模态弹窗
- 新增本机监听地址（`local_bind_host`）、固定本机端口（`local_port`）与固定 Agent 连接密码（`agent_password`）持久化及弹窗内自定义编辑能力；新建后除手动修改或点击轮换外，端口与密码始终保持固定不变
- 为 macOS 菜单栏图标与 Windows 系统托盘图标新增右键上下文菜单（支持「显示 / 隐藏工作台」与「退出 AgentGate」安全退出）
- 顶部工具栏移除「收起到菜单栏」文字按钮，并将深浅色主题切换升级为纯几何太阳/弯月图标按钮

### 🐛 Bug Fixes
- 修复 macOS 下点击菜单栏图标有概率无法拉起窗口的问题：基于 `CGWindowListCopyWindowInfo` 实时窗口 Z 序检测遮挡状态、过滤 GPUI 内部 `500x500` 空窗口、在点击事件主线程同步执行 `orderFrontRegardless` 拉起置顶，并支持跨显示器与跨桌面空间（Spaces）自动跟随

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
