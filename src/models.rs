use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Local;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

static NEXT_AUDIT_LOG_SEQ: AtomicU64 = AtomicU64::new(1);

/// 远端真实机器认证方式（仅加密保存在本机，永不暴露给 Agent）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RealAuthConfig {
    Password {
        password: String,
    },
    PrivateKey {
        private_key_pem: String,
        passphrase: Option<String>,
    },
}

impl RealAuthConfig {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Password { .. } => "真实密码认证",
            Self::PrivateKey { .. } => "真实私钥认证",
        }
    }
}

/// 出站代理配置（用于连接真实远端 SSH）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ProxyConfig {
    #[default]
    None,
    Socks5 {
        host: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    },
    HttpConnect {
        host: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    },
}

impl ProxyConfig {
    pub fn badge_text(&self) -> String {
        match self {
            Self::None => "直连".to_string(),
            Self::Socks5 { host, port, .. } => format!("SOCKS5 {}:{}", host, port),
            Self::HttpConnect { host, port, .. } => format!("HTTP {}:{}", host, port),
        }
    }

    pub fn mode_label(&self) -> &'static str {
        match self {
            Self::None => "直连 (无代理)",
            Self::Socks5 { .. } => "SOCKS5 代理",
            Self::HttpConnect { .. } => "HTTP CONNECT 代理",
        }
    }
}

/// 暴露给本地 AI Agent 的认证方式
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AgentAuthMode {
    /// 每次启动或轮换时生成高熵临时密码
    #[default]
    EphemeralPassword,
    /// 使用本机专为此代号生成的独立 Ed25519 密钥对
    DedicatedKey,
}

impl AgentAuthMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::EphemeralPassword => "临时随机密码",
            Self::DedicatedKey => "专用本地密钥 (Ed25519)",
        }
    }
}

/// 单条 SSH 中转主机配置（持久化在加密仓库 vault.enc 中）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayHost {
    pub id: Uuid,
    /// 机器唯一代号（供 AI Agent 与人类共同识别，同时作为本地 SSH 登录用户名）
    pub codename: String,
    /// 本机可见备注（不进入 Agent 提示词）
    pub label: String,
    /// 本机 SSH 中转监听地址（默认 127.0.0.1，可在新建/编辑弹窗中自定义）
    #[serde(default = "RelayHost::default_local_bind_host")]
    pub local_bind_host: String,
    /// 本机 SSH 中转监听固定端口（新建时自动分配未占用端口并持久化，除手动修改外保持不变）
    #[serde(default)]
    pub local_port: u16,
    /// 暴露给 Agent 的本地固定密码（新建时生成并持久化，除手动修改或点击轮换外保持不变）
    #[serde(default = "RelayHost::generate_ephemeral_password")]
    pub agent_password: String,
    /// 真实远端主机地址（IP 或域名，不进 Agent）
    pub real_host: String,
    /// 真实远端 SSH 端口
    pub real_port: u16,
    /// 真实远端登录用户名
    pub real_user: String,
    /// 真实远端认证信息
    pub real_auth: RealAuthConfig,
    /// 代理设置
    pub proxy: ProxyConfig,
    /// 对 Agent 暴露的本地认证方式
    pub agent_auth_mode: AgentAuthMode,
    /// 本机为此条目生成的专用 Ed25519 私钥（OpenSSH PEM 格式）
    pub dedicated_key_openssh_pem: Option<String>,
    /// 远端真实 SSH 主机公钥（OpenSSH 格式，首次连接 TOFU 绑定或手动固定，防中间人攻击）
    #[serde(default)]
    pub pinned_host_key_openssh: Option<String>,
    /// 创建时间与更新时间
    pub created_at: String,
    pub updated_at: String,
}

impl RelayHost {
    pub fn default_local_bind_host() -> String {
        "127.0.0.1".to_string()
    }

    /// 探测并返回一个本机当前未占用的随机端口
    pub fn allocate_free_local_port(bind_host: &str) -> u16 {
        let host = if bind_host.trim().is_empty() {
            "127.0.0.1"
        } else {
            bind_host.trim()
        };
        if let Ok(listener) = std::net::TcpListener::bind((host, 0))
            && let Ok(addr) = listener.local_addr()
        {
            return addr.port();
        }
        let mut rng = rand::rng();
        rng.random_range(20000..60000)
    }

    pub fn new_template(existing_count: usize) -> Self {
        let now = Self::now_str();
        let local_bind_host = Self::default_local_bind_host();
        let local_port = Self::allocate_free_local_port(&local_bind_host);
        Self {
            id: Uuid::new_v4(),
            codename: Self::generate_codename(existing_count),
            label: String::new(),
            local_bind_host,
            local_port,
            agent_password: Self::generate_ephemeral_password(),
            real_host: "127.0.0.1".to_string(),
            real_port: 22,
            real_user: "root".to_string(),
            real_auth: RealAuthConfig::Password {
                password: String::new(),
            },
            proxy: ProxyConfig::None,
            agent_auth_mode: AgentAuthMode::EphemeralPassword,
            dedicated_key_openssh_pem: None,
            pinned_host_key_openssh: None,
            created_at: now.clone(),
            updated_at: now,
        }
    }

    /// 对真实主机地址进行脱敏显示，防止界面截屏或旁观泄露
    pub fn masked_real_endpoint(&self) -> String {
        let host = self.real_host.trim();
        let parts: Vec<&str> = host.split('.').collect();
        let masked_host = if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
            format!("***.***.{}.{}", parts[2], parts[3])
        } else if parts.len() >= 2 {
            let tail = parts[parts.len() - 2..].join(".");
            format!("***.{}", tail)
        } else if host.len() > 4 {
            format!("***{}", &host[host.len() - 3..])
        } else {
            "***".to_string()
        };
        format!("{}@{}:{}", mask_user(&self.real_user), masked_host, self.real_port)
    }

    /// 生成易读且便于 AI 区分的默认代号
    pub fn generate_codename(existing_count: usize) -> String {
        const ADJECTIVES: &[&str] = &[
            "amber", "cobalt", "crimson", "emerald", "frost", "granite", "jade", "lunar",
            "nova", "onyx", "quartz", "silver", "solar", "titan", "velvet", "zenith",
        ];
        const NOUNS: &[&str] = &[
            "anchor", "beacon", "canyon", "citadel", "forge", "harbor", "matrix", "nexus",
            "orbit", "prism", "relay", "sentry", "summit", "tower", "vault", "vertex",
        ];
        let mut rng = rand::rng();
        let adj = ADJECTIVES[rng.random_range(0..ADJECTIVES.len())];
        let noun = NOUNS[rng.random_range(0..NOUNS.len())];
        let suffix = (existing_count + 1) % 100;
        format!("{}-{}-{:02}", adj, noun, suffix)
    }

    /// 生成 24 位高熵临时密码（仅包含无歧义字母与数字，避免 shell 转义问题）
    pub fn generate_ephemeral_password() -> String {
        const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        let mut rng = rand::rng();
        let mut out = String::with_capacity(24);
        for i in 0..24 {
            if i > 0 && i % 6 == 0 {
                out.push('-');
            }
            let idx = rng.random_range(0..CHARSET.len());
            out.push(CHARSET[idx] as char);
        }
        out
    }

    pub fn now_str() -> String {
        Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
    }
}

fn mask_user(user: &str) -> String {
    let trimmed = user.trim();
    if trimmed.is_empty() {
        "***".to_string()
    } else if trimmed.len() <= 2 {
        format!("{}*", &trimmed[..1])
    } else {
        format!("{}***", &trimmed[..2])
    }
}

/// 单条中转服务的运行状态
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RelayStatus {
    #[default]
    Stopped,
    Starting,
    Running {
        local_port: u16,
        active_sessions: usize,
    },
    Error(String),
}

impl RelayStatus {
    pub fn is_running(&self) -> bool {
        matches!(self, Self::Running { .. })
    }

    pub fn local_port(&self) -> Option<u16> {
        match self {
            Self::Running { local_port, .. } => Some(*local_port),
            _ => None,
        }
    }

    pub fn active_sessions(&self) -> usize {
        match self {
            Self::Running {
                active_sessions, ..
            } => *active_sessions,
            _ => 0,
        }
    }
}

/// 审计与连接日志条目（严格脱敏，不包含真实远端 IP 或真实密码）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayAuditLog {
    #[serde(default)]
    pub seq: u64,
    pub timestamp: String,
    pub codename: String,
    pub event: String,
    pub detail: String,
    pub is_error: bool,
}

/// 单条中转主机在内存中的实时运行态
#[derive(Debug, Clone, Default)]
pub struct RelayRuntimeState {
    pub status: RelayStatus,
    pub current_temp_password: Option<String>,
    pub dedicated_key_path: Option<String>,
    pub dedicated_pubkey_openssh: Option<String>,
    pub total_connections: u64,
    pub logs: Vec<RelayAuditLog>,
}

impl RelayRuntimeState {
    pub fn rotate_or_clear_temp_password(&mut self, next: Option<String>) {
        if let Some(mut old) = self.current_temp_password.take() {
            // 覆写旧临时密码内存字节后再释放
            unsafe {
                old.as_bytes_mut().fill(0);
            }
            std::sync::atomic::compiler_fence(Ordering::SeqCst);
        }
        self.current_temp_password = next;
    }

    pub fn push_log(&mut self, codename: &str, event: impl Into<String>, detail: impl Into<String>, is_error: bool) {
        let entry = RelayAuditLog {
            seq: NEXT_AUDIT_LOG_SEQ.fetch_add(1, Ordering::Relaxed),
            timestamp: Local::now().format("%H:%M:%S").to_string(),
            codename: codename.to_string(),
            event: event.into(),
            detail: detail.into(),
            is_error,
        };
        self.logs.insert(0, entry);
        if self.logs.len() > 80 {
            self.logs.truncate(80);
        }
    }
}

/// 复制给 Agent 的配置格式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyFormat {
    /// 完整 Agent 提示词卡片（含代号、127.0.0.1、端口、账号、临时密码/专用密钥路径、SSH 命令）
    AgentPromptCard,
    /// 纯 SSH 命令行
    SshCommandOnly,
}

impl CopyFormat {
    pub fn label(&self) -> &'static str {
        match self {
            Self::AgentPromptCard => "复制 Agent 提示词配置",
            Self::SshCommandOnly => "复制纯 SSH 命令",
        }
    }
}

/// 全局所有操作二次确认动作定义
#[derive(Debug, Clone)]
pub enum PendingAction {
    StartRelay {
        id: Uuid,
        codename: String,
    },
    StopRelay {
        id: Uuid,
        codename: String,
        local_port: u16,
    },
    StopAllRelays {
        running_count: usize,
    },
    SaveHost {
        host: Box<RelayHost>,
        is_new: bool,
    },
    DeleteHost {
        id: Uuid,
        codename: String,
    },
    RotateCredentials {
        id: Uuid,
        codename: String,
        mode: AgentAuthMode,
    },
    ToggleAgentAuthMode {
        id: Uuid,
        codename: String,
        target_mode: AgentAuthMode,
    },
    CopyAgentConfig {
        id: Uuid,
        codename: String,
        format: CopyFormat,
    },
}

impl PendingAction {
    pub fn title(&self) -> &'static str {
        match self {
            Self::StartRelay { .. } => "确认开启本地 SSH 中转服务",
            Self::StopRelay { .. } => "确认停止本地 SSH 中转服务",
            Self::StopAllRelays { .. } => "确认停止全部运行中的中转服务",
            Self::SaveHost { is_new: true, .. } => "确认新建 SSH 中转主机",
            Self::SaveHost { is_new: false, .. } => "确认保存主机与代理配置修改",
            Self::DeleteHost { .. } => "确认删除 SSH 中转主机",
            Self::RotateCredentials { .. } => "确认轮换本地 Agent 专用凭证",
            Self::ToggleAgentAuthMode { .. } => "确认切换 Agent 认证方式",
            Self::CopyAgentConfig { .. } => "确认复制本地中转配置发给 Agent",
        }
    }

    pub fn codename(&self) -> String {
        match self {
            Self::StartRelay { codename, .. }
            | Self::StopRelay { codename, .. }
            | Self::DeleteHost { codename, .. }
            | Self::RotateCredentials { codename, .. }
            | Self::ToggleAgentAuthMode { codename, .. }
            | Self::CopyAgentConfig { codename, .. } => codename.clone(),
            Self::SaveHost { host, .. } => host.codename.clone(),
            Self::StopAllRelays { running_count } => format!("全部运行节点 ({} 条)", running_count),
        }
    }

    pub fn description(&self) -> String {
        match self {
            Self::StartRelay { codename, .. } => format!(
                "将按代号 [{}] 已保存的本机监听地址与固定端口启动 SSH 中转服务。真实主机地址与真实密码不会暴露。",
                codename
            ),
            Self::StopRelay {
                codename,
                local_port,
                ..
            } => format!(
                "将立即关闭代号 [{}] 在端口 {} 上的本地监听并断开当前活跃会话（已保存的本机端口与密码保持不变）。",
                codename, local_port
            ),
            Self::StopAllRelays { running_count } => format!(
                "将立即关闭当前全部 {} 条正在运行的本地 SSH 中转监听（各主机已保存的端口与密码保持不变）。",
                running_count
            ),
            Self::SaveHost { host, is_new } => {
                let action_word = if *is_new { "新增" } else { "更新" };
                format!(
                    "将{}代号为 [{}] 的主机配置（本机监听：{}:{}，代理：{}，Agent 认证：{}），并使用 AES-256-GCM 加密写入本机安全仓库。",
                    action_word,
                    host.codename,
                    host.local_bind_host,
                    host.local_port,
                    host.proxy.badge_text(),
                    host.agent_auth_mode.label()
                )
            }
            Self::DeleteHost { codename, .. } => format!(
                "将从本机加密仓库永久删除代号 [{}] 的配置及专用密钥文件；若该条目正在运行将先停止其中转服务。",
                codename
            ),
            Self::RotateCredentials { codename, mode, .. } => match mode {
                AgentAuthMode::EphemeralPassword => format!(
                    "将为代号 [{}] 重新生成 24 位高熵临时密码，旧临时密码将立即失效。",
                    codename
                ),
                AgentAuthMode::DedicatedKey => format!(
                    "将为代号 [{}] 重新生成本机专用 Ed25519 密钥对并覆盖旧密钥文件，旧私钥将立即无法登录。",
                    codename
                ),
            },
            Self::ToggleAgentAuthMode {
                codename,
                target_mode,
                ..
            } => format!(
                "将代号 [{}] 对 Agent 暴露的认证模式切换为「{}」并立即生效。",
                codename,
                target_mode.label()
            ),
            Self::CopyAgentConfig {
                codename, format, ..
            } => format!(
                "将复制代号 [{}] 的「{}」到系统剪贴板。复制内容仅含 127.0.0.1、本地随机端口与本地凭证，绝不包含真实地址与真实密码。",
                codename,
                format.label()
            ),
        }
    }

    pub fn confirm_button_label(&self) -> &'static str {
        match self {
            Self::DeleteHost { .. } | Self::StopRelay { .. } | Self::StopAllRelays { .. } => {
                "确认停止/删除"
            }
            Self::StartRelay { .. } => "确认启动中转",
            Self::CopyAgentConfig { .. } => "确认写入剪贴板",
            _ => "确认执行",
        }
    }

    pub fn is_destructive(&self) -> bool {
        matches!(
            self,
            Self::DeleteHost { .. } | Self::StopRelay { .. } | Self::StopAllRelays { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codename_generation_and_real_endpoint_masking() {
        let c1 = RelayHost::generate_codename(0);
        let c2 = RelayHost::generate_codename(1);
        assert!(c1.ends_with("-01"));
        assert!(c2.ends_with("-02"));

        let mut host = RelayHost::new_template(0);
        host.real_host = "10.96.1.108".to_string();
        host.real_port = 2222;
        host.real_user = "root".to_string();
        let masked = host.masked_real_endpoint();
        assert_eq!(masked, "ro***@***.***.1.108:2222");
        assert!(!masked.contains("10.96"));
        assert!(!masked.contains("root"));

        host.real_host = "ssh.internal.example.com".to_string();
        let masked_domain = host.masked_real_endpoint();
        assert!(!masked_domain.contains("internal"));
        assert!(masked_domain.ends_with(":2222"));
    }

    #[test]
    fn test_ephemeral_password_entropy_and_format() {
        let p1 = RelayHost::generate_ephemeral_password();
        let p2 = RelayHost::generate_ephemeral_password();
        assert_ne!(p1, p2);
        // 24 位字符 + 3 个分隔连字符 = 27 字符
        assert_eq!(p1.len(), 27);
        assert_eq!(p1.chars().filter(|&c| c == '-').count(), 3);
    }

    #[test]
    fn test_all_pending_actions_confirmation_metadata() {
        let id = Uuid::new_v4();
        let host = Box::new(RelayHost::new_template(2));
        let actions = vec![
            PendingAction::StartRelay {
                id,
                codename: "amber-falcon-03".to_string(),
            },
            PendingAction::StopRelay {
                id,
                codename: "amber-falcon-03".to_string(),
                local_port: 51234,
            },
            PendingAction::StopAllRelays { running_count: 3 },
            PendingAction::SaveHost {
                host: host.clone(),
                is_new: true,
            },
            PendingAction::DeleteHost {
                id,
                codename: "amber-falcon-03".to_string(),
            },
            PendingAction::RotateCredentials {
                id,
                codename: "amber-falcon-03".to_string(),
                mode: AgentAuthMode::EphemeralPassword,
            },
            PendingAction::ToggleAgentAuthMode {
                id,
                codename: "amber-falcon-03".to_string(),
                target_mode: AgentAuthMode::DedicatedKey,
            },
            PendingAction::CopyAgentConfig {
                id,
                codename: "amber-falcon-03".to_string(),
                format: CopyFormat::AgentPromptCard,
            },
        ];

        for act in actions {
            assert!(!act.title().is_empty());
            assert!(!act.codename().is_empty());
            assert!(!act.description().is_empty());
            assert!(!act.confirm_button_label().is_empty());
        }
    }
}
