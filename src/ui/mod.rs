pub mod text_input;
pub mod theme;

use std::collections::HashMap;
use std::fs;
use std::time::Duration;

use gpui::{
    App, ClipboardItem, Context, ElementId, Entity, FocusHandle, Focusable, KeyBinding,
    MouseButton, SharedString, Stateful, Window, actions, div, hsla, prelude::*, px, rgb,
};
use russh::keys::ssh_key::PrivateKey;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::models::{
    AgentAuthMode, CopyFormat, PendingAction, ProxyConfig, RealAuthConfig, RelayHost,
    RelayRuntimeState, RelayStatus,
};
use crate::prompt_tpl::render_agent_snippet;
use crate::ssh_relay::{
    LiveCredentials, RelayEvent, RunningRelayControl, global_tokio_runtime, start_host_relay,
};
use crate::storage::EncryptedStorage;
use crate::tray::{TrayCommand, is_window_visible, platform_set_window_visible, poll_tray_command};
use crate::ui::text_input::{TextField, bind_text_input_keys};
use crate::ui::theme::WorkbenchTheme;

actions!(
    agentgate_workbench,
    [
        ConfirmModalAction,
        CancelModalAction,
        NextFieldTab,
        PrevFieldTab,
        HideToTrayAction,
        QuitApp
    ]
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RightPanelTab {
    #[default]
    Overview,
    HostForm,
    AuditLogs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormRealAuthKind {
    Password,
    PrivateKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormProxyKind {
    None,
    Socks5,
    HttpConnect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedUiPrefs {
    pub is_dark: bool,
    pub active_tab: RightPanelTab,
    pub selected_host_id: Option<Uuid>,
}

impl Default for PersistedUiPrefs {
    fn default() -> Self {
        Self {
            is_dark: true,
            active_tab: RightPanelTab::Overview,
            selected_host_id: None,
        }
    }
}

pub fn register_workbench_keys(cx: &mut App) {
    bind_text_input_keys(cx);
    cx.bind_keys([
        KeyBinding::new("enter", ConfirmModalAction, None),
        KeyBinding::new("escape", CancelModalAction, None),
        KeyBinding::new("tab", NextFieldTab, None),
        KeyBinding::new("shift-tab", PrevFieldTab, None),
        KeyBinding::new("cmd-w", HideToTrayAction, None),
        KeyBinding::new("ctrl-w", HideToTrayAction, None),
        KeyBinding::new("cmd-q", QuitApp, None),
        KeyBinding::new("ctrl-q", QuitApp, None),
        KeyBinding::new("alt-f4", QuitApp, None),
    ]);
}

pub struct AgentGateWorkbench {
    focus_handle: FocusHandle,
    storage: EncryptedStorage,
    hosts: Vec<RelayHost>,
    runtimes: HashMap<Uuid, RelayRuntimeState>,
    controls: HashMap<Uuid, RunningRelayControl>,
    event_tx: mpsc::UnboundedSender<RelayEvent>,

    is_dark: bool,
    active_tab: RightPanelTab,
    selected_host_id: Option<Uuid>,
    pending_confirm: Option<PendingAction>,
    status_banner: Option<(String, bool)>,

    // 搜索输入框
    search_input: Entity<TextField>,

    // 主机与代理编辑表单状态
    editing_host_id: Option<Uuid>,
    form_codename: Entity<TextField>,
    form_label: Entity<TextField>,
    form_real_host: Entity<TextField>,
    form_real_port: Entity<TextField>,
    form_real_user: Entity<TextField>,
    form_real_auth_kind: FormRealAuthKind,
    form_real_secret: Entity<TextField>,
    form_real_passphrase: Entity<TextField>,
    form_proxy_kind: FormProxyKind,
    form_proxy_host: Entity<TextField>,
    form_proxy_port: Entity<TextField>,
    form_proxy_user: Entity<TextField>,
    form_proxy_pass: Entity<TextField>,
    form_agent_auth_mode: AgentAuthMode,
}

impl Focusable for AgentGateWorkbench {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl AgentGateWorkbench {
    pub fn new(_window: &mut Window, cx: &mut Context<Self>) -> Self {
        let storage = EncryptedStorage::new_default()
            .expect("初始化 AgentGate 本地加密仓库目录失败");
        let prefs = Self::load_ui_prefs(&storage);
        let mut hosts = storage.load_hosts().unwrap_or_default();
        let mut runtimes = HashMap::new();

        let mut modified_keys = false;
        for host in &mut hosts {
            let had_key = host.dedicated_key_openssh_pem.is_some();
            let (key_path, pubkey) = storage
                .ensure_dedicated_agent_key(host, false)
                .unwrap_or_else(|_| (storage.dedicated_key_path_for(&host.codename), String::new()));
            if !had_key && host.dedicated_key_openssh_pem.is_some() {
                modified_keys = true;
            }
            runtimes.insert(
                host.id,
                RelayRuntimeState {
                    status: RelayStatus::Stopped,
                    current_temp_password: Some(RelayHost::generate_ephemeral_password()),
                    dedicated_key_path: Some(key_path.to_string_lossy().to_string()),
                    dedicated_pubkey_openssh: Some(pubkey),
                    total_connections: 0,
                    logs: Vec::new(),
                },
            );
        }
        if modified_keys {
            let _ = storage.save_hosts(&hosts);
        }

        let selected_host_id = prefs
            .selected_host_id
            .filter(|id| hosts.iter().any(|h| &h.id == id))
            .or_else(|| hosts.first().map(|h| h.id));

        let (event_tx, mut event_rx) = mpsc::unbounded_channel::<RelayEvent>();

        let search_input = cx.new(|cx| TextField::new(cx, "按代号或备注筛选...", false));
        let form_codename = cx.new(|cx| TextField::new(cx, "例如: cobalt-nexus-01", false));
        let form_label = cx.new(|cx| TextField::new(cx, "本机可见备注（不发给 Agent）", false));
        let form_real_host = cx.new(|cx| TextField::new(cx, "真实远端 IP 或域名（仅存本机）", false));
        let form_real_port = cx.new(|cx| TextField::new(cx, "22", false));
        let form_real_user = cx.new(|cx| TextField::new(cx, "root / ubuntu", false));
        let form_real_secret = cx.new(|cx| TextField::new(cx, "真实登录密码或 OpenSSH 私钥 PEM", true));
        let form_real_passphrase = cx.new(|cx| TextField::new(cx, "私钥口令（无口令可留空）", true));
        let form_proxy_host = cx.new(|cx| TextField::new(cx, "127.0.0.1", false));
        let form_proxy_port = cx.new(|cx| TextField::new(cx, "7890", false));
        let form_proxy_user = cx.new(|cx| TextField::new(cx, "代理用户名（可选）", false));
        let form_proxy_pass = cx.new(|cx| TextField::new(cx, "代理密码（可选）", true));

        let mut this = Self {
            focus_handle: cx.focus_handle(),
            storage,
            hosts,
            runtimes,
            controls: HashMap::new(),
            event_tx,
            is_dark: prefs.is_dark,
            active_tab: if selected_host_id.is_none() {
                RightPanelTab::HostForm
            } else {
                prefs.active_tab
            },
            selected_host_id,
            pending_confirm: None,
            status_banner: Some(("就绪".to_string(), false)),
            search_input,
            editing_host_id: None,
            form_codename,
            form_label,
            form_real_host,
            form_real_port,
            form_real_user,
            form_real_auth_kind: FormRealAuthKind::Password,
            form_real_secret,
            form_real_passphrase,
            form_proxy_kind: FormProxyKind::None,
            form_proxy_host,
            form_proxy_port,
            form_proxy_user,
            form_proxy_pass,
            form_agent_auth_mode: AgentAuthMode::EphemeralPassword,
        };

        this.sync_inputs_theme(cx);
        this.reset_form_for_new_host(cx);
        this.apply_optional_demo_seed(cx);

        // 后台事件轮询器：将 Tokio SSH 中转事件同步到 GPUI 界面
        cx.spawn(async move |weak_this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(80))
                    .await;
                let mut tray_cmds = Vec::new();
                while let Some(cmd) = poll_tray_command() {
                    tray_cmds.push(cmd);
                }
                let mut batch = Vec::new();
                while let Ok(ev) = event_rx.try_recv() {
                    batch.push(ev);
                }
                if batch.is_empty() && tray_cmds.is_empty() {
                    continue;
                }
                let Ok( updated ) = weak_this.update(cx, |this, cx| {
                    for cmd in tray_cmds {
                        match cmd {
                            TrayCommand::ToggleWindow => {
                                let next = !is_window_visible();
                                platform_set_window_visible(next);
                            }
                            TrayCommand::ShowWindow => {
                                platform_set_window_visible(true);
                            }
                            TrayCommand::HideWindow => {
                                platform_set_window_visible(false);
                            }
                            TrayCommand::QuitApp => {
                                cx.quit();
                            }
                        }
                    }
                    for ev in batch {
                        this.apply_relay_event(ev);
                    }
                    cx.notify();
                }) else {
                    break;
                };
                let _ = updated;
            }
        })
        .detach();

        this
    }

    fn load_ui_prefs(storage: &EncryptedStorage) -> PersistedUiPrefs {
        let path = storage.base_dir().join("ui_state.json");
        fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save_ui_prefs(&self) {
        let prefs = PersistedUiPrefs {
            is_dark: self.is_dark,
            active_tab: self.active_tab,
            selected_host_id: self.selected_host_id,
        };
        if let Ok(json) = serde_json::to_string_pretty(&prefs) {
            let _ = fs::write(self.storage.base_dir().join("ui_state.json"), json);
        }
    }

    fn apply_optional_demo_seed(&mut self, cx: &mut Context<Self>) {
        if std::env::var("AGENTGATE_DEMO_SEED").as_deref() != Ok("1") {
            return;
        }
        if self.hosts.is_empty() {
            let now = RelayHost::now_str();
            let mut h1 = RelayHost {
                id: Uuid::new_v4(),
                codename: "cobalt-nexus-01".to_string(),
                label: "内网测试机 108 (容器集群)".to_string(),
                real_host: "10.96.1.108".to_string(),
                real_port: 22,
                real_user: "root".to_string(),
                real_auth: RealAuthConfig::Password {
                    password: "DemoRealSecretPassword#108".to_string(),
                },
                proxy: ProxyConfig::Socks5 {
                    host: "127.0.0.1".to_string(),
                    port: 7890,
                    username: None,
                    password: None,
                },
                agent_auth_mode: AgentAuthMode::EphemeralPassword,
                dedicated_key_openssh_pem: None,
                created_at: now.clone(),
                updated_at: now.clone(),
            };
            let mut h2 = RelayHost {
                id: Uuid::new_v4(),
                codename: "jade-sentry-02".to_string(),
                label: "训练推理节点 (GPU-A100)".to_string(),
                real_host: "172.20.14.66".to_string(),
                real_port: 22022,
                real_user: "ubuntu".to_string(),
                real_auth: RealAuthConfig::Password {
                    password: "DemoRealSecretPassword#GPU".to_string(),
                },
                proxy: ProxyConfig::HttpConnect {
                    host: "127.0.0.1".to_string(),
                    port: 8080,
                    username: Some("corp_proxy".to_string()),
                    password: Some("proxy_pass".to_string()),
                },
                agent_auth_mode: AgentAuthMode::DedicatedKey,
                dedicated_key_openssh_pem: None,
                created_at: now.clone(),
                updated_at: now.clone(),
            };
            let h3 = RelayHost {
                id: Uuid::new_v4(),
                codename: "amber-citadel-03".to_string(),
                label: "只读预发节点 (直连)".to_string(),
                real_host: "192.168.31.205".to_string(),
                real_port: 22,
                real_user: "deploy".to_string(),
                real_auth: RealAuthConfig::Password {
                    password: "DemoRealSecretPassword#Stage".to_string(),
                },
                proxy: ProxyConfig::None,
                agent_auth_mode: AgentAuthMode::EphemeralPassword,
                dedicated_key_openssh_pem: None,
                created_at: now.clone(),
                updated_at: now,
            };

            for mut h in [h1.clone(), h2.clone(), h3] {
                let (key_path, pubkey) = self
                    .storage
                    .ensure_dedicated_agent_key(&mut h, false)
                    .unwrap_or_else(|_| (self.storage.dedicated_key_path_for(&h.codename), String::new()));
                let mut rt = RelayRuntimeState {
                    status: RelayStatus::Stopped,
                    current_temp_password: Some(RelayHost::generate_ephemeral_password()),
                    dedicated_key_path: Some(key_path.to_string_lossy().to_string()),
                    dedicated_pubkey_openssh: Some(pubkey),
                    total_connections: 0,
                    logs: Vec::new(),
                };
                rt.push_log(
                    &h.codename,
                    "初始化就绪",
                    format!("代理: {} | 暴露模式: {}", h.proxy.badge_text(), h.agent_auth_mode.label()),
                    false,
                );
                self.runtimes.insert(h.id, rt);
                self.hosts.push(h);
            }
            let _ = self.storage.save_hosts(&self.hosts);
            h1 = self.hosts[0].clone();
            h2 = self.hosts[1].clone();

            // 默认启动第一条主机展示运行态与随机端口
            self.execute_confirmed_action(
                PendingAction::StartRelay {
                    id: h1.id,
                    codename: h1.codename.clone(),
                },
                cx,
            );
            if let Some(rt) = self.runtimes.get_mut(&h1.id) {
                rt.total_connections = 3;
                rt.push_log(
                    &h1.codename,
                    "Agent 临时密码认证通过",
                    "本地用户 `cobalt-nexus-01` 自 127.0.0.1:59412 通过恒定时间临时密码验证",
                    false,
                );
                rt.push_log(
                    &h1.codename,
                    "上游隧道已就绪",
                    "已通过 SOCKS5 127.0.0.1:7890 建立加密中转会话（真实地址已隐藏）",
                    false,
                );
                rt.push_log(
                    &h1.codename,
                    "执行命令",
                    "exec: docker ps --format 'table {{.Names}}\\t{{.Status}}'",
                    false,
                );
            }
            self.selected_host_id = Some(h1.id);
            self.active_tab = RightPanelTab::Overview;

            if let Ok(view_mode) = std::env::var("AGENTGATE_DEMO_VIEW") {
                match view_mode.as_str() {
                    "confirm_copy" => {
                        self.pending_confirm = Some(PendingAction::CopyAgentConfig {
                            id: h1.id,
                            codename: h1.codename.clone(),
                            format: CopyFormat::AgentPromptCard,
                        });
                    }
                    "confirm_start_key" => {
                        self.selected_host_id = Some(h2.id);
                        self.pending_confirm = Some(PendingAction::StartRelay {
                            id: h2.id,
                            codename: h2.codename.clone(),
                        });
                    }
                    "host_form" => {
                        self.populate_form_from_host(&h1, cx);
                        self.active_tab = RightPanelTab::HostForm;
                    }
                    "audit_logs" => {
                        self.active_tab = RightPanelTab::AuditLogs;
                    }
                    "light_overview" => {
                        self.is_dark = false;
                        self.sync_inputs_theme(cx);
                        self.selected_host_id = Some(h2.id);
                        self.active_tab = RightPanelTab::Overview;
                    }
                    _ => {}
                }
            }
        }
    }

    fn sync_inputs_theme(&mut self, cx: &mut Context<Self>) {
        let is_dark = self.is_dark;
        for field in [
            &self.search_input,
            &self.form_codename,
            &self.form_label,
            &self.form_real_host,
            &self.form_real_port,
            &self.form_real_user,
            &self.form_real_secret,
            &self.form_real_passphrase,
            &self.form_proxy_host,
            &self.form_proxy_port,
            &self.form_proxy_user,
            &self.form_proxy_pass,
        ] {
            field.update(cx, |f, cx| f.set_dark(is_dark, cx));
        }
    }

    fn apply_relay_event(&mut self, event: RelayEvent) {
        match event {
            RelayEvent::Started {
                host_id,
                codename,
                local_port,
            } => {
                let rt = self.runtimes.entry(host_id).or_default();
                rt.status = RelayStatus::Running {
                    local_port,
                    active_sessions: 0,
                };
                self.status_banner = Some((
                    format!("代号 [{}] 已启动本地 SSH 中转：127.0.0.1:{}", codename, local_port),
                    false,
                ));
            }
            RelayEvent::Stopped { host_id, codename } => {
                let rt = self.runtimes.entry(host_id).or_default();
                rt.status = RelayStatus::Stopped;
                self.controls.remove(&host_id);
                self.status_banner = Some((format!("代号 [{}] 本地监听已停止", codename), false));
            }
            RelayEvent::SessionsChanged {
                host_id,
                active_sessions,
                total_connections,
            } => {
                let rt = self.runtimes.entry(host_id).or_default();
                if let RelayStatus::Running { local_port, .. } = rt.status {
                    rt.status = RelayStatus::Running {
                        local_port,
                        active_sessions,
                    };
                }
                rt.total_connections = total_connections;
            }
            RelayEvent::AuditLog {
                host_id,
                codename,
                event,
                detail,
                is_error,
            } => {
                let rt = self.runtimes.entry(host_id).or_default();
                rt.push_log(&codename, event, detail, is_error);
            }
            RelayEvent::Error {
                host_id,
                codename,
                message,
            } => {
                let rt = self.runtimes.entry(host_id).or_default();
                rt.status = RelayStatus::Error(message.clone());
                rt.push_log(&codename, "服务异常", message.clone(), true);
                self.controls.remove(&host_id);
                self.status_banner = Some((format!("代号 [{}] 异常: {}", codename, message), true));
            }
        }
    }

    fn reset_form_for_new_host(&mut self, cx: &mut Context<Self>) {
        self.editing_host_id = None;
        let next_codename = RelayHost::generate_codename(self.hosts.len());
        self.form_codename.update(cx, |f, cx| f.set_text(next_codename, cx));
        self.form_label.update(cx, |f, cx| f.set_text("", cx));
        self.form_real_host.update(cx, |f, cx| f.set_text("", cx));
        self.form_real_port.update(cx, |f, cx| f.set_text("22", cx));
        self.form_real_user.update(cx, |f, cx| f.set_text("root", cx));
        self.form_real_auth_kind = FormRealAuthKind::Password;
        self.form_real_secret.update(cx, |f, cx| {
            f.set_masked(true, cx);
            f.set_text("", cx);
        });
        self.form_real_passphrase.update(cx, |f, cx| f.set_text("", cx));
        self.form_proxy_kind = FormProxyKind::None;
        self.form_proxy_host.update(cx, |f, cx| f.set_text("127.0.0.1", cx));
        self.form_proxy_port.update(cx, |f, cx| f.set_text("7890", cx));
        self.form_proxy_user.update(cx, |f, cx| f.set_text("", cx));
        self.form_proxy_pass.update(cx, |f, cx| f.set_text("", cx));
        self.form_agent_auth_mode = AgentAuthMode::EphemeralPassword;
    }

    fn populate_form_from_host(&mut self, host: &RelayHost, cx: &mut Context<Self>) {
        self.editing_host_id = Some(host.id);
        self.form_codename
            .update(cx, |f, cx| f.set_text(host.codename.clone(), cx));
        self.form_label
            .update(cx, |f, cx| f.set_text(host.label.clone(), cx));
        self.form_real_host
            .update(cx, |f, cx| f.set_text(host.real_host.clone(), cx));
        self.form_real_port
            .update(cx, |f, cx| f.set_text(host.real_port.to_string(), cx));
        self.form_real_user
            .update(cx, |f, cx| f.set_text(host.real_user.clone(), cx));
        match &host.real_auth {
            RealAuthConfig::Password { password } => {
                self.form_real_auth_kind = FormRealAuthKind::Password;
                self.form_real_secret.update(cx, |f, cx| {
                    f.set_masked(true, cx);
                    f.set_text(password.clone(), cx);
                });
                self.form_real_passphrase
                    .update(cx, |f, cx| f.set_text("", cx));
            }
            RealAuthConfig::PrivateKey {
                private_key_pem,
                passphrase,
            } => {
                self.form_real_auth_kind = FormRealAuthKind::PrivateKey;
                self.form_real_secret.update(cx, |f, cx| {
                    f.set_masked(false, cx);
                    f.set_text(private_key_pem.clone(), cx);
                });
                self.form_real_passphrase.update(cx, |f, cx| {
                    f.set_text(passphrase.clone().unwrap_or_default(), cx)
                });
            }
        }
        match &host.proxy {
            ProxyConfig::None => {
                self.form_proxy_kind = FormProxyKind::None;
                self.form_proxy_host
                    .update(cx, |f, cx| f.set_text("127.0.0.1", cx));
                self.form_proxy_port
                    .update(cx, |f, cx| f.set_text("7890", cx));
                self.form_proxy_user.update(cx, |f, cx| f.set_text("", cx));
                self.form_proxy_pass.update(cx, |f, cx| f.set_text("", cx));
            }
            ProxyConfig::Socks5 {
                host: ph,
                port: pp,
                username,
                password,
            } => {
                self.form_proxy_kind = FormProxyKind::Socks5;
                self.form_proxy_host
                    .update(cx, |f, cx| f.set_text(ph.clone(), cx));
                self.form_proxy_port
                    .update(cx, |f, cx| f.set_text(pp.to_string(), cx));
                self.form_proxy_user.update(cx, |f, cx| {
                    f.set_text(username.clone().unwrap_or_default(), cx)
                });
                self.form_proxy_pass.update(cx, |f, cx| {
                    f.set_text(password.clone().unwrap_or_default(), cx)
                });
            }
            ProxyConfig::HttpConnect {
                host: ph,
                port: pp,
                username,
                password,
            } => {
                self.form_proxy_kind = FormProxyKind::HttpConnect;
                self.form_proxy_host
                    .update(cx, |f, cx| f.set_text(ph.clone(), cx));
                self.form_proxy_port
                    .update(cx, |f, cx| f.set_text(pp.to_string(), cx));
                self.form_proxy_user.update(cx, |f, cx| {
                    f.set_text(username.clone().unwrap_or_default(), cx)
                });
                self.form_proxy_pass.update(cx, |f, cx| {
                    f.set_text(password.clone().unwrap_or_default(), cx)
                });
            }
        }
        self.form_agent_auth_mode = host.agent_auth_mode;
    }

    fn validate_and_build_host(&self, cx: &App) -> Result<(RelayHost, bool), String> {
        let codename = self.form_codename.read(cx).text().trim().to_string();
        if codename.is_empty() {
            return Err("机器代号 (Codename) 不能为空".to_string());
        }
        if !codename
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err("机器代号仅允许包含字母、数字、连字符(-)或下划线(_)".to_string());
        }
        let is_new = self.editing_host_id.is_none();
        let id = self.editing_host_id.unwrap_or_else(Uuid::new_v4);
        if self
            .hosts
            .iter()
            .any(|h| h.id != id && h.codename.eq_ignore_ascii_case(&codename))
        {
            return Err(format!("代号 [{}] 已存在，请使用唯一代号以便 AI 区分", codename));
        }

        let real_host = self.form_real_host.read(cx).text().trim().to_string();
        if real_host.is_empty() {
            return Err("真实远端主机地址不能为空".to_string());
        }
        let real_port: u16 = self
            .form_real_port
            .read(cx)
            .text()
            .trim()
            .parse()
            .ok()
            .filter(|p| *p > 0)
            .ok_or_else(|| "真实远端 SSH 端口必须是 1~65535 之间的整数".to_string())?;

        let real_user = self.form_real_user.read(cx).text().trim().to_string();
        if real_user.is_empty() {
            return Err("真实远端登录用户名不能为空".to_string());
        }

        let secret = self.form_real_secret.read(cx).text();
        if secret.trim().is_empty() {
            return Err("真实远端认证密码或私钥内容不能为空".to_string());
        }

        let real_auth = match self.form_real_auth_kind {
            FormRealAuthKind::Password => RealAuthConfig::Password { password: secret },
            FormRealAuthKind::PrivateKey => {
                let pass = self.form_real_passphrase.read(cx).text();
                RealAuthConfig::PrivateKey {
                    private_key_pem: secret,
                    passphrase: (!pass.is_empty()).then_some(pass),
                }
            }
        };

        let proxy = match self.form_proxy_kind {
            FormProxyKind::None => ProxyConfig::None,
            FormProxyKind::Socks5 | FormProxyKind::HttpConnect => {
                let ph = self.form_proxy_host.read(cx).text().trim().to_string();
                if ph.is_empty() {
                    return Err("启用代理时，代理服务器地址不能为空".to_string());
                }
                let pp: u16 = self
                    .form_proxy_port
                    .read(cx)
                    .text()
                    .trim()
                    .parse()
                    .ok()
                    .filter(|p| *p > 0)
                    .ok_or_else(|| "代理端口必须是 1~65535 之间的整数".to_string())?;
                let pu = self.form_proxy_user.read(cx).text().trim().to_string();
                let pw = self.form_proxy_pass.read(cx).text();
                let username = (!pu.is_empty()).then_some(pu);
                let password = (!pw.is_empty()).then_some(pw);
                if self.form_proxy_kind == FormProxyKind::Socks5 {
                    ProxyConfig::Socks5 {
                        host: ph,
                        port: pp,
                        username,
                        password,
                    }
                } else {
                    ProxyConfig::HttpConnect {
                        host: ph,
                        port: pp,
                        username,
                        password,
                    }
                }
            }
        };

        let existing = self.hosts.iter().find(|h| h.id == id);
        let now = RelayHost::now_str();
        let host = RelayHost {
            id,
            codename,
            label: self.form_label.read(cx).text().trim().to_string(),
            real_host,
            real_port,
            real_user,
            real_auth,
            proxy,
            agent_auth_mode: self.form_agent_auth_mode,
            dedicated_key_openssh_pem: existing.and_then(|h| h.dedicated_key_openssh_pem.clone()),
            created_at: existing
                .map(|h| h.created_at.clone())
                .unwrap_or_else(|| now.clone()),
            updated_at: now,
        };
        Ok((host, is_new))
    }

    fn build_live_credentials(host: &RelayHost, rt: &RelayRuntimeState) -> LiveCredentials {
        let dedicated_pubkey = host
            .dedicated_key_openssh_pem
            .as_deref()
            .and_then(|pem| PrivateKey::from_openssh(pem).ok())
            .map(|k| k.public_key().clone());
        LiveCredentials {
            mode: host.agent_auth_mode,
            temp_password: rt.current_temp_password.clone(),
            dedicated_pubkey,
        }
    }

    fn request_confirmation(&mut self, action: PendingAction, cx: &mut Context<Self>) {
        self.pending_confirm = Some(action);
        cx.notify();
    }

    fn on_confirm_modal_action(
        &mut self,
        _: &ConfirmModalAction,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Some(action) = self.pending_confirm.take() {
            self.execute_confirmed_action(action, cx);
        }
    }

    fn on_cancel_modal_action(
        &mut self,
        _: &CancelModalAction,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.pending_confirm.is_some() {
            self.pending_confirm = None;
            self.status_banner = Some(("已取消该操作".to_string(), false));
            cx.notify();
        }
    }

    fn execute_confirmed_action(&mut self, action: PendingAction, cx: &mut Context<Self>) {
        match action {
            PendingAction::StartRelay { id, codename } => {
                if let Some(existing_ctrl) = self.controls.remove(&id) {
                    existing_ctrl.stop();
                }
                let Some(host) = self.hosts.iter().find(|h| h.id == id).cloned() else {
                    return;
                };
                let rt = self.runtimes.entry(id).or_default();
                if rt.current_temp_password.is_none() {
                    rt.current_temp_password = Some(RelayHost::generate_ephemeral_password());
                }
                rt.status = RelayStatus::Starting;
                let live_creds = Self::build_live_credentials(&host, rt);
                let tx = self.event_tx.clone();
                let handle_res = global_tokio_runtime()
                    .block_on(start_host_relay(host, live_creds, tx));
                match handle_res {
                    Ok(ctrl) => {
                        let port = ctrl.local_port;
                        self.controls.insert(id, ctrl);
                        if let Some(rt) = self.runtimes.get_mut(&id) {
                            rt.status = RelayStatus::Running {
                                local_port: port,
                                active_sessions: 0,
                            };
                        }
                        self.status_banner = Some((
                            format!("已启动代号 [{}] 本地随机端口监听 127.0.0.1:{}", codename, port),
                            false,
                        ));
                    }
                    Err(err) => {
                        if let Some(rt) = self.runtimes.get_mut(&id) {
                            rt.status = RelayStatus::Error(err.to_string());
                        }
                        self.status_banner =
                            Some((format!("启动代号 [{}] 失败: {}", codename, err), true));
                    }
                }
            }
            PendingAction::StopRelay {
                id,
                codename,
                local_port,
            } => {
                if let Some(ctrl) = self.controls.remove(&id) {
                    ctrl.stop();
                }
                if let Some(rt) = self.runtimes.get_mut(&id) {
                    rt.status = RelayStatus::Stopped;
                    // 停止后自动更换下次启动的临时密码
                    rt.current_temp_password = Some(RelayHost::generate_ephemeral_password());
                }
                self.status_banner = Some((
                    format!("已停止代号 [{}] 在 127.0.0.1:{} 的中转服务", codename, local_port),
                    false,
                ));
            }
            PendingAction::StopAllRelays { running_count } => {
                for (_, ctrl) in self.controls.drain() {
                    ctrl.stop();
                }
                for rt in self.runtimes.values_mut() {
                    if rt.status.is_running() {
                        rt.status = RelayStatus::Stopped;
                        rt.current_temp_password = Some(RelayHost::generate_ephemeral_password());
                    }
                }
                self.status_banner = Some((
                    format!("已停止全部 {} 条本地 SSH 中转服务", running_count),
                    false,
                ));
            }
            PendingAction::SaveHost { mut host, is_new } => {
                let (key_path, pubkey) = match self
                    .storage
                    .ensure_dedicated_agent_key(&mut host, false)
                {
                    Ok(v) => v,
                    Err(err) => {
                        self.status_banner =
                            Some((format!("生成专用密钥失败: {}", err), true));
                        cx.notify();
                        return;
                    }
                };

                let id = host.id;
                let codename = host.codename.clone();
                if is_new {
                    self.hosts.push((*host).clone());
                } else if let Some(slot) = self.hosts.iter_mut().find(|h| h.id == id) {
                    *slot = (*host).clone();
                }

                if let Err(err) = self.storage.save_hosts(&self.hosts) {
                    self.status_banner =
                        Some((format!("加密保存仓库失败: {}", err), true));
                    cx.notify();
                    return;
                }

                let rt = self.runtimes.entry(id).or_insert_with(|| RelayRuntimeState {
                    status: RelayStatus::Stopped,
                    current_temp_password: Some(RelayHost::generate_ephemeral_password()),
                    dedicated_key_path: None,
                    dedicated_pubkey_openssh: None,
                    total_connections: 0,
                    logs: Vec::new(),
                });
                rt.dedicated_key_path = Some(key_path.to_string_lossy().to_string());
                rt.dedicated_pubkey_openssh = Some(pubkey);
                rt.push_log(
                    &codename,
                    if is_new { "新建主机" } else { "更新主机" },
                    format!("代理: {} | Agent 认证: {}", host.proxy.badge_text(), host.agent_auth_mode.label()),
                    false,
                );

                if let Some(ctrl) = self.controls.get(&id) {
                    let creds = Self::build_live_credentials(&host, rt);
                    ctrl.update_credentials(creds);
                }

                self.selected_host_id = Some(id);
                self.active_tab = RightPanelTab::Overview;
                self.save_ui_prefs();
                self.status_banner = Some((
                    format!("代号 [{}] 已通过 AES-256-GCM 加密写入本机仓库", codename),
                    false,
                ));
            }
            PendingAction::DeleteHost { id, codename } => {
                if let Some(ctrl) = self.controls.remove(&id) {
                    ctrl.stop();
                }
                self.storage.remove_dedicated_key_file(&codename);
                self.hosts.retain(|h| h.id != id);
                self.runtimes.remove(&id);
                let _ = self.storage.save_hosts(&self.hosts);
                if self.selected_host_id == Some(id) {
                    self.selected_host_id = self.hosts.first().map(|h| h.id);
                }
                self.save_ui_prefs();
                self.status_banner = Some((format!("已删除代号 [{}] 及其专用密钥", codename), false));
            }
            PendingAction::RotateCredentials { id, codename, mode } => {
                let Some(host_idx) = self.hosts.iter().position(|h| h.id == id) else {
                    return;
                };
                match mode {
                    AgentAuthMode::EphemeralPassword => {
                        let new_pwd = RelayHost::generate_ephemeral_password();
                        if let Some(rt) = self.runtimes.get_mut(&id) {
                            rt.current_temp_password = Some(new_pwd);
                            rt.push_log(&codename, "轮换临时密码", "已生成新 24 位临时密码，旧密码已失效", false);
                        }
                    }
                    AgentAuthMode::DedicatedKey => {
                        if let Ok((key_path, pubkey)) = self
                            .storage
                            .ensure_dedicated_agent_key(&mut self.hosts[host_idx], true)
                        {
                            let _ = self.storage.save_hosts(&self.hosts);
                            if let Some(rt) = self.runtimes.get_mut(&id) {
                                rt.dedicated_key_path = Some(key_path.to_string_lossy().to_string());
                                rt.dedicated_pubkey_openssh = Some(pubkey);
                                rt.push_log(&codename, "重置专用密钥", "已重新生成本机 Ed25519 密钥对", false);
                            }
                        }
                    }
                }
                let host = &self.hosts[host_idx];
                if let (Some(ctrl), Some(rt)) = (self.controls.get(&id), self.runtimes.get(&id)) {
                    ctrl.update_credentials(Self::build_live_credentials(host, rt));
                }
                self.status_banner = Some((
                    format!("代号 [{}] 的「{}」已完成轮换并实时生效", codename, mode.label()),
                    false,
                ));
            }
            PendingAction::ToggleAgentAuthMode {
                id,
                codename,
                target_mode,
            } => {
                if let Some(host) = self.hosts.iter_mut().find(|h| h.id == id) {
                    host.agent_auth_mode = target_mode;
                    host.updated_at = RelayHost::now_str();
                }
                let _ = self.storage.save_hosts(&self.hosts);
                if let (Some(host), Some(rt)) = (
                    self.hosts.iter().find(|h| h.id == id),
                    self.runtimes.get_mut(&id),
                ) {
                    rt.push_log(
                        &codename,
                        "切换认证模式",
                        format!("当前对 Agent 暴露模式: {}", target_mode.label()),
                        false,
                    );
                    if let Some(ctrl) = self.controls.get(&id) {
                        ctrl.update_credentials(Self::build_live_credentials(host, rt));
                    }
                }
                self.status_banner = Some((
                    format!("代号 [{}] 已切换为「{}」", codename, target_mode.label()),
                    false,
                ));
            }
            PendingAction::CopyAgentConfig {
                id,
                codename,
                format,
            } => {
                let Some(host) = self.hosts.iter().find(|h| h.id == id) else {
                    return;
                };
                let Some(rt) = self.runtimes.get_mut(&id) else {
                    return;
                };
                match render_agent_snippet(host, rt, format) {
                    Ok(snippet) => {
                        cx.write_to_clipboard(ClipboardItem::new_string(snippet));
                        rt.push_log(
                            &codename,
                            "复制 Agent 配置",
                            format!("已复制「{}」到剪贴板（零真实地址泄露）", format.label()),
                            false,
                        );
                        self.status_banner = Some((
                            format!("已复制代号 [{}] 的「{}」到剪贴板，可直接粘贴发给 Agent", codename, format.label()),
                            false,
                        ));
                    }
                    Err(err) => {
                        self.status_banner = Some((err.to_string(), true));
                    }
                }
            }
        }
        cx.notify();
    }

    fn render_top_bar(&self, theme: WorkbenchTheme, cx: &mut Context<Self>) -> impl IntoElement {
        let running_count = self
            .runtimes
            .values()
            .filter(|r| r.status.is_running())
            .count();
        let active_sessions: usize = self
            .runtimes
            .values()
            .map(|r| r.status.active_sessions())
            .sum();

        div()
            .h(px(56.))
            .w_full()
            .px_4()
            .flex()
            .items_center()
            .justify_between()
            .bg(theme.bg_surface)
            .border_b_1()
            .border_color(theme.border)
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .px_2p5()
                            .py_1()
                            .rounded(px(6.))
                            .bg(theme.accent)
                            .text_color(rgb(0xffffff))
                            .text_size(px(14.))
                            .font_weight(gpui::FontWeight::BOLD)
                            .child("AgentGate"),
                    )
                    .child(
                        div()
                            .px_2()
                            .py_0p5()
                            .rounded(px(5.))
                            .bg(theme.success_soft)
                            .text_color(theme.success)
                            .text_size(px(12.))
                            .child(format!("运行中 {} / {}", running_count, self.hosts.len())),
                    )
                    .child(
                        div()
                            .px_2()
                            .py_0p5()
                            .rounded(px(5.))
                            .bg(theme.accent_soft)
                            .text_color(theme.accent_hover)
                            .text_size(px(12.))
                            .child(format!("活跃 Agent 会话: {}", active_sessions)),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(div().w(px(210.)).child(self.search_input.clone()))
                    .child(
                        action_button(
                            "btn-stop-all",
                            "全部停止",
                            theme,
                            running_count > 0,
                            true,
                        )
                        .on_click(cx.listener(move |this, _, _, cx| {
                            if running_count > 0 {
                                this.request_confirmation(
                                    PendingAction::StopAllRelays { running_count },
                                    cx,
                                );
                            }
                        })),
                    )
                    .child(
                        action_button(
                            "btn-new-host",
                            "+ 新建主机",
                            theme,
                            true,
                            false,
                        )
                        .bg(theme.accent)
                        .text_color(rgb(0xffffff))
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.reset_form_for_new_host(cx);
                            this.active_tab = RightPanelTab::HostForm;
                            this.save_ui_prefs();
                            cx.notify();
                        })),
                    )
                    .child(
                        action_button(
                            "btn-theme-toggle",
                            if self.is_dark { "浅色模式" } else { "深色模式" },
                            theme,
                            true,
                            false,
                        )
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.is_dark = !this.is_dark;
                            this.sync_inputs_theme(cx);
                            this.save_ui_prefs();
                            cx.notify();
                        })),
                    )
                    .child(
                        action_button(
                            "btn-hide-tray",
                            "收起到菜单栏",
                            theme,
                            true,
                            false,
                        )
                        .on_click(cx.listener(|_, _, _, _| {
                            platform_set_window_visible(false);
                        })),
                    ),
            )
    }

    fn render_status_bar(&self, theme: WorkbenchTheme) -> impl IntoElement {
        let (msg, is_err) = self
            .status_banner
            .clone()
            .unwrap_or_else(|| ("就绪".to_string(), false));
        let dot_color = if is_err { theme.danger } else { theme.success };

        div()
            .h(px(32.))
            .w_full()
            .px_4()
            .flex()
            .items_center()
            .justify_between()
            .bg(theme.bg_elevated)
            .border_b_1()
            .border_color(theme.border)
            .text_size(px(12.))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(div().size(px(8.)).rounded(px(4.)).bg(dot_color))
                    .child(
                        div()
                            .text_color(if is_err {
                                theme.danger
                            } else {
                                theme.text_primary
                            })
                            .child(msg),
                    ),
            )
    }

    fn render_left_host_list(
        &self,
        theme: WorkbenchTheme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let filter = self.search_input.read(cx).text().trim().to_lowercase();
        let filtered_hosts: Vec<RelayHost> = self
            .hosts
            .iter()
            .filter(|h| {
                filter.is_empty()
                    || h.codename.to_lowercase().contains(&filter)
                    || h.label.to_lowercase().contains(&filter)
            })
            .cloned()
            .collect();

        div()
            .w(px(420.))
            .h_full()
            .flex()
            .flex_col()
            .bg(theme.bg_surface)
            .border_r_1()
            .border_color(theme.border)
            .child(
                div()
                    .h(px(40.))
                    .px_4()
                    .flex()
                    .items_center()
                    .justify_between()
                    .border_b_1()
                    .border_color(theme.border)
                    .text_size(px(12.))
                    .text_color(theme.text_secondary)
                    .child(format!("机器代号列表 ({})", filtered_hosts.len())),
            )
            .child(
                div()
                    .id("host-list-scroll")
                    .flex_1()
                    .overflow_scroll()
                    .flex()
                    .flex_col()
                    .when(filtered_hosts.is_empty(), |this| {
                        this.child(
                            div()
                                .p_6()
                                .flex()
                                .flex_col()
                                .gap_2()
                                .text_size(px(13.))
                                .text_color(theme.text_muted)
                                .child("暂无匹配的 SSH 中转机器")
                                .child("点击右上角「+ 新建主机」添加第一台受保护的 SSH 机器。"),
                        )
                    })
                    .children(filtered_hosts.into_iter().enumerate().map(|(idx, host)| {
                        let id = host.id;
                        let codename = host.codename.clone();
                        let is_selected = self.selected_host_id == Some(id);
                        let rt = self.runtimes.get(&id).cloned().unwrap_or_default();
                        let is_running = rt.status.is_running();
                        let local_port = rt.status.local_port();

                        let row_bg = if is_selected {
                            theme.bg_subtle
                        } else {
                            theme.bg_surface
                        };

                        div()
                            .id(("host-row", idx))
                            .w_full()
                            .p_3()
                            .bg(row_bg)
                            .border_b_1()
                            .border_color(theme.border)
                            .hover(|s| s.bg(theme.bg_elevated))
                            .cursor_pointer()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.selected_host_id = Some(id);
                                if this.active_tab == RightPanelTab::HostForm
                                    && this.editing_host_id.is_some()
                                    && let Some(h) =
                                        this.hosts.iter().find(|h| h.id == id).cloned()
                                {
                                    this.populate_form_from_host(&h, cx);
                                }
                                this.save_ui_prefs();
                                cx.notify();
                            }))
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_2()
                                            .child(
                                                div()
                                                    .size(px(8.))
                                                    .rounded(px(4.))
                                                    .bg(if is_running {
                                                        theme.success
                                                    } else {
                                                        theme.text_muted
                                                    }),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(14.))
                                                    .font_weight(gpui::FontWeight::BOLD)
                                                    .text_color(theme.text_primary)
                                                    .child(format!("[{}]", host.codename)),
                                            )
                                            .when(!host.label.is_empty(), |d| {
                                                d.child(
                                                    div()
                                                        .text_size(px(12.))
                                                        .text_color(theme.text_secondary)
                                                        .child(host.label.clone()),
                                                )
                                            }),
                                    )
                                    .child(
                                        div()
                                            .px_2()
                                            .py_0p5()
                                            .rounded(px(4.))
                                            .text_size(px(11.))
                                            .bg(if is_running {
                                                theme.success_soft
                                            } else {
                                                hsla(0., 0., 0.5, 0.12)
                                            })
                                            .text_color(if is_running {
                                                theme.success
                                            } else {
                                                theme.text_muted
                                            })
                                            .child(match local_port {
                                                Some(p) => format!("127.0.0.1:{}", p),
                                                None => "已停止".to_string(),
                                            }),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .gap_2()
                                    .text_size(px(11.))
                                    .text_color(theme.text_muted)
                                    .child(format!(
                                        "{} · {}",
                                        host.masked_real_endpoint(),
                                        host.proxy.badge_text()
                                    ))
                                    .child(format!(
                                        "{} · {} 会话",
                                        match host.agent_auth_mode {
                                            AgentAuthMode::EphemeralPassword => "临时密码",
                                            AgentAuthMode::DedicatedKey => "专用密钥",
                                        },
                                        rt.status.active_sessions()
                                    )),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child({
                                        let codename_toggle = codename.clone();
                                        action_button(
                                            ("row-toggle", idx),
                                            if is_running {
                                                "停止中转"
                                            } else {
                                                "开启中转"
                                            },
                                            theme,
                                            true,
                                            is_running,
                                        )
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.selected_host_id = Some(id);
                                            if let Some(p) = local_port {
                                                this.request_confirmation(
                                                    PendingAction::StopRelay {
                                                        id,
                                                        codename: codename_toggle.clone(),
                                                        local_port: p,
                                                    },
                                                    cx,
                                                );
                                            } else {
                                                this.request_confirmation(
                                                    PendingAction::StartRelay {
                                                        id,
                                                        codename: codename_toggle.clone(),
                                                    },
                                                    cx,
                                                );
                                            }
                                        }))
                                    })
                                    .child({
                                        let codename_copy = codename.clone();
                                        action_button(
                                            ("row-copy-card", idx),
                                            "复制发给 Agent",
                                            theme,
                                            is_running,
                                            false,
                                        )
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.selected_host_id = Some(id);
                                            if is_running {
                                                this.request_confirmation(
                                                    PendingAction::CopyAgentConfig {
                                                        id,
                                                        codename: codename_copy.clone(),
                                                        format: CopyFormat::AgentPromptCard,
                                                    },
                                                    cx,
                                                );
                                            } else {
                                                this.status_banner = Some((
                                                    format!(
                                                        "请先开启代号 [{}] 的中转服务以分配本地随机端口",
                                                        codename_copy
                                                    ),
                                                    true,
                                                ));
                                                cx.notify();
                                            }
                                        }))
                                    })
                                    .child({
                                        let host_for_edit = host.clone();
                                        action_button(
                                            ("row-edit", idx),
                                            "编辑",
                                            theme,
                                            true,
                                            false,
                                        )
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.selected_host_id = Some(id);
                                            this.populate_form_from_host(&host_for_edit, cx);
                                            this.active_tab = RightPanelTab::HostForm;
                                            this.save_ui_prefs();
                                            cx.notify();
                                        }))
                                    }),
                            )
                    })),
            )
    }

    fn render_right_workspace(
        &self,
        theme: WorkbenchTheme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let tabs = [
            (RightPanelTab::Overview, "连接详情与 Agent 凭证"),
            (
                RightPanelTab::HostForm,
                if self.editing_host_id.is_some() {
                    "编辑主机与代理"
                } else {
                    "新建/编辑主机"
                },
            ),
            (RightPanelTab::AuditLogs, "实时转发审计日志"),
        ];

        div()
            .flex_1()
            .min_w_0()
            .h_full()
            .overflow_hidden()
            .flex()
            .flex_col()
            .bg(theme.bg_app)
            .child(
                div()
                    .h(px(40.))
                    .px_4()
                    .flex()
                    .items_center()
                    .gap_2()
                    .bg(theme.bg_surface)
                    .border_b_1()
                    .border_color(theme.border)
                    .children(tabs.into_iter().enumerate().map(|(ix, (tab, label))| {
                        let active = self.active_tab == tab;
                        div()
                            .id(("right-tab", ix))
                            .px_3()
                            .h(px(30.))
                            .rounded(px(5.))
                            .flex()
                            .items_center()
                            .text_size(px(12.))
                            .cursor_pointer()
                            .bg(if active {
                                theme.accent_soft
                            } else {
                                hsla(0., 0., 0., 0.)
                            })
                            .text_color(if active {
                                theme.accent_hover
                            } else {
                                theme.text_secondary
                            })
                            .font_weight(if active {
                                gpui::FontWeight::BOLD
                            } else {
                                gpui::FontWeight::NORMAL
                            })
                            .child(label)
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.active_tab = tab;
                                if tab == RightPanelTab::HostForm
                                    && this.editing_host_id.is_none()
                                    && let Some(sel_id) = this.selected_host_id
                                    && let Some(h) =
                                        this.hosts.iter().find(|h| h.id == sel_id).cloned()
                                {
                                    this.populate_form_from_host(&h, cx);
                                }
                                this.save_ui_prefs();
                                cx.notify();
                            }))
                    })),
            )
            .child(
                div()
                    .id("right-panel-scroll")
                    .flex_1()
                    .w_full()
                    .min_w_0()
                    .overflow_scroll()
                    .p_5()
                    .map(|panel| match self.active_tab {
                        RightPanelTab::Overview => {
                            panel.child(self.render_overview_tab(theme, cx))
                        }
                        RightPanelTab::HostForm => {
                            panel.child(self.render_host_form_tab(theme, cx))
                        }
                        RightPanelTab::AuditLogs => {
                            panel.child(self.render_audit_logs_tab(theme, cx))
                        }
                    }),
            )
    }

    fn render_overview_tab(
        &self,
        theme: WorkbenchTheme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let Some(selected_id) = self.selected_host_id else {
            return div()
                .p_6()
                .text_size(px(13.))
                .text_color(theme.text_muted)
                .child("请从左侧选择一条机器代号，或切换到「新建/编辑主机」添加新条目。")
                .into_any_element();
        };
        let Some(host) = self.hosts.iter().find(|h| h.id == selected_id).cloned() else {
            return div()
                .p_6()
                .text_size(px(13.))
                .text_color(theme.text_muted)
                .child("未找到选中的主机条目")
                .into_any_element();
        };
        let rt = self
            .runtimes
            .get(&selected_id)
            .cloned()
            .unwrap_or_default();
        let is_running = rt.status.is_running();
        let local_port = rt.status.local_port();
        let codename = host.codename.clone();

        let snippet_preview = if is_running {
            render_agent_snippet(&host, &rt, CopyFormat::AgentPromptCard)
                .unwrap_or_else(|e| e.to_string())
        } else {
            format!(
                "[SSH 目标代号: {}]\n状态: 当前未开启监听（点击上方「启动中转」后将自动绑定 127.0.0.1 随机未占用端口并生成可复制配置）",
                host.codename
            )
        };

        div()
            .w_full()
            .min_w_0()
            .flex()
            .flex_col()
            .gap_4()
            // 第一区：代号主标题与快速操作栏
            .child(
                div()
                    .w_full()
                    .min_w_0()
                    .overflow_hidden()
                    .p_4()
                    .rounded(px(6.))
                    .bg(theme.bg_surface)
                    .border_1()
                    .border_color(theme.border)
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2p5()
                                    .child(
                                        div()
                                            .text_size(px(18.))
                                            .font_weight(gpui::FontWeight::BOLD)
                                            .text_color(theme.text_primary)
                                            .child(format!("代号 [{}]", host.codename)),
                                    )
                                    .child(
                                        div()
                                            .px_2()
                                            .py_0p5()
                                            .rounded(px(4.))
                                            .text_size(px(12.))
                                            .bg(if is_running {
                                                theme.success_soft
                                            } else {
                                                hsla(0., 0., 0.5, 0.14)
                                            })
                                            .text_color(if is_running {
                                                theme.success
                                            } else {
                                                theme.text_muted
                                            })
                                            .child(match local_port {
                                                Some(p) => format!("运行中 127.0.0.1:{}", p),
                                                None => "未启动".to_string(),
                                            }),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child({
                                        let c_toggle = codename.clone();
                                        action_button(
                                            "detail-toggle-relay",
                                            if is_running {
                                                "停止该中转"
                                            } else {
                                                "启动该中转"
                                            },
                                            theme,
                                            true,
                                            is_running,
                                        )
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            if let Some(p) = local_port {
                                                this.request_confirmation(
                                                    PendingAction::StopRelay {
                                                        id: selected_id,
                                                        codename: c_toggle.clone(),
                                                        local_port: p,
                                                    },
                                                    cx,
                                                );
                                            } else {
                                                this.request_confirmation(
                                                    PendingAction::StartRelay {
                                                        id: selected_id,
                                                        codename: c_toggle.clone(),
                                                    },
                                                    cx,
                                                );
                                            }
                                        }))
                                    })
                                    .child({
                                        let host_edit = host.clone();
                                        action_button(
                                            "detail-edit-host",
                                            "编辑配置",
                                            theme,
                                            true,
                                            false,
                                        )
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.populate_form_from_host(&host_edit, cx);
                                            this.active_tab = RightPanelTab::HostForm;
                                            this.save_ui_prefs();
                                            cx.notify();
                                        }))
                                    })
                                    .child({
                                        let c_del = codename.clone();
                                        action_button(
                                            "detail-delete-host",
                                            "删除主机",
                                            theme,
                                            true,
                                            true,
                                        )
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.request_confirmation(
                                                PendingAction::DeleteHost {
                                                    id: selected_id,
                                                    codename: c_del.clone(),
                                                },
                                                cx,
                                            );
                                        }))
                                    }),
                            ),
                    )
                    .child(
                        div()
                            .text_size(px(12.))
                            .text_color(theme.text_secondary)
                            .child(format!(
                                "备注: {}    |    脱敏远端: {}    |    出站代理: {}",
                                if host.label.is_empty() {
                                    "无"
                                } else {
                                    &host.label
                                },
                                host.masked_real_endpoint(),
                                host.proxy.badge_text()
                            )),
                    ),
            )
            // 第二区：Agent 专用认证模式切换与实时凭证轮换
            .child(
                div()
                    .w_full()
                    .min_w_0()
                    .overflow_hidden()
                    .p_4()
                    .rounded(px(6.))
                    .bg(theme.bg_surface)
                    .border_1()
                    .border_color(theme.border)
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .text_size(px(14.))
                                    .font_weight(gpui::FontWeight::BOLD)
                                    .text_color(theme.text_primary)
                                    .child("暴露给 Agent 的本地隔离凭证"),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child({
                                        let c1 = codename.clone();
                                        let is_pwd =
                                            host.agent_auth_mode == AgentAuthMode::EphemeralPassword;
                                        action_button(
                                            "switch-mode-pwd",
                                            "使用临时随机密码",
                                            theme,
                                            !is_pwd,
                                            false,
                                        )
                                        .when(is_pwd, |b| {
                                            b.bg(theme.accent).text_color(rgb(0xffffff))
                                        })
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            if !is_pwd {
                                                this.request_confirmation(
                                                    PendingAction::ToggleAgentAuthMode {
                                                        id: selected_id,
                                                        codename: c1.clone(),
                                                        target_mode:
                                                            AgentAuthMode::EphemeralPassword,
                                                    },
                                                    cx,
                                                );
                                            }
                                        }))
                                    })
                                    .child({
                                        let c2 = codename.clone();
                                        let is_key =
                                            host.agent_auth_mode == AgentAuthMode::DedicatedKey;
                                        action_button(
                                            "switch-mode-key",
                                            "使用本机专用密钥 (Ed25519)",
                                            theme,
                                            !is_key,
                                            false,
                                        )
                                        .when(is_key, |b| {
                                            b.bg(theme.accent).text_color(rgb(0xffffff))
                                        })
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            if !is_key {
                                                this.request_confirmation(
                                                    PendingAction::ToggleAgentAuthMode {
                                                        id: selected_id,
                                                        codename: c2.clone(),
                                                        target_mode: AgentAuthMode::DedicatedKey,
                                                    },
                                                    cx,
                                                );
                                            }
                                        }))
                                    })
                                    .child({
                                        let c_rot = codename.clone();
                                        let mode = host.agent_auth_mode;
                                        action_button(
                                            "btn-rotate-cred",
                                            match mode {
                                                AgentAuthMode::EphemeralPassword => "轮换临时密码",
                                                AgentAuthMode::DedicatedKey => "重置专用密钥",
                                            },
                                            theme,
                                            true,
                                            false,
                                        )
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.request_confirmation(
                                                PendingAction::RotateCredentials {
                                                    id: selected_id,
                                                    codename: c_rot.clone(),
                                                    mode,
                                                },
                                                cx,
                                            );
                                        }))
                                    }),
                            ),
                    )
                    .child(
                        div()
                            .w_full()
                            .min_w_0()
                            .overflow_hidden()
                            .p_3()
                            .rounded(px(5.))
                            .bg(theme.bg_code)
                            .border_1()
                            .border_color(theme.border)
                            .flex()
                            .flex_col()
                            .gap_1p5()
                            .text_size(px(12.))
                            .child(
                                div()
                                    .text_color(theme.text_secondary)
                                    .child(format!(
                                        "本地监听地址: 127.0.0.1:{}    |    本地 SSH 用户名: {}",
                                        local_port
                                            .map(|p| p.to_string())
                                            .unwrap_or_else(|| "待启动分配".to_string()),
                                        host.codename
                                    )),
                            )
                            .child(
                                div()
                                    .text_color(theme.text_primary)
                                    .child(match host.agent_auth_mode {
                                        AgentAuthMode::EphemeralPassword => format!(
                                            "当前生效临时密码: {}",
                                            rt.current_temp_password
                                                .as_deref()
                                                .unwrap_or("未生成")
                                        ),
                                        AgentAuthMode::DedicatedKey => format!(
                                            "本机专用私钥路径: {}",
                                            rt.dedicated_key_path
                                                .as_deref()
                                                .unwrap_or("未生成")
                                        ),
                                    }),
                            ),
                    ),
            )
            // 第三区：一键复制发给 Agent 的配置预览与操作
            .child(
                div()
                    .w_full()
                    .min_w_0()
                    .overflow_hidden()
                    .p_4()
                    .rounded(px(6.))
                    .bg(theme.bg_surface)
                    .border_1()
                    .border_color(theme.border)
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .text_size(px(14.))
                                    .font_weight(gpui::FontWeight::BOLD)
                                    .text_color(theme.text_primary)
                                    .child("发给 AI Agent 的本地连接配置"),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child({
                                        let c_card = codename.clone();
                                        action_button(
                                            "btn-copy-agent-card",
                                            "复制 Agent 提示词配置",
                                            theme,
                                            is_running,
                                            false,
                                        )
                                        .when(is_running, |b| {
                                            b.bg(theme.accent).text_color(rgb(0xffffff))
                                        })
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            if is_running {
                                                this.request_confirmation(
                                                    PendingAction::CopyAgentConfig {
                                                        id: selected_id,
                                                        codename: c_card.clone(),
                                                        format: CopyFormat::AgentPromptCard,
                                                    },
                                                    cx,
                                                );
                                            }
                                        }))
                                    })
                                    .child({
                                        let c_cmd = codename.clone();
                                        action_button(
                                            "btn-copy-ssh-cmd",
                                            "复制纯 SSH 命令",
                                            theme,
                                            is_running,
                                            false,
                                        )
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            if is_running {
                                                this.request_confirmation(
                                                    PendingAction::CopyAgentConfig {
                                                        id: selected_id,
                                                        codename: c_cmd.clone(),
                                                        format: CopyFormat::SshCommandOnly,
                                                    },
                                                    cx,
                                                );
                                            }
                                        }))
                                    }),
                            ),
                    )
                    .child(
                        div()
                            .w_full()
                            .min_w_0()
                            .overflow_hidden()
                            .p_3()
                            .rounded(px(5.))
                            .bg(theme.bg_code)
                            .border_1()
                            .border_color(theme.border)
                            .text_size(px(12.))
                            .text_color(theme.text_primary)
                            .flex()
                            .flex_col()
                            .gap_1()
                            .children(
                                snippet_preview
                                    .lines()
                                    .map(|line| div().child(line.to_string())),
                            ),
                    ),
            )
            .into_any_element()
    }

    fn render_host_form_tab(
        &self,
        theme: WorkbenchTheme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let is_editing = self.editing_host_id.is_some();
        let secret_masked = self.form_real_secret.read(cx).is_masked();

        div()
            .p_4()
            .rounded(px(6.))
            .bg(theme.bg_surface)
            .border_1()
            .border_color(theme.border)
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .text_size(px(15.))
                            .font_weight(gpui::FontWeight::BOLD)
                            .text_color(theme.text_primary)
                            .child(if is_editing {
                                "编辑 SSH 中转主机与代理配置"
                            } else {
                                "新建 SSH 中转主机与代理配置"
                            }),
                    )
                    .child(
                        action_button("form-reset-new", "清空为新建主机", theme, true, false)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.reset_form_for_new_host(cx);
                                cx.notify();
                            })),
                    ),
            )
            // 第一行：代号与备注
            .child(
                div()
                    .flex()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .flex()
                            .flex_col()
                            .gap_1p5()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .child(field_label("机器代号 (Codename，供人和 AI 区分)", theme))
                                    .child(
                                        div()
                                            .id("btn-random-codename")
                                            .text_size(px(11.))
                                            .text_color(theme.accent_hover)
                                            .cursor_pointer()
                                            .child("随机生成代号")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                let generated = RelayHost::generate_codename(
                                                    this.hosts.len(),
                                                );
                                                this.form_codename
                                                    .update(cx, |f, cx| f.set_text(generated, cx));
                                                cx.notify();
                                            })),
                                    ),
                            )
                            .child(self.form_codename.clone()),
                    )
                    .child(
                        div()
                            .flex_1()
                            .flex()
                            .flex_col()
                            .gap_1p5()
                            .child(field_label("本机备注 (仅本机可见，不进 Agent)", theme))
                            .child(self.form_label.clone()),
                    ),
            )
            // 第二行：真实远端地址、端口、用户名
            .child(
                div()
                    .flex()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .flex()
                            .flex_col()
                            .gap_1p5()
                            .child(field_label("真实远端主机地址 (IP 或域名)", theme))
                            .child(self.form_real_host.clone()),
                    )
                    .child(
                        div()
                            .w(px(120.))
                            .flex()
                            .flex_col()
                            .gap_1p5()
                            .child(field_label("真实 SSH 端口", theme))
                            .child(self.form_real_port.clone()),
                    )
                    .child(
                        div()
                            .w(px(180.))
                            .flex()
                            .flex_col()
                            .gap_1p5()
                            .child(field_label("真实登录用户名", theme))
                            .child(self.form_real_user.clone()),
                    ),
            )
            // 第三行：真实认证方式与密码/私钥输入
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(field_label("真实远端认证方式 (AES-256-GCM 本机加密存储)", theme))
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(
                                        action_button(
                                            "auth-kind-pwd",
                                            "真实密码认证",
                                            theme,
                                            true,
                                            false,
                                        )
                                        .when(
                                            self.form_real_auth_kind == FormRealAuthKind::Password,
                                            |b| b.bg(theme.accent).text_color(rgb(0xffffff)),
                                        )
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.form_real_auth_kind = FormRealAuthKind::Password;
                                            this.form_real_secret
                                                .update(cx, |f, cx| f.set_masked(true, cx));
                                            cx.notify();
                                        })),
                                    )
                                    .child(
                                        action_button(
                                            "auth-kind-key",
                                            "真实私钥 PEM",
                                            theme,
                                            true,
                                            false,
                                        )
                                        .when(
                                            self.form_real_auth_kind
                                                == FormRealAuthKind::PrivateKey,
                                            |b| b.bg(theme.accent).text_color(rgb(0xffffff)),
                                        )
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.form_real_auth_kind = FormRealAuthKind::PrivateKey;
                                            cx.notify();
                                        })),
                                    )
                                    .child(
                                        action_button(
                                            "toggle-secret-mask",
                                            if secret_masked {
                                                "显示明文"
                                            } else {
                                                "隐藏明文"
                                            },
                                            theme,
                                            true,
                                            false,
                                        )
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.form_real_secret.update(cx, |f, cx| {
                                                f.set_masked(!secret_masked, cx);
                                            });
                                            cx.notify();
                                        })),
                                    ),
                            ),
                    )
                    .child(self.form_real_secret.clone())
                    .when(
                        self.form_real_auth_kind == FormRealAuthKind::PrivateKey,
                        |d| {
                            d.child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(field_label("真实私钥解密口令 (无口令留空)", theme))
                                    .child(self.form_real_passphrase.clone()),
                            )
                        },
                    ),
            )
            // 第四行：出站代理配置
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(field_label("出站代理设置 (连接真实远端 SSH 时使用)", theme))
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(
                                        action_button("proxy-none", "直连 (无代理)", theme, true, false)
                                            .when(self.form_proxy_kind == FormProxyKind::None, |b| {
                                                b.bg(theme.accent).text_color(rgb(0xffffff))
                                            })
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.form_proxy_kind = FormProxyKind::None;
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        action_button("proxy-socks5", "SOCKS5 代理", theme, true, false)
                                            .when(
                                                self.form_proxy_kind == FormProxyKind::Socks5,
                                                |b| b.bg(theme.accent).text_color(rgb(0xffffff)),
                                            )
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.form_proxy_kind = FormProxyKind::Socks5;
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        action_button(
                                            "proxy-http",
                                            "HTTP CONNECT 代理",
                                            theme,
                                            true,
                                            false,
                                        )
                                        .when(
                                            self.form_proxy_kind == FormProxyKind::HttpConnect,
                                            |b| b.bg(theme.accent).text_color(rgb(0xffffff)),
                                        )
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.form_proxy_kind = FormProxyKind::HttpConnect;
                                            cx.notify();
                                        })),
                                    ),
                            ),
                    )
                    .when(self.form_proxy_kind != FormProxyKind::None, |d| {
                        d.child(
                            div()
                                .flex()
                                .gap_3()
                                .child(
                                    div()
                                        .flex_1()
                                        .flex()
                                        .flex_col()
                                        .gap_1()
                                        .child(field_label("代理主机地址", theme))
                                        .child(self.form_proxy_host.clone()),
                                )
                                .child(
                                    div()
                                        .w(px(110.))
                                        .flex()
                                        .flex_col()
                                        .gap_1()
                                        .child(field_label("代理端口", theme))
                                        .child(self.form_proxy_port.clone()),
                                )
                                .child(
                                    div()
                                        .w(px(150.))
                                        .flex()
                                        .flex_col()
                                        .gap_1()
                                        .child(field_label("代理账号 (可选)", theme))
                                        .child(self.form_proxy_user.clone()),
                                )
                                .child(
                                    div()
                                        .w(px(150.))
                                        .flex()
                                        .flex_col()
                                        .gap_1()
                                        .child(field_label("代理密码 (可选)", theme))
                                        .child(self.form_proxy_pass.clone()),
                                ),
                        )
                    }),
            )
            // 第五行：暴露给 Agent 的默认认证方式与保存按钮
            .child(
                div()
                    .pt_2()
                    .border_t_1()
                    .border_color(theme.border)
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(field_label("对 Agent 暴露认证方式:", theme))
                            .child(
                                action_button(
                                    "form-agent-mode-pwd",
                                    "临时随机密码",
                                    theme,
                                    true,
                                    false,
                                )
                                .when(
                                    self.form_agent_auth_mode == AgentAuthMode::EphemeralPassword,
                                    |b| b.bg(theme.accent).text_color(rgb(0xffffff)),
                                )
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.form_agent_auth_mode = AgentAuthMode::EphemeralPassword;
                                    cx.notify();
                                })),
                            )
                            .child(
                                action_button(
                                    "form-agent-mode-key",
                                    "专用本地密钥 (Ed25519)",
                                    theme,
                                    true,
                                    false,
                                )
                                .when(
                                    self.form_agent_auth_mode == AgentAuthMode::DedicatedKey,
                                    |b| b.bg(theme.accent).text_color(rgb(0xffffff)),
                                )
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.form_agent_auth_mode = AgentAuthMode::DedicatedKey;
                                    cx.notify();
                                })),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(
                                action_button(
                                    "form-save-submit",
                                    if is_editing {
                                        "保存配置修改 (需二次确认)"
                                    } else {
                                        "创建中转主机 (需二次确认)"
                                    },
                                    theme,
                                    true,
                                    false,
                                )
                                .bg(theme.accent)
                                .text_color(rgb(0xffffff))
                                .on_click(cx.listener(|this, _, _, cx| {
                                    match this.validate_and_build_host(cx) {
                                        Ok((host, is_new)) => {
                                            this.request_confirmation(
                                                PendingAction::SaveHost {
                                                    host: Box::new(host),
                                                    is_new,
                                                },
                                                cx,
                                            );
                                        }
                                        Err(err_msg) => {
                                            this.status_banner = Some((err_msg, true));
                                            cx.notify();
                                        }
                                    }
                                })),
                            ),
                    ),
            )
    }

    fn render_audit_logs_tab(
        &self,
        theme: WorkbenchTheme,
        _cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let mut all_logs = Vec::new();
        for host in &self.hosts {
            if let Some(rt) = self.runtimes.get(&host.id) {
                for log in &rt.logs {
                    all_logs.push(log.clone());
                }
            }
        }
        all_logs.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        div()
            .p_4()
            .rounded(px(6.))
            .bg(theme.bg_surface)
            .border_1()
            .border_color(theme.border)
            .flex()
            .flex_col()
            .gap_2()
            .child(
                div()
                    .text_size(px(14.))
                    .font_weight(gpui::FontWeight::BOLD)
                    .text_color(theme.text_primary)
                    .child("本地 SSH 认证与通道转发脱敏审计日志"),
            )
            .when(all_logs.is_empty(), |d| {
                d.child(
                    div()
                        .py_6()
                        .text_size(px(12.))
                        .text_color(theme.text_muted)
                        .child("暂无转发审计记录。启动任意机器中转或由 Agent 发起连接后将实时记录。"),
                )
            })
            .children(all_logs.into_iter().take(60).map(|entry| {
                div()
                    .px_3()
                    .py_2()
                    .rounded(px(4.))
                    .bg(theme.bg_code)
                    .border_1()
                    .border_color(theme.border)
                    .flex()
                    .items_center()
                    .justify_between()
                    .text_size(px(12.))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2p5()
                            .child(
                                div()
                                    .text_color(theme.text_muted)
                                    .child(entry.timestamp),
                            )
                            .child(
                                div()
                                    .px_1p5()
                                    .py_0p5()
                                    .rounded(px(3.))
                                    .bg(theme.accent_soft)
                                    .text_color(theme.accent_hover)
                                    .child(format!("[{}]", entry.codename)),
                            )
                            .child(
                                div()
                                    .font_weight(gpui::FontWeight::BOLD)
                                    .text_color(if entry.is_error {
                                        theme.danger
                                    } else {
                                        theme.text_primary
                                    })
                                    .child(entry.event),
                            ),
                    )
                    .child(
                        div()
                            .text_color(theme.text_secondary)
                            .child(entry.detail),
                    )
            }))
    }

    fn render_confirm_modal(
        &self,
        action: &PendingAction,
        theme: WorkbenchTheme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let is_destructive = action.is_destructive();
        let confirm_action_clone = action.clone();

        div()
            .id("confirm-modal-backdrop")
            .occlude()
            .absolute()
            .top_0()
            .left_0()
            .size_full()
            .bg(hsla(0., 0., 0., 0.62))
            .flex()
            .items_center()
            .justify_center()
            .on_mouse_down(MouseButton::Left, |_, _, _| {})
            .child(
                div()
                    .w(px(480.))
                    .p_5()
                    .rounded(px(8.))
                    .bg(theme.bg_surface)
                    .border_1()
                    .border_color(if is_destructive {
                        theme.danger
                    } else {
                        theme.border_focus
                    })
                    .shadow_lg()
                    .flex()
                    .flex_col()
                    .gap_3p5()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .text_size(px(16.))
                                    .font_weight(gpui::FontWeight::BOLD)
                                    .text_color(theme.text_primary)
                                    .child(action.title()),
                            )
                            .child(
                                div()
                                    .px_2()
                                    .py_0p5()
                                    .rounded(px(4.))
                                    .bg(if is_destructive {
                                        theme.danger_soft
                                    } else {
                                        theme.accent_soft
                                    })
                                    .text_color(if is_destructive {
                                        theme.danger
                                    } else {
                                        theme.accent_hover
                                    })
                                    .text_size(px(12.))
                                    .child(format!("目标: [{}]", action.codename())),
                            ),
                    )
                    .child(
                        div()
                            .p_3()
                            .rounded(px(5.))
                            .bg(theme.bg_code)
                            .border_1()
                            .border_color(theme.border)
                            .text_size(px(13.))
                            .text_color(theme.text_secondary)
                            .child(action.description()),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_end()
                            .gap_2p5()
                            .child(
                                action_button("modal-cancel-btn", "取消 (Esc)", theme, true, false)
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.pending_confirm = None;
                                        this.status_banner =
                                            Some(("已取消该操作".to_string(), false));
                                        cx.notify();
                                    })),
                            )
                            .child(
                                action_button(
                                    "modal-confirm-btn",
                                    action.confirm_button_label(),
                                    theme,
                                    true,
                                    is_destructive,
                                )
                                .bg(if is_destructive {
                                    theme.danger
                                } else {
                                    theme.accent
                                })
                                .text_color(rgb(0xffffff))
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.pending_confirm = None;
                                    this.execute_confirmed_action(
                                        confirm_action_clone.clone(),
                                        cx,
                                    );
                                })),
                            ),
                    ),
            )
    }
}

impl Render for AgentGateWorkbench {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = if self.is_dark {
            WorkbenchTheme::dark()
        } else {
            WorkbenchTheme::light()
        };

        div()
            .id("agentgate-root")
            .track_focus(&self.focus_handle)
            .on_action(cx.listener(Self::on_confirm_modal_action))
            .on_action(cx.listener(Self::on_cancel_modal_action))
            .on_action(|_: &HideToTrayAction, _window: &mut Window, _cx: &mut App| {
                platform_set_window_visible(false);
            })
            .on_action(|_: &NextFieldTab, window: &mut Window, _cx: &mut App| {
                window.focus_next();
            })
            .on_action(|_: &PrevFieldTab, window: &mut Window, _cx: &mut App| {
                window.focus_prev();
            })
            .size_full()
            .relative()
            .flex()
            .flex_col()
            .bg(theme.bg_app)
            .text_color(theme.text_primary)
            .child(self.render_top_bar(theme, cx))
            .child(self.render_status_bar(theme))
            .child(
                div()
                    .flex_1()
                    .w_full()
                    .overflow_hidden()
                    .flex()
                    .flex_row()
                    .child(self.render_left_host_list(theme, cx))
                    .child(self.render_right_workspace(theme, cx)),
            )
            .when_some(self.pending_confirm.clone(), |root, pending| {
                root.child(self.render_confirm_modal(&pending, theme, cx))
            })
    }
}

fn field_label(text: &'static str, theme: WorkbenchTheme) -> impl IntoElement {
    div()
        .text_size(px(12.))
        .font_weight(gpui::FontWeight::MEDIUM)
        .text_color(theme.text_secondary)
        .child(text)
}

fn action_button(
    id: impl Into<ElementId>,
    label: impl Into<SharedString>,
    theme: WorkbenchTheme,
    enabled: bool,
    danger: bool,
) -> Stateful<gpui::Div> {
    let border_col = if danger { theme.danger } else { theme.border };
    let text_col = if !enabled {
        theme.text_muted
    } else if danger {
        theme.danger_hover
    } else {
        theme.text_primary
    };

    div()
        .id(id)
        .h(px(30.))
        .px_3()
        .rounded(px(5.))
        .border_1()
        .border_color(border_col)
        .bg(theme.bg_elevated)
        .text_color(text_col)
        .text_size(px(12.))
        .flex()
        .items_center()
        .justify_center()
        .when(enabled, |b| {
            b.cursor_pointer().hover(move |s| {
                if danger {
                    s.bg(theme.danger).text_color(rgb(0xffffff))
                } else {
                    s.bg(theme.bg_subtle)
                }
            })
        })
        .when(!enabled, |b| b.opacity(0.45))
        .child(label.into())
}
