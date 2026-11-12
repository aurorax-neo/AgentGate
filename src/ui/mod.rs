pub mod text_input;
pub mod theme;

use std::collections::HashMap;
use std::fs;
use std::time::Duration;

use gpui::{
    App, ClipboardItem, Context, ElementId, Entity, FocusHandle, Focusable, KeyBinding,
    MouseButton, PathBuilder, SharedString, Stateful, Window, WindowControlArea, actions, canvas,
    div, hsla, point, prelude::*, px, rgb,
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
use crate::tray::{
    TrayCommand, is_window_visible, platform_set_window_visible, platform_toggle_maximize_window,
    poll_tray_command, restore_normal_window_level,
};
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
pub enum LogScope {
    #[default]
    SelectedHost,
    AllHosts,
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
    #[serde(default)]
    pub log_scope: LogScope,
    pub selected_host_id: Option<Uuid>,
}

impl Default for PersistedUiPrefs {
    fn default() -> Self {
        Self {
            is_dark: true,
            log_scope: LogScope::SelectedHost,
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
    show_local_pwd: bool,
    log_scope: LogScope,
    selected_host_id: Option<Uuid>,
    show_host_modal: bool,
    form_error: Option<String>,
    pending_confirm: Option<PendingAction>,
    status_banner: Option<(String, bool)>,

    // 搜索输入框
    search_input: Entity<TextField>,

    // 主机与代理弹窗表单状态
    editing_host_id: Option<Uuid>,
    form_codename: Entity<TextField>,
    form_label: Entity<TextField>,
    form_local_host: Entity<TextField>,
    form_local_port: Entity<TextField>,
    form_agent_password: Entity<TextField>,
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
            if host.local_bind_host.trim().is_empty() {
                host.local_bind_host = RelayHost::default_local_bind_host();
                modified_keys = true;
            }
            if host.local_port == 0 {
                host.local_port = std::env::var("AGENTGATE_MIGRATE_PORT")
                    .ok()
                    .and_then(|s| s.parse::<u16>().ok())
                    .filter(|p| *p > 0)
                    .unwrap_or_else(|| RelayHost::allocate_free_local_port(&host.local_bind_host));
                modified_keys = true;
            }
            if host.agent_password.trim().is_empty() {
                host.agent_password = RelayHost::generate_ephemeral_password();
                modified_keys = true;
            }
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
                    current_temp_password: Some(host.agent_password.clone()),
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
        let form_local_host = cx.new(|cx| TextField::new(cx, "127.0.0.1", false));
        let form_local_port = cx.new(|cx| TextField::new(cx, "本机固定端口 (1~65535)", false));
        let form_agent_password = cx.new(|cx| TextField::new(cx, "暴露给 Agent 的本地连接密码", true));
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
            show_local_pwd: false,
            log_scope: prefs.log_scope,
            selected_host_id,
            show_host_modal: false,
            form_error: None,
            pending_confirm: None,
            status_banner: Some(("就绪".to_string(), false)),
            search_input,
            editing_host_id: None,
            form_codename,
            form_label,
            form_local_host,
            form_local_port,
            form_agent_password,
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
                                if next {
                                    Self::activate_gpui_windows(cx);
                                    cx.spawn(async move |_, cx| {
                                        cx.background_executor()
                                            .timer(Duration::from_millis(120))
                                            .await;
                                        let _ = cx.update(|_cx| {
                                            restore_normal_window_level();
                                        });
                                    })
                                    .detach();
                                }
                                #[cfg(any(target_os = "linux", target_os = "freebsd"))]
                                Self::sync_linux_gpui_window_visibility(next, cx);
                            }
                            TrayCommand::ShowWindow => {
                                platform_set_window_visible(true);
                                Self::activate_gpui_windows(cx);
                                cx.spawn(async move |_, cx| {
                                    cx.background_executor()
                                        .timer(Duration::from_millis(120))
                                        .await;
                                    let _ = cx.update(|_cx| {
                                        restore_normal_window_level();
                                    });
                                })
                                .detach();
                                #[cfg(any(target_os = "linux", target_os = "freebsd"))]
                                Self::sync_linux_gpui_window_visibility(true, cx);
                            }
                            TrayCommand::HideWindow => {
                                platform_set_window_visible(false);
                                #[cfg(any(target_os = "linux", target_os = "freebsd"))]
                                Self::sync_linux_gpui_window_visibility(false, cx);
                            }
                            TrayCommand::QuitApp => {
                                this.shutdown_all_and_quit(cx);
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

    fn shutdown_all_and_quit(&mut self, cx: &mut Context<Self>) {
        for (_, ctrl) in self.controls.drain() {
            ctrl.stop();
        }
        for rt in self.runtimes.values_mut() {
            rt.rotate_or_clear_temp_password(None);
        }
        self.save_ui_prefs();
        cx.quit();
        std::process::exit(0);
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
            log_scope: self.log_scope,
            selected_host_id: self.selected_host_id,
        };
        if let Ok(json) = serde_json::to_string_pretty(&prefs) {
            let _ = fs::write(self.storage.base_dir().join("ui_state.json"), json);
        }
    }

    fn activate_gpui_windows(cx: &mut App) {
        cx.activate(true);
        for handle in cx.windows() {
            let _ = handle.update(cx, |_, window, _| {
                window.activate_window();
            });
        }
    }

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    fn sync_linux_gpui_window_visibility(visible: bool, cx: &mut App) {
        for handle in cx.windows() {
            let _ = handle.update(cx, |_, window, _| {
                if visible {
                    window.activate_window();
                } else {
                    window.minimize_window();
                }
            });
        }
    }

    fn apply_optional_demo_seed(&mut self, cx: &mut Context<Self>) {
        if !cfg!(debug_assertions) {
            return;
        }
        if std::env::var("AGENTGATE_DEMO_SEED").as_deref() != Ok("1") {
            return;
        }
        if self.hosts.is_empty() {
            let now = RelayHost::now_str();
            let mut h1 = RelayHost {
                id: Uuid::new_v4(),
                codename: "cobalt-nexus-01".to_string(),
                label: "内网测试机 108 (容器集群)".to_string(),
                local_bind_host: "127.0.0.1".to_string(),
                local_port: RelayHost::allocate_free_local_port("127.0.0.1"),
                agent_password: RelayHost::generate_ephemeral_password(),
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
                pinned_host_key_openssh: None,
                created_at: now.clone(),
                updated_at: now.clone(),
            };
            let mut h2 = RelayHost {
                id: Uuid::new_v4(),
                codename: "jade-sentry-02".to_string(),
                label: "训练推理节点 (GPU-A100)".to_string(),
                local_bind_host: "127.0.0.1".to_string(),
                local_port: RelayHost::allocate_free_local_port("127.0.0.1"),
                agent_password: RelayHost::generate_ephemeral_password(),
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
                pinned_host_key_openssh: None,
                created_at: now.clone(),
                updated_at: now.clone(),
            };
            let h3 = RelayHost {
                id: Uuid::new_v4(),
                codename: "amber-citadel-03".to_string(),
                label: "只读预发节点 (直连)".to_string(),
                local_bind_host: "127.0.0.1".to_string(),
                local_port: RelayHost::allocate_free_local_port("127.0.0.1"),
                agent_password: RelayHost::generate_ephemeral_password(),
                real_host: "192.168.31.205".to_string(),
                real_port: 22,
                real_user: "deploy".to_string(),
                real_auth: RealAuthConfig::Password {
                    password: "DemoRealSecretPassword#Stage".to_string(),
                },
                proxy: ProxyConfig::None,
                agent_auth_mode: AgentAuthMode::EphemeralPassword,
                dedicated_key_openssh_pem: None,
                pinned_host_key_openssh: None,
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
                    current_temp_password: Some(h.agent_password.clone()),
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
                    "host_form" | "host_modal" => {
                        self.populate_form_from_host(&h1, cx);
                        self.show_host_modal = true;
                    }
                    "audit_logs" => {
                        self.log_scope = LogScope::AllHosts;
                    }
                    "light_overview" => {
                        self.is_dark = false;
                        self.sync_inputs_theme(cx);
                        self.selected_host_id = Some(h2.id);
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
            &self.form_local_host,
            &self.form_local_port,
            &self.form_agent_password,
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
            RelayEvent::Stopped {
                host_id,
                codename,
                local_port,
            } => {
                if self
                    .controls
                    .get(&host_id)
                    .is_some_and(|ctrl| ctrl.local_port != local_port)
                {
                    return;
                }
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
            RelayEvent::HostKeyPinned {
                host_id,
                codename: _,
                pubkey_openssh,
            } => {
                if let Some(host) = self.hosts.iter_mut().find(|h| h.id == host_id) {
                    host.pinned_host_key_openssh = Some(pubkey_openssh);
                    let _ = self.storage.save_hosts(&self.hosts);
                }
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
                local_port,
                message,
            } => {
                if self
                    .controls
                    .get(&host_id)
                    .is_some_and(|ctrl| ctrl.local_port != local_port)
                {
                    return;
                }
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
        self.form_error = None;
        let next_codename = RelayHost::generate_codename(self.hosts.len());
        let default_bind = RelayHost::default_local_bind_host();
        let free_port = RelayHost::allocate_free_local_port(&default_bind);
        let init_pwd = RelayHost::generate_ephemeral_password();
        self.form_codename.update(cx, |f, cx| f.set_text(next_codename, cx));
        self.form_label.update(cx, |f, cx| f.set_text("", cx));
        self.form_local_host
            .update(cx, |f, cx| f.set_text(default_bind, cx));
        self.form_local_port
            .update(cx, |f, cx| f.set_text(free_port.to_string(), cx));
        self.form_agent_password
            .update(cx, |f, cx| f.set_text(init_pwd, cx));
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
        self.form_error = None;
        self.form_codename
            .update(cx, |f, cx| f.set_text(host.codename.clone(), cx));
        self.form_label
            .update(cx, |f, cx| f.set_text(host.label.clone(), cx));
        self.form_local_host.update(cx, |f, cx| {
            f.set_text(
                if host.local_bind_host.trim().is_empty() {
                    RelayHost::default_local_bind_host()
                } else {
                    host.local_bind_host.clone()
                },
                cx,
            )
        });
        self.form_local_port
            .update(cx, |f, cx| f.set_text(host.local_port.to_string(), cx));
        self.form_agent_password
            .update(cx, |f, cx| f.set_text(host.agent_password.clone(), cx));
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
        if codename.eq_ignore_ascii_case("agent") {
            return Err("不允许使用通用保留名 `agent` 作为代号，请使用可区分的唯一代号".to_string());
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

        let local_bind_host = self.form_local_host.read(cx).text().trim().to_string();
        if local_bind_host.is_empty() {
            return Err("本机监听地址不能为空（推荐填写 127.0.0.1）".to_string());
        }
        let local_port: u16 = self
            .form_local_port
            .read(cx)
            .text()
            .trim()
            .parse()
            .ok()
            .filter(|p| *p > 0)
            .ok_or_else(|| "本机监听端口必须是 1~65535 之间的整数".to_string())?;
        if self
            .hosts
            .iter()
            .any(|h| h.id != id && h.local_bind_host == local_bind_host && h.local_port == local_port)
        {
            return Err(format!(
                "本机监听地址 {}:{} 已被其它机器条目占用，请更换端口",
                local_bind_host, local_port
            ));
        }
        let agent_password = self.form_agent_password.read(cx).text().trim().to_string();
        if agent_password.is_empty() {
            return Err("本地连接密码不能为空".to_string());
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
        if codename.eq_ignore_ascii_case(&real_user) {
            return Err("为保障身份隔离，机器代号 (Codename) 不能与真实远端用户名相同".to_string());
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
        let pinned_host_key_openssh = existing.and_then(|h| {
            if h.real_host == real_host && h.real_port == real_port {
                h.pinned_host_key_openssh.clone()
            } else {
                None
            }
        });
        let now = RelayHost::now_str();
        let host = RelayHost {
            id,
            codename,
            label: self.form_label.read(cx).text().trim().to_string(),
            local_bind_host,
            local_port,
            agent_password,
            real_host,
            real_port,
            real_user,
            real_auth,
            proxy,
            agent_auth_mode: self.form_agent_auth_mode,
            dedicated_key_openssh_pem: existing.and_then(|h| h.dedicated_key_openssh_pem.clone()),
            pinned_host_key_openssh,
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
            temp_password: rt
                .current_temp_password
                .clone()
                .or_else(|| Some(host.agent_password.clone())),
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
        } else if self.show_host_modal {
            self.show_host_modal = false;
            self.form_error = None;
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
                rt.current_temp_password = Some(host.agent_password.clone());
                rt.status = RelayStatus::Starting;
                let live_creds = Self::build_live_credentials(&host, rt);
                let tx = self.event_tx.clone();
                let bind_host = host.local_bind_host.clone();
                let handle_res = global_tokio_runtime()
                    .block_on(start_host_relay(host, live_creds, tx));
                match handle_res {
                    Ok(ctrl) => {
                        let port = ctrl.local_port;
                        if let Some(h) = self.hosts.iter_mut().find(|h| h.id == id)
                            && h.local_port != port
                        {
                            h.local_port = port;
                            let _ = self.storage.save_hosts(&self.hosts);
                        }
                        self.controls.insert(id, ctrl);
                        if let Some(rt) = self.runtimes.get_mut(&id) {
                            rt.status = RelayStatus::Running {
                                local_port: port,
                                active_sessions: 0,
                            };
                        }
                        self.status_banner = Some((
                            format!("已启动代号 [{}] 本地监听 {}:{}", codename, bind_host, port),
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
                }
                self.status_banner = Some((
                    format!("已停止代号 [{}] 在端口 {} 的中转服务（端口与密码保持不变）", codename, local_port),
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
                    }
                }
                self.status_banner = Some((
                    format!("已停止全部 {} 条本地 SSH 中转服务", running_count),
                    false,
                ));
            }
            PendingAction::SaveHost { mut host, is_new } => {
                let prev_snapshot = if !is_new {
                    self.hosts
                        .iter()
                        .find(|h| h.id == host.id)
                        .map(|h| (h.codename.clone(), h.local_bind_host.clone(), h.local_port))
                } else {
                    None
                };

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

                if let Some((prev_name, _, _)) = &prev_snapshot
                    && prev_name != &host.codename
                {
                    self.storage.remove_dedicated_key_file(&prev_name);
                }

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
                    current_temp_password: Some(host.agent_password.clone()),
                    dedicated_key_path: None,
                    dedicated_pubkey_openssh: None,
                    total_connections: 0,
                    logs: Vec::new(),
                });
                rt.rotate_or_clear_temp_password(Some(host.agent_password.clone()));
                rt.dedicated_key_path = Some(key_path.to_string_lossy().to_string());
                rt.dedicated_pubkey_openssh = Some(pubkey);
                rt.push_log(
                    &codename,
                    if is_new { "新建主机" } else { "更新主机" },
                    format!(
                        "本机监听: {}:{} | 代理: {} | Agent 认证: {}",
                        host.local_bind_host,
                        host.local_port,
                        host.proxy.badge_text(),
                        host.agent_auth_mode.label()
                    ),
                    false,
                );

                let bind_changed = prev_snapshot
                    .as_ref()
                    .is_some_and(|(_, old_bind, old_port)| {
                        old_bind != &host.local_bind_host || *old_port != host.local_port
                    });
                if bind_changed && self.controls.contains_key(&id) {
                    if let Some(old_ctrl) = self.controls.remove(&id) {
                        old_ctrl.stop();
                    }
                    let live_creds = Self::build_live_credentials(&host, rt);
                    let tx = self.event_tx.clone();
                    if let Ok(new_ctrl) = global_tokio_runtime()
                        .block_on(start_host_relay((*host).clone(), live_creds, tx))
                    {
                        let p = new_ctrl.local_port;
                        self.controls.insert(id, new_ctrl);
                        if let Some(rt) = self.runtimes.get_mut(&id) {
                            rt.status = RelayStatus::Running {
                                local_port: p,
                                active_sessions: 0,
                            };
                        }
                    }
                } else if let Some(ctrl) = self.controls.get(&id) {
                    let creds = Self::build_live_credentials(&host, rt);
                    ctrl.update_host((*host).clone());
                    ctrl.update_credentials(creds);
                }

                self.selected_host_id = Some(id);
                self.show_host_modal = false;
                self.form_error = None;
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
                        self.hosts[host_idx].agent_password = new_pwd.clone();
                        self.hosts[host_idx].updated_at = RelayHost::now_str();
                        let _ = self.storage.save_hosts(&self.hosts);
                        if let Some(rt) = self.runtimes.get_mut(&id) {
                            rt.rotate_or_clear_temp_password(Some(new_pwd));
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
        let (banner_msg, banner_is_err) = self
            .status_banner
            .clone()
            .unwrap_or_else(|| ("就绪".to_string(), false));
        let dot_color = if banner_is_err {
            theme.danger
        } else {
            theme.success
        };

        div()
            .h(px(50.))
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
                    .flex_1()
                    .h_full()
                    .flex()
                    .items_center()
                    .gap_2p5()
                    .min_w_0()
                    .window_control_area(WindowControlArea::Drag)
                    .child(
                        div()
                            .px_2p5()
                            .h(px(28.))
                            .rounded(px(5.))
                            .bg(theme.accent)
                            .text_color(rgb(0xffffff))
                            .text_size(px(13.))
                            .font_weight(gpui::FontWeight::BOLD)
                            .flex()
                            .items_center()
                            .child("AgentGate"),
                    )
                    .child(
                        div()
                            .px_2()
                            .h(px(24.))
                            .rounded(px(4.))
                            .bg(theme.success_soft)
                            .text_color(theme.success)
                            .text_size(px(11.5))
                            .flex()
                            .items_center()
                            .child(format!("运行中 {} / {}", running_count, self.hosts.len())),
                    )
                    .child(
                        div()
                            .px_2()
                            .h(px(24.))
                            .rounded(px(4.))
                            .bg(theme.accent_soft)
                            .text_color(theme.accent_hover)
                            .text_size(px(11.5))
                            .flex()
                            .items_center()
                            .child(format!("活跃会话 {}", active_sessions)),
                    )
                    .child(
                        div()
                            .pl_2()
                            .flex()
                            .items_center()
                            .gap_1p5()
                            .text_size(px(12.))
                            .child(div().size(px(7.)).rounded(px(3.5)).bg(dot_color))
                            .child(
                                div()
                                    .text_color(if banner_is_err {
                                        theme.danger
                                    } else {
                                        theme.text_secondary
                                    })
                                    .child(banner_msg),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(div().w(px(196.)).child(self.search_input.clone()))
                    .child(
                        action_button(
                            "btn-new-host",
                            "+ 新建",
                            theme,
                            true,
                            false,
                        )
                        .bg(theme.accent)
                        .text_color(rgb(0xffffff))
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.reset_form_for_new_host(cx);
                            this.show_host_modal = true;
                            cx.notify();
                        })),
                    )
                    .child(
                        action_button(
                            "btn-stop-all",
                            "全停",
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
                        theme_icon_button("btn-theme-toggle", self.is_dark, theme)
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.is_dark = !this.is_dark;
                            this.sync_inputs_theme(cx);
                            this.save_ui_prefs();
                            cx.notify();
                        })),
                    )
                    .when(cfg!(not(target_os = "macos")), |bar| {
                        bar.child(
                            div()
                                .pl_1()
                                .flex()
                                .items_center()
                                .gap_1()
                                .child(
                                    window_ctrl_button("win-btn-min", "—", theme, false)
                                        .on_click(cx.listener(|_, _, window, _| {
                                            platform_set_window_visible(false);
                                            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
                                            window.minimize_window();
                                            #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
                                            let _ = window;
                                        })),
                                )
                                .child(
                                    window_ctrl_button("win-btn-max", "□", theme, false)
                                        .on_click(cx.listener(|_, _, window, _| {
                                            platform_toggle_maximize_window(window);
                                        })),
                                )
                                .child(
                                    window_ctrl_button("win-btn-close", "×", theme, true)
                                        .on_click(cx.listener(|_, _, window, _| {
                                            platform_set_window_visible(false);
                                            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
                                            window.minimize_window();
                                            #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
                                            let _ = window;
                                        })),
                                ),
                        )
                    }),
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
            .w(px(300.))
            .h_full()
            .flex()
            .flex_col()
            .bg(theme.bg_surface)
            .border_r_1()
            .border_color(theme.border)
            .child(
                div()
                    .h(px(36.))
                    .px_3p5()
                    .flex()
                    .items_center()
                    .justify_between()
                    .border_b_1()
                    .border_color(theme.border)
                    .text_size(px(11.5))
                    .text_color(theme.text_secondary)
                    .child("机器代号列表")
                    .child(format!("{} 台", filtered_hosts.len())),
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
                                .p_5()
                                .flex()
                                .flex_col()
                                .gap_2()
                                .text_size(px(12.5))
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
                        let active_port = rt.status.local_port().unwrap_or(host.local_port);
                        let bind_host = if host.local_bind_host.trim().is_empty() {
                            "127.0.0.1"
                        } else {
                            host.local_bind_host.trim()
                        };

                        let row_bg = if is_selected {
                            theme.bg_subtle
                        } else {
                            theme.bg_surface
                        };

                        div()
                            .id(("host-row", idx))
                            .w_full()
                            .px_3()
                            .py_2p5()
                            .bg(row_bg)
                            .border_b_1()
                            .border_color(theme.border)
                            .border_l_2()
                            .border_color(if is_selected {
                                theme.accent
                            } else {
                                theme.border
                            })
                            .hover(|s| s.bg(theme.bg_elevated))
                            .cursor_pointer()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.selected_host_id = Some(id);
                                this.save_ui_prefs();
                                cx.notify();
                            }))
                            .flex()
                            .flex_col()
                            .gap_1p5()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_1p5()
                                            .child(
                                                div()
                                                    .size(px(7.))
                                                    .rounded(px(3.5))
                                                    .bg(if is_running {
                                                        theme.success
                                                    } else {
                                                        theme.text_muted
                                                    }),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(13.5))
                                                    .font_weight(gpui::FontWeight::BOLD)
                                                    .text_color(theme.text_primary)
                                                    .child(format!("[{}]", host.codename)),
                                            ),
                                    )
                                    .child({
                                        let codename_toggle = codename.clone();
                                        let stop_port = rt.status.local_port();
                                        action_button(
                                            ("row-toggle", idx),
                                            if is_running { "停止" } else { "启动" },
                                            theme,
                                            true,
                                            is_running,
                                        )
                                        .h(px(23.))
                                        .px_2()
                                        .text_size(px(11.))
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.selected_host_id = Some(id);
                                            if let Some(p) = stop_port {
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
                                    }),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .text_size(px(11.5))
                                    .child(
                                        div()
                                            .text_color(if is_running {
                                                theme.success
                                            } else {
                                                theme.text_secondary
                                            })
                                            .child(format!("{}:{}", bind_host, active_port)),
                                    )
                                    .child(
                                        div()
                                            .text_color(theme.text_muted)
                                            .child(format!(
                                                "{} · {}",
                                                host.proxy.badge_text(),
                                                match host.agent_auth_mode {
                                                    AgentAuthMode::EphemeralPassword => "密码",
                                                    AgentAuthMode::DedicatedKey => "密钥",
                                                }
                                            )),
                                    ),
                            )
                            .child(
                                div()
                                    .text_size(px(11.))
                                    .text_color(theme.text_muted)
                                    .child(if host.label.is_empty() {
                                        host.masked_real_endpoint()
                                    } else {
                                        host.label.clone()
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
        let Some(selected_id) = self.selected_host_id else {
            return div()
                .flex_1()
                .h_full()
                .p_8()
                .flex()
                .items_center()
                .justify_center()
                .text_size(px(13.))
                .text_color(theme.text_muted)
                .child("请从左侧选择一条机器代号，或点击右上角「+ 新建主机」弹窗创建。")
                .into_any_element();
        };
        let Some(host) = self.hosts.iter().find(|h| h.id == selected_id).cloned() else {
            return div()
                .flex_1()
                .h_full()
                .p_8()
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
        let running_port = rt.status.local_port();
        let display_port = running_port.unwrap_or(host.local_port);
        let bind_host = if host.local_bind_host.trim().is_empty() {
            "127.0.0.1"
        } else {
            host.local_bind_host.trim()
        };
        let codename = host.codename.clone();

        let mut preview_rt = rt.clone();
        if !is_running && display_port > 0 {
            preview_rt.status = RelayStatus::Running {
                local_port: display_port,
                active_sessions: 0,
            };
        }
        let snippet_preview =
            render_agent_snippet(&host, &preview_rt, CopyFormat::AgentPromptCard)
                .unwrap_or_else(|e| e.to_string());

        div()
            .flex_1()
            .min_w_0()
            .h_full()
            .overflow_hidden()
            .flex()
            .flex_col()
            .bg(theme.bg_app)
            // 第一区：主机顶栏（身份、固定监听端口状态、核心操作按钮）
            .child(
                div()
                    .w_full()
                    .px_5()
                    .py_3p5()
                    .bg(theme.bg_surface)
                    .border_b_1()
                    .border_color(theme.border)
                    .flex()
                    .flex_col()
                    .gap_1p5()
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
                                            .text_size(px(17.))
                                            .font_weight(gpui::FontWeight::BOLD)
                                            .text_color(theme.text_primary)
                                            .child(format!("[{}]", host.codename)),
                                    )
                                    .child(
                                        div()
                                            .px_2()
                                            .py_0p5()
                                            .rounded(px(4.))
                                            .text_size(px(11.5))
                                            .bg(if is_running {
                                                theme.success_soft
                                            } else {
                                                hsla(0., 0., 0.5, 0.14)
                                            })
                                            .text_color(if is_running {
                                                theme.success
                                            } else {
                                                theme.text_secondary
                                            })
                                            .child(if is_running {
                                                format!("运行中 · {}:{}", bind_host, display_port)
                                            } else {
                                                format!("已停止 · 固定端口 {}:{}", bind_host, display_port)
                                            }),
                                    )
                                    .when(!host.label.is_empty(), |d| {
                                        d.child(
                                            div()
                                                .text_size(px(12.5))
                                                .text_color(theme.text_secondary)
                                                .child(host.label.clone()),
                                        )
                                            }),
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
                                                "停止"
                                            } else {
                                                "启动"
                                            },
                                            theme,
                                            true,
                                            is_running,
                                        )
                                        .when(!is_running, |b| {
                                            b.bg(theme.accent).text_color(rgb(0xffffff))
                                        })
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            if let Some(p) = running_port {
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
                                            "编辑",
                                            theme,
                                            true,
                                            false,
                                        )
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.populate_form_from_host(&host_edit, cx);
                                            this.show_host_modal = true;
                                            cx.notify();
                                        }))
                                    })
                                    .child({
                                        let c_del = codename.clone();
                                        action_button(
                                            "detail-delete-host",
                                            "删除",
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
                            .text_size(px(11.5))
                            .text_color(theme.text_muted)
                            .child(format!(
                                "本机监听: {}:{}   ·   脱敏远端: {}   ·   出站代理: {}   ·   指纹: {}   ·   会话: {} 活跃 / {} 累计",
                                bind_host,
                                display_port,
                                host.masked_real_endpoint(),
                                host.proxy.badge_text(),
                                if host.pinned_host_key_openssh.is_some() {
                                    "已绑定 (TOFU)"
                                } else {
                                    "首次连接自动绑定"
                                },
                                rt.status.active_sessions(),
                                rt.total_connections
                            )),
                    ),
            )
            // 第二区：双栏核心操作区（左栏：本地监听与凭证控制；右栏：发给 AI Agent 的配置与一键复制）
            .child(
                div()
                    .w_full()
                    .px_5()
                    .py_4()
                    .border_b_1()
                    .border_color(theme.border)
                    .flex()
                    .gap_4()
                    .child(
                        // 左栏：本地隔离凭证与认证方式
                        div()
                            .flex_1()
                            .min_w_0()
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
                                            .text_size(px(13.5))
                                            .font_weight(gpui::FontWeight::BOLD)
                                            .text_color(theme.text_primary)
                                            .child("本地隔离凭证"),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_1p5()
                                            .child({
                                                let c1 = codename.clone();
                                                let is_pwd = host.agent_auth_mode
                                                    == AgentAuthMode::EphemeralPassword;
                                                action_button(
                                                    "switch-mode-pwd",
                                                    "密码",
                                                    theme,
                                                    !is_pwd,
                                                    false,
                                                )
                                                .h(px(26.))
                                                .px_2p5()
                                                .when(is_pwd, |b| {
                                                    b.bg(theme.accent)
                                                        .text_color(rgb(0xffffff))
                                                        .opacity(1.0)
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
                                                let is_key = host.agent_auth_mode
                                                    == AgentAuthMode::DedicatedKey;
                                                action_button(
                                                    "switch-mode-key",
                                                    "密钥",
                                                    theme,
                                                    !is_key,
                                                    false,
                                                )
                                                .h(px(26.))
                                                .px_2p5()
                                                .when(is_key, |b| {
                                                    b.bg(theme.accent)
                                                        .text_color(rgb(0xffffff))
                                                        .opacity(1.0)
                                                })
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    if !is_key {
                                                        this.request_confirmation(
                                                            PendingAction::ToggleAgentAuthMode {
                                                                id: selected_id,
                                                                codename: c2.clone(),
                                                                target_mode:
                                                                    AgentAuthMode::DedicatedKey,
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
                                    .p_3()
                                    .rounded(px(5.))
                                    .bg(theme.bg_code)
                                    .border_1()
                                    .border_color(theme.border)
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .gap_2()
                                    .child(
                                        div()
                                            .flex_1()
                                            .min_w_0()
                                            .overflow_hidden()
                                            .flex()
                                            .flex_col()
                                            .gap_1()
                                            .child(
                                                div()
                                                    .text_size(px(11.))
                                                    .text_color(theme.text_muted)
                                                    .child(match host.agent_auth_mode {
                                                        AgentAuthMode::EphemeralPassword => {
                                                            "当前本地连接密码 (除手动更改外固定不变)"
                                                        }
                                                        AgentAuthMode::DedicatedKey => {
                                                            "本机专用 Ed25519 私钥路径 (0600 权限)"
                                                        }
                                                    }),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(12.5))
                                                    .font_weight(gpui::FontWeight::BOLD)
                                                    .text_color(theme.text_primary)
                                                    .child(match host.agent_auth_mode {
                                                        AgentAuthMode::EphemeralPassword => {
                                                            if self.show_local_pwd {
                                                                host.agent_password.clone()
                                                            } else {
                                                                "•".repeat(host.agent_password.len().min(27))
                                                            }
                                                        }
                                                        AgentAuthMode::DedicatedKey => rt
                                                            .dedicated_key_path
                                                            .clone()
                                                            .unwrap_or_else(|| "未生成".to_string()),
                                                    }),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_1p5()
                                            .when(
                                                host.agent_auth_mode
                                                    == AgentAuthMode::EphemeralPassword,
                                                |row| {
                                                    row.child(
                                                        eye_icon_button(
                                                            "btn-eye-local-pwd",
                                                            self.show_local_pwd,
                                                            theme,
                                                        )
                                                        .on_click(cx.listener(|this, _, _, cx| {
                                                            this.show_local_pwd =
                                                                !this.show_local_pwd;
                                                            cx.notify();
                                                        })),
                                                    )
                                                },
                                            )
                                            .child({
                                                let val_to_copy = match host.agent_auth_mode {
                                                    AgentAuthMode::EphemeralPassword => {
                                                        host.agent_password.clone()
                                                    }
                                                    AgentAuthMode::DedicatedKey => rt
                                                        .dedicated_key_path
                                                        .clone()
                                                        .unwrap_or_default(),
                                                };
                                                let c_copy = codename.clone();
                                                action_button(
                                                    "btn-copy-local-cred",
                                                    "复制",
                                                    theme,
                                                    !val_to_copy.is_empty(),
                                                    false,
                                                )
                                                .h(px(26.))
                                                .px_2p5()
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    if !val_to_copy.is_empty() {
                                                        cx.write_to_clipboard(
                                                            ClipboardItem::new_string(
                                                                val_to_copy.clone(),
                                                            ),
                                                        );
                                                        this.status_banner = Some((
                                                            format!(
                                                                "已复制代号 [{}] 的本地凭证到剪贴板",
                                                                c_copy
                                                            ),
                                                            false,
                                                        ));
                                                        cx.notify();
                                                    }
                                                }))
                                            })
                                            .child({
                                                let c_rot = codename.clone();
                                                let mode = host.agent_auth_mode;
                                                action_button(
                                                    "btn-rotate-cred",
                                                    match mode {
                                                        AgentAuthMode::EphemeralPassword => "轮换",
                                                        AgentAuthMode::DedicatedKey => "重置",
                                                    },
                                                    theme,
                                                    true,
                                                    false,
                                                )
                                                .h(px(26.))
                                                .px_2p5()
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
                                    .flex()
                                    .flex_col()
                                    .gap_1p5()
                                    .text_size(px(12.))
                                    .child(
                                        div()
                                            .flex()
                                            .justify_between()
                                            .child(
                                                div().text_color(theme.text_muted).child("本机固定监听"),
                                            )
                                            .child(
                                                div()
                                                    .text_color(theme.text_primary)
                                                    .child(format!("{}:{}", bind_host, display_port)),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .justify_between()
                                            .child(
                                                div()
                                                    .text_color(theme.text_muted)
                                                    .child("Agent 登录用户"),
                                            )
                                            .child(
                                                div()
                                                    .text_color(theme.text_primary)
                                                    .child(host.codename.clone()),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .justify_between()
                                            .child(
                                                div().text_color(theme.text_muted).child("真实远端目标"),
                                            )
                                            .child(
                                                div()
                                                    .text_color(theme.text_secondary)
                                                    .child(host.masked_real_endpoint()),
                                            ),
                                    ),
                            ),
                    )
                    .child(
                        // 右栏：发给 AI Agent 的配置预览与一键复制
                        div()
                            .flex_1()
                            .min_w_0()
                            .p_4()
                            .rounded(px(6.))
                            .bg(theme.bg_surface)
                            .border_1()
                            .border_color(theme.border)
                            .flex()
                            .flex_col()
                            .gap_2p5()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .child(
                                        div()
                                            .text_size(px(13.5))
                                            .font_weight(gpui::FontWeight::BOLD)
                                            .text_color(theme.text_primary)
                                            .child("AI Agent 接入配置"),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_1p5()
                                            .child({
                                                let c_card = codename.clone();
                                                action_button(
                                                    "btn-copy-agent-card",
                                                    "复制卡片",
                                                    theme,
                                                    is_running,
                                                    false,
                                                )
                                                .h(px(26.))
                                                .px_2p5()
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
                                                    } else {
                                                        this.status_banner = Some((
                                                            format!(
                                                                "请先启动代号 [{}] 的中转服务后再复制",
                                                                c_card
                                                            ),
                                                            true,
                                                        ));
                                                        cx.notify();
                                                    }
                                                }))
                                            })
                                            .child({
                                                let c_cmd = codename.clone();
                                                action_button(
                                                    "btn-copy-ssh-cmd",
                                                    "复制命令",
                                                    theme,
                                                    is_running,
                                                    false,
                                                )
                                                .h(px(26.))
                                                .px_2p5()
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
                                    .p_2p5()
                                    .rounded(px(5.))
                                    .bg(theme.bg_code)
                                    .border_1()
                                    .border_color(theme.border)
                                    .text_size(px(11.5))
                                    .text_color(theme.text_primary)
                                    .flex()
                                    .flex_col()
                                    .gap_0p5()
                                    .children(
                                        snippet_preview
                                            .lines()
                                            .map(|line| div().child(line.to_string())),
                                    ),
                            ),
                    ),
            )
            // 第三区：底部实时转发审计流
            .child(self.render_audit_logs_tab(theme, cx))
            .into_any_element()
    }

    fn render_host_modal(
        &self,
        theme: WorkbenchTheme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let is_editing = self.editing_host_id.is_some();
        let secret_masked = self.form_real_secret.read(cx).is_masked();
        let agent_pwd_masked = self.form_agent_password.read(cx).is_masked();
        let proxy_pwd_masked = self.form_proxy_pass.read(cx).is_masked();

        div()
            .id("host-editor-modal-backdrop")
            .occlude()
            .absolute()
            .top_0()
            .left_0()
            .size_full()
            .bg(hsla(0., 0., 0., 0.58))
            .flex()
            .items_center()
            .justify_center()
            .on_mouse_down(MouseButton::Left, |_, _, _| {})
            .child(
                div()
                    .w(px(660.))
                    .p_5()
                    .rounded(px(8.))
                    .bg(theme.bg_surface)
                    .border_1()
                    .border_color(theme.border_focus)
                    .shadow_lg()
                    .flex()
                    .flex_col()
                    .gap_3p5()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .pb_2p5()
                            .border_b_1()
                            .border_color(theme.border)
                            .child(
                                div()
                                    .text_size(px(15.5))
                                    .font_weight(gpui::FontWeight::BOLD)
                                    .text_color(theme.text_primary)
                                    .child(if is_editing {
                                        "编辑 SSH 中转主机与监听配置"
                                    } else {
                                        "新建 SSH 中转主机"
                                    }),
                            )
                            .child(
                                action_button("form-modal-close", "关闭", theme, true, false)
                                    .h(px(26.))
                                    .px_2p5()
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.show_host_modal = false;
                                        this.form_error = None;
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
                                    .gap_1()
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .justify_between()
                                            .child(field_label(
                                                "机器代号 (Codename)",
                                                theme,
                                            ))
                                            .child(
                                                div()
                                                    .id("btn-random-codename")
                                                    .text_size(px(11.))
                                                    .text_color(theme.accent_hover)
                                                    .cursor_pointer()
                                                    .child("随机")
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        let generated =
                                                            RelayHost::generate_codename(
                                                                this.hosts.len(),
                                                            );
                                                        this.form_codename.update(cx, |f, cx| {
                                                            f.set_text(generated, cx)
                                                        });
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
                                    .gap_1()
                                    .child(field_label("本机备注 (仅本机可见)", theme))
                                    .child(self.form_label.clone()),
                            ),
                    )
                    // 第二行：本机监听地址、本机固定端口、本机连接密码（新建后除手动修改外固定不变）
                    .child(
                        div()
                            .flex()
                            .gap_3()
                            .child(
                                div()
                                    .w(px(150.))
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(field_label("本机监听地址", theme))
                                    .child(self.form_local_host.clone()),
                            )
                            .child(
                                div()
                                    .w(px(130.))
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .justify_between()
                                            .child(field_label("本机固定端口", theme))
                                            .child(
                                                div()
                                                    .id("btn-random-port")
                                                    .text_size(px(11.))
                                                    .text_color(theme.accent_hover)
                                                    .cursor_pointer()
                                                    .child("随机")
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        let bind = this
                                                            .form_local_host
                                                            .read(cx)
                                                            .text()
                                                            .trim()
                                                            .to_string();
                                                        let p =
                                                            RelayHost::allocate_free_local_port(
                                                                &bind,
                                                            );
                                                        this.form_local_port.update(cx, |f, cx| {
                                                            f.set_text(p.to_string(), cx)
                                                        });
                                                        cx.notify();
                                                    })),
                                            ),
                                    )
                                    .child(self.form_local_port.clone()),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .justify_between()
                                            .child(field_label("Agent 本地连接密码", theme))
                                            .child(
                                                div()
                                                    .flex()
                                                    .items_center()
                                                    .gap_1p5()
                                                    .child(
                                                        eye_icon_button(
                                                            "btn-eye-form-agent-pwd",
                                                            !agent_pwd_masked,
                                                            theme,
                                                        )
                                                        .size(px(22.))
                                                        .on_click(cx.listener(
                                                            move |this, _, _, cx| {
                                                                this.form_agent_password.update(
                                                                    cx,
                                                                    |f, cx| {
                                                                        f.set_masked(
                                                                            !agent_pwd_masked,
                                                                            cx,
                                                                        )
                                                                    },
                                                                );
                                                                cx.notify();
                                                            },
                                                        )),
                                                    )
                                                    .child(
                                                        div()
                                                            .id("btn-copy-form-agent-pwd")
                                                            .text_size(px(11.))
                                                            .text_color(theme.accent_hover)
                                                            .cursor_pointer()
                                                            .child("复制")
                                                            .on_click(cx.listener(
                                                                |this, _, _, cx| {
                                                                    let val = this
                                                                        .form_agent_password
                                                                        .read(cx)
                                                                        .text();
                                                                    if !val.is_empty() {
                                                                        cx.write_to_clipboard(
                                                                            ClipboardItem::new_string(
                                                                                val,
                                                                            ),
                                                                        );
                                                                        this.status_banner = Some((
                                                                            "已复制本地连接密码到剪贴板"
                                                                                .to_string(),
                                                                            false,
                                                                        ));
                                                                        cx.notify();
                                                                    }
                                                                },
                                                            )),
                                                    )
                                                    .child(
                                                        div()
                                                            .id("btn-random-agent-pwd")
                                                            .text_size(px(11.))
                                                            .text_color(theme.accent_hover)
                                                            .cursor_pointer()
                                                            .child("随机")
                                                            .on_click(cx.listener(
                                                                |this, _, _, cx| {
                                                                    let pwd = RelayHost::generate_ephemeral_password();
                                                                    this.form_agent_password
                                                                        .update(cx, |f, cx| {
                                                                            f.set_text(pwd, cx)
                                                                        });
                                                                    cx.notify();
                                                                },
                                                            )),
                                                    ),
                                            ),
                                    )
                                    .child(self.form_agent_password.clone()),
                            ),
                    )
                    // 第三行：真实远端地址、端口、用户名
                    .child(
                        div()
                            .flex()
                            .gap_3()
                            .child(
                                div()
                                    .flex_1()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(field_label("真实远端主机地址 (IP 或域名)", theme))
                                    .child(self.form_real_host.clone()),
                            )
                            .child(
                                div()
                                    .w(px(110.))
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(field_label("真实 SSH 端口", theme))
                                    .child(self.form_real_port.clone()),
                            )
                            .child(
                                div()
                                    .w(px(160.))
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(field_label("真实登录用户名", theme))
                                    .child(self.form_real_user.clone()),
                            ),
                    )
                    // 第四行：真实认证方式与密码/私钥输入
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1p5()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .child(field_label("真实远端认证凭据 (AES-256-GCM 加密)", theme))
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_1p5()
                                            .child(
                                                action_button(
                                                    "auth-kind-pwd",
                                                    "密码",
                                                    theme,
                                                    true,
                                                    false,
                                                )
                                                .h(px(25.))
                                                .px_2p5()
                                                .when(
                                                    self.form_real_auth_kind
                                                        == FormRealAuthKind::Password,
                                                    |b| b.bg(theme.accent).text_color(rgb(0xffffff)),
                                                )
                                                .on_click(cx.listener(|this, _, _, cx| {
                                                    this.form_real_auth_kind =
                                                        FormRealAuthKind::Password;
                                                    this.form_real_secret.update(cx, |f, cx| {
                                                        f.set_masked(true, cx)
                                                    });
                                                    cx.notify();
                                                })),
                                            )
                                            .child(
                                                action_button(
                                                    "auth-kind-key",
                                                    "私钥",
                                                    theme,
                                                    true,
                                                    false,
                                                )
                                                .h(px(25.))
                                                .px_2p5()
                                                .when(
                                                    self.form_real_auth_kind
                                                        == FormRealAuthKind::PrivateKey,
                                                    |b| b.bg(theme.accent).text_color(rgb(0xffffff)),
                                                )
                                                .on_click(cx.listener(|this, _, _, cx| {
                                                    this.form_real_auth_kind =
                                                        FormRealAuthKind::PrivateKey;
                                                    cx.notify();
                                                })),
                                            )
                                            .child(
                                                eye_icon_button(
                                                    "toggle-secret-mask",
                                                    !secret_masked,
                                                    theme,
                                                )
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.form_real_secret.update(cx, |f, cx| {
                                                        f.set_masked(!secret_masked, cx);
                                                    });
                                                    cx.notify();
                                                })),
                                            )
                                            .child(
                                                action_button(
                                                    "btn-copy-real-secret",
                                                    "复制",
                                                    theme,
                                                    true,
                                                    false,
                                                )
                                                .h(px(25.))
                                                .px_2p5()
                                                .on_click(cx.listener(|this, _, _, cx| {
                                                    let val =
                                                        this.form_real_secret.read(cx).text();
                                                    if !val.is_empty() {
                                                        cx.write_to_clipboard(
                                                            ClipboardItem::new_string(val),
                                                        );
                                                        this.status_banner = Some((
                                                            "已复制远端认证凭据到剪贴板"
                                                                .to_string(),
                                                            false,
                                                        ));
                                                        cx.notify();
                                                    }
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
                                            .child(field_label(
                                                "真实私钥解密口令 (无口令留空)",
                                                theme,
                                            ))
                                            .child(self.form_real_passphrase.clone()),
                                    )
                                },
                            ),
                    )
                    // 第五行：出站代理配置
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1p5()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .child(field_label("出站代理设置", theme))
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_1p5()
                                            .child(
                                                action_button(
                                                    "proxy-none",
                                                    "直连",
                                                    theme,
                                                    true,
                                                    false,
                                                )
                                                .h(px(25.))
                                                .px_2p5()
                                                .when(
                                                    self.form_proxy_kind == FormProxyKind::None,
                                                    |b| b.bg(theme.accent).text_color(rgb(0xffffff)),
                                                )
                                                .on_click(cx.listener(|this, _, _, cx| {
                                                    this.form_proxy_kind = FormProxyKind::None;
                                                    cx.notify();
                                                })),
                                            )
                                            .child(
                                                action_button(
                                                    "proxy-socks5",
                                                    "SOCKS5",
                                                    theme,
                                                    true,
                                                    false,
                                                )
                                                .h(px(25.))
                                                .px_2p5()
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
                                                    "HTTP",
                                                    theme,
                                                    true,
                                                    false,
                                                )
                                                .h(px(25.))
                                                .px_2p5()
                                                .when(
                                                    self.form_proxy_kind
                                                        == FormProxyKind::HttpConnect,
                                                    |b| b.bg(theme.accent).text_color(rgb(0xffffff)),
                                                )
                                                .on_click(cx.listener(|this, _, _, cx| {
                                                    this.form_proxy_kind =
                                                        FormProxyKind::HttpConnect;
                                                    cx.notify();
                                                })),
                                            ),
                                    ),
                            )
                            .when(self.form_proxy_kind != FormProxyKind::None, |d| {
                                d.child(
                                    div()
                                        .flex()
                                        .gap_2p5()
                                        .child(
                                            div()
                                                .flex_1()
                                                .flex()
                                                .flex_col()
                                                .gap_1()
                                                .child(field_label("代理地址", theme))
                                                .child(self.form_proxy_host.clone()),
                                        )
                                        .child(
                                            div()
                                                .w(px(96.))
                                                .flex()
                                                .flex_col()
                                                .gap_1()
                                                .child(field_label("代理端口", theme))
                                                .child(self.form_proxy_port.clone()),
                                        )
                                        .child(
                                            div()
                                                .w(px(136.))
                                                .flex()
                                                .flex_col()
                                                .gap_1()
                                                .child(field_label("代理账号", theme))
                                                .child(self.form_proxy_user.clone()),
                                        )
                                        .child(
                                            div()
                                                .w(px(136.))
                                                .flex()
                                                .flex_col()
                                                .gap_1()
                                                .child(
                                                    div()
                                                        .flex()
                                                        .items_center()
                                                        .justify_between()
                                                        .child(field_label("代理密码", theme))
                                                        .child(
                                                            eye_icon_button(
                                                                "btn-eye-proxy-pwd",
                                                                !proxy_pwd_masked,
                                                                theme,
                                                            )
                                                            .size(px(20.))
                                                            .on_click(cx.listener(
                                                                move |this, _, _, cx| {
                                                                    this.form_proxy_pass.update(
                                                                        cx,
                                                                        |f, cx| {
                                                                            f.set_masked(
                                                                                !proxy_pwd_masked,
                                                                                cx,
                                                                            )
                                                                        },
                                                                    );
                                                                    cx.notify();
                                                                },
                                                            )),
                                                        ),
                                                )
                                                .child(self.form_proxy_pass.clone()),
                                        ),
                                )
                            }),
                    )
                    // 第六行：暴露给 Agent 的默认认证方式
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(field_label("对 Agent 暴露认证方式:", theme))
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_1p5()
                                    .child(
                                        action_button(
                                            "form-agent-mode-pwd",
                                            "密码",
                                            theme,
                                            true,
                                            false,
                                        )
                                        .h(px(26.))
                                        .px_2p5()
                                        .when(
                                            self.form_agent_auth_mode
                                                == AgentAuthMode::EphemeralPassword,
                                            |b| b.bg(theme.accent).text_color(rgb(0xffffff)),
                                        )
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.form_agent_auth_mode =
                                                AgentAuthMode::EphemeralPassword;
                                            cx.notify();
                                        })),
                                    )
                                    .child(
                                        action_button(
                                            "form-agent-mode-key",
                                            "密钥",
                                            theme,
                                            true,
                                            false,
                                        )
                                        .h(px(26.))
                                        .px_2p5()
                                        .when(
                                            self.form_agent_auth_mode
                                                == AgentAuthMode::DedicatedKey,
                                            |b| b.bg(theme.accent).text_color(rgb(0xffffff)),
                                        )
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.form_agent_auth_mode = AgentAuthMode::DedicatedKey;
                                            cx.notify();
                                        })),
                                    ),
                            ),
                    )
                    // 底部栏：校验反馈 + 取消与保存按钮
                    .child(
                        div()
                            .pt_2p5()
                            .border_t_1()
                            .border_color(theme.border)
                            .flex()
                            .items_center()
                            .justify_between()
                            .gap_3()
                            .child(
                                div()
                                    .flex_1()
                                    .text_size(px(12.))
                                    .text_color(theme.danger)
                                    .child(self.form_error.clone().unwrap_or_default()),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(
                                        action_button(
                                            "form-modal-cancel",
                                            "取消",
                                            theme,
                                            true,
                                            false,
                                        )
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.show_host_modal = false;
                                            this.form_error = None;
                                            cx.notify();
                                        })),
                                    )
                                    .child(
                                        action_button(
                                            "form-save-submit",
                                            if is_editing {
                                                "保存"
                                            } else {
                                                "创建"
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
                                                    this.form_error = None;
                                                    this.request_confirmation(
                                                        PendingAction::SaveHost {
                                                            host: Box::new(host),
                                                            is_new,
                                                        },
                                                        cx,
                                                    );
                                                }
                                                Err(err_msg) => {
                                                    this.form_error = Some(err_msg.clone());
                                                    this.status_banner = Some((err_msg, true));
                                                    cx.notify();
                                                }
                                            }
                                        })),
                                    ),
                            ),
                    ),
            )
    }

    fn render_audit_logs_tab(
        &self,
        theme: WorkbenchTheme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let mut all_logs = Vec::new();
        for host in &self.hosts {
            if self.log_scope == LogScope::SelectedHost
                && self.selected_host_id.is_some_and(|sel| sel != host.id)
            {
                continue;
            }
            if let Some(rt) = self.runtimes.get(&host.id) {
                for log in &rt.logs {
                    all_logs.push(log.clone());
                }
            }
        }
        all_logs.sort_by(|a, b| b.seq.cmp(&a.seq));
        let is_cur_scope = self.log_scope == LogScope::SelectedHost;
        let all_logs_for_copy = all_logs.clone();

        div()
            .flex_1()
            .min_h_0()
            .w_full()
            .px_5()
            .py_3()
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
                            .text_size(px(13.))
                            .font_weight(gpui::FontWeight::BOLD)
                            .text_color(theme.text_primary)
                            .child(format!("日志 ({})", all_logs.len())),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_1p5()
                            .child(
                                action_button(
                                    "log-copy-all",
                                    "复制全部",
                                    theme,
                                    !all_logs_for_copy.is_empty(),
                                    false,
                                )
                                .h(px(24.))
                                .px_2p5()
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    if !all_logs_for_copy.is_empty() {
                                        let text = all_logs_for_copy
                                            .iter()
                                            .map(|l| {
                                                format!(
                                                    "[{}] [{}] {} — {}",
                                                    l.timestamp, l.codename, l.event, l.detail
                                                )
                                            })
                                            .collect::<Vec<_>>()
                                            .join("\n");
                                        cx.write_to_clipboard(ClipboardItem::new_string(text));
                                        this.status_banner = Some((
                                            format!(
                                                "已复制全部 {} 条日志到剪贴板",
                                                all_logs_for_copy.len()
                                            ),
                                            false,
                                        ));
                                        cx.notify();
                                    }
                                })),
                            )
                            .child(
                                action_button(
                                    "log-scope-selected",
                                    "当前",
                                    theme,
                                    !is_cur_scope,
                                    false,
                                )
                                .h(px(24.))
                                .px_2p5()
                                .when(is_cur_scope, |b| {
                                    b.bg(theme.accent).text_color(rgb(0xffffff)).opacity(1.0)
                                })
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.log_scope = LogScope::SelectedHost;
                                    this.save_ui_prefs();
                                    cx.notify();
                                })),
                            )
                            .child(
                                action_button(
                                    "log-scope-all",
                                    "全部",
                                    theme,
                                    is_cur_scope,
                                    false,
                                )
                                .h(px(24.))
                                .px_2p5()
                                .when(!is_cur_scope, |b| {
                                    b.bg(theme.accent).text_color(rgb(0xffffff)).opacity(1.0)
                                })
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.log_scope = LogScope::AllHosts;
                                    this.save_ui_prefs();
                                    cx.notify();
                                })),
                            ),
                    ),
            )
            .child(
                div()
                    .id("audit-log-scroll")
                    .flex_1()
                    .min_h_0()
                    .overflow_scroll()
                    .rounded(px(6.))
                    .bg(theme.bg_surface)
                    .border_1()
                    .border_color(theme.border)
                    .p_2()
                    .flex()
                    .flex_col()
                    .gap_1p5()
                    .when(all_logs.is_empty(), |d| {
                        d.child(
                            div()
                                .p_4()
                                .text_size(px(12.))
                                .text_color(theme.text_muted)
                                .child("暂无日志记录。启动中转或由 Agent 发起连接后将实时记录详细诊断信息。"),
                        )
                    })
                    .children(all_logs.into_iter().take(80).enumerate().map(|(idx, entry)| {
                        let copy_line = format!(
                            "[{}] [{}] {} — {}",
                            entry.timestamp, entry.codename, entry.event, entry.detail
                        );
                        div()
                            .px_2p5()
                            .py_1p5()
                            .rounded(px(4.))
                            .bg(theme.bg_code)
                            .border_1()
                            .border_color(theme.border)
                            .flex()
                            .items_center()
                            .justify_between()
                            .gap_2()
                            .text_size(px(11.5))
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .flex()
                                    .items_center()
                                    .gap_2()
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
                                    )
                                    .child(
                                        div()
                                            .flex_1()
                                            .min_w_0()
                                            .text_color(if entry.is_error {
                                                theme.danger_hover
                                            } else {
                                                theme.text_secondary
                                            })
                                            .child(entry.detail),
                                    ),
                            )
                            .child(
                                action_button(("copy-log-row", idx), "复制", theme, true, false)
                                    .h(px(22.))
                                    .px_2()
                                    .text_size(px(11.))
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        cx.write_to_clipboard(ClipboardItem::new_string(
                                            copy_line.clone(),
                                        ));
                                        this.status_banner =
                                            Some(("已复制该条日志详情到剪贴板".to_string(), false));
                                        cx.notify();
                                    })),
                            )
                    })),
            )
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
                                action_button("modal-cancel-btn", "取消", theme, true, false)
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
            .on_action(|_: &HideToTrayAction, window: &mut Window, _cx: &mut App| {
                platform_set_window_visible(false);
                #[cfg(any(target_os = "linux", target_os = "freebsd"))]
                window.minimize_window();
                #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
                let _ = window;
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
            .when(self.show_host_modal, |root| {
                root.child(self.render_host_modal(theme, cx))
            })
            .when_some(self.pending_confirm.clone(), |root, pending| {
                root.child(self.render_confirm_modal(&pending, theme, cx))
            })
    }
}

/// 渲染深浅色主题切换纯图标按钮（深色下显示太阳图标，浅色下显示新月图标）
fn theme_icon_button(
    id: impl Into<ElementId>,
    is_dark: bool,
    theme: WorkbenchTheme,
) -> Stateful<gpui::Div> {
    div()
        .id(id)
        .size(px(30.))
        .rounded(px(5.))
        .border_1()
        .border_color(theme.border)
        .bg(theme.bg_elevated)
        .flex()
        .items_center()
        .justify_center()
        .cursor_pointer()
        .hover(move |s| s.bg(theme.bg_subtle))
        .child(if is_dark {
            // 太阳图标：外环光晕 + 中心暖金圆核
            div()
                .size(px(16.))
                .rounded(px(8.))
                .border_1()
                .border_color(theme.warning)
                .flex()
                .items_center()
                .justify_center()
                .child(div().size(px(8.)).rounded(px(4.)).bg(theme.warning))
                .into_any_element()
        } else {
            // 新月图标：深色圆底 + 右上偏移同背景色圆遮罩形成弯月
            div()
                .size(px(14.))
                .relative()
                .child(
                    div()
                        .size(px(14.))
                        .rounded(px(7.))
                        .bg(theme.text_primary),
                )
                .child(
                    div()
                        .absolute()
                        .top(px(-2.))
                        .right(px(-2.))
                        .size(px(11.))
                        .rounded(px(5.5))
                        .bg(theme.bg_elevated),
                )
                .into_any_element()
        })
}

/// 辅助函数：将点序列按斜线走廊 `|x - y| / sqrt(2) >= gap` 切分为多段连续折线并绘制
fn paint_clipped_polyline(
    window: &mut Window,
    pts: &[(f32, f32)],
    center: gpui::Point<gpui::Pixels>,
    scale: f32,
    stroke_width: gpui::Pixels,
    color: gpui::Rgba,
    clip_slash_gap: Option<f32>,
) {
    let mut current_seg: Vec<gpui::Point<gpui::Pixels>> = Vec::new();
    for &(lx, ly) in pts {
        let keep = if let Some(gap) = clip_slash_gap {
            ((lx - ly).abs() * std::f32::consts::FRAC_1_SQRT_2) >= gap
        } else {
            true
        };
        if keep {
            current_seg.push(point(center.x + px(lx * scale), center.y + px(ly * scale)));
        } else if current_seg.len() >= 2 {
            let mut pb = PathBuilder::stroke(stroke_width);
            pb.move_to(current_seg[0]);
            for &pt in &current_seg[1..] {
                pb.line_to(pt);
            }
            if let Ok(path) = pb.build() {
                window.paint_path(path, color);
            }
            current_seg.clear();
        } else {
            current_seg.clear();
        }
    }
    if current_seg.len() >= 2 {
        let mut pb = PathBuilder::stroke(stroke_width);
        pb.move_to(current_seg[0]);
        for &pt in &current_seg[1..] {
            pb.line_to(pt);
        }
        if let Ok(path) = pb.build() {
            window.paint_path(path, color);
        }
    }
}

/// 渲染矢量小眼睛显隐控制图标按钮（is_visible=true 绘制杏仁眼框+空心圆瞳孔，false 绘制分段眼框+斜杠）
fn eye_icon_button(
    id: impl Into<ElementId>,
    is_visible: bool,
    theme: WorkbenchTheme,
) -> Stateful<gpui::Div> {
    let stroke = if is_visible {
        theme.text_primary
    } else {
        theme.text_secondary
    };
    div()
        .id(id)
        .w(px(28.))
        .h(px(26.))
        .rounded(px(5.))
        .border_1()
        .border_color(theme.border)
        .bg(theme.bg_elevated)
        .flex()
        .items_center()
        .justify_center()
        .cursor_pointer()
        .hover(move |s| s.bg(theme.bg_subtle))
        .child(
            canvas(
                |_, _, _| (),
                move |bounds, _, window, _| {
                    let center = bounds.center();
                    // 采用 Lucide 24x24 标准比例（眼宽 20，眼高 14.4，中心圆瞳孔半径 3.3）
                    let scale = 0.74_f32;
                    let sw = px(1.55);
                    let gap = if is_visible { None } else { Some(2.45_f32) };

                    // 上眼睑与下眼睑完整采样（饱满圆润杏仁形）
                    let steps = 40usize;
                    let mut upper = Vec::with_capacity(steps + 1);
                    let mut lower = Vec::with_capacity(steps + 1);
                    for i in 0..=steps {
                        let u = (i as f32) / (steps as f32);
                        let x = -10.0 + 20.0 * u;
                        let y = 7.2 * (u * std::f32::consts::PI).sin();
                        upper.push((x, -y));
                        lower.push((x, y));
                    }
                    paint_clipped_polyline(window, &upper, center, scale, sw, stroke, gap);
                    paint_clipped_polyline(window, &lower, center, scale, sw, stroke, gap);

                    // 中心空心圆瞳孔（半径 3.3）
                    let pupil_steps = 48usize;
                    let r = 3.3_f32;
                    let mut pupil = Vec::with_capacity(pupil_steps + 1);
                    for i in 0..=pupil_steps {
                        // 从 45°（斜线处）开始采样，确保闭眼态下圆弧起止点自然对齐斜线缺口
                        let ang = std::f32::consts::FRAC_PI_4
                            + (i as f32) * std::f32::consts::TAU / (pupil_steps as f32);
                        pupil.push((r * ang.cos(), r * ang.sin()));
                    }
                    paint_clipped_polyline(window, &pupil, center, scale, sw, stroke, gap);

                    // 闭眼态绘制左上到右下贯穿斜杠
                    if !is_visible {
                        let mut slash = PathBuilder::stroke(sw);
                        slash.move_to(point(
                            center.x + px(-8.4 * scale),
                            center.y + px(-8.4 * scale),
                        ));
                        slash.line_to(point(
                            center.x + px(8.4 * scale),
                            center.y + px(8.4 * scale),
                        ));
                        if let Ok(path) = slash.build() {
                            window.paint_path(path, stroke);
                        }
                    }
                },
            )
            .size(px(18.)),
        )
}

/// 渲染非 macOS 平台的最小化 / 最大化 / 关闭窗口图标按钮
fn window_ctrl_button(
    id: impl Into<ElementId>,
    symbol: &'static str,
    theme: WorkbenchTheme,
    is_close: bool,
) -> Stateful<gpui::Div> {
    div()
        .id(id)
        .size(px(28.))
        .rounded(px(4.))
        .border_1()
        .border_color(theme.border)
        .bg(theme.bg_elevated)
        .text_color(theme.text_secondary)
        .text_size(px(12.))
        .flex()
        .items_center()
        .justify_center()
        .cursor_pointer()
        .hover(move |s| {
            if is_close {
                s.bg(theme.danger).text_color(rgb(0xffffff))
            } else {
                s.bg(theme.bg_subtle).text_color(theme.text_primary)
            }
        })
        .child(symbol)
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
