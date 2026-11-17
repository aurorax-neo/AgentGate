pub mod text_input;
pub mod theme;

use std::collections::{HashMap, HashSet};
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
    LiveCredentials, RelayEvent, RunningRelayControl, global_tokio_runtime,
    start_host_relay_with_id, test_upstream_connection,
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
    #[serde(default)]
    pub running_host_ids: Option<Vec<Uuid>>,
}

impl Default for PersistedUiPrefs {
    fn default() -> Self {
        Self {
            is_dark: true,
            log_scope: LogScope::SelectedHost,
            selected_host_id: None,
            running_host_ids: None,
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
    desired_relay_instance: HashMap<Uuid, Uuid>,
    event_tx: mpsc::UnboundedSender<RelayEvent>,

    is_dark: bool,
    show_local_pwd: bool,
    log_scope: LogScope,
    selected_host_id: Option<Uuid>,
    show_host_modal: bool,
    form_error: Option<String>,
    form_test_ok: Option<String>,
    form_testing: bool,
    form_session_seq: u64,
    form_verified_host_key: Option<(String, u16, String)>,
    testing_host_ids: HashSet<Uuid>,
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
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let storage =
            EncryptedStorage::new_default().expect("初始化 AgentGate 本地加密仓库目录失败");
        let prefs = Self::load_ui_prefs(&storage);
        let mut hosts = storage.load_hosts().unwrap_or_default();
        let mut runtimes = HashMap::new();

        let mut modified_keys = false;
        for host in &mut hosts {
            match RelayHost::validate_loopback_bind_host(&host.local_bind_host) {
                Ok(normalized) => {
                    if normalized != host.local_bind_host {
                        host.local_bind_host = normalized;
                        modified_keys = true;
                    }
                }
                Err(_) => {
                    host.local_bind_host = RelayHost::default_local_bind_host();
                    modified_keys = true;
                }
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
                .unwrap_or_else(|_| {
                    (
                        storage.dedicated_key_path_for(&host.id, &host.codename),
                        String::new(),
                    )
                });
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
        let form_agent_password =
            cx.new(|cx| TextField::new(cx, "暴露给 Agent 的本地连接密码", true));
        let form_real_host =
            cx.new(|cx| TextField::new(cx, "真实远端 IP 或域名（仅存本机）", false));
        let form_real_port = cx.new(|cx| TextField::new(cx, "22", false));
        let form_real_user = cx.new(|cx| TextField::new(cx, "root / ubuntu", false));
        let form_real_secret =
            cx.new(|cx| TextField::new(cx, "真实登录密码或 OpenSSH 私钥 PEM", true));
        let form_real_passphrase =
            cx.new(|cx| TextField::new(cx, "私钥口令（无口令可留空）", true));
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
            desired_relay_instance: HashMap::new(),
            event_tx,
            is_dark: prefs.is_dark,
            show_local_pwd: false,
            log_scope: prefs.log_scope,
            selected_host_id,
            show_host_modal: false,
            form_error: None,
            form_test_ok: None,
            form_testing: false,
            form_session_seq: 0,
            form_verified_host_key: None,
            testing_host_ids: HashSet::new(),
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

        window.focus(&this.focus_handle);
        this.sync_inputs_theme(cx);
        this.reset_form_for_new_host(cx);
        let demo_seeded = this.apply_optional_demo_seed(cx);

        // 自动恢复上次退出前处于运行中的中转主机（若本次为首次 Demo Seed 则保持其预设运行态，避免重复并发启动）
        if !demo_seeded {
            let resume_ids: Vec<Uuid> = prefs
                .running_host_ids
                .clone()
                .unwrap_or_else(|| this.hosts.iter().map(|h| h.id).collect());
            for resume_id in &resume_ids {
                if this.controls.contains_key(resume_id)
                    || this.desired_relay_instance.contains_key(resume_id)
                {
                    continue;
                }
                if let Some(host) = this.hosts.iter().find(|h| &h.id == resume_id).cloned() {
                    let rt = this.runtimes.entry(host.id).or_default();
                    rt.current_temp_password = Some(host.agent_password.clone());
                    rt.status = RelayStatus::Starting;
                    let live_creds = Self::build_live_credentials(&host, rt);
                    this.spawn_start_relay_async(host, live_creds, false, cx);
                }
            }
        }

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
                let Ok(updated) = weak_this.update(cx, |this, cx| {
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
        // 先持久化退出前运行列表，再统一停止本地监听句柄
        self.save_ui_prefs();
        self.desired_relay_instance.clear();
        for (_, ctrl) in self.controls.drain() {
            ctrl.stop();
        }
        for rt in self.runtimes.values_mut() {
            rt.rotate_or_clear_temp_password(None);
        }
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
        let mut running_host_ids: Vec<Uuid> = self.controls.keys().copied().collect();
        for (id, rt) in &self.runtimes {
            if (rt.status.is_running() || matches!(rt.status, RelayStatus::Starting))
                && !running_host_ids.contains(id)
            {
                running_host_ids.push(*id);
            }
        }
        let prefs = PersistedUiPrefs {
            is_dark: self.is_dark,
            log_scope: self.log_scope,
            selected_host_id: self.selected_host_id,
            running_host_ids: Some(running_host_ids),
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

    fn apply_optional_demo_seed(&mut self, cx: &mut Context<Self>) -> bool {
        if !cfg!(debug_assertions) {
            return false;
        }
        if std::env::var("AGENTGATE_DEMO_SEED").as_deref() != Ok("1") {
            return false;
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
                    .unwrap_or_else(|_| {
                        (
                            self.storage.dedicated_key_path_for(&h.id, &h.codename),
                            String::new(),
                        )
                    });
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
                    format!(
                        "代理: {} | 暴露模式: {}",
                        h.proxy.badge_text(),
                        h.agent_auth_mode.label()
                    ),
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
                    "Agent 密码认证通过",
                    "本地用户 `cobalt-nexus-01` 自 127.0.0.1:59412 通过恒定时间本地密码验证",
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
            return true;
        }
        false
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
                instance_id,
                codename,
                local_port,
            } => {
                if self.desired_relay_instance.get(&host_id).copied() != Some(instance_id)
                    || !self.hosts.iter().any(|h| h.id == host_id)
                {
                    return;
                }
                let rt = self.runtimes.entry(host_id).or_default();
                let prev_sessions = rt.status.active_sessions();
                rt.status = RelayStatus::Running {
                    local_port,
                    active_sessions: prev_sessions,
                };
                self.status_banner = Some((
                    format!(
                        "代号 [{}] 已启动本地 SSH 中转：127.0.0.1:{}",
                        codename, local_port
                    ),
                    false,
                ));
            }
            RelayEvent::Stopped {
                host_id,
                instance_id,
                codename,
                local_port: _,
            } => {
                if self.desired_relay_instance.get(&host_id).copied() != Some(instance_id) {
                    return;
                }
                self.desired_relay_instance.remove(&host_id);
                self.controls.remove(&host_id);
                if let Some(rt) = self.runtimes.get_mut(&host_id) {
                    rt.status = RelayStatus::Stopped;
                }
                self.save_ui_prefs();
                self.status_banner = Some((format!("代号 [{}] 本地监听已停止", codename), false));
            }
            RelayEvent::SessionsChanged {
                host_id,
                active_sessions,
                total_connections,
            } => {
                let Some(rt) = self.runtimes.get_mut(&host_id) else {
                    return;
                };
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
                if let Some(rt) = self.runtimes.get_mut(&host_id) {
                    rt.push_log(&codename, event, detail, is_error);
                }
            }
            RelayEvent::Error {
                host_id,
                instance_id,
                codename,
                local_port: _,
                message,
            } => {
                if self.desired_relay_instance.get(&host_id).copied() != Some(instance_id) {
                    return;
                }
                self.desired_relay_instance.remove(&host_id);
                self.controls.remove(&host_id);
                if let Some(rt) = self.runtimes.get_mut(&host_id) {
                    rt.status = RelayStatus::Error(message.clone());
                    rt.push_log(&codename, "服务异常", message.clone(), true);
                }
                self.save_ui_prefs();
                self.status_banner = Some((format!("代号 [{}] 异常: {}", codename, message), true));
            }
        }
    }

    fn close_host_modal(&mut self) {
        self.show_host_modal = false;
        self.form_error = None;
        self.form_test_ok = None;
        self.form_testing = false;
        self.form_verified_host_key = None;
        self.form_session_seq = self.form_session_seq.wrapping_add(1);
    }

    fn reset_form_for_new_host(&mut self, cx: &mut Context<Self>) {
        self.editing_host_id = None;
        self.form_error = None;
        self.form_test_ok = None;
        self.form_testing = false;
        self.form_verified_host_key = None;
        self.form_session_seq = self.form_session_seq.wrapping_add(1);
        let next_codename = RelayHost::generate_codename(self.hosts.len());
        let default_bind = RelayHost::default_local_bind_host();
        let free_port = RelayHost::allocate_free_local_port(&default_bind);
        let init_pwd = RelayHost::generate_ephemeral_password();
        self.form_codename
            .update(cx, |f, cx| f.set_text(next_codename, cx));
        self.form_label.update(cx, |f, cx| f.set_text("", cx));
        self.form_local_host
            .update(cx, |f, cx| f.set_text(default_bind, cx));
        self.form_local_port
            .update(cx, |f, cx| f.set_text(free_port.to_string(), cx));
        self.form_agent_password
            .update(cx, |f, cx| f.set_text(init_pwd, cx));
        self.form_real_host.update(cx, |f, cx| f.set_text("", cx));
        self.form_real_port.update(cx, |f, cx| f.set_text("22", cx));
        self.form_real_user
            .update(cx, |f, cx| f.set_text("root", cx));
        self.form_real_auth_kind = FormRealAuthKind::Password;
        self.form_real_secret.update(cx, |f, cx| {
            f.set_masked(true, cx);
            f.set_text("", cx);
        });
        self.form_real_passphrase
            .update(cx, |f, cx| f.set_text("", cx));
        self.form_proxy_kind = FormProxyKind::None;
        self.form_proxy_host
            .update(cx, |f, cx| f.set_text("127.0.0.1", cx));
        self.form_proxy_port
            .update(cx, |f, cx| f.set_text("7890", cx));
        self.form_proxy_user.update(cx, |f, cx| f.set_text("", cx));
        self.form_proxy_pass.update(cx, |f, cx| f.set_text("", cx));
        self.form_agent_auth_mode = AgentAuthMode::EphemeralPassword;
    }

    fn populate_form_from_host(&mut self, host: &RelayHost, cx: &mut Context<Self>) {
        self.editing_host_id = Some(host.id);
        self.form_error = None;
        self.form_test_ok = None;
        self.form_testing = false;
        self.form_verified_host_key = host
            .pinned_host_key_openssh
            .clone()
            .map(|pk| (host.real_host.clone(), host.real_port, pk));
        self.form_session_seq = self.form_session_seq.wrapping_add(1);
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
            return Err(
                "不允许使用通用保留名 `agent` 作为代号，请使用可区分的唯一代号".to_string(),
            );
        }
        let is_new = self.editing_host_id.is_none();
        let id = self.editing_host_id.unwrap_or_else(Uuid::new_v4);
        if self
            .hosts
            .iter()
            .any(|h| h.id != id && h.codename.eq_ignore_ascii_case(&codename))
        {
            return Err(format!(
                "代号 [{}] 已存在，请使用唯一代号以便 AI 区分",
                codename
            ));
        }

        let raw_bind_host = self.form_local_host.read(cx).text().trim().to_string();
        if raw_bind_host.is_empty() {
            return Err("本机监听地址不能为空（推荐填写 127.0.0.1）".to_string());
        }
        let local_bind_host = RelayHost::validate_loopback_bind_host(&raw_bind_host)?;
        let local_port: u16 = self
            .form_local_port
            .read(cx)
            .text()
            .trim()
            .parse()
            .ok()
            .filter(|p| *p > 0)
            .ok_or_else(|| "本机监听端口必须是 1~65535 之间的整数".to_string())?;
        if self.hosts.iter().any(|h| {
            h.id != id && h.local_bind_host == local_bind_host && h.local_port == local_port
        }) {
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
        let pinned_host_key_openssh = existing
            .and_then(|h| {
                if h.real_host == real_host && h.real_port == real_port {
                    h.pinned_host_key_openssh.clone()
                } else {
                    None
                }
            })
            .or_else(|| {
                self.form_verified_host_key
                    .as_ref()
                    .and_then(|(vh, vp, pk)| {
                        (vh == &real_host && *vp == real_port).then(|| pk.clone())
                    })
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
        let pwd = if !host.agent_password.trim().is_empty() {
            Some(host.agent_password.clone())
        } else {
            rt.current_temp_password.clone()
        };
        LiveCredentials {
            mode: host.agent_auth_mode,
            temp_password: pwd,
            dedicated_pubkey,
        }
    }

    /// 异步非阻塞启动单条 SSH 中转监听，避免在 GPUI 主线程调用 `block_on` 造成界面卡顿（修复 [MED-02] 及固定端口重启竞态）
    fn spawn_start_relay_async(
        &mut self,
        host: RelayHost,
        live_creds: LiveCredentials,
        update_banner_on_ok: bool,
        cx: &mut Context<Self>,
    ) {
        let id = host.id;
        let instance_id = Uuid::new_v4();
        self.desired_relay_instance.insert(id, instance_id);
        let codename = host.codename.clone();
        let bind_host = host.local_bind_host.clone();
        let tx = self.event_tx.clone();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();

        global_tokio_runtime().spawn(async move {
            let res = start_host_relay_with_id(host, live_creds, instance_id, tx).await;
            let _ = done_tx.send(res);
        });

        cx.spawn(async move |weak_this, cx| {
            if let Ok(handle_res) = done_rx.await {
                let updated = weak_this.update(cx, |this, cx| {
                    // 若在异步启动期间用户已停止、删除或发起了更新一轮的重启，立即终止当前过期监听句柄
                    if this.desired_relay_instance.get(&id).copied() != Some(instance_id)
                        || !this.hosts.iter().any(|h| h.id == id)
                    {
                        if let Ok(stale_ctrl) = handle_res {
                            stale_ctrl.stop();
                        }
                        return;
                    }
                    match handle_res {
                        Ok(ctrl) => {
                            let port = ctrl.local_port;
                            if let Some(h) = this.hosts.iter_mut().find(|h| h.id == id)
                                && h.local_port != port
                            {
                                h.local_port = port;
                                let _ = this.storage.save_hosts(&this.hosts);
                            }
                            if let Some(prev_ctrl) = this.controls.insert(id, ctrl) {
                                prev_ctrl.stop();
                            }
                            if let Some(rt) = this.runtimes.get_mut(&id) {
                                let prev_sessions = rt.status.active_sessions();
                                rt.status = RelayStatus::Running {
                                    local_port: port,
                                    active_sessions: prev_sessions,
                                };
                            }
                            this.save_ui_prefs();
                            if update_banner_on_ok {
                                this.status_banner = Some((
                                    format!(
                                        "已启动代号 [{}] 本地监听 {}:{}",
                                        codename, bind_host, port
                                    ),
                                    false,
                                ));
                            }
                        }
                        Err(err) => {
                            this.desired_relay_instance.remove(&id);
                            if let Some(rt) = this.runtimes.get_mut(&id) {
                                rt.status = RelayStatus::Error(err.to_string());
                            }
                            this.save_ui_prefs();
                            this.status_banner =
                                Some((format!("启动代号 [{}] 失败: {}", codename, err), true));
                        }
                    }
                    cx.notify();
                });
                let _ = updated;
            }
        })
        .detach();
    }

    /// 异步测试上游真实 SSH 主机连通性、代理握手与身份认证（支持在主界面与新建/编辑弹窗中直接调用）
    fn spawn_test_upstream(&mut self, host: RelayHost, from_modal: bool, cx: &mut Context<Self>) {
        let id = host.id;
        let codename = host.codename.clone();
        let target_real_host = host.real_host.clone();
        let target_real_port = host.real_port;
        self.testing_host_ids.insert(id);
        let modal_req_seq = if from_modal {
            self.form_session_seq = self.form_session_seq.wrapping_add(1);
            self.form_testing = true;
            self.form_error = None;
            self.form_test_ok = None;
            Some(self.form_session_seq)
        } else {
            None
        };
        if let Some(rt) = self.runtimes.get_mut(&id) {
            rt.push_log(
                &codename,
                "发起上游测试",
                format!(
                    "正在测试上游连接 (代理: {}, 认证: {})",
                    host.proxy.badge_text(),
                    host.real_auth.label()
                ),
                false,
            );
        }
        self.status_banner = Some((
            format!("正在测试代号 [{}] 的上游 SSH 连接与凭据...", codename),
            false,
        ));
        cx.notify();

        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        global_tokio_runtime().spawn(async move {
            let res = test_upstream_connection(host).await;
            let _ = done_tx.send(res);
        });

        cx.spawn(async move |weak_this, cx| {
            if let Ok(test_res) = done_rx.await {
                let _ = weak_this.update(cx, |this, cx| {
                    this.testing_host_ids.remove(&id);
                    let modal_still_matches = modal_req_seq
                        .is_some_and(|seq| this.show_host_modal && this.form_session_seq == seq);
                    if modal_still_matches {
                        this.form_testing = false;
                    }
                    match test_res {
                        Ok((elapsed_ms, pinned_key)) => {
                            if let Some(pk) = pinned_key {
                                if modal_still_matches {
                                    this.form_verified_host_key = Some((
                                        target_real_host.clone(),
                                        target_real_port,
                                        pk.clone(),
                                    ));
                                }
                                if let Some(h) = this.hosts.iter_mut().find(|h| h.id == id)
                                    && h.real_host == target_real_host
                                    && h.real_port == target_real_port
                                    && h.pinned_host_key_openssh.is_none()
                                {
                                    h.pinned_host_key_openssh = Some(pk);
                                    let _ = this.storage.save_hosts(&this.hosts);
                                }
                            }
                            let detail = format!("连接与认证通过 (耗时: {}ms)", elapsed_ms);
                            if let Some(rt) = this.runtimes.get_mut(&id) {
                                rt.push_log(&codename, "上游测试成功", detail.clone(), false);
                            }
                            if !from_modal || modal_still_matches {
                                this.status_banner = Some((
                                    format!("代号 [{}] 上游测试成功 — {}", codename, detail),
                                    false,
                                ));
                            }
                            if modal_still_matches {
                                this.form_test_ok = Some(format!("上游测试成功：{}", detail));
                            }
                        }
                        Err(err) => {
                            let err_str = err.to_string();
                            if let Some(rt) = this.runtimes.get_mut(&id) {
                                rt.push_log(&codename, "上游测试失败", err_str.clone(), true);
                            }
                            if !from_modal || modal_still_matches {
                                this.status_banner = Some((
                                    format!("代号 [{}] 上游测试失败 — {}", codename, err_str),
                                    true,
                                ));
                            }
                            if modal_still_matches {
                                this.form_error = Some(format!("上游测试失败 — {}", err_str));
                            }
                        }
                    }
                    cx.notify();
                });
            }
        })
        .detach();
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
            self.close_host_modal();
            cx.notify();
        }
    }

    fn execute_confirmed_action(&mut self, action: PendingAction, cx: &mut Context<Self>) {
        match action {
            PendingAction::StartRelay { id, codename } => {
                self.desired_relay_instance.remove(&id);
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
                self.status_banner =
                    Some((format!("正在启动代号 [{}] 本地监听...", codename), false));
                self.spawn_start_relay_async(host, live_creds, true, cx);
            }
            PendingAction::StopRelay {
                id,
                codename,
                local_port,
            } => {
                self.desired_relay_instance.remove(&id);
                if let Some(ctrl) = self.controls.remove(&id) {
                    ctrl.stop();
                }
                if let Some(rt) = self.runtimes.get_mut(&id) {
                    rt.status = RelayStatus::Stopped;
                }
                self.save_ui_prefs();
                self.status_banner = Some((
                    format!(
                        "已停止代号 [{}] 在端口 {} 的中转服务（端口与密码保持不变）",
                        codename, local_port
                    ),
                    false,
                ));
            }
            PendingAction::StopAllRelays { running_count } => {
                self.desired_relay_instance.clear();
                for (_, ctrl) in self.controls.drain() {
                    ctrl.stop();
                }
                for rt in self.runtimes.values_mut() {
                    if rt.status.is_running() || matches!(rt.status, RelayStatus::Starting) {
                        rt.status = RelayStatus::Stopped;
                    }
                }
                self.save_ui_prefs();
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

                let (key_path, pubkey) =
                    match self.storage.ensure_dedicated_agent_key(&mut host, false) {
                        Ok(v) => v,
                        Err(err) => {
                            self.status_banner = Some((format!("生成专用密钥失败: {}", err), true));
                            cx.notify();
                            return;
                        }
                    };

                if let Some((prev_name, _, _)) = &prev_snapshot
                    && prev_name != &host.codename
                {
                    self.storage.remove_dedicated_key_file(&host.id, prev_name);
                }

                let id = host.id;
                let codename = host.codename.clone();
                if is_new {
                    self.hosts.push((*host).clone());
                } else if let Some(slot) = self.hosts.iter_mut().find(|h| h.id == id) {
                    *slot = (*host).clone();
                }

                if let Err(err) = self.storage.save_hosts(&self.hosts) {
                    self.status_banner = Some((format!("加密保存仓库失败: {}", err), true));
                    cx.notify();
                    return;
                }

                let rt = self
                    .runtimes
                    .entry(id)
                    .or_insert_with(|| RelayRuntimeState {
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
                    if is_new {
                        "新建主机"
                    } else {
                        "更新主机"
                    },
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
                let was_active =
                    self.controls.contains_key(&id) || self.desired_relay_instance.contains_key(&id);
                if bind_changed && was_active {
                    self.desired_relay_instance.remove(&id);
                    if let Some(old_ctrl) = self.controls.remove(&id) {
                        old_ctrl.stop();
                    }
                    let live_creds = Self::build_live_credentials(&host, rt);
                    rt.status = RelayStatus::Starting;
                    self.spawn_start_relay_async((*host).clone(), live_creds, false, cx);
                } else if let Some(ctrl) = self.controls.get(&id) {
                    let creds = Self::build_live_credentials(&host, rt);
                    ctrl.update_host((*host).clone());
                    ctrl.update_credentials(creds);
                }

                self.selected_host_id = Some(id);
                self.close_host_modal();
                self.save_ui_prefs();
                self.status_banner = Some((
                    format!("代号 [{}] 已通过 AES-256-GCM 加密写入本机仓库", codename),
                    false,
                ));
            }
            PendingAction::DeleteHost { id, codename } => {
                self.desired_relay_instance.remove(&id);
                if let Some(ctrl) = self.controls.remove(&id) {
                    ctrl.stop();
                }
                self.storage.remove_dedicated_key_file(&id, &codename);
                self.hosts.retain(|h| h.id != id);
                self.runtimes.remove(&id);
                let _ = self.storage.save_hosts(&self.hosts);
                if self.selected_host_id == Some(id) {
                    self.selected_host_id = self.hosts.first().map(|h| h.id);
                }
                self.save_ui_prefs();
                self.status_banner =
                    Some((format!("已删除代号 [{}] 及其专用密钥", codename), false));
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
                            rt.push_log(
                                &codename,
                                "重置本地密码",
                                "已生成新 24 位本地固定密码，旧密码已失效",
                                false,
                            );
                        }
                    }
                    AgentAuthMode::DedicatedKey => {
                        if let Ok((key_path, pubkey)) = self
                            .storage
                            .ensure_dedicated_agent_key(&mut self.hosts[host_idx], true)
                        {
                            let _ = self.storage.save_hosts(&self.hosts);
                            if let Some(rt) = self.runtimes.get_mut(&id) {
                                rt.dedicated_key_path =
                                    Some(key_path.to_string_lossy().to_string());
                                rt.dedicated_pubkey_openssh = Some(pubkey);
                                rt.push_log(
                                    &codename,
                                    "重置专用密钥",
                                    "已重新生成本机 Ed25519 密钥对",
                                    false,
                                );
                            }
                        }
                    }
                }
                let host = &self.hosts[host_idx];
                if let (Some(ctrl), Some(rt)) = (self.controls.get(&id), self.runtimes.get(&id)) {
                    ctrl.update_credentials(Self::build_live_credentials(host, rt));
                }
                self.status_banner = Some((
                    format!(
                        "代号 [{}] 的「{}」已完成重置并实时生效",
                        codename,
                        mode.label()
                    ),
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
                            format!(
                                "已复制代号 [{}] 的「{}」到剪贴板，可直接粘贴发给 Agent",
                                codename,
                                format.label()
                            ),
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

    fn render_status_strip(&self, theme: WorkbenchTheme) -> impl IntoElement {
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
            .w_full()
            .flex_shrink_0()
            .px_4()
            .py_2()
            .rounded(px(8.))
            .bg(if banner_is_err {
                theme.danger_soft
            } else {
                gpui::Hsla::from(theme.bg_surface)
            })
            .border_1()
            .border_color(if banner_is_err {
                theme.danger
            } else {
                theme.border
            })
            .flex()
            .items_start()
            .gap_2p5()
            .child(
                div()
                    .mt(px(5.))
                    .size(px(7.))
                    .flex_shrink_0()
                    .rounded(px(3.5))
                    .bg(dot_color),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .whitespace_normal()
                    .line_clamp(2)
                    .text_size(px(12.))
                    .text_color(if banner_is_err {
                        theme.danger
                    } else {
                        theme.text_secondary
                    })
                    .child(banner_msg),
            )
    }

    fn render_top_bar(&self, theme: WorkbenchTheme, cx: &mut Context<Self>) -> impl IntoElement {
        let running_count = self
            .runtimes
            .values()
            .filter(|r| r.status.is_running())
            .count();
        let stoppable_count = self
            .runtimes
            .values()
            .filter(|r| r.status.is_running() || matches!(r.status, RelayStatus::Starting))
            .count();
        let active_sessions: usize = self
            .runtimes
            .values()
            .map(|r| r.status.active_sessions())
            .sum();
        div()
            .h(px(56.))
            .flex_shrink_0()
            .w_full()
            .px(px(22.))
            .flex()
            .items_center()
            .justify_between()
            .bg(theme.bg_surface)
            .border_b_1()
            .border_color(theme.border)
            .window_control_area(WindowControlArea::Drag)
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
                            .px_3()
                            .h(px(30.))
                            .rounded(px(6.))
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
                            .px_2p5()
                            .h(px(26.))
                            .rounded(px(5.))
                            .bg(theme.success_soft)
                            .text_color(theme.success)
                            .text_size(px(11.5))
                            .flex()
                            .items_center()
                            .child(format!("运行中 {} / {}", running_count, self.hosts.len())),
                    )
                    .child(
                        div()
                            .px_2p5()
                            .h(px(26.))
                            .rounded(px(5.))
                            .bg(theme.accent_soft)
                            .text_color(theme.accent_hover)
                            .text_size(px(11.5))
                            .flex()
                            .items_center()
                            .child(format!("活跃会话 {}", active_sessions)),
                    ),
            )
            .child(
                div()
                    .occlude()
                    .flex()
                    .flex_shrink_0()
                    .items_center()
                    .gap_2p5()
                    .child(div().w(px(216.)).child(self.search_input.clone()))
                    .child(
                        action_button("btn-new-host", "+ 新建", theme, true, false)
                            .h(px(34.))
                            .px_3p5()
                            .rounded(px(6.))
                            .bg(theme.accent)
                            .text_color(rgb(0xffffff))
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.reset_form_for_new_host(cx);
                                this.show_host_modal = true;
                                let fh = this.form_codename.read(cx).focus_handle(cx);
                                window.focus(&fh);
                                cx.notify();
                            })),
                    )
                    .child(
                        action_button("btn-stop-all", "全停", theme, stoppable_count > 0, true)
                            .h(px(34.))
                            .px_3()
                            .rounded(px(6.))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                if stoppable_count > 0 {
                                    this.request_confirmation(
                                        PendingAction::StopAllRelays {
                                            running_count: stoppable_count,
                                        },
                                        cx,
                                    );
                                }
                            })),
                    )
                    .child(
                        theme_icon_button("btn-theme-toggle", self.is_dark, theme)
                            .size(px(34.))
                            .rounded(px(6.))
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
                                .pl_1p5()
                                .flex()
                                .items_center()
                                .gap_1p5()
                                .child(
                                    window_ctrl_button("win-btn-min", "—", theme, false).on_click(
                                        cx.listener(|_, _, window, _| {
                                            platform_set_window_visible(false);
                                            #[cfg(any(
                                                target_os = "linux",
                                                target_os = "freebsd"
                                            ))]
                                            window.minimize_window();
                                            #[cfg(not(any(
                                                target_os = "linux",
                                                target_os = "freebsd"
                                            )))]
                                            let _ = window;
                                        }),
                                    ),
                                )
                                .child(
                                    window_ctrl_button("win-btn-max", "□", theme, false).on_click(
                                        cx.listener(|_, _, window, _| {
                                            platform_toggle_maximize_window(window);
                                        }),
                                    ),
                                )
                                .child(
                                    window_ctrl_button("win-btn-close", "×", theme, true).on_click(
                                        cx.listener(|_, _, window, _| {
                                            platform_set_window_visible(false);
                                            #[cfg(any(
                                                target_os = "linux",
                                                target_os = "freebsd"
                                            ))]
                                            window.minimize_window();
                                            #[cfg(not(any(
                                                target_os = "linux",
                                                target_os = "freebsd"
                                            )))]
                                            let _ = window;
                                        }),
                                    ),
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
            .w(px(320.))
            .flex_shrink_0()
            .h_full()
            .min_h_0()
            .flex()
            .flex_col()
            .rounded(px(10.))
            .bg(theme.bg_surface)
            .border_1()
            .border_color(theme.border)
            .overflow_hidden()
            .child(
                div()
                    .h(px(42.))
                    .flex_shrink_0()
                    .px_4()
                    .flex()
                    .items_center()
                    .justify_between()
                    .border_b_1()
                    .border_color(theme.border)
                    .text_size(px(12.))
                    .text_color(theme.text_secondary)
                    .child("机器代号列表")
                    .child(
                        div()
                            .px_2()
                            .py_0p5()
                            .rounded(px(4.))
                            .bg(theme.bg_subtle)
                            .text_size(px(11.))
                            .text_color(theme.text_secondary)
                            .child(format!("{} 台", filtered_hosts.len())),
                    ),
            )
            .child(
                div()
                    .id("host-list-scroll")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .p(px(10.))
                    .flex()
                    .flex_col()
                    .gap(px(8.))
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
                        let is_starting = matches!(rt.status, RelayStatus::Starting);
                        let is_error = matches!(rt.status, RelayStatus::Error(_));
                        let active_port = rt.status.local_port().unwrap_or(host.local_port);
                        let bind_host = if host.local_bind_host.trim().is_empty() {
                            "127.0.0.1"
                        } else {
                            host.local_bind_host.trim()
                        };

                        let selected_bg = if theme.is_dark {
                            hsla(0.48, 0.78, 0.42, 0.24)
                        } else {
                            hsla(0.48, 0.85, 0.34, 0.15)
                        };
                        let selected_hover_bg = if theme.is_dark {
                            hsla(0.48, 0.78, 0.45, 0.28)
                        } else {
                            hsla(0.48, 0.85, 0.34, 0.19)
                        };
                        let accent_edge = if theme.is_dark {
                            theme.accent_hover
                        } else {
                            theme.accent
                        };

                        let row_base = div()
                            .id(("host-row", idx))
                            .w_full()
                            .relative()
                            .px_3p5()
                            .py_3()
                            .rounded(px(8.))
                            .border_1();
                        let row_styled = if is_selected {
                            row_base
                                .bg(selected_bg)
                                .border_color(accent_edge)
                                .hover(move |s| s.bg(selected_hover_bg))
                        } else {
                            row_base
                                .bg(theme.bg_elevated)
                                .border_color(theme.border)
                                .hover(move |s| s.bg(theme.bg_subtle))
                        };

                        row_styled
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
                                    .gap_2()
                                    .child(
                                        div()
                                            .flex_1()
                                            .min_w_0()
                                            .flex()
                                            .items_center()
                                            .gap_1p5()
                                            .child(
                                                div()
                                                    .flex_shrink_0()
                                                    .size(px(7.))
                                                    .rounded(px(3.5))
                                                    .bg(if is_running {
                                                        theme.success
                                                    } else if is_starting {
                                                        theme.warning
                                                    } else if is_error {
                                                        theme.danger
                                                    } else {
                                                        theme.text_muted
                                                    }),
                                            )
                                            .child(
                                                div()
                                                    .min_w_0()
                                                    .truncate()
                                                    .text_size(px(13.5))
                                                    .font_weight(gpui::FontWeight::BOLD)
                                                    .text_color(if is_selected {
                                                        accent_edge
                                                    } else {
                                                        theme.text_primary
                                                    })
                                                    .child(format!("[{}]", host.codename)),
                                            )
                                            .when(is_selected, |el| {
                                                el.child(
                                                    div()
                                                        .flex_shrink_0()
                                                        .px_1p5()
                                                        .h(px(17.))
                                                        .rounded(px(3.))
                                                        .bg(accent_edge)
                                                        .text_color(rgb(0xffffff))
                                                        .text_size(px(10.))
                                                        .font_weight(gpui::FontWeight::BOLD)
                                                        .flex()
                                                        .items_center()
                                                        .child("当前"),
                                                )
                                            }),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .flex_shrink_0()
                                            .items_center()
                                            .gap_1p5()
                                            .child({
                                                let host_test = host.clone();
                                                let is_testing = self.testing_host_ids.contains(&id);
                                                action_button(
                                                    ("row-test", idx),
                                                    if is_testing { "测试中" } else { "测试" },
                                                    theme,
                                                    !is_testing,
                                                    false,
                                                )
                                                .h(px(23.))
                                                .px_2()
                                                .flex_shrink_0()
                                                .text_size(px(11.))
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.selected_host_id = Some(id);
                                                    if !this.testing_host_ids.contains(&id) {
                                                        this.spawn_test_upstream(
                                                            host_test.clone(),
                                                            false,
                                                            cx,
                                                        );
                                                    }
                                                }))
                                            })
                                            .child({
                                                let codename_toggle = codename.clone();
                                                let stop_port = rt.status.local_port();
                                                action_button(
                                                    ("row-toggle", idx),
                                                    if is_running {
                                                        "停止"
                                                    } else if is_starting {
                                                        "启动中"
                                                    } else {
                                                        "启动"
                                                    },
                                                    theme,
                                                    !is_starting,
                                                    is_running,
                                                )
                                                .h(px(23.))
                                                .px_2()
                                                .flex_shrink_0()
                                                .text_size(px(11.))
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    if is_starting {
                                                        return;
                                                    }
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
                                    ),
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
                                    .child(div().text_color(theme.text_muted).child(format!(
                                        "{} · {}",
                                        host.proxy.badge_text(),
                                        match host.agent_auth_mode {
                                            AgentAuthMode::EphemeralPassword => "密码",
                                            AgentAuthMode::DedicatedKey => "密钥",
                                        }
                                    ))),
                            )
                            .child(
                                div()
                                    .truncate()
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
                .min_w_0()
                .h_full()
                .p_8()
                .rounded(px(10.))
                .bg(theme.bg_surface)
                .border_1()
                .border_color(theme.border)
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
                .min_w_0()
                .h_full()
                .p_8()
                .rounded(px(10.))
                .bg(theme.bg_surface)
                .border_1()
                .border_color(theme.border)
                .flex()
                .items_center()
                .justify_center()
                .text_size(px(13.))
                .text_color(theme.text_muted)
                .child("未找到选中的主机条目")
                .into_any_element();
        };
        let rt = self.runtimes.get(&selected_id).cloned().unwrap_or_default();
        let is_running = rt.status.is_running();
        let is_starting = matches!(rt.status, RelayStatus::Starting);
        let is_error = matches!(rt.status, RelayStatus::Error(_));
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
        let snippet_preview = render_agent_snippet(&host, &preview_rt, CopyFormat::AgentPromptCard)
            .unwrap_or_else(|e| e.to_string());

        div()
            .flex_1()
            .min_w_0()
            .h_full()
            .min_h_0()
            .overflow_hidden()
            .flex()
            .flex_col()
            .gap(px(14.))
            // 第一区：主机顶栏卡片（身份、固定监听端口状态、核心操作按钮）
            .child(
                div()
                    .w_full()
                    .flex_shrink_0()
                    .px_5()
                    .py_4()
                    .rounded(px(10.))
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
                            .gap_3()
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .flex()
                                    .items_center()
                                    .gap_2p5()
                                    .child(
                                        div()
                                            .flex_shrink_0()
                                            .text_size(px(17.))
                                            .font_weight(gpui::FontWeight::BOLD)
                                            .text_color(theme.text_primary)
                                            .child(format!("[{}]", host.codename)),
                                    )
                                    .child(
                                        div()
                                            .flex_shrink_0()
                                            .px_2()
                                            .py_0p5()
                                            .rounded(px(4.))
                                            .text_size(px(11.5))
                                            .bg(if is_running {
                                                theme.success_soft
                                            } else if is_error {
                                                theme.danger_soft
                                            } else {
                                                hsla(0., 0., 0.5, 0.14)
                                            })
                                            .text_color(if is_running {
                                                theme.success
                                            } else if is_starting {
                                                theme.warning
                                            } else if is_error {
                                                theme.danger
                                            } else {
                                                theme.text_secondary
                                            })
                                            .child(if is_running {
                                                format!("运行中 · {}:{}", bind_host, display_port)
                                            } else if is_starting {
                                                format!("启动中 · {}:{}", bind_host, display_port)
                                            } else if is_error {
                                                format!("监听异常 · {}:{}", bind_host, display_port)
                                            } else {
                                                format!("已停止 · 固定端口 {}:{}", bind_host, display_port)
                                            }),
                                    )
                                    .when(!host.label.is_empty(), |d| {
                                        d.child(
                                            div()
                                                .min_w_0()
                                                .truncate()
                                                .text_size(px(12.5))
                                                .text_color(theme.text_secondary)
                                                .child(host.label.clone()),
                                        )
                                    }),
                            )
                            .child(
                                div()
                                    .flex_shrink_0()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child({
                                        let c_toggle = codename.clone();
                                        action_button(
                                            "detail-toggle-relay",
                                            if is_running {
                                                "停止"
                                            } else if is_starting {
                                                "启动中..."
                                            } else {
                                                "启动"
                                            },
                                            theme,
                                            !is_starting,
                                            is_running,
                                        )
                                        .when(!is_running && !is_starting, |b| {
                                            b.bg(theme.accent).text_color(rgb(0xffffff))
                                        })
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            if is_starting {
                                                return;
                                            }
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
                                        let host_test = host.clone();
                                        let is_testing =
                                            self.testing_host_ids.contains(&selected_id);
                                        action_button(
                                            "detail-test-upstream",
                                            if is_testing { "测试中..." } else { "测试" },
                                            theme,
                                            !is_testing,
                                            false,
                                        )
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            if !this.testing_host_ids.contains(&selected_id) {
                                                this.spawn_test_upstream(
                                                    host_test.clone(),
                                                    false,
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
                                        .on_click(cx.listener(move |this, _, window, cx| {
                                            this.populate_form_from_host(&host_edit, cx);
                                            this.show_host_modal = true;
                                            let fh = this.form_codename.read(cx).focus_handle(cx);
                                            window.focus(&fh);
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
                            .truncate()
                            .text_size(px(12.))
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
                    .flex_shrink_0()
                    .flex()
                    .gap(px(16.))
                    .child(
                        // 左栏：本地隔离凭证与认证方式
                        div()
                            .flex_1()
                            .min_w_0()
                            .p(px(18.))
                            .rounded(px(10.))
                            .bg(theme.bg_surface)
                            .border_1()
                            .border_color(theme.border)
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
                                    .rounded(px(7.))
                                    .bg(theme.bg_code)
                                    .border_1()
                                    .border_color(theme.border)
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .gap_2p5()
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
                                                    .truncate()
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
                                            .flex_shrink_0()
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
                                                    "重置",
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
                                    .gap_2()
                                    .text_size(px(12.))
                                    .child(
                                        div()
                                            .flex()
                                            .justify_between()
                                            .gap_3()
                                            .child(
                                                div()
                                                    .flex_shrink_0()
                                                    .text_color(theme.text_muted)
                                                    .child("本机固定监听"),
                                            )
                                            .child(
                                                div()
                                                    .min_w_0()
                                                    .truncate()
                                                    .text_color(theme.text_primary)
                                                    .child(format!("{}:{}", bind_host, display_port)),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .justify_between()
                                            .gap_3()
                                            .child(
                                                div()
                                                    .flex_shrink_0()
                                                    .text_color(theme.text_muted)
                                                    .child("Agent 登录用户"),
                                            )
                                            .child(
                                                div()
                                                    .min_w_0()
                                                    .truncate()
                                                    .text_color(theme.text_primary)
                                                    .child(host.codename.clone()),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .justify_between()
                                            .gap_3()
                                            .child(
                                                div()
                                                    .flex_shrink_0()
                                                    .text_color(theme.text_muted)
                                                    .child("真实远端目标"),
                                            )
                                            .child(
                                                div()
                                                    .min_w_0()
                                                    .truncate()
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
                            .p(px(18.))
                            .rounded(px(10.))
                            .bg(theme.bg_surface)
                            .border_1()
                            .border_color(theme.border)
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
                                    .flex_1()
                                    .w_full()
                                    .min_w_0()
                                    .overflow_hidden()
                                    .p_3()
                                    .rounded(px(7.))
                                    .bg(theme.bg_code)
                                    .border_1()
                                    .border_color(theme.border)
                                    .text_size(px(11.5))
                                    .text_color(theme.text_primary)
                                    .flex()
                                    .flex_col()
                                    .justify_center()
                                    .gap_1()
                                    .children(
                                        snippet_preview
                                            .lines()
                                            .map(|line| div().whitespace_normal().child(line.to_string())),
                                    ),
                            ),
                    ),
            )
            // 第三区：底部实时转发审计流
            .child(self.render_audit_logs_tab(theme, cx))
            .into_any_element()
    }

    fn render_host_modal(&self, theme: WorkbenchTheme, cx: &mut Context<Self>) -> impl IntoElement {
        let is_editing = self.editing_host_id.is_some();
        let secret_masked = self.form_real_secret.read(cx).is_masked();
        let agent_pwd_masked = self.form_agent_password.read(cx).is_masked();
        let proxy_pwd_masked = self.form_proxy_pass.read(cx).is_masked();
        let form_feedback_is_err = self.form_error.is_some();
        let form_feedback = self
            .form_error
            .clone()
            .or_else(|| self.form_test_ok.clone())
            .or_else(|| {
                if self.form_testing {
                    Some("正在连接上游服务器验证代理与凭据...".to_string())
                } else {
                    None
                }
            });

        div()
            .id("host-editor-modal-backdrop")
            .occlude()
            .absolute()
            .top_0()
            .left_0()
            .size_full()
            .px(px(32.))
            .py(px(24.))
            .bg(hsla(0., 0., 0., 0.58))
            .flex()
            .items_center()
            .justify_center()
            .on_mouse_down(MouseButton::Left, |_, _, _| {})
            .child(
                div()
                    .w(px(680.))
                    .max_w_full()
                    .h(gpui::relative(0.94))
                    .max_h(px(650.))
                    .overflow_hidden()
                    .p(px(24.))
                    .rounded(px(12.))
                    .bg(theme.bg_surface)
                    .border_1()
                    .border_color(theme.border_focus)
                    .shadow_lg()
                    .flex()
                    .flex_col()
                    .gap_3p5()
                    .child(
                        div()
                            .flex_shrink_0()
                            .flex()
                            .items_center()
                            .justify_between()
                            .pb_3()
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
                                        this.close_host_modal();
                                        cx.notify();
                                    })),
                            ),
                    )
                    .child(
                        div()
                            .id("host-editor-form-scroll")
                            .w_full()
                            .min_h_0()
                            .flex_1()
                            .overflow_y_scroll()
                            .pr_1p5()
                            .py_0p5()
                            .flex()
                            .flex_col()
                            .gap_4()
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
                    )
                    // 底部栏：校验反馈 + 取消与保存按钮
                    .child(
                        div()
                            .flex_shrink_0()
                            .pt_3()
                            .border_t_1()
                            .border_color(theme.border)
                            .flex()
                            .flex_col()
                            .gap_2p5()
                            .when(form_feedback.is_some(), |footer| {
                                let message = form_feedback.clone().unwrap_or_default();
                                let copy_message = message.clone();
                                footer.child(
                                    div()
                                        .w_full()
                                        .flex()
                                        .items_start()
                                        .gap_2()
                                        .child(
                                            div()
                                                .id("form-test-feedback")
                                                .flex_1()
                                                .min_w_0()
                                                .max_h(px(84.))
                                                .overflow_y_scroll()
                                                .whitespace_normal()
                                                .text_size(px(12.))
                                                .text_color(if form_feedback_is_err {
                                                    theme.danger
                                                } else if self.form_test_ok.is_some() {
                                                    theme.success
                                                } else {
                                                    theme.accent_hover
                                                })
                                                .child(message),
                                        )
                                        .child(
                                            action_button(
                                                "form-copy-feedback",
                                                "复制",
                                                theme,
                                                !copy_message.is_empty(),
                                                false,
                                            )
                                            .h(px(26.))
                                            .px_2()
                                            .flex_shrink_0()
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                cx.write_to_clipboard(ClipboardItem::new_string(
                                                    copy_message.clone(),
                                                ));
                                                this.status_banner =
                                                    Some(("已复制测试结果".to_string(), false));
                                                cx.notify();
                                            })),
                                        ),
                                )
                            })
                            .child(
                                div()
                                    .w_full()
                                    .flex()
                                    .flex_shrink_0()
                                    .items_center()
                                    .justify_end()
                                    .gap_2p5()
                                    .child(
                                        action_button(
                                            "form-test-upstream",
                                            if self.form_testing {
                                                "测试中..."
                                            } else {
                                                "测试连接"
                                            },
                                            theme,
                                            !self.form_testing,
                                            false,
                                        )
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            if this.form_testing {
                                                return;
                                            }
                                            match this.validate_and_build_host(cx) {
                                                Ok((host, _)) => {
                                                    this.spawn_test_upstream(host, true, cx);
                                                }
                                                Err(err_msg) => {
                                                    this.form_error = Some(err_msg.clone());
                                                    this.form_test_ok = None;
                                                    this.status_banner = Some((err_msg, true));
                                                    cx.notify();
                                                }
                                            }
                                        })),
                                    )
                                    .child(
                                        action_button(
                                            "form-modal-cancel",
                                            "取消",
                                            theme,
                                            true,
                                            false,
                                        )
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.close_host_modal();
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
            .p(px(18.))
            .rounded(px(10.))
            .bg(theme.bg_surface)
            .border_1()
            .border_color(theme.border)
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex_shrink_0()
                    .pb_2p5()
                    .border_b_1()
                    .border_color(theme.border)
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .text_size(px(13.5))
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
                    .overflow_y_scroll()
                    .pr_1()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .when(all_logs.is_empty(), |d| {
                        d.child(
                            div()
                                .p_4()
                                .rounded(px(7.))
                                .bg(theme.bg_code)
                                .border_1()
                                .border_color(theme.border)
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
                            .px_3()
                            .py_2()
                            .rounded(px(6.))
                            .bg(theme.bg_code)
                            .border_1()
                            .border_color(theme.border)
                            .flex()
                            .items_center()
                            .justify_between()
                            .gap_3()
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
                                            .flex_shrink_0()
                                            .text_color(theme.text_muted)
                                            .child(entry.timestamp),
                                    )
                                    .child(
                                        div()
                                            .flex_shrink_0()
                                            .px_1p5()
                                            .py_0p5()
                                            .rounded(px(3.))
                                            .bg(theme.accent_soft)
                                            .text_color(theme.accent_hover)
                                            .child(format!("[{}]", entry.codename)),
                                    )
                                    .child(
                                        div()
                                            .flex_shrink_0()
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
                                            .whitespace_normal()
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
                                    .flex_shrink_0()
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
            .p(px(28.))
            .bg(hsla(0., 0., 0., 0.62))
            .flex()
            .items_center()
            .justify_center()
            .on_mouse_down(MouseButton::Left, |_, _, _| {})
            .child(
                div()
                    .w(px(480.))
                    .max_w_full()
                    .p(px(24.))
                    .rounded(px(12.))
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
                    .gap_4()
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
                            .p_3p5()
                            .rounded(px(7.))
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
                                .on_click(cx.listener(
                                    move |this, _, _, cx| {
                                        this.pending_confirm = None;
                                        this.execute_confirmed_action(
                                            confirm_action_clone.clone(),
                                            cx,
                                        );
                                    },
                                )),
                            ),
                    ),
            )
    }
}

impl Render for AgentGateWorkbench {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        // 保持焦点链始终挂载在当前活跃视图树上，确保未点击输入框时 Enter / Esc / Tab / Cmd+W 快捷键均可靠触发
        if self.pending_confirm.is_some() {
            if !self.focus_handle.is_focused(window) {
                window.focus(&self.focus_handle);
            }
        } else if self.show_host_modal {
            if window.focused(cx).is_none() || self.focus_handle.is_focused(window) {
                let fh = self.form_codename.read(cx).focus_handle(cx);
                window.focus(&fh);
            }
        } else if !self.focus_handle.is_focused(window)
            && !self.search_input.read(cx).focus_handle(cx).is_focused(window)
        {
            window.focus(&self.focus_handle);
        }

        let theme = if self.is_dark {
            WorkbenchTheme::dark()
        } else {
            WorkbenchTheme::light()
        };

        div()
            .id("agentgate-root")
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
                    .id("agentgate-workspace-body")
                    .track_focus(&self.focus_handle)
                    .flex_1()
                    .min_h_0()
                    .w_full()
                    .relative()
                    .overflow_hidden()
                    .flex()
                    .flex_col()
                    .child(
                        div()
                            .id("agentgate-workspace-canvas")
                            .size_full()
                            .min_h_0()
                            .px(px(22.))
                            .pt(px(16.))
                            .pb(px(22.))
                            .flex()
                            .flex_col()
                            .gap(px(14.))
                            .child(self.render_status_strip(theme))
                            .child(
                                div()
                                    .flex_1()
                                    .min_h_0()
                                    .w_full()
                                    .flex()
                                    .flex_row()
                                    .gap(px(16.))
                                    .child(self.render_left_host_list(theme, cx))
                                    .child(self.render_right_workspace(theme, cx)),
                            ),
                    )
                    .when(self.show_host_modal, |body| {
                        body.child(self.render_host_modal(theme, cx))
                    })
                    .when_some(self.pending_confirm.clone(), |body, pending| {
                        body.child(self.render_confirm_modal(&pending, theme, cx))
                    }),
            )
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
                .child(div().size(px(14.)).rounded(px(7.)).bg(theme.text_primary))
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

#[cfg(debug_assertions)]
pub mod live_selftest {
    use super::*;
    use bytes::Bytes;
    use gpui::{
        Application, Bounds, Keystroke, Modifiers, MouseDownEvent, MouseMoveEvent, MouseUpEvent,
        TitlebarOptions, WindowBounds, WindowKind, WindowOptions, size,
    };
    use russh::keys::ssh_key::{Algorithm, PublicKey};
    use russh::server::{Auth, Msg as ServerMsg, Session as ServerSession, VerifiedPublicKey};
    use russh::{Channel, ChannelId, Pty, server};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    struct LiveProbeUpstreamServer {
        expected_user: String,
        expected_password: String,
        expected_pubkey: Option<PublicKey>,
        chan_modes: HashMap<ChannelId, String>,
        chan_stdin_bytes: HashMap<ChannelId, usize>,
    }

    impl server::Handler for LiveProbeUpstreamServer {
        type Error = russh::Error;

        async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
            if user == self.expected_user && password == self.expected_password {
                Ok(Auth::Accept)
            } else {
                Ok(Auth::reject())
            }
        }

        async fn auth_publickey(
            &mut self,
            user: &str,
            key: VerifiedPublicKey<'_>,
        ) -> Result<Auth, Self::Error> {
            if user == self.expected_user
                && self
                    .expected_pubkey
                    .as_ref()
                    .is_some_and(|pk| pk == key.public_key)
            {
                Ok(Auth::Accept)
            } else {
                Ok(Auth::reject())
            }
        }

        async fn channel_open_session(
            &mut self,
            channel: Channel<ServerMsg>,
            reply: server::ChannelOpenHandle,
            _session: &mut ServerSession,
        ) -> Result<(), Self::Error> {
            drop(channel);
            reply.accept().await;
            Ok(())
        }

        async fn pty_request(
            &mut self,
            channel: ChannelId,
            _term: &str,
            _col_width: u32,
            _row_height: u32,
            _pix_width: u32,
            _pix_height: u32,
            _modes: &[(Pty, u32)],
            session: &mut ServerSession,
        ) -> Result<(), Self::Error> {
            let _ = session.channel_success(channel);
            Ok(())
        }

        async fn shell_request(
            &mut self,
            channel: ChannelId,
            session: &mut ServerSession,
        ) -> Result<(), Self::Error> {
            self.chan_modes.insert(channel, "shell".to_string());
            let _ = session.channel_success(channel);
            let _ = session
                .handle()
                .data(channel, Bytes::from("LIVE_PTY_READY> "))
                .await;
            Ok(())
        }

        async fn exec_request(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut ServerSession,
        ) -> Result<(), Self::Error> {
            let cmd = String::from_utf8_lossy(data).trim().to_string();
            let _ = session.channel_success(channel);
            let handle = session.handle();
            match cmd.as_str() {
                "sink_count" => {
                    self.chan_modes.insert(channel, "sink_count".to_string());
                    self.chan_stdin_bytes.insert(channel, 0);
                }
                "big_stdout" => {
                    tokio::spawn(async move {
                        let chunk = Bytes::from(vec![b'A'; 16384]);
                        for _ in 0..32 {
                            if handle.data(channel, chunk.clone()).await.is_err() {
                                return;
                            }
                        }
                        let _ = handle.exit_status_request(channel, 0).await;
                        let _ = handle.eof(channel).await;
                        let _ = handle.close(channel).await;
                    });
                }
                "stderr_and_exit_42" => {
                    let _ = handle.data(channel, Bytes::from("OUT_LINE\n")).await;
                    let _ = handle
                        .extended_data(channel, 1, Bytes::from("ERR_LINE\n"))
                        .await;
                    let _ = handle.exit_status_request(channel, 42).await;
                    let _ = handle.eof(channel).await;
                    let _ = handle.close(channel).await;
                }
                _ => {
                    let reply = format!("EXEC_OK:{}\n", cmd);
                    let _ = handle.data(channel, Bytes::from(reply)).await;
                    let _ = handle.exit_status_request(channel, 0).await;
                    let _ = handle.eof(channel).await;
                    let _ = handle.close(channel).await;
                }
            }
            Ok(())
        }

        async fn subsystem_request(
            &mut self,
            channel: ChannelId,
            name: &str,
            session: &mut ServerSession,
        ) -> Result<(), Self::Error> {
            if name == "echo_subsys" {
                let _ = session.channel_success(channel);
                let handle = session.handle();
                let _ = handle.data(channel, Bytes::from("SUBSYS_OK\n")).await;
                let _ = handle.exit_status_request(channel, 0).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
            } else {
                let _ = session.channel_failure(channel);
            }
            Ok(())
        }

        async fn data(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut ServerSession,
        ) -> Result<(), Self::Error> {
            match self.chan_modes.get(&channel).map(String::as_str) {
                Some("sink_count") => {
                    *self.chan_stdin_bytes.entry(channel).or_insert(0) += data.len();
                }
                Some("shell") => {
                    let s = String::from_utf8_lossy(data);
                    let handle = session.handle();
                    let _ = handle
                        .data(channel, Bytes::from(format!("PTY_ECHO:{}", s)))
                        .await;
                    if s.contains("exit") {
                        let _ = handle.exit_status_request(channel, 0).await;
                        let _ = handle.eof(channel).await;
                        let _ = handle.close(channel).await;
                    }
                }
                _ => {}
            }
            Ok(())
        }

        async fn channel_eof(
            &mut self,
            channel: ChannelId,
            session: &mut ServerSession,
        ) -> Result<(), Self::Error> {
            if self.chan_modes.get(&channel).map(String::as_str) == Some("sink_count") {
                let total = self.chan_stdin_bytes.get(&channel).copied().unwrap_or(0);
                let handle = session.handle();
                let _ = handle
                    .data(channel, Bytes::from(format!("STDIN_BYTES:{}\n", total)))
                    .await;
                let _ = handle.exit_status_request(channel, 0).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
            }
            Ok(())
        }
    }

    pub fn run_live_workbench_selftest() {
        let temp_root: PathBuf =
            std::env::temp_dir().join(format!("agentgate-selftest-{}", Uuid::new_v4().simple()));
        let data_dir = temp_root.join("agentgate_data");
        std::fs::create_dir_all(&data_dir).expect("mkdir data");
        unsafe {
            std::env::set_var("AGENTGATE_DATA_DIR", &data_dir);
            std::env::set_var("AGENTGATE_DEMO_SEED", "1");
        }

        // 启动真实上游模拟 SSH 服务器 + 慢速 Tarpit 端口（用于测试模态框关闭后异步回调串台）
        let rt_handle = global_tokio_runtime();
        let (remote_port, tarpit_port) = rt_handle.block_on(async {
            let remote_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind remote");
            let r_port = remote_listener.local_addr().unwrap().port();
            let remote_key =
                PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("remote key");
            let remote_cfg = Arc::new(server::Config {
                keys: vec![remote_key],
                auth_rejection_time: Duration::from_millis(10),
                auth_rejection_time_initial: Some(Duration::from_millis(0)),
                ..Default::default()
            });
            tokio::spawn(async move {
                while let Ok((socket, _)) = remote_listener.accept().await {
                    let cfg = remote_cfg.clone();
                    tokio::spawn(async move {
                        let handler = LiveProbeUpstreamServer {
                            expected_user: "real_ops_admin".to_string(),
                            expected_password: "RealUpstreamSecret#2026".to_string(),
                            expected_pubkey: None,
                            chan_modes: HashMap::new(),
                            chan_stdin_bytes: HashMap::new(),
                        };
                        let _ = server::run_stream(cfg, socket, handler).await;
                    });
                }
            });

            let tarpit_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tarpit");
            let t_port = tarpit_listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                while let Ok((socket, _)) = tarpit_listener.accept().await {
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(350)).await;
                        drop(socket);
                    });
                }
            });

            (r_port, t_port)
        });

        let findings: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let findings_ref = findings.clone();
        let temp_path = temp_root.clone();

        Application::new().run(move |cx: &mut App| {
            register_workbench_keys(cx);
            cx.activate(true);
            let orig_clipboard = cx.read_from_clipboard().and_then(|c| c.text());

            let bounds = Bounds::centered(None, size(px(1280.0), px(820.0)), cx);
            let win_handle = cx
                .open_window(
                    WindowOptions {
                        window_bounds: Some(WindowBounds::Windowed(bounds)),
                        window_min_size: Some(size(px(1040.0), px(680.0))),
                        titlebar: Some(TitlebarOptions {
                            title: Some("AgentGate-LiveTest".into()),
                            appears_transparent: false,
                            traffic_light_position: None,
                        }),
                        focus: true,
                        show: true,
                        kind: WindowKind::Normal,
                        is_movable: true,
                        is_resizable: true,
                        is_minimizable: true,
                        ..Default::default()
                    },
                    |window, cx| cx.new(|cx| AgentGateWorkbench::new(window, cx)),
                )
                .expect("open live GPUI window");

            let entity = win_handle.entity(cx).expect("workbench entity");
            let findings_inner = findings_ref.clone();

            cx.spawn(async move |cx| {
                let record = |msg: String| {
                    println!("{}", msg);
                    findings_inner.lock().unwrap().push(msg);
                };

                // 等待首次渲染与异步启动完成
                cx.background_executor()
                    .timer(Duration::from_millis(550))
                    .await;

                // === Phase 1: 启动状态、Demo Seed 与顶栏布局边界 ===
                let _ = win_handle.update(cx, |this, window, cx| {
                    let vp = window.viewport_size();
                    record(format!(
                        "[INFO] Phase 1 viewport = {:?}, hosts = {}",
                        vp,
                        this.hosts.len()
                    ));
                    if let Some((msg, is_err)) = &this.status_banner {
                        if *is_err {
                            record(format!(
                                "[FAIL] Phase 1 startup status_banner has error: {}",
                                msg
                            ));
                        } else {
                            record(format!("[PASS] Phase 1 startup status_banner ok: {}", msg));
                        }
                    }
                    let running_codes: Vec<String> = this
                        .hosts
                        .iter()
                        .filter(|h| {
                            this.runtimes
                                .get(&h.id)
                                .is_some_and(|r| r.status.is_running())
                        })
                        .map(|h| h.codename.clone())
                        .collect();
                    if running_codes.len() != 1 {
                        record(format!(
                            "[FAIL] Phase 1 demo_seed expected only h1 running, but running = {:?}",
                            running_codes
                        ));
                    } else {
                        record(format!(
                            "[PASS] Phase 1 demo_seed running hosts = {:?}",
                            running_codes
                        ));
                    }
                    if let Some(sb) = this.search_input.read(cx).last_bounds() {
                        record(format!("[INFO] Phase 1 search_input bounds = {:?}", sb));
                    } else {
                        record("[FAIL] Phase 1 search_input did not paint bounds".to_string());
                    }

                    // 1b: 验证在未点击任何输入框前打开确认弹窗，直接按 Esc 即可关闭弹窗（焦点链完整性验证）
                    let h1 = this.hosts[0].clone();
                    this.request_confirmation(
                        PendingAction::CopyAgentConfig {
                            id: h1.id,
                            codename: h1.codename.clone(),
                            format: CopyFormat::AgentPromptCard,
                        },
                        cx,
                    );
                });

                let any_win_init: gpui::AnyWindowHandle = win_handle.into();
                let _ = any_win_init.update(cx, |_, window, cx| {
                    let _ = window.dispatch_keystroke(Keystroke::parse("escape").unwrap(), cx);
                });

                let _ = win_handle.update(cx, |this, window, cx| {
                    if this.pending_confirm.is_none() {
                        record(
                            "[PASS] Phase 1b Escape dismissed confirm modal without prior input click"
                                .to_string(),
                        );
                    } else {
                        record(
                            "[FAIL] Phase 1b Escape failed to dismiss confirm modal without prior input click"
                                .to_string(),
                        );
                        this.pending_confirm = None;
                    }

                    // 打开主机编辑弹窗进入 Phase 2
                    let h1 = this.hosts[0].clone();
                    this.populate_form_from_host(&h1, cx);
                    this.show_host_modal = true;
                    let fh = this.form_codename.read(cx).focus_handle(cx);
                    window.focus(&fh);
                    window.activate_window();
                    cx.notify();
                    window.refresh();
                });

                for _ in 0..12 {
                    cx.background_executor()
                        .timer(Duration::from_millis(60))
                        .await;
                    let painted = win_handle
                        .update(cx, |this, window, cx| {
                            if this.form_codename.read(cx).last_bounds().is_some() {
                                true
                            } else {
                                cx.activate(true);
                                window.activate_window();
                                window.refresh();
                                false
                            }
                        })
                        .unwrap_or(false);
                    if painted {
                        break;
                    }
                }

                // === Phase 2: 实机窗口鼠标单击/双击/三击全选 + 抖动容错 + Cmd+C ===
                let _ = win_handle.update(cx, |this, window, cx| {
                    let Some(cb) = this.form_codename.read(cx).last_bounds() else {
                        record("[FAIL] Phase 2 form_codename last_bounds is None".to_string());
                        return;
                    };
                    record(format!("[INFO] Phase 2 form_codename bounds = {:?}", cb));

                    // 检查模态框外边距（窗口宽 1280，模态框宽 680 居中，左右应 > 280px 且 < 1000px）
                    if cb.left() < px(280.) || cb.right() > px(1000.) {
                        record(format!(
                            "[FAIL] Phase 2 form_codename outside expected centered modal margins: {:?}",
                            cb
                        ));
                    } else {
                        record("[PASS] Phase 2 modal input outer margins verified".to_string());
                    }

                    let click_pt = gpui::point(cb.left() + px(22.), cb.center().y);

                    // 1) 单击
                    this.form_codename.update(cx, |f, cx| {
                        f.on_mouse_down(
                            &MouseDownEvent {
                                button: MouseButton::Left,
                                position: click_pt,
                                modifiers: Modifiers::default(),
                                click_count: 1,
                                first_mouse: false,
                            },
                            window,
                            cx,
                        );
                        f.on_mouse_up(
                            &MouseUpEvent {
                                button: MouseButton::Left,
                                position: click_pt,
                                modifiers: Modifiers::default(),
                                click_count: 1,
                            },
                            window,
                            cx,
                        );
                    });
                    let r1 = this.form_codename.read(cx).selected_range();
                    if r1.is_empty() && r1.start > 0 && r1.start < 15 {
                        record(format!("[PASS] Phase 2 single-click placed cursor at {:?}", r1));
                    } else {
                        record(format!("[FAIL] Phase 2 single-click unexpected range {:?}", r1));
                    }

                    // 2) 双击 + 2px 抖动（应选中首词 "cobalt" = 0..6）
                    this.form_codename.update(cx, |f, cx| {
                        f.on_mouse_down(
                            &MouseDownEvent {
                                button: MouseButton::Left,
                                position: click_pt,
                                modifiers: Modifiers::default(),
                                click_count: 2,
                                first_mouse: false,
                            },
                            window,
                            cx,
                        );
                        f.on_mouse_move(
                            &MouseMoveEvent {
                                position: gpui::point(click_pt.x + px(2.), click_pt.y + px(1.)),
                                pressed_button: Some(MouseButton::Left),
                                modifiers: Modifiers::default(),
                            },
                            window,
                            cx,
                        );
                        f.on_mouse_up(
                            &MouseUpEvent {
                                button: MouseButton::Left,
                                position: click_pt,
                                modifiers: Modifiers::default(),
                                click_count: 2,
                            },
                            window,
                            cx,
                        );
                    });
                    let r2 = this.form_codename.read(cx).selected_range();
                    if r2 == (0..6) {
                        record("[PASS] Phase 2 double-click + jitter selected 'cobalt' (0..6)".to_string());
                    } else {
                        record(format!("[FAIL] Phase 2 double-click expected 0..6, got {:?}", r2));
                    }

                    // 3) 三击 + 6px 鼠标抖动（必须全选整个 "cobalt-nexus-01" = 0..15）
                    this.form_codename.update(cx, |f, cx| {
                        f.on_mouse_down(
                            &MouseDownEvent {
                                button: MouseButton::Left,
                                position: click_pt,
                                modifiers: Modifiers::default(),
                                click_count: 3,
                                first_mouse: false,
                            },
                            window,
                            cx,
                        );
                        f.on_mouse_move(
                            &MouseMoveEvent {
                                position: gpui::point(click_pt.x + px(6.), click_pt.y - px(2.)),
                                pressed_button: Some(MouseButton::Left),
                                modifiers: Modifiers::default(),
                            },
                            window,
                            cx,
                        );
                        f.on_mouse_up(
                            &MouseUpEvent {
                                button: MouseButton::Left,
                                position: click_pt,
                                modifiers: Modifiers::default(),
                                click_count: 3,
                            },
                            window,
                            cx,
                        );
                    });
                    let r3 = this.form_codename.read(cx).selected_range();
                    let full_len = this.form_codename.read(cx).text().len();
                    if r3 == (0..full_len) && full_len == 15 {
                        record("[PASS] Phase 2 triple-click + jitter selected ALL (0..15)".to_string());
                    } else {
                        record(format!(
                            "[FAIL] Phase 2 triple-click expected 0..{}, got {:?}",
                            full_len, r3
                        ));
                    }

                    // 5) 缩放窗口至最小尺寸 1040x680 验证不崩溃
                    window.resize(size(px(1040.0), px(680.0)));
                    window.refresh();
                });

                // 4) 在不持有 AgentGateWorkbench 借用的窗口上下文中派发真实按键 Cmd+C
                let any_win: gpui::AnyWindowHandle = win_handle.into();
                let _ = any_win.update(cx, |_, window, cx| {
                    cx.write_to_clipboard(ClipboardItem::new_string("__INIT__".to_string()));
                    let _ = window.dispatch_keystroke(Keystroke::parse("cmd-c").unwrap(), cx);
                    let clip_after = cx.read_from_clipboard().and_then(|c| c.text());
                    if clip_after.as_deref() == Some("cobalt-nexus-01") {
                        record("[PASS] Phase 2 Cmd+C copied triple-click selection".to_string());
                    } else {
                        record(format!(
                            "[FAIL] Phase 2 Cmd+C clipboard = {:?}",
                            clip_after
                        ));
                    }
                });

                cx.background_executor()
                    .timer(Duration::from_millis(150))
                    .await;

                // === Phase 3: 模态框 Esc 关闭状态清理与慢速测试串台检查 ===
                let _ = win_handle.update(cx, |this, _window, cx| {
                    let mut tarpit_host = this.hosts[0].clone();
                    tarpit_host.real_host = "127.0.0.1".to_string();
                    tarpit_host.real_port = tarpit_port;
                    tarpit_host.proxy = ProxyConfig::None;
                    this.form_test_ok = Some("上次残留成功提示".to_string());
                    this.spawn_test_upstream(tarpit_host, true, cx);
                });

                let _ = any_win.update(cx, |_, window, cx| {
                    // 按 Esc 关闭编辑弹窗
                    let _ = window.dispatch_keystroke(Keystroke::parse("escape").unwrap(), cx);
                });

                let _ = win_handle.update(cx, |this, _window, cx| {
                    if this.show_host_modal {
                        record("[FAIL] Phase 3 Escape did not close host modal".to_string());
                    }
                    if this.form_testing || this.form_test_ok.is_some() {
                        record(format!(
                            "[FAIL] Phase 3 Escape left stale modal state: form_testing={}, form_test_ok={:?}",
                            this.form_testing, this.form_test_ok
                        ));
                    } else {
                        record("[PASS] Phase 3 Escape cleaned modal test state".to_string());
                    }

                    // 立即点击「+ 新建」打开新表单，等待刚才 350ms 的 tarpit 测试返回
                    this.reset_form_for_new_host(cx);
                    this.show_host_modal = true;
                    cx.notify();
                });

                cx.background_executor()
                    .timer(Duration::from_millis(500))
                    .await;

                let _ = win_handle.update(cx, |this, _window, cx| {
                    if let Some(leaked_err) = &this.form_error {
                        record(format!(
                            "[FAIL] Phase 3 stale upstream test leaked error into newly opened modal: {}",
                            leaked_err
                        ));
                    } else {
                        record("[PASS] Phase 3 no stale upstream test leakage into new modal".to_string());
                    }
                    this.show_host_modal = false;
                    cx.notify();
                });

                // === Phase 4: 固定端口 Stop -> 立即 Start 及运行中重复 Start 竞态测试 ===
                let probe_port = RelayHost::allocate_free_local_port("127.0.0.1");
                let probe_pwd = "ProbeLocalPwd-2026-AbcXyz".to_string();
                let probe_id = Uuid::new_v4();
                let probe_host = RelayHost {
                    id: probe_id,
                    codename: "live-probe-01".to_string(),
                    label: "实机探针节点".to_string(),
                    local_bind_host: "127.0.0.1".to_string(),
                    local_port: probe_port,
                    agent_password: probe_pwd.clone(),
                    real_host: "127.0.0.1".to_string(),
                    real_port: remote_port,
                    real_user: "real_ops_admin".to_string(),
                    real_auth: RealAuthConfig::Password {
                        password: "RealUpstreamSecret#2026".to_string(),
                    },
                    proxy: ProxyConfig::None,
                    agent_auth_mode: AgentAuthMode::EphemeralPassword,
                    dedicated_key_openssh_pem: None,
                    pinned_host_key_openssh: None,
                    created_at: RelayHost::now_str(),
                    updated_at: RelayHost::now_str(),
                };

                let _ = entity.update(cx, |this, cx| {
                    this.execute_confirmed_action(
                        PendingAction::SaveHost {
                            host: Box::new(probe_host.clone()),
                            is_new: true,
                        },
                        cx,
                    );
                    this.execute_confirmed_action(
                        PendingAction::StartRelay {
                            id: probe_id,
                            codename: "live-probe-01".to_string(),
                        },
                        cx,
                    );
                });

                cx.background_executor()
                    .timer(Duration::from_millis(300))
                    .await;

                // 执行 StopRelay 紧接着立即 StartRelay（同固定端口 probe_port）
                let _ = entity.update(cx, |this, cx| {
                    this.execute_confirmed_action(
                        PendingAction::StopRelay {
                            id: probe_id,
                            codename: "live-probe-01".to_string(),
                            local_port: probe_port,
                        },
                        cx,
                    );
                    this.execute_confirmed_action(
                        PendingAction::StartRelay {
                            id: probe_id,
                            codename: "live-probe-01".to_string(),
                        },
                        cx,
                    );
                });

                // 等待超过 80ms 轮询周期，观察旧实例的 RelayEvent::Stopped 是否误杀新实例！
                cx.background_executor()
                    .timer(Duration::from_millis(350))
                    .await;

                let mut key_path_opt: Option<String> = None;
                let _ = entity.update(cx, |this, _cx| {
                    let rt = this.runtimes.get(&probe_id).cloned().unwrap_or_default();
                    let has_ctrl = this.controls.contains_key(&probe_id);
                    key_path_opt = rt.dedicated_key_path.clone();
                    if rt.status.is_running() && has_ctrl {
                        record(format!(
                            "[PASS] Phase 4 fixed-port Stop->Start stayed Running on :{}",
                            probe_port
                        ));
                    } else {
                        record(format!(
                            "[FAIL] Phase 4 fixed-port Stop->Start broken! status={:?}, has_ctrl={}",
                            rt.status, has_ctrl
                        ));
                    }
                });

                // 若 Phase 4 被误杀，再重新启动一次以便继续执行 Phase 5~7 协议实测
                let need_restart = entity
                    .read_with(cx, |this, _| !this.controls.contains_key(&probe_id))
                    .unwrap_or(false);
                if need_restart {
                    let _ = entity.update(cx, |this, cx| {
                        this.execute_confirmed_action(
                            PendingAction::StartRelay {
                                id: probe_id,
                                codename: "live-probe-01".to_string(),
                            },
                            cx,
                        );
                    });
                    cx.background_executor()
                        .timer(Duration::from_millis(300))
                        .await;
                }

                // === Phase 5 & 6: 调用系统真实 /usr/bin/ssh 执行全矩阵实测 ===
                let askpass_script = temp_path.join("askpass.sh");
                std::fs::write(
                    &askpass_script,
                    format!("#!/bin/sh\necho '{}'\n", probe_pwd),
                )
                .expect("write askpass");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(
                        &askpass_script,
                        std::fs::Permissions::from_mode(0o700),
                    )
                    .expect("chmod askpass");
                }

                let key_path_str = key_path_opt.unwrap_or_default();
                let askpass_str = askpass_script.to_string_lossy().to_string();

                let ssh_results = global_tokio_runtime()
                    .spawn_blocking(move || {
                        let mut logs = Vec::new();

                        // 5a: 默认密码认证 (SSH_ASKPASS_REQUIRE=force, PubkeyAuthentication=no)
                        let out_pwd = std::process::Command::new("ssh")
                            .env("SSH_ASKPASS", &askpass_str)
                            .env("SSH_ASKPASS_REQUIRE", "force")
                            .env("DISPLAY", ":0")
                            .args([
                                "-o",
                                "StrictHostKeyChecking=no",
                                "-o",
                                "UserKnownHostsFile=/dev/null",
                                "-o",
                                "PubkeyAuthentication=no",
                                "-o",
                                "ConnectTimeout=5",
                                "-p",
                                &probe_port.to_string(),
                                "live-probe-01@127.0.0.1",
                                "hello_pwd",
                            ])
                            .output()
                            .expect("ssh pwd");
                        if out_pwd.status.success()
                            && String::from_utf8_lossy(&out_pwd.stdout).trim() == "EXEC_OK:hello_pwd"
                        {
                            logs.push("[PASS] Phase 5a real /usr/bin/ssh password auth via SSH_ASKPASS".to_string());
                        } else {
                            logs.push(format!(
                                "[FAIL] Phase 5a ssh password auth failed: status={}, stdout={:?}, stderr={:?}",
                                out_pwd.status,
                                String::from_utf8_lossy(&out_pwd.stdout),
                                String::from_utf8_lossy(&out_pwd.stderr)
                            ));
                        }

                        // 5b: 强制 keyboard-interactive 认证（模拟 MobaXterm / PAM 客户端）
                        let out_kbd = std::process::Command::new("ssh")
                            .env("SSH_ASKPASS", &askpass_str)
                            .env("SSH_ASKPASS_REQUIRE", "force")
                            .env("DISPLAY", ":0")
                            .args([
                                "-o",
                                "StrictHostKeyChecking=no",
                                "-o",
                                "UserKnownHostsFile=/dev/null",
                                "-o",
                                "PreferredAuthentications=keyboard-interactive",
                                "-o",
                                "ConnectTimeout=5",
                                "-p",
                                &probe_port.to_string(),
                                "live-probe-01@127.0.0.1",
                                "hello_kbd",
                            ])
                            .output()
                            .expect("ssh kbd");
                        if out_kbd.status.success()
                            && String::from_utf8_lossy(&out_kbd.stdout).trim() == "EXEC_OK:hello_kbd"
                        {
                            logs.push("[PASS] Phase 5b real /usr/bin/ssh keyboard-interactive auth".to_string());
                        } else {
                            logs.push(format!(
                                "[FAIL] Phase 5b ssh keyboard-interactive auth rejected (MethodSet missing KeyboardInteractive?): stderr={:?}",
                                String::from_utf8_lossy(&out_kbd.stderr)
                            ));
                        }

                        // 6a: 专用 Ed25519 密钥认证（即使当前面板处于 EphemeralPassword 模式也应同时生效）
                        let out_key = std::process::Command::new("ssh")
                            .args([
                                "-i",
                                &key_path_str,
                                "-o",
                                "IdentitiesOnly=yes",
                                "-o",
                                "BatchMode=yes",
                                "-o",
                                "StrictHostKeyChecking=no",
                                "-o",
                                "UserKnownHostsFile=/dev/null",
                                "-p",
                                &probe_port.to_string(),
                                "live-probe-01@127.0.0.1",
                                "hello_key",
                            ])
                            .output()
                            .expect("ssh key");
                        if out_key.status.success()
                            && String::from_utf8_lossy(&out_key.stdout).trim() == "EXEC_OK:hello_key"
                        {
                            logs.push("[PASS] Phase 6a real /usr/bin/ssh dedicated key auth".to_string());
                        } else {
                            logs.push(format!(
                                "[FAIL] Phase 6a ssh key auth failed: stderr={:?}",
                                String::from_utf8_lossy(&out_key.stderr)
                            ));
                        }

                        // 6b: 512KB 大数据流 stdin 管道写入 + EOF 传递测试
                        use std::io::Write;
                        let mut child_in = std::process::Command::new("ssh")
                            .args([
                                "-i",
                                &key_path_str,
                                "-o",
                                "IdentitiesOnly=yes",
                                "-o",
                                "BatchMode=yes",
                                "-o",
                                "StrictHostKeyChecking=no",
                                "-o",
                                "UserKnownHostsFile=/dev/null",
                                "-p",
                                &probe_port.to_string(),
                                "live-probe-01@127.0.0.1",
                                "sink_count",
                            ])
                            .stdin(std::process::Stdio::piped())
                            .stdout(std::process::Stdio::piped())
                            .stderr(std::process::Stdio::piped())
                            .spawn()
                            .expect("spawn ssh sink_count");
                        let payload = vec![b'X'; 524_288];
                        if let Some(mut stdin) = child_in.stdin.take() {
                            let _ = stdin.write_all(&payload);
                        }
                        let out_sink = child_in.wait_with_output().expect("wait sink_count");
                        let sink_stdout = String::from_utf8_lossy(&out_sink.stdout).trim().to_string();
                        if out_sink.status.success() && sink_stdout == "STDIN_BYTES:524288" {
                            logs.push("[PASS] Phase 6b 512KB piped stdin + EOF flow control".to_string());
                        } else {
                            logs.push(format!(
                                "[FAIL] Phase 6b 512KB piped stdin failed: status={}, stdout={:?}, stderr={:?}",
                                out_sink.status,
                                sink_stdout,
                                String::from_utf8_lossy(&out_sink.stderr)
                            ));
                        }

                        // 6c: 512KB 大数据流 stdout 下行读取测试
                        let out_big = std::process::Command::new("ssh")
                            .args([
                                "-i",
                                &key_path_str,
                                "-o",
                                "IdentitiesOnly=yes",
                                "-o",
                                "BatchMode=yes",
                                "-o",
                                "StrictHostKeyChecking=no",
                                "-o",
                                "UserKnownHostsFile=/dev/null",
                                "-p",
                                &probe_port.to_string(),
                                "live-probe-01@127.0.0.1",
                                "big_stdout",
                            ])
                            .output()
                            .expect("ssh big_stdout");
                        if out_big.status.success() && out_big.stdout.len() == 524_288 {
                            logs.push("[PASS] Phase 6c 512KB upstream stdout streaming".to_string());
                        } else {
                            logs.push(format!(
                                "[FAIL] Phase 6c 512KB stdout expected 524288 bytes, got {} (status={})",
                                out_big.stdout.len(),
                                out_big.status
                            ));
                        }

                        // 6d: stdout / stderr 通道分离与非零退出码 42 透传
                        let out_err42 = std::process::Command::new("ssh")
                            .args([
                                "-i",
                                &key_path_str,
                                "-o",
                                "IdentitiesOnly=yes",
                                "-o",
                                "BatchMode=yes",
                                "-o",
                                "StrictHostKeyChecking=no",
                                "-o",
                                "UserKnownHostsFile=/dev/null",
                                "-o",
                                "LogLevel=ERROR",
                                "-p",
                                &probe_port.to_string(),
                                "live-probe-01@127.0.0.1",
                                "stderr_and_exit_42",
                            ])
                            .output()
                            .expect("ssh exit 42");
                        if out_err42.status.code() == Some(42)
                            && out_err42.stdout == b"OUT_LINE\n"
                            && String::from_utf8_lossy(&out_err42.stderr).contains("ERR_LINE")
                        {
                            logs.push("[PASS] Phase 6d stdout/stderr separation & exit code 42".to_string());
                        } else {
                            logs.push(format!(
                                "[FAIL] Phase 6d exit42 mismatch: code={:?}, stdout={:?}, stderr={:?}",
                                out_err42.status.code(),
                                String::from_utf8_lossy(&out_err42.stdout),
                                String::from_utf8_lossy(&out_err42.stderr)
                            ));
                        }

                        // 6e: direct-tcpip (-W) 与 tcpip-forward (-R) 端口转发拦截测试
                        let out_fwd_w = std::process::Command::new("ssh")
                            .args([
                                "-i",
                                &key_path_str,
                                "-o",
                                "IdentitiesOnly=yes",
                                "-o",
                                "BatchMode=yes",
                                "-o",
                                "StrictHostKeyChecking=no",
                                "-o",
                                "UserKnownHostsFile=/dev/null",
                                "-o",
                                "ConnectTimeout=5",
                                "-W",
                                "127.0.0.1:80",
                                "-p",
                                &probe_port.to_string(),
                                "live-probe-01@127.0.0.1",
                            ])
                            .output()
                            .expect("ssh -W");
                        let out_fwd_r = std::process::Command::new("ssh")
                            .args([
                                "-i",
                                &key_path_str,
                                "-o",
                                "IdentitiesOnly=yes",
                                "-o",
                                "BatchMode=yes",
                                "-o",
                                "StrictHostKeyChecking=no",
                                "-o",
                                "UserKnownHostsFile=/dev/null",
                                "-o",
                                "ExitOnForwardFailure=yes",
                                "-R",
                                "0:127.0.0.1:80",
                                "-p",
                                &probe_port.to_string(),
                                "live-probe-01@127.0.0.1",
                                "hello_r",
                            ])
                            .output()
                            .expect("ssh -R");
                        if !out_fwd_w.status.success() && !out_fwd_r.status.success() {
                            logs.push(
                                "[PASS] Phase 6e direct-tcpip (-W) & tcpip-forward (-R) blocked as expected"
                                    .to_string(),
                            );
                        } else {
                            logs.push(format!(
                                "[FAIL] Phase 6e port forwarding was not blocked: -W={}, -R={}",
                                out_fwd_w.status, out_fwd_r.status
                            ));
                        }

                        // 6f: 子系统透传与不存在子系统快速返回 CHANNEL_FAILURE（不卡死）测试
                        let out_sub_ok = std::process::Command::new("ssh")
                            .args([
                                "-i",
                                &key_path_str,
                                "-o",
                                "IdentitiesOnly=yes",
                                "-o",
                                "BatchMode=yes",
                                "-o",
                                "StrictHostKeyChecking=no",
                                "-o",
                                "UserKnownHostsFile=/dev/null",
                                "-p",
                                &probe_port.to_string(),
                                "-s",
                                "live-probe-01@127.0.0.1",
                                "echo_subsys",
                            ])
                            .output()
                            .expect("ssh -s echo_subsys");
                        let out_sub_bad = std::process::Command::new("ssh")
                            .args([
                                "-i",
                                &key_path_str,
                                "-o",
                                "IdentitiesOnly=yes",
                                "-o",
                                "BatchMode=yes",
                                "-o",
                                "StrictHostKeyChecking=no",
                                "-o",
                                "UserKnownHostsFile=/dev/null",
                                "-p",
                                &probe_port.to_string(),
                                "-s",
                                "live-probe-01@127.0.0.1",
                                "nonexistent_subsys",
                            ])
                            .output()
                            .expect("ssh -s nonexistent_subsys");
                        if out_sub_ok.status.success()
                            && String::from_utf8_lossy(&out_sub_ok.stdout).trim() == "SUBSYS_OK"
                            && !out_sub_bad.status.success()
                        {
                            logs.push(
                                "[PASS] Phase 6f subsystem success & fast CHANNEL_FAILURE propagation"
                                    .to_string(),
                            );
                        } else {
                            logs.push(format!(
                                "[FAIL] Phase 6f subsystem mismatch: ok=({},{:?}), bad={}",
                                out_sub_ok.status,
                                String::from_utf8_lossy(&out_sub_ok.stdout),
                                out_sub_bad.status
                            ));
                        }

                        // 7a: 真实伪终端交互式 Shell (`ssh -tt`) 测试
                        let pty_py = r#"
import os, pty, select, subprocess, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvp("ssh", [
        "ssh", "-tt",
        "-i", sys.argv[1],
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-p", sys.argv[2],
        "live-probe-01@127.0.0.1"
    ])
buf = b""
sent = False
deadline = time.time() + 5.0
while time.time() < deadline:
    r, _, _ = select.select([fd], [], [], 0.1)
    if r:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        if (not sent) and b"LIVE_PTY_READY>" in buf:
            os.write(fd, b"ping_pty_ok\nexit\n")
            sent = True
    wpid, status = os.waitpid(pid, os.WNOHANG)
    if wpid == pid:
        break
os.close(fd)
sys.stdout.buffer.write(buf)
"#;
                        let out_pty = std::process::Command::new("python3")
                            .args(["-c", pty_py, &key_path_str, &probe_port.to_string()])
                            .output()
                            .expect("python3 pty ssh -tt");
                        let pty_str = String::from_utf8_lossy(&out_pty.stdout);
                        if out_pty.status.success()
                            && pty_str.contains("LIVE_PTY_READY>")
                            && pty_str.contains("PTY_ECHO:ping_pty_ok")
                        {
                            logs.push(
                                "[PASS] Phase 7a real interactive PTY terminal (`ssh -tt`) session"
                                    .to_string(),
                            );
                        } else {
                            logs.push(format!(
                                "[FAIL] Phase 7a interactive PTY failed: status={}, out={:?}, err={:?}",
                                out_pty.status,
                                pty_str,
                                String::from_utf8_lossy(&out_pty.stderr)
                            ));
                        }

                        logs
                    })
                    .await
                    .expect("join ssh probe");

                for line in ssh_results {
                    record(line);
                }

                // === Phase 7b: 热轮换密码与专用密钥（旧凭证立即失效、新凭证立即通过）+ 持久化校验 ===
                let old_pwd = probe_pwd.clone();
                let mut rotated_pwd = String::new();
                let mut rotated_key_path = String::new();
                let old_key_copy = temp_path.join("old_agent_key");
                if let Some(existing_kp) = entity
                    .read_with(cx, |this, _| {
                        this.runtimes
                            .get(&probe_id)
                            .and_then(|r| r.dedicated_key_path.clone())
                    })
                    .ok()
                    .flatten()
                {
                    let _ = std::fs::copy(&existing_kp, &old_key_copy);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(
                            &old_key_copy,
                            std::fs::Permissions::from_mode(0o600),
                        );
                    }
                }

                let _ = entity.update(cx, |this, cx| {
                    this.execute_confirmed_action(
                        PendingAction::RotateCredentials {
                            id: probe_id,
                            codename: "live-probe-01".to_string(),
                            mode: AgentAuthMode::EphemeralPassword,
                        },
                        cx,
                    );
                    this.execute_confirmed_action(
                        PendingAction::RotateCredentials {
                            id: probe_id,
                            codename: "live-probe-01".to_string(),
                            mode: AgentAuthMode::DedicatedKey,
                        },
                        cx,
                    );
                    if let Some(h) = this.hosts.iter().find(|h| h.id == probe_id) {
                        rotated_pwd = h.agent_password.clone();
                    }
                    if let Some(rt) = this.runtimes.get(&probe_id) {
                        rotated_key_path = rt.dedicated_key_path.clone().unwrap_or_default();
                    }
                });

                let new_askpass = temp_path.join("askpass_new.sh");
                std::fs::write(&new_askpass, format!("#!/bin/sh\necho '{}'\n", rotated_pwd))
                    .expect("write new askpass");
                let old_askpass = temp_path.join("askpass_old.sh");
                std::fs::write(&old_askpass, format!("#!/bin/sh\necho '{}'\n", old_pwd))
                    .expect("write old askpass");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        &new_askpass,
                        std::fs::Permissions::from_mode(0o700),
                    );
                    let _ = std::fs::set_permissions(
                        &old_askpass,
                        std::fs::Permissions::from_mode(0o700),
                    );
                }
                let old_askpass_s = old_askpass.to_string_lossy().to_string();
                let new_askpass_s = new_askpass.to_string_lossy().to_string();
                let old_key_s = old_key_copy.to_string_lossy().to_string();

                let rot_logs = global_tokio_runtime()
                    .spawn_blocking(move || {
                        let mut logs = Vec::new();
                        let old_p = std::process::Command::new("ssh")
                            .env("SSH_ASKPASS", &old_askpass_s)
                            .env("SSH_ASKPASS_REQUIRE", "force")
                            .env("DISPLAY", ":0")
                            .args([
                                "-o",
                                "StrictHostKeyChecking=no",
                                "-o",
                                "UserKnownHostsFile=/dev/null",
                                "-o",
                                "PubkeyAuthentication=no",
                                "-p",
                                &probe_port.to_string(),
                                "live-probe-01@127.0.0.1",
                                "old_pwd_check",
                            ])
                            .output()
                            .expect("old pwd ssh");
                        let new_p = std::process::Command::new("ssh")
                            .env("SSH_ASKPASS", &new_askpass_s)
                            .env("SSH_ASKPASS_REQUIRE", "force")
                            .env("DISPLAY", ":0")
                            .args([
                                "-o",
                                "StrictHostKeyChecking=no",
                                "-o",
                                "UserKnownHostsFile=/dev/null",
                                "-o",
                                "PubkeyAuthentication=no",
                                "-p",
                                &probe_port.to_string(),
                                "live-probe-01@127.0.0.1",
                                "new_pwd_check",
                            ])
                            .output()
                            .expect("new pwd ssh");
                        let old_k = std::process::Command::new("ssh")
                            .args([
                                "-i",
                                &old_key_s,
                                "-o",
                                "IdentitiesOnly=yes",
                                "-o",
                                "BatchMode=yes",
                                "-o",
                                "StrictHostKeyChecking=no",
                                "-o",
                                "UserKnownHostsFile=/dev/null",
                                "-p",
                                &probe_port.to_string(),
                                "live-probe-01@127.0.0.1",
                                "old_key_check",
                            ])
                            .output()
                            .expect("old key ssh");
                        let new_k = std::process::Command::new("ssh")
                            .args([
                                "-i",
                                &rotated_key_path,
                                "-o",
                                "IdentitiesOnly=yes",
                                "-o",
                                "BatchMode=yes",
                                "-o",
                                "StrictHostKeyChecking=no",
                                "-o",
                                "UserKnownHostsFile=/dev/null",
                                "-p",
                                &probe_port.to_string(),
                                "live-probe-01@127.0.0.1",
                                "new_key_check",
                            ])
                            .output()
                            .expect("new key ssh");
                        if !old_p.status.success()
                            && new_p.status.success()
                            && !old_k.status.success()
                            && new_k.status.success()
                        {
                            logs.push(
                                "[PASS] Phase 7b live password & Ed25519 key hot-rotation invalidated old creds immediately"
                                    .to_string(),
                            );
                        } else {
                            logs.push(format!(
                                "[FAIL] Phase 7b credential rotation mismatch: old_p={}, new_p={}, old_k={}, new_k={}",
                                old_p.status, new_p.status, old_k.status, new_k.status
                            ));
                        }
                        logs
                    })
                    .await
                    .expect("join rot check");

                for line in rot_logs {
                    record(line);
                }

                // === Phase 7c: 验证弹窗「测试连接」TOFU 公钥直接带入新建主机 + AES-GCM 磁盘重载一致性 ===
                let _ = win_handle.update(cx, |this, _window, cx| {
                    this.reset_form_for_new_host(cx);
                    this.show_host_modal = true;
                    this.form_codename
                        .update(cx, |f, cx| f.set_text("modal-tofu-02", cx));
                    this.form_real_host
                        .update(cx, |f, cx| f.set_text("127.0.0.1", cx));
                    this.form_real_port
                        .update(cx, |f, cx| f.set_text(remote_port.to_string(), cx));
                    this.form_real_user
                        .update(cx, |f, cx| f.set_text("real_ops_admin", cx));
                    this.form_real_secret
                        .update(cx, |f, cx| f.set_text("RealUpstreamSecret#2026", cx));
                    let (built, _) = this.validate_and_build_host(cx).expect("build modal host");
                    this.spawn_test_upstream(built, true, cx);
                });

                cx.background_executor()
                    .timer(Duration::from_millis(350))
                    .await;

                let _ = win_handle.update(cx, |this, _window, cx| {
                    if this.form_test_ok.is_some() && !this.form_testing {
                        let (built_after_test, is_new) = this
                            .validate_and_build_host(cx)
                            .expect("build modal host after test");
                        if built_after_test.pinned_host_key_openssh.is_some() {
                            record(
                                "[PASS] Phase 7c modal upstream test preserved verified TOFU host key on new host"
                                    .to_string(),
                            );
                        } else {
                            record(
                                "[FAIL] Phase 7c modal upstream test dropped TOFU host key on new host"
                                    .to_string(),
                            );
                        }
                        this.execute_confirmed_action(
                            PendingAction::SaveHost {
                                host: Box::new(built_after_test),
                                is_new,
                            },
                            cx,
                        );
                    } else {
                        record(format!(
                            "[FAIL] Phase 7c modal upstream test did not complete: ok={:?}, err={:?}",
                            this.form_test_ok, this.form_error
                        ));
                    }

                    // 重新从磁盘加载 EncryptedStorage 校验持久化一致性
                    let reloaded_storage = EncryptedStorage::new_default().expect("reload storage");
                    let reloaded_hosts = reloaded_storage.load_hosts().expect("reload hosts");
                    let saved_probe = reloaded_hosts.iter().find(|h| h.id == probe_id);
                    if saved_probe.is_some_and(|h| {
                        h.local_port == probe_port
                            && h.agent_password == rotated_pwd
                            && h.pinned_host_key_openssh.is_some()
                    }) {
                        record(
                            "[PASS] Phase 7d AES-256-GCM vault reload verified fixed port, rotated password & TOFU key"
                                .to_string(),
                        );
                    } else {
                        record("[FAIL] Phase 7d vault reload mismatch".to_string());
                    }
                });

                // 恢复系统剪贴板、清理临时目录，并在 cx.quit() 前校验退出码（macOS NSApp terminate 会直接退出）
                let _ = cx.update(|cx| {
                    if let Some(orig) = orig_clipboard {
                        cx.write_to_clipboard(ClipboardItem::new_string(orig));
                    }
                    let _ = std::fs::remove_dir_all(&temp_path);
                    let final_findings = findings_inner.lock().unwrap().clone();
                    let failures: Vec<&String> = final_findings
                        .iter()
                        .filter(|s| s.starts_with("[FAIL]"))
                        .collect();
                    if !failures.is_empty() {
                        eprintln!("Live machine E2E uncovered {} issues:", failures.len());
                        for f in &failures {
                            eprintln!("  {}", f);
                        }
                        std::process::exit(1);
                    }
                    let pass_count = final_findings
                        .iter()
                        .filter(|s| s.starts_with("[PASS]"))
                        .count();
                    println!("ALL {} LIVE SELFTEST CHECKS PASSED!", pass_count);
                    cx.quit();
                });
            })
            .detach();
        });
    }
}
