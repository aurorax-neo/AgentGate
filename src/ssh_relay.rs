use std::borrow::Cow;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use russh::keys::ssh_key::{Algorithm, EcdsaCurve, HashAlg, PrivateKey, PublicKey};
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate, decode_secret_key};
use russh::server::{
    Auth, Msg as ServerMsg, PublicKeyOffer, Session as ServerSession, VerifiedPublicKey,
};
use russh::{
    Channel, ChannelId, ChannelMsg, ChannelOpenFailure, ChannelReadHalf, ChannelWriteHalf,
    Disconnect, MethodSet, Preferred, Pty, Sig, SshId, client, server,
};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::{Mutex as AsyncMutex, mpsc, watch};
use tokio::time::timeout;
use uuid::Uuid;

use crate::models::{AgentAuthMode, ProxyConfig, RealAuthConfig, RelayHost};
use crate::proxy::connect_via_proxy;

const UPSTREAM_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// 全局后台 Tokio 运行时，供 GPUI 前台线程非阻塞调度 SSH 服务与代理任务
pub fn global_tokio_runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .thread_name("agentgate-ssh-worker")
            .build()
            .expect("初始化 AgentGate Tokio 运行时失败")
    })
}

/// 中转服务向 UI 推送的实时状态与审计事件
#[derive(Debug, Clone)]
pub enum RelayEvent {
    Started {
        host_id: Uuid,
        codename: String,
        local_port: u16,
    },
    Stopped {
        host_id: Uuid,
        codename: String,
        local_port: u16,
    },
    SessionsChanged {
        host_id: Uuid,
        active_sessions: usize,
        total_connections: u64,
    },
    HostKeyPinned {
        host_id: Uuid,
        codename: String,
        pubkey_openssh: String,
    },
    AuditLog {
        host_id: Uuid,
        codename: String,
        event: String,
        detail: String,
        is_error: bool,
    },
    Error {
        host_id: Uuid,
        codename: String,
        local_port: u16,
        message: String,
    },
}

/// 支持运行时热轮换的 Agent 本地认证凭证
#[derive(Debug, Clone)]
pub struct LiveCredentials {
    pub mode: AgentAuthMode,
    pub temp_password: Option<String>,
    pub dedicated_pubkey: Option<PublicKey>,
}

/// 单条运行中中转实例的控制句柄
pub struct RunningRelayControl {
    pub local_port: u16,
    pub live_host: Arc<RwLock<RelayHost>>,
    pub live_creds: Arc<RwLock<LiveCredentials>>,
    shutdown_tx: watch::Sender<bool>,
}

impl RunningRelayControl {
    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    pub fn update_credentials(&self, creds: LiveCredentials) {
        if let Ok(mut guard) = self.live_creds.write() {
            *guard = creds;
        }
    }

    pub fn update_host(&self, host: RelayHost) {
        if let Ok(mut guard) = self.live_host.write() {
            *guard = host;
        }
    }
}

/// 启动单条主机的本地 SSH 中转服务（强制仅允许绑定本机回环地址，修复 [HIGH-02]）
pub async fn start_host_relay(
    host: RelayHost,
    initial_creds: LiveCredentials,
    event_tx: mpsc::UnboundedSender<RelayEvent>,
) -> Result<RunningRelayControl> {
    let bind_host = RelayHost::validate_loopback_bind_host(&host.local_bind_host)
        .map_err(|e| anyhow!("{}", e))?;
    let listener = TcpListener::bind((bind_host.as_str(), host.local_port))
        .await
        .with_context(|| format!("绑定本机 {}:{} 端口失败", bind_host, host.local_port))?;
    let local_port = listener
        .local_addr()
        .context("读取本地监听端口失败")?
        .port();

    // 基于主机条目唯一 ID 确定性派生本地 SSH 服务端 Ed25519 主机密钥，避免重启后本地指纹频繁变更（修复 [VERIFY-03]）
    let seed_digest = ring::digest::digest(
        &ring::digest::SHA256,
        format!("AgentGate::LocalServerHostKey::v1::{}", host.id).as_bytes(),
    );
    let mut seed = [0u8; 32];
    seed.copy_from_slice(seed_digest.as_ref());
    let ed_keypair = russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&seed);
    let host_key = PrivateKey::from(ed_keypair);

    let mut server_cfg = server::Config {
        server_id: SshId::Standard(Cow::Borrowed("SSH-2.0-AgentGate_LocalRelay")),
        methods: MethodSet::server_supported(),
        auth_rejection_time: Duration::from_millis(80),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        keys: vec![host_key],
        inactivity_timeout: Some(Duration::from_secs(1800)),
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 6,
        nodelay: true,
        ..Default::default()
    };
    server_cfg.preferred = Preferred::default();
    let server_cfg = Arc::new(server_cfg);

    let live_host = Arc::new(RwLock::new(host.clone()));
    let live_host_for_loop = live_host.clone();
    let live_creds = Arc::new(RwLock::new(initial_creds));
    let live_creds_for_loop = live_creds.clone();
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    let active_sessions = Arc::new(AtomicUsize::new(0));
    let total_connections = Arc::new(AtomicU64::new(0));

    let host_id = host.id;
    let codename = host.codename.clone();
    let _ = event_tx.send(RelayEvent::Started {
        host_id,
        codename: codename.clone(),
        local_port,
    });
    let _ = event_tx.send(RelayEvent::AuditLog {
        host_id,
        codename: codename.clone(),
        event: "本地监听已启动".to_string(),
        detail: format!(
            "绑定 {}:{} (代理: {})",
            bind_host,
            local_port,
            host.proxy.badge_text()
        ),
        is_error: false,
    });

    tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((socket, peer_addr)) => {
                            let _ = socket.set_nodelay(true);
                            let cfg = server_cfg.clone();
                            let host_lock = live_host_for_loop.clone();
                            let creds_clone = live_creds_for_loop.clone();
                            let tx = event_tx.clone();
                            let active_counter = active_sessions.clone();
                            let total_counter = total_connections.clone();
                            let mut client_shutdown = shutdown_rx.clone();

                            tokio::spawn(async move {
                                let handler = LocalSshHandler::new(
                                    host_lock.clone(),
                                    creds_clone,
                                    peer_addr,
                                    tx.clone(),
                                    active_counter.clone(),
                                    total_counter.clone(),
                                );
                                let session_fut = server::run_stream(cfg, socket, handler);
                                tokio::select! {
                                    _ = client_shutdown.changed() => {}
                                    res = session_fut => {
                                        if let Err(err) = res {
                                            if let Ok(h) = host_lock.read() {
                                                let _ = tx.send(RelayEvent::AuditLog {
                                                    host_id: h.id,
                                                    codename: h.codename.clone(),
                                                    event: "会话断开".to_string(),
                                                    detail: format!("本地连接结束 ({})", sanitize_error(&err.to_string(), &h)),
                                                    is_error: false,
                                                });
                                            }
                                        }
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            let cur_codename = live_host_for_loop
                                .read()
                                .map(|h| h.codename.clone())
                                .unwrap_or_else(|_| codename.clone());
                            let _ = event_tx.send(RelayEvent::Error {
                                host_id,
                                codename: cur_codename,
                                local_port,
                                message: format!("本地端口接收连接异常: {}", e),
                            });
                            break;
                        }
                    }
                }
            }
        }

        let final_codename = live_host_for_loop
            .read()
            .map(|h| h.codename.clone())
            .unwrap_or(codename);
        let _ = event_tx.send(RelayEvent::Stopped {
            host_id,
            codename: final_codename.clone(),
            local_port,
        });
        let _ = event_tx.send(RelayEvent::AuditLog {
            host_id,
            codename: final_codename,
            event: "本地监听已停止".to_string(),
            detail: format!("已释放 127.0.0.1:{}", local_port),
            is_error: false,
        });
    });

    Ok(RunningRelayControl {
        local_port,
        live_host,
        live_creds,
        shutdown_tx,
    })
}

/// 上游 SSH 客户端处理器（连接真实远端 SSH 主机）
struct UpstreamClientHandler {
    live_host: Option<Arc<RwLock<RelayHost>>>,
    event_tx: Option<mpsc::UnboundedSender<RelayEvent>>,
}

impl UpstreamClientHandler {
    fn new(live_host: Arc<RwLock<RelayHost>>, event_tx: mpsc::UnboundedSender<RelayEvent>) -> Self {
        Self {
            live_host: Some(live_host),
            event_tx: Some(event_tx),
        }
    }

    #[cfg(test)]
    fn permissive_for_test() -> Self {
        Self {
            live_host: None,
            event_tx: None,
        }
    }
}

impl client::Handler for UpstreamClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let Some(live_host) = &self.live_host else {
            return Ok(true);
        };

        let presented_openssh = match server_public_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.to_openssh().ok(),
            PublicKeyOrCertificate::Certificate(cert) => cert.to_openssh().ok(),
        };
        let Some(presented) = presented_openssh else {
            return Ok(false);
        };

        let existing_check = live_host
            .read()
            .ok()
            .map(|h| (h.id, h.codename.clone(), h.pinned_host_key_openssh.clone()));

        let Some((host_id, codename, pinned_opt)) = existing_check else {
            return Ok(false);
        };

        if let Some(pinned) = pinned_opt {
            let matched: bool = pinned.as_bytes().ct_eq(presented.as_bytes()).into();
            if !matched {
                if let Some(tx) = &self.event_tx {
                    let _ = tx.send(RelayEvent::AuditLog {
                        host_id,
                        codename,
                        event: "主机密钥校验拦截".to_string(),
                        detail: "远端 SSH 主机公钥与已绑定指纹不匹配，已阻断连接以防范中间人攻击".to_string(),
                        is_error: true,
                    });
                }
                return Ok(false);
            }
            Ok(true)
        } else {
            if let Ok(mut guard) = live_host.write() {
                guard.pinned_host_key_openssh = Some(presented.clone());
            }
            if let Some(tx) = &self.event_tx {
                let _ = tx.send(RelayEvent::HostKeyPinned {
                    host_id,
                    codename: codename.clone(),
                    pubkey_openssh: presented,
                });
                let _ = tx.send(RelayEvent::AuditLog {
                    host_id,
                    codename,
                    event: "首次绑定主机密钥".to_string(),
                    detail: "已完成上游 SSH 主机公钥 TOFU 绑定并写入加密仓库".to_string(),
                    is_error: false,
                });
            }
            Ok(true)
        }
    }
}

/// 本地 SSH 服务端处理器（验证 Agent 凭证并将所有通道透明桥接到上游主机）
struct LocalSshHandler {
    live_host: Arc<RwLock<RelayHost>>,
    live_creds: Arc<RwLock<LiveCredentials>>,
    peer_addr: SocketAddr,
    event_tx: mpsc::UnboundedSender<RelayEvent>,
    active_sessions: Arc<AtomicUsize>,
    total_connections: Arc<AtomicU64>,
    session_counted: bool,
    upstream_failed: bool,
    upstream: Option<Arc<client::Handle<UpstreamClientHandler>>>,
    channels: Arc<AsyncMutex<HashMap<ChannelId, Arc<ChannelWriteHalf<client::Msg>>>>>,
}

impl LocalSshHandler {
    fn new(
        live_host: Arc<RwLock<RelayHost>>,
        live_creds: Arc<RwLock<LiveCredentials>>,
        peer_addr: SocketAddr,
        event_tx: mpsc::UnboundedSender<RelayEvent>,
        active_sessions: Arc<AtomicUsize>,
        total_connections: Arc<AtomicU64>,
    ) -> Self {
        Self {
            live_host,
            live_creds,
            peer_addr,
            event_tx,
            active_sessions,
            total_connections,
            session_counted: false,
            upstream_failed: false,
            upstream: None,
            channels: Arc::new(AsyncMutex::new(HashMap::new())),
        }
    }

    fn current_host(&self) -> RelayHost {
        self.live_host
            .read()
            .map(|h| h.clone())
            .expect("读取运行时主机配置锁失败")
    }

    fn is_valid_agent_user(&self, user: &str) -> bool {
        self.live_host
            .read()
            .map(|h| user == h.codename)
            .unwrap_or(false)
    }

    fn emit_log(&self, event: impl Into<String>, detail: impl Into<String>, is_error: bool) {
        if let Ok(h) = self.live_host.read() {
            let _ = self.event_tx.send(RelayEvent::AuditLog {
                host_id: h.id,
                codename: h.codename.clone(),
                event: event.into(),
                detail: detail.into(),
                is_error,
            });
        }
    }

    async fn ensure_upstream(&mut self) -> Result<Arc<client::Handle<UpstreamClientHandler>>> {
        if self.upstream_failed {
            return Err(anyhow!("上游会话建立已失败"));
        }
        if let Some(existing) = &self.upstream
            && !existing.is_closed()
        {
            return Ok(existing.clone());
        }

        let host = self.current_host();
        let live_host_ref = self.live_host.clone();
        let event_tx = self.event_tx.clone();
        let started = Instant::now();

        let connect_fut = async {
            let tcp_stream =
                connect_via_proxy(&host.proxy, &host.real_host, host.real_port).await?;

            let preferred = Preferred {
                kex: Cow::Borrowed(&[
                    russh::kex::MLKEM768X25519_SHA256,
                    russh::kex::CURVE25519,
                    russh::kex::CURVE25519_PRE_RFC_8731,
                    russh::kex::ECDH_SHA2_NISTP256,
                    russh::kex::ECDH_SHA2_NISTP384,
                    russh::kex::ECDH_SHA2_NISTP521,
                    russh::kex::DH_GEX_SHA256,
                    russh::kex::DH_G18_SHA512,
                    russh::kex::DH_G17_SHA512,
                    russh::kex::DH_G16_SHA512,
                    russh::kex::DH_G15_SHA512,
                    russh::kex::DH_G14_SHA256,
                    russh::kex::DH_GEX_SHA1,
                    russh::kex::DH_G14_SHA1,
                    russh::kex::DH_G1_SHA1,
                    russh::kex::EXTENSION_SUPPORT_AS_CLIENT,
                    russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
                ]),
                key: Cow::Borrowed(&[
                    Algorithm::Ed25519,
                    Algorithm::Ecdsa {
                        curve: EcdsaCurve::NistP256,
                    },
                    Algorithm::Ecdsa {
                        curve: EcdsaCurve::NistP384,
                    },
                    Algorithm::Ecdsa {
                        curve: EcdsaCurve::NistP521,
                    },
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha512),
                    },
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha256),
                    },
                    Algorithm::Rsa { hash: None },
                ]),
                cipher: Cow::Borrowed(&[
                    russh::cipher::CHACHA20_POLY1305,
                    russh::cipher::AES_256_GCM,
                    russh::cipher::AES_128_GCM,
                    russh::cipher::AES_256_CTR,
                    russh::cipher::AES_192_CTR,
                    russh::cipher::AES_128_CTR,
                    russh::cipher::AES_256_CBC,
                    russh::cipher::AES_192_CBC,
                    russh::cipher::AES_128_CBC,
                ]),
                mac: Cow::Borrowed(&[
                    russh::mac::HMAC_SHA512_ETM,
                    russh::mac::HMAC_SHA256_ETM,
                    russh::mac::HMAC_SHA512,
                    russh::mac::HMAC_SHA256,
                    russh::mac::HMAC_SHA1_ETM,
                    russh::mac::HMAC_SHA1,
                ]),
                ..Preferred::DEFAULT
            };

            let client_cfg = Arc::new(client::Config {
                inactivity_timeout: Some(Duration::from_secs(1800)),
                keepalive_interval: Some(Duration::from_secs(30)),
                keepalive_max: 6,
                nodelay: true,
                preferred,
                ..Default::default()
            });

            let mut handle = client::connect_stream(
                client_cfg,
                tcp_stream,
                UpstreamClientHandler::new(live_host_ref, event_tx),
            )
            .await
            .map_err(|e| {
                anyhow!(
                    "[阶段: SSH协议握手] 协商失败 (代理: {}, 端口: :{}, 耗时: {}ms, 原因: {})",
                    host.proxy.badge_text(),
                    host.real_port,
                    started.elapsed().as_millis(),
                    sanitize_error(&e.to_string(), &host)
                )
            })?;

            let (auth_ok, auth_diag) = match &host.real_auth {
                RealAuthConfig::Password { password } => {
                    let pwd_clean = password.trim_matches(['\r', '\n']);
                    let pwd_res = handle
                        .authenticate_password(&host.real_user, pwd_clean.to_string())
                        .await
                        .map_err(|e| {
                            anyhow!(
                                "[阶段: SSH密码认证] 请求异常 (耗时: {}ms, 原因: {})",
                                started.elapsed().as_millis(),
                                sanitize_error(&e.to_string(), &host)
                            )
                        })?;
                    if pwd_res.success() {
                        (true, String::new())
                    } else {
                        let remaining_str = format!("{:?}", pwd_res);
                        // 自动回退尝试 PAM keyboard-interactive 认证
                        let mut kbd_ok = false;
                        if let Ok(mut resp) = handle
                            .authenticate_keyboard_interactive_start(&host.real_user, None)
                            .await
                        {
                            for _ in 0..4 {
                                match resp {
                                    client::KeyboardInteractiveAuthResponse::Success => {
                                        kbd_ok = true;
                                        break;
                                    }
                                    client::KeyboardInteractiveAuthResponse::Failure { .. } => {
                                        break;
                                    }
                                    client::KeyboardInteractiveAuthResponse::InfoRequest {
                                        prompts,
                                        ..
                                    } => {
                                        let answers = if prompts.is_empty() {
                                            Vec::new()
                                        } else {
                                            vec![pwd_clean.to_string(); prompts.len()]
                                        };
                                        match handle
                                            .authenticate_keyboard_interactive_respond(answers)
                                            .await
                                        {
                                            Ok(next) => resp = next,
                                            Err(_) => break,
                                        }
                                    }
                                }
                            }
                        }
                        let root_hint = if host.real_user == "root"
                            && remaining_str.contains("PublicKey")
                            && remaining_str.contains("Password")
                        {
                            " [排查建议: 确认 root 密码无误，或检查远端 /etc/ssh/sshd_config 是否已设置 PermitRootLogin yes（Debian/Ubuntu 默认 prohibit-password 会拒绝 root 密码登录）]"
                        } else {
                            ""
                        };
                        (
                            kbd_ok,
                            format!(
                                "password 与 keyboard-interactive 均被拒绝 (密码长度: {} 字符, 服务端返回: {}){}",
                                pwd_clean.chars().count(),
                                sanitize_error(&remaining_str, &host),
                                root_hint
                            ),
                        )
                    }
                }
                RealAuthConfig::PrivateKey {
                    private_key_pem,
                    passphrase,
                } => {
                    let decoded_key = decode_secret_key(
                        private_key_pem,
                        passphrase.as_deref().filter(|p| !p.is_empty()),
                    )
                    .map_err(|e| {
                        anyhow!(
                            "[阶段: 本地私钥解析] 解析真实远端私钥失败 ({})",
                            sanitize_error(&e.to_string(), &host)
                        )
                    })?;
                    let rsa_hash = if decoded_key.algorithm().is_rsa() {
                        handle
                            .best_supported_rsa_hash()
                            .await
                            .ok()
                            .flatten()
                            .flatten()
                    } else {
                        None
                    };
                    let key_res = handle
                        .authenticate_publickey(
                            &host.real_user,
                            PrivateKeyWithHashAlg::new(Arc::new(decoded_key), rsa_hash),
                        )
                        .await
                        .map_err(|e| {
                            anyhow!(
                                "[阶段: SSH公钥认证] 请求异常 (耗时: {}ms, 原因: {})",
                                started.elapsed().as_millis(),
                                sanitize_error(&e.to_string(), &host)
                            )
                        })?;
                    let ok = key_res.success();
                    (ok, format!("服务端返回: {:?}", key_res))
                }
            };

            if !auth_ok {
                return Err(anyhow!(
                    "[阶段: SSH身份认证] 真实远端服务器拒绝了凭据 (端口: :{}, 耗时: {}ms, 详情: {})",
                    host.real_port,
                    started.elapsed().as_millis(),
                    auth_diag
                ));
            }

            Ok(Arc::new(handle))
        };

        match timeout(UPSTREAM_HANDSHAKE_TIMEOUT, connect_fut).await {
            Ok(Ok(shared)) => {
                self.upstream = Some(shared.clone());
                Ok(shared)
            }
            Ok(Err(e)) => {
                self.upstream_failed = true;
                Err(e)
            }
            Err(_) => {
                self.upstream_failed = true;
                Err(anyhow!(
                    "[阶段: 上游总超时] 建立上游 SSH 隧道超过 {}s 限制 (代理: {}, 目标端口: :{})",
                    UPSTREAM_HANDSHAKE_TIMEOUT.as_secs(),
                    host.proxy.badge_text(),
                    host.real_port
                ))
            }
        }
    }

    fn spawn_upstream_to_local_bridge(
        mut upstream_read: ChannelReadHalf,
        server_handle: server::Handle,
        local_id: ChannelId,
        channels: Arc<AsyncMutex<HashMap<ChannelId, Arc<ChannelWriteHalf<client::Msg>>>>>,
    ) {
        tokio::spawn(async move {
            while let Some(msg) = upstream_read.wait().await {
                match msg {
                    ChannelMsg::Data { data } => {
                        if server_handle.data(local_id, data).await.is_err() {
                            break;
                        }
                    }
                    ChannelMsg::ExtendedData { data, ext } => {
                        if server_handle
                            .extended_data(local_id, ext, data)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    ChannelMsg::ExitStatus { exit_status } => {
                        let _ = server_handle
                            .exit_status_request(local_id, exit_status)
                            .await;
                    }
                    ChannelMsg::ExitSignal {
                        signal_name,
                        core_dumped,
                        error_message,
                        lang_tag,
                    } => {
                        let _ = server_handle
                            .exit_signal_request(
                                local_id,
                                signal_name,
                                core_dumped,
                                error_message,
                                lang_tag,
                            )
                            .await;
                    }
                    ChannelMsg::XonXoff { client_can_do } => {
                        let _ = server_handle
                            .xon_xoff_request(local_id, client_can_do)
                            .await;
                    }
                    ChannelMsg::Eof => {
                        let _ = server_handle.eof(local_id).await;
                    }
                    ChannelMsg::Close => {
                        let _ = server_handle.close(local_id).await;
                        break;
                    }
                    _ => {}
                }
            }
            channels.lock().await.remove(&local_id);
        });
    }
}

impl Drop for LocalSshHandler {
    fn drop(&mut self) {
        if self.session_counted {
            let prev = self.active_sessions.fetch_sub(1, Ordering::SeqCst);
            let active = prev.saturating_sub(1);
            let total = self.total_connections.load(Ordering::SeqCst);
            if let Ok(h) = self.live_host.read() {
                let _ = self.event_tx.send(RelayEvent::SessionsChanged {
                    host_id: h.id,
                    active_sessions: active,
                    total_connections: total,
                });
            }
        }
    }
}

impl server::Handler for LocalSshHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if !self.is_valid_agent_user(user) {
            self.emit_log(
                "Agent 认证拒绝",
                format!("未知本地用户名 `{}` (来自 {})", user, self.peer_addr),
                true,
            );
            return Ok(Auth::reject());
        }

        let matched = {
            let guard = self.live_creds.read().ok();
            if let Some(creds) = guard {
                if creds.mode != AgentAuthMode::EphemeralPassword {
                    false
                } else if let Some(expected) = &creds.temp_password {
                    expected.as_bytes().ct_eq(password.as_bytes()).into()
                } else {
                    false
                }
            } else {
                false
            }
        };

        if matched {
            self.emit_log(
                "Agent 密码认证通过",
                format!("本地用户 `{}` 自 {} 通过临时密码验证", user, self.peer_addr),
                false,
            );
            Ok(Auth::Accept)
        } else {
            self.emit_log(
                "Agent 密码认证拒绝",
                format!("本地用户 `{}` 临时密码不匹配或模式未开启", user),
                true,
            );
            Ok(Auth::reject())
        }
    }

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        offer: PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        if !self.is_valid_agent_user(user) {
            return Ok(Auth::reject());
        }
        let matched = {
            let guard = self.live_creds.read().ok();
            if let Some(creds) = guard {
                creds.mode == AgentAuthMode::DedicatedKey
                    && creds
                        .dedicated_pubkey
                        .as_ref()
                        .is_some_and(|expected| expected == offer.public_key)
            } else {
                false
            }
        };
        if matched {
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
        if !self.is_valid_agent_user(user) {
            return Ok(Auth::reject());
        }
        let matched = {
            let guard = self.live_creds.read().ok();
            if let Some(creds) = guard {
                creds.mode == AgentAuthMode::DedicatedKey
                    && creds
                        .dedicated_pubkey
                        .as_ref()
                        .is_some_and(|expected| expected == key.public_key)
            } else {
                false
            }
        };
        if matched {
            self.emit_log(
                "Agent 密钥认证通过",
                format!(
                    "本地用户 `{}` 自 {} 通过专用 Ed25519 密钥验证",
                    user, self.peer_addr
                ),
                false,
            );
            Ok(Auth::Accept)
        } else {
            self.emit_log(
                "Agent 密钥认证拒绝",
                format!("本地用户 `{}` 提供的公钥与专用密钥不匹配", user),
                true,
            );
            Ok(Auth::reject())
        }
    }

    async fn auth_succeeded(&mut self, session: &mut ServerSession) -> Result<(), Self::Error> {
        let host = self.current_host();
        if !self.session_counted {
            self.session_counted = true;
            let active = self.active_sessions.fetch_add(1, Ordering::SeqCst) + 1;
            let total = self.total_connections.fetch_add(1, Ordering::SeqCst) + 1;
            let _ = self.event_tx.send(RelayEvent::SessionsChanged {
                host_id: host.id,
                active_sessions: active,
                total_connections: total,
            });
        }

        if let Err(err) = self.ensure_upstream().await {
            let clean_msg = sanitize_error(&err.to_string(), &host);
            self.emit_log("上游连接失败", clean_msg, true);
            let _ = session
                .handle()
                .disconnect(
                    Disconnect::ByApplication,
                    "AgentGate upstream relay connection failed".to_string(),
                    "en".to_string(),
                )
                .await;
        } else {
            self.emit_log(
                "上游隧道已就绪",
                format!("已通过 {} 建立加密中转会话", host.proxy.badge_text()),
                false,
            );
        }
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<ServerMsg>,
        reply: server::ChannelOpenHandle,
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        let local_id = channel.id();
        drop(channel);
        let host = self.current_host();

        let upstream = match self.ensure_upstream().await {
            Ok(u) => u,
            Err(err) => {
                let clean = sanitize_error(&err.to_string(), &host);
                self.emit_log("打开会话通道失败", clean, true);
                reply.reject(ChannelOpenFailure::ConnectFailed).await;
                return Ok(());
            }
        };

        match upstream.channel_open_session().await {
            Ok(up_chan) => {
                let (upstream_read, upstream_write) = up_chan.split();
                self.channels
                    .lock()
                    .await
                    .insert(local_id, Arc::new(upstream_write));
                reply.accept().await;
                Self::spawn_upstream_to_local_bridge(
                    upstream_read,
                    session.handle(),
                    local_id,
                    self.channels.clone(),
                );
            }
            Err(err) => {
                self.emit_log(
                    "上游会话通道拒绝",
                    sanitize_error(&err.to_string(), &host),
                    true,
                );
                reply
                    .reject(ChannelOpenFailure::AdministrativelyProhibited)
                    .await;
            }
        }
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<ServerMsg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        drop(channel);
        // 默认拒绝 AI Agent 发起的 direct-tcpip (`ssh -L` / `-W` / `-D`) 横向端口转发，防止利用跳板扫描远端内网或元数据服务（修复 [HIGH-04]）
        self.emit_log(
            "端口转发已拦截",
            format!(
                "已根据默认安全隔离策略拒绝 direct-tcpip 请求 -> {}:{} (来源 {}:{})",
                host_to_connect, port_to_connect, originator_address, originator_port
            ),
            true,
        );
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        let up = self.channels.lock().await.get(&channel).cloned();
        if let Some(up) = up {
            if up
                .request_pty(
                    false,
                    term,
                    col_width,
                    row_height,
                    pix_width,
                    pix_height,
                    modes,
                )
                .await
                .is_ok()
            {
                let _ = session.channel_success(channel);
            } else {
                let _ = session.channel_failure(channel);
            }
        } else {
            let _ = session.channel_failure(channel);
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        self.emit_log("交互终端", "Agent 请求打开交互式 Shell", false);
        let up = self.channels.lock().await.get(&channel).cloned();
        if let Some(up) = up {
            if up.request_shell(false).await.is_ok() {
                let _ = session.channel_success(channel);
            } else {
                let _ = session.channel_failure(channel);
            }
        } else {
            let _ = session.channel_failure(channel);
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        let cmd_preview: String = String::from_utf8_lossy(data).chars().take(100).collect();
        self.emit_log("执行命令", format!("exec: {}", cmd_preview), false);

        let up = self.channels.lock().await.get(&channel).cloned();
        if let Some(up) = up {
            if up.exec(false, data).await.is_ok() {
                let _ = session.channel_success(channel);
            } else {
                let _ = session.channel_failure(channel);
            }
        } else {
            let _ = session.channel_failure(channel);
        }
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        self.emit_log("子系统请求", format!("subsystem: {}", name), false);
        let up = self.channels.lock().await.get(&channel).cloned();
        if let Some(up) = up {
            if up.request_subsystem(false, name).await.is_ok() {
                let _ = session.channel_success(channel);
            } else {
                let _ = session.channel_failure(channel);
            }
        } else {
            let _ = session.channel_failure(channel);
        }
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        let up = self.channels.lock().await.get(&channel).cloned();
        if let Some(up) = up {
            let _ = up.set_env(false, variable_name, variable_value).await;
            let _ = session.channel_success(channel);
        } else {
            let _ = session.channel_failure(channel);
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        let up = self.channels.lock().await.get(&channel).cloned();
        if let Some(up) = up {
            let _ = up
                .window_change(col_width, row_height, pix_width, pix_height)
                .await;
            let _ = session.channel_success(channel);
        }
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        let up = self.channels.lock().await.get(&channel).cloned();
        if let Some(up) = up {
            let _ = up.signal(signal).await;
        }
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        let up = self.channels.lock().await.get(&channel).cloned();
        if let Some(up) = up {
            let _ = up.data_bytes(Bytes::copy_from_slice(data)).await;
        }
        Ok(())
    }

    async fn extended_data(
        &mut self,
        channel: ChannelId,
        code: u32,
        data: &[u8],
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        let up = self.channels.lock().await.get(&channel).cloned();
        if let Some(up) = up {
            let _ = up
                .extended_data_bytes(code, Bytes::copy_from_slice(data))
                .await;
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        let up = self.channels.lock().await.get(&channel).cloned();
        if let Some(up) = up {
            let _ = up.eof().await;
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        let removed = self.channels.lock().await.remove(&channel);
        if let Some(up) = removed {
            let _ = up.close().await;
        }
        Ok(())
    }
}

/// 过滤任何可能包含真实主机地址或真实用户名/密码的错误字符串
fn sanitize_error(raw: &str, host: &RelayHost) -> String {
    let mut out = raw.to_string();
    if !host.real_host.is_empty() {
        out = out.replace(&host.real_host, "<redacted-host>");
    }
    if !host.real_user.is_empty() {
        out = out.replace(&host.real_user, "<redacted-user>");
    }
    match &host.real_auth {
        RealAuthConfig::Password { password } => {
            if !password.is_empty() {
                out = out.replace(password, "<redacted-secret>");
            }
        }
        RealAuthConfig::PrivateKey {
            private_key_pem: _,
            passphrase,
        } => {
            if let Some(p) = passphrase.as_deref()
                && !p.is_empty()
            {
                out = out.replace(p, "<redacted-secret>");
            }
        }
    }
    match &host.proxy {
        ProxyConfig::None => {}
        ProxyConfig::Socks5 {
            host: ph,
            username,
            password,
            ..
        }
        | ProxyConfig::HttpConnect {
            host: ph,
            username,
            password,
            ..
        } => {
            if !ph.is_empty() {
                out = out.replace(ph, "<redacted-proxy>");
            }
            if let Some(pu) = username.as_deref()
                && !pu.is_empty()
            {
                out = out.replace(pu, "<redacted-proxy-user>");
            }
            if let Some(pw) = password.as_deref()
                && !pw.is_empty()
            {
                out = out.replace(pw, "<redacted-proxy-secret>");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ProxyConfig;

    /// 模拟远端真实 SSH 服务器（用于端到端测试 AgentGate 的认证隔离与命令转发）
    struct MockRemoteSshServer {
        expected_user: String,
        expected_password: String,
    }

    impl server::Handler for MockRemoteSshServer {
        type Error = russh::Error;

        async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
            if user == self.expected_user && password == self.expected_password {
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

        async fn exec_request(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut ServerSession,
        ) -> Result<(), Self::Error> {
            let cmd = String::from_utf8_lossy(data);
            let _ = session.channel_success(channel);
            let handle = session.handle();
            let response = format!("REMOTE_EXEC_OK:{}\n", cmd.trim());
            let _ = handle.data(channel, Bytes::from(response)).await;
            let _ = handle.exit_status_request(channel, 0).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
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

        async fn env_request(
            &mut self,
            channel: ChannelId,
            _variable_name: &str,
            _variable_value: &str,
            session: &mut ServerSession,
        ) -> Result<(), Self::Error> {
            // 模拟 Debian sshd 默认拒绝未在 AcceptEnv 中的环境变量
            let _ = session.channel_failure(channel);
            Ok(())
        }

        async fn shell_request(
            &mut self,
            channel: ChannelId,
            session: &mut ServerSession,
        ) -> Result<(), Self::Error> {
            let _ = session.channel_success(channel);
            let handle = session.handle();
            let _ = handle.data(channel, Bytes::from("SHELL_READY$ ")).await;
            Ok(())
        }

        async fn data(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut ServerSession,
        ) -> Result<(), Self::Error> {
            let input = String::from_utf8_lossy(data);
            let handle = session.handle();
            let reply = format!("ECHO:{}", input);
            let _ = handle.data(channel, Bytes::from(reply)).await;
            if input.contains("exit") {
                let _ = handle.exit_status_request(channel, 0).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_end_to_end_ssh_relay_with_ephemeral_password_and_dedicated_key() {
        let remote_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind remote");
        let remote_port = remote_listener.local_addr().expect("remote addr").port();
        let remote_key =
            PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("remote key");
        let remote_cfg = Arc::new(server::Config {
            keys: vec![remote_key],
            auth_rejection_time: Duration::from_millis(20),
            auth_rejection_time_initial: Some(Duration::from_millis(0)),
            ..Default::default()
        });

        tokio::spawn(async move {
            while let Ok((socket, _)) = remote_listener.accept().await {
                let cfg = remote_cfg.clone();
                tokio::spawn(async move {
                    let handler = MockRemoteSshServer {
                        expected_user: "real_prod_root".to_string(),
                        expected_password: "RealRootPassword#2026".to_string(),
                    };
                    let _ = server::run_stream(cfg, socket, handler).await;
                });
            }
        });

        let host = RelayHost {
            id: Uuid::new_v4(),
            codename: "cobalt-nexus-01".to_string(),
            label: "模拟远端测试机".to_string(),
            local_bind_host: "127.0.0.1".to_string(),
            local_port: 0,
            agent_password: RelayHost::generate_ephemeral_password(),
            real_host: "127.0.0.1".to_string(),
            real_port: remote_port,
            real_user: "real_prod_root".to_string(),
            real_auth: RealAuthConfig::Password {
                password: "RealRootPassword#2026".to_string(),
            },
            proxy: ProxyConfig::None,
            agent_auth_mode: AgentAuthMode::EphemeralPassword,
            dedicated_key_openssh_pem: None,
            pinned_host_key_openssh: None,
            created_at: RelayHost::now_str(),
            updated_at: RelayHost::now_str(),
        };

        let temp_password = RelayHost::generate_ephemeral_password();
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let control = start_host_relay(
            host.clone(),
            LiveCredentials {
                mode: AgentAuthMode::EphemeralPassword,
                temp_password: Some(temp_password.clone()),
                dedicated_pubkey: None,
            },
            event_tx,
        )
        .await
        .expect("start host relay");

        assert!(control.local_port > 0);
        assert_ne!(control.local_port, remote_port);

        let client_cfg = Arc::new(client::Config::default());
        let mut bad_session = client::connect(
            client_cfg.clone(),
            ("127.0.0.1", control.local_port),
            UpstreamClientHandler::permissive_for_test(),
        )
        .await
        .expect("connect local relay");
        let bad_auth = bad_session
            .authenticate_password("cobalt-nexus-01", "wrong-password")
            .await
            .expect("bad auth call");
        assert!(!bad_auth.success());

        let mut good_session = client::connect(
            client_cfg.clone(),
            ("127.0.0.1", control.local_port),
            UpstreamClientHandler::permissive_for_test(),
        )
        .await
        .expect("connect local relay 2");
        let good_auth = good_session
            .authenticate_password("cobalt-nexus-01", &temp_password)
            .await
            .expect("good auth call");
        assert!(good_auth.success());

        let mut channel = good_session
            .channel_open_session()
            .await
            .expect("open session channel");
        channel
            .exec(true, b"uname -a")
            .await
            .expect("send exec request");

        let mut stdout_buf = Vec::new();
        let mut exit_code = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => stdout_buf.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => exit_code = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        assert_eq!(
            String::from_utf8_lossy(&stdout_buf),
            "REMOTE_EXEC_OK:uname -a\n"
        );
        assert_eq!(exit_code, Some(0));

        let dedicated_priv =
            PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("gen ed25519");
        let dedicated_pub = dedicated_priv.public_key().clone();
        control.update_credentials(LiveCredentials {
            mode: AgentAuthMode::DedicatedKey,
            temp_password: None,
            dedicated_pubkey: Some(dedicated_pub),
        });

        let mut key_session = client::connect(
            client_cfg,
            ("127.0.0.1", control.local_port),
            UpstreamClientHandler::permissive_for_test(),
        )
        .await
        .expect("connect local relay with key");
        let key_auth = key_session
            .authenticate_publickey(
                "cobalt-nexus-01",
                PrivateKeyWithHashAlg::new(Arc::new(dedicated_priv), None),
            )
            .await
            .expect("pubkey auth");
        assert!(key_auth.success());

        let mut chan2 = key_session.channel_open_session().await.expect("open chan2");
        chan2.exec(true, b"whoami").await.expect("exec whoami");
        let mut out2 = Vec::new();
        while let Some(msg) = chan2.wait().await {
            match msg {
                ChannelMsg::Data { data } => out2.extend_from_slice(&data),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        assert_eq!(String::from_utf8_lossy(&out2), "REMOTE_EXEC_OK:whoami\n");

        // 验证交互式 PTY + env + Shell + 双向终端流不会卡死
        let mut shell_chan = key_session
            .channel_open_session()
            .await
            .expect("open interactive shell chan");
        shell_chan
            .request_pty(true, "xterm-256color", 80, 24, 0, 0, &[])
            .await
            .expect("request pty");
        shell_chan
            .set_env(false, "LANG", "zh_CN.UTF-8")
            .await
            .expect("set env");
        shell_chan
            .request_shell(true)
            .await
            .expect("request shell");
        shell_chan
            .data(&b"hello_pty\nexit\n"[..])
            .await
            .expect("send interactive input");

        let mut shell_out = Vec::new();
        let mut got_pty_success = 0usize;
        while let Some(msg) = timeout(Duration::from_secs(3), shell_chan.wait())
            .await
            .expect("interactive shell should not hang")
        {
            match msg {
                ChannelMsg::Success => got_pty_success += 1,
                ChannelMsg::Data { data } => shell_out.extend_from_slice(&data),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        assert_eq!(got_pty_success, 2, "both pty-req and shell should receive CHANNEL_SUCCESS");
        let shell_str = String::from_utf8_lossy(&shell_out);
        assert!(shell_str.contains("SHELL_READY$ "));
        assert!(shell_str.contains("ECHO:hello_pty"));

        control.stop();
    }

    #[tokio::test]
    async fn test_credential_hot_rotation_username_isolation_and_error_sanitization() {
        // 1. 验证错误日志脱敏绝不泄露真实 IP、真实用户名和真实密码
        let host = RelayHost {
            id: Uuid::new_v4(),
            codename: "cipher-harbor-05".to_string(),
            label: "生产核心节点".to_string(),
            local_bind_host: "127.0.0.1".to_string(),
            local_port: 0,
            agent_password: RelayHost::generate_ephemeral_password(),
            real_host: "10.96.1.104".to_string(),
            real_port: 22,
            real_user: "prod_super_admin".to_string(),
            real_auth: RealAuthConfig::Password {
                password: "UltraSecretProdPwd!2026".to_string(),
            },
            proxy: ProxyConfig::Socks5 {
                host: "10.0.99.88".to_string(),
                port: 1080,
                username: Some("corp_socks_u".to_string()),
                password: Some("corp_socks_p".to_string()),
            },
            agent_auth_mode: AgentAuthMode::EphemeralPassword,
            dedicated_key_openssh_pem: None,
            pinned_host_key_openssh: None,
            created_at: RelayHost::now_str(),
            updated_at: RelayHost::now_str(),
        };
        let raw_err =
            "Failed to authenticate prod_super_admin@10.96.1.104 via proxy corp_socks_u:corp_socks_p@10.0.99.88 with UltraSecretProdPwd!2026";
        let sanitized = sanitize_error(raw_err, &host);
        assert!(!sanitized.contains("10.96.1.104"));
        assert!(!sanitized.contains("prod_super_admin"));
        assert!(!sanitized.contains("UltraSecretProdPwd!2026"));
        assert!(!sanitized.contains("10.0.99.88"));
        assert!(!sanitized.contains("corp_socks_u"));
        assert!(!sanitized.contains("corp_socks_p"));
        assert!(sanitized.contains("<redacted-host>"));
        assert!(sanitized.contains("<redacted-user>"));
        assert!(sanitized.contains("<redacted-secret>"));
        assert!(sanitized.contains("<redacted-proxy>"));

        // 2. 验证真实用户名无法登录本地中转端口，以及临时密码热轮换后旧密码立即失效
        let remote_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind remote");
        let remote_port = remote_listener.local_addr().expect("remote addr").port();
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
                    let handler = MockRemoteSshServer {
                        expected_user: "prod_super_admin".to_string(),
                        expected_password: "UltraSecretProdPwd!2026".to_string(),
                    };
                    let _ = server::run_stream(cfg, socket, handler).await;
                });
            }
        });

        let mut relay_host = host.clone();
        relay_host.real_host = "127.0.0.1".to_string();
        relay_host.real_port = remote_port;
        relay_host.proxy = ProxyConfig::None;

        let pwd_v1 = RelayHost::generate_ephemeral_password();
        let pwd_v2 = RelayHost::generate_ephemeral_password();
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let control = start_host_relay(
            relay_host,
            LiveCredentials {
                mode: AgentAuthMode::EphemeralPassword,
                temp_password: Some(pwd_v1.clone()),
                dedicated_pubkey: None,
            },
            event_tx,
        )
        .await
        .expect("start relay");

        let client_cfg = Arc::new(client::Config::default());

        // 使用真实用户名 prod_super_admin + 正确的临时密码，必须被本地中转拒绝
        let mut wrong_user_sess = client::connect(
            client_cfg.clone(),
            ("127.0.0.1", control.local_port),
            UpstreamClientHandler::permissive_for_test(),
        )
        .await
        .expect("connect wrong user");
        let wrong_user_auth = wrong_user_sess
            .authenticate_password("prod_super_admin", &pwd_v1)
            .await
            .expect("auth wrong user");
        assert!(!wrong_user_auth.success());

        // 使用通用用户名 agent + 正确的临时密码，同样必须被拒绝（仅允许唯一 codename）
        let mut agent_user_sess = client::connect(
            client_cfg.clone(),
            ("127.0.0.1", control.local_port),
            UpstreamClientHandler::permissive_for_test(),
        )
        .await
        .expect("connect agent user");
        let agent_user_auth = agent_user_sess
            .authenticate_password("agent", &pwd_v1)
            .await
            .expect("auth agent user");
        assert!(!agent_user_auth.success());

        // 热轮换临时密码为 pwd_v2
        control.update_credentials(LiveCredentials {
            mode: AgentAuthMode::EphemeralPassword,
            temp_password: Some(pwd_v2.clone()),
            dedicated_pubkey: None,
        });

        // 旧临时密码 pwd_v1 必须立即失效
        let mut old_pwd_sess = client::connect(
            client_cfg.clone(),
            ("127.0.0.1", control.local_port),
            UpstreamClientHandler::permissive_for_test(),
        )
        .await
        .expect("connect old pwd");
        let old_pwd_auth = old_pwd_sess
            .authenticate_password("cipher-harbor-05", &pwd_v1)
            .await
            .expect("auth old pwd");
        assert!(!old_pwd_auth.success());

        // 新临时密码 pwd_v2 立即生效
        let mut new_pwd_sess = client::connect(
            client_cfg,
            ("127.0.0.1", control.local_port),
            UpstreamClientHandler::permissive_for_test(),
        )
        .await
        .expect("connect new pwd");
        let new_pwd_auth = new_pwd_sess
            .authenticate_password("cipher-harbor-05", &pwd_v2)
            .await
            .expect("auth new pwd");
        assert!(new_pwd_auth.success());

        control.stop();
    }

    #[tokio::test]
    async fn test_real_system_openssh_cli_via_socks5_proxy_end_to_end() {
        use crate::storage::EncryptedStorage;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        // 1. 启动模拟远端真实 SSH 主机
        let remote_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind remote");
        let remote_port = remote_listener.local_addr().expect("remote addr").port();
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
                    let handler = MockRemoteSshServer {
                        expected_user: "hidden_real_root".to_string(),
                        expected_password: "HiddenRealPassword!2026".to_string(),
                    };
                    let _ = server::run_stream(cfg, socket, handler).await;
                });
            }
        });

        // 2. 启动本地模拟 SOCKS5 代理服务器（带用户名密码认证）
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind socks5");
        let socks_port = socks_listener.local_addr().expect("socks5 addr").port();
        tokio::spawn(async move {
            while let Ok((mut client, _)) = socks_listener.accept().await {
                tokio::spawn(async move {
                    let mut greeting = [0u8; 4];
                    if client.read_exact(&mut greeting).await.is_err() {
                        return;
                    }
                    let _ = client.write_all(&[0x05, 0x02]).await;
                    let mut ver = [0u8; 1];
                    let _ = client.read_exact(&mut ver).await;
                    let mut ulen = [0u8; 1];
                    let _ = client.read_exact(&mut ulen).await;
                    let mut ubuf = vec![0u8; ulen[0] as usize];
                    let _ = client.read_exact(&mut ubuf).await;
                    let mut plen = [0u8; 1];
                    let _ = client.read_exact(&mut plen).await;
                    let mut pbuf = vec![0u8; plen[0] as usize];
                    let _ = client.read_exact(&mut pbuf).await;
                    if ubuf != b"proxy_u" || pbuf != b"proxy_p" {
                        let _ = client.write_all(&[0x01, 0x01]).await;
                        return;
                    }
                    let _ = client.write_all(&[0x01, 0x00]).await;

                    let mut req = [0u8; 10];
                    if client.read_exact(&mut req).await.is_err() {
                        return;
                    }
                    let port = u16::from_be_bytes([req[8], req[9]]);
                    if let Ok(mut upstream) = TcpStream::connect(("127.0.0.1", port)).await {
                        let _ = client
                            .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                            .await;
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                    }
                });
            }
        });

        // 3. 使用 EncryptedStorage 生成 0600 专用 Ed25519 密钥并启动 AgentGate 中转
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let storage = EncryptedStorage::new_in_dir(temp_dir.path()).expect("storage");
        let mut host = RelayHost {
            id: Uuid::new_v4(),
            codename: "titan-sentry-07".to_string(),
            label: "SOCKS5 全链路测试机".to_string(),
            local_bind_host: "127.0.0.1".to_string(),
            local_port: 0,
            agent_password: RelayHost::generate_ephemeral_password(),
            real_host: "127.0.0.1".to_string(),
            real_port: remote_port,
            real_user: "hidden_real_root".to_string(),
            real_auth: RealAuthConfig::Password {
                password: "HiddenRealPassword!2026".to_string(),
            },
            proxy: ProxyConfig::Socks5 {
                host: "127.0.0.1".to_string(),
                port: socks_port,
                username: Some("proxy_u".to_string()),
                password: Some("proxy_p".to_string()),
            },
            agent_auth_mode: AgentAuthMode::DedicatedKey,
            dedicated_key_openssh_pem: None,
            pinned_host_key_openssh: None,
            created_at: RelayHost::now_str(),
            updated_at: RelayHost::now_str(),
        };
        let (key_path, _) = storage
            .ensure_dedicated_agent_key(&mut host, false)
            .expect("ensure key");
        let priv_key = PrivateKey::from_openssh(
            host.dedicated_key_openssh_pem.as_deref().expect("pem"),
        )
        .expect("parse key");

        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let control = start_host_relay(
            host.clone(),
            LiveCredentials {
                mode: AgentAuthMode::DedicatedKey,
                temp_password: None,
                dedicated_pubkey: Some(priv_key.public_key().clone()),
            },
            event_tx,
        )
        .await
        .expect("start relay");

        // 4. 调用操作系统真实的 `ssh` 命令连接本地中转端口并执行远端命令
        let null_dev = crate::prompt_tpl::platform_null_known_hosts();
        let local_port = control.local_port;
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new("ssh")
                .args([
                    "-i",
                    &key_path.to_string_lossy(),
                    "-o",
                    "IdentitiesOnly=yes",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    &format!("UserKnownHostsFile={}", null_dev),
                    "-p",
                    &local_port.to_string(),
                    "titan-sentry-07@127.0.0.1",
                    "hostname && id",
                ])
                .output()
                .expect("run system ssh binary")
        })
        .await
        .expect("join ssh task");

        assert!(
            output.status.success(),
            "system ssh failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(stdout, "REMOTE_EXEC_OK:hostname && id\n");

        control.stop();
    }

    #[tokio::test]
    async fn test_upstream_host_key_tofu_pinning_and_mitm_rejection() {
        let remote_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind remote");
        let remote_port = remote_listener.local_addr().expect("remote addr").port();
        let legitimate_key =
            PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("legit key");
        let expected_pubkey_openssh = legitimate_key
            .public_key()
            .to_openssh()
            .expect("legit pubkey openssh");

        let remote_cfg = Arc::new(server::Config {
            keys: vec![legitimate_key],
            auth_rejection_time: Duration::from_millis(10),
            auth_rejection_time_initial: Some(Duration::from_millis(0)),
            ..Default::default()
        });
        tokio::spawn(async move {
            while let Ok((socket, _)) = remote_listener.accept().await {
                let cfg = remote_cfg.clone();
                tokio::spawn(async move {
                    let handler = MockRemoteSshServer {
                        expected_user: "root".to_string(),
                        expected_password: "RootPass!2026".to_string(),
                    };
                    let _ = server::run_stream(cfg, socket, handler).await;
                });
            }
        });

        let host = RelayHost {
            id: Uuid::new_v4(),
            codename: "tofu-guard-01".to_string(),
            label: "TOFU 测试节点".to_string(),
            local_bind_host: "127.0.0.1".to_string(),
            local_port: 0,
            agent_password: RelayHost::generate_ephemeral_password(),
            real_host: "127.0.0.1".to_string(),
            real_port: remote_port,
            real_user: "root".to_string(),
            real_auth: RealAuthConfig::Password {
                password: "RootPass!2026".to_string(),
            },
            proxy: ProxyConfig::None,
            agent_auth_mode: AgentAuthMode::EphemeralPassword,
            dedicated_key_openssh_pem: None,
            pinned_host_key_openssh: None,
            created_at: RelayHost::now_str(),
            updated_at: RelayHost::now_str(),
        };

        let temp_pwd = RelayHost::generate_ephemeral_password();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let control = start_host_relay(
            host.clone(),
            LiveCredentials {
                mode: AgentAuthMode::EphemeralPassword,
                temp_password: Some(temp_pwd.clone()),
                dedicated_pubkey: None,
            },
            event_tx,
        )
        .await
        .expect("start relay");

        let client_cfg = Arc::new(client::Config::default());
        let mut sess1 = client::connect(
            client_cfg.clone(),
            ("127.0.0.1", control.local_port),
            UpstreamClientHandler::permissive_for_test(),
        )
        .await
        .expect("connect 1");
        let auth1 = sess1
            .authenticate_password("tofu-guard-01", &temp_pwd)
            .await
            .expect("auth 1");
        assert!(auth1.success());
        let mut chan1 = sess1.channel_open_session().await.expect("open chan 1");
        chan1.exec(true, b"echo tofu").await.expect("exec 1");
        while let Some(msg) = chan1.wait().await {
            if matches!(msg, ChannelMsg::Close) {
                break;
            }
        }

        // 验证首次连接已自动绑定远端主机公钥并通过事件发出
        let pinned_in_live = control
            .live_host
            .read()
            .expect("read live_host")
            .pinned_host_key_openssh
            .clone();
        assert_eq!(pinned_in_live.as_deref(), Some(expected_pubkey_openssh.as_str()));

        let mut saw_pin_event = false;
        while let Ok(ev) = event_rx.try_recv() {
            if let RelayEvent::HostKeyPinned { pubkey_openssh, .. } = ev {
                assert_eq!(pubkey_openssh, expected_pubkey_openssh);
                saw_pin_event = true;
            }
        }
        assert!(saw_pin_event, "应当触发 HostKeyPinned 事件");

        // 篡改已绑定的主机公钥为另一把伪造密钥，验证下次连接被 check_server_key 阻断
        let fake_key =
            PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("fake key");
        let mut tampered_host = control.live_host.read().expect("read").clone();
        tampered_host.pinned_host_key_openssh =
            Some(fake_key.public_key().to_openssh().expect("fake openssh"));
        control.update_host(tampered_host);

        let mut sess2 = client::connect(
            client_cfg,
            ("127.0.0.1", control.local_port),
            UpstreamClientHandler::permissive_for_test(),
        )
        .await
        .expect("connect 2");
        let _ = sess2
            .authenticate_password("tofu-guard-01", &temp_pwd)
            .await;
        let chan2_res = sess2.channel_open_session().await;
        assert!(
            chan2_res.is_err(),
            "当远端主机公钥与已绑定指纹不匹配时，必须拒绝建立会话通道"
        );

        control.stop();
    }

    #[tokio::test]
    async fn test_non_loopback_bind_rejected_and_direct_tcpip_blocked() {
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let mut bad_host = RelayHost::new_template(0);
        bad_host.local_bind_host = "0.0.0.0".to_string();
        bad_host.local_port = 0;
        let err_res = start_host_relay(
            bad_host,
            LiveCredentials {
                mode: AgentAuthMode::EphemeralPassword,
                temp_password: Some("test-pwd".to_string()),
                dedicated_pubkey: None,
            },
            event_tx.clone(),
        )
        .await;
        assert!(
            err_res.is_err(),
            "绑定 0.0.0.0 非回环地址必须在启动层被强制拦截"
        );

        // 启动合法回环监听并验证 direct-tcpip 被 AdministrativelyProhibited 拦截
        let remote_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind remote");
        let remote_port = remote_listener.local_addr().expect("remote addr").port();
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
                    let handler = MockRemoteSshServer {
                        expected_user: "root".to_string(),
                        expected_password: "RootPass!2026".to_string(),
                    };
                    let _ = server::run_stream(cfg, socket, handler).await;
                });
            }
        });

        let mut host = RelayHost::new_template(1);
        host.codename = "guard-tcpip-01".to_string();
        host.local_bind_host = "127.0.0.1".to_string();
        host.local_port = 0;
        host.real_host = "127.0.0.1".to_string();
        host.real_port = remote_port;
        host.real_user = "root".to_string();
        host.real_auth = RealAuthConfig::Password {
            password: "RootPass!2026".to_string(),
        };

        let temp_pwd = RelayHost::generate_ephemeral_password();
        let control = start_host_relay(
            host,
            LiveCredentials {
                mode: AgentAuthMode::EphemeralPassword,
                temp_password: Some(temp_pwd.clone()),
                dedicated_pubkey: None,
            },
            event_tx,
        )
        .await
        .expect("start loopback relay");

        let client_cfg = Arc::new(client::Config::default());
        let mut sess = client::connect(
            client_cfg,
            ("127.0.0.1", control.local_port),
            UpstreamClientHandler::permissive_for_test(),
        )
        .await
        .expect("connect relay");
        let auth = sess
            .authenticate_password("guard-tcpip-01", &temp_pwd)
            .await
            .expect("auth");
        assert!(auth.success());

        let tcpip_res = sess
            .channel_open_direct_tcpip("169.254.169.254", 80, "127.0.0.1", 55123)
            .await;
        assert!(
            tcpip_res.is_err(),
            "Agent 发起的 direct-tcpip 端口转发必须被默认拦截"
        );

        control.stop();
    }
}
