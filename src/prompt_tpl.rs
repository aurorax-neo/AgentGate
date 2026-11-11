use anyhow::{Result, anyhow};

use crate::models::{AgentAuthMode, CopyFormat, RelayHost, RelayRuntimeState};

/// 返回当前操作系统下 OpenSSH 的空 known_hosts 设备路径（Windows 为 NUL，Linux/macOS 为 /dev/null）
pub fn platform_null_known_hosts() -> &'static str {
    if cfg!(windows) { "NUL" } else { "/dev/null" }
}

/// 生成安全暴露给 AI Agent 的连接说明或 SSH 命令（绝不包含真实远端地址、真实账号或真实密码）
pub fn render_agent_snippet(
    host: &RelayHost,
    runtime: &RelayRuntimeState,
    format: CopyFormat,
) -> Result<String> {
    render_agent_snippet_with_null_dev(host, runtime, format, platform_null_known_hosts())
}

/// 按指定空设备路径生成 Agent 连接配置（支持跨平台 Linux / Windows / macOS 测试验证）
pub fn render_agent_snippet_with_null_dev(
    host: &RelayHost,
    runtime: &RelayRuntimeState,
    format: CopyFormat,
    null_hosts_dev: &str,
) -> Result<String> {
    let local_port = runtime
        .status
        .local_port()
        .ok_or_else(|| anyhow!("代号 [{}] 尚未启动本地监听，请先开启中转后再复制配置", host.codename))?;

    let bind_host = if host.local_bind_host.trim().is_empty() {
        "127.0.0.1"
    } else {
        host.local_bind_host.trim()
    };
    let codename = host.codename.trim();
    match format {
        CopyFormat::AgentPromptCard => match host.agent_auth_mode {
            AgentAuthMode::EphemeralPassword => {
                let temp_pwd = runtime
                    .current_temp_password
                    .as_deref()
                    .or({
                        let p = host.agent_password.trim();
                        (!p.is_empty()).then_some(p)
                    })
                    .ok_or_else(|| anyhow!("当前未生成临时密码，请先轮换或重启该条中转"))?;
                Ok(format!(
                    "[SSH 目标代号: {codename}]\n\
                     Host: {bind_host}\n\
                     Port: {local_port}\n\
                     User: {codename}\n\
                     AuthMode: TemporaryPassword\n\
                     Password: {temp_pwd}\n\
                     Command: ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile={null_hosts_dev} -p {local_port} {codename}@{bind_host}"
                ))
            }
            AgentAuthMode::DedicatedKey => {
                let key_path = runtime
                    .dedicated_key_path
                    .as_deref()
                    .ok_or_else(|| anyhow!("当前未找到本机专用密钥文件，请重置专用密钥"))?;
                Ok(format!(
                    "[SSH 目标代号: {codename}]\n\
                     Host: {bind_host}\n\
                     Port: {local_port}\n\
                     User: {codename}\n\
                     AuthMode: DedicatedKey\n\
                     IdentityFile: {key_path}\n\
                     Command: ssh -i \"{key_path}\" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile={null_hosts_dev} -p {local_port} {codename}@{bind_host}"
                ))
            }
        },
        CopyFormat::SshCommandOnly => match host.agent_auth_mode {
            AgentAuthMode::EphemeralPassword => Ok(format!(
                "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile={null_hosts_dev} -p {local_port} {codename}@{bind_host}"
            )),
            AgentAuthMode::DedicatedKey => {
                let key_path = runtime
                    .dedicated_key_path
                    .as_deref()
                    .ok_or_else(|| anyhow!("当前未找到本机专用密钥文件，请重置专用密钥"))?;
                Ok(format!(
                    "ssh -i \"{key_path}\" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile={null_hosts_dev} -p {local_port} {codename}@{bind_host}"
                ))
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ProxyConfig, RealAuthConfig, RelayStatus};
    use uuid::Uuid;

    #[test]
    fn test_agent_snippet_never_leaks_real_credentials() {
        let host = RelayHost {
            id: Uuid::new_v4(),
            codename: "jade-sentry-01".to_string(),
            label: "内网测试机".to_string(),
            local_bind_host: "127.0.0.1".to_string(),
            local_port: 54321,
            agent_password: "TempAbc123-Xyz789-Qwe456".to_string(),
            real_host: "10.96.1.108".to_string(),
            real_port: 22022,
            real_user: "real_admin_user".to_string(),
            real_auth: RealAuthConfig::Password {
                password: "RealRootSecretPassword999".to_string(),
            },
            proxy: ProxyConfig::Socks5 {
                host: "192.168.5.2".to_string(),
                port: 7890,
                username: Some("proxy_user".to_string()),
                password: Some("proxy_secret".to_string()),
            },
            agent_auth_mode: AgentAuthMode::EphemeralPassword,
            dedicated_key_openssh_pem: None,
            pinned_host_key_openssh: None,
            created_at: "2026-11-10 12:00:00".to_string(),
            updated_at: "2026-11-10 12:00:00".to_string(),
        };

        let runtime = RelayRuntimeState {
            status: RelayStatus::Running {
                local_port: 54321,
                active_sessions: 0,
            },
            current_temp_password: Some("TempAbc123-Xyz789-Qwe456".to_string()),
            dedicated_key_path: Some("/tmp/jade-sentry-01_id_ed25519".to_string()),
            dedicated_pubkey_openssh: None,
            total_connections: 0,
            logs: vec![],
        };

        let card = render_agent_snippet(&host, &runtime, CopyFormat::AgentPromptCard)
            .expect("render card");
        assert!(card.contains("jade-sentry-01"));
        assert!(card.contains("127.0.0.1"));
        assert!(card.contains("54321"));
        assert!(card.contains("TempAbc123-Xyz789-Qwe456"));

        // 严格断言：任何真实地址、真实端口、真实用户名、真实密码、代理信息及本机备注均不得出现
        assert!(!card.contains("10.96.1.108"));
        assert!(!card.contains("22022"));
        assert!(!card.contains("real_admin_user"));
        assert!(!card.contains("RealRootSecretPassword999"));
        assert!(!card.contains("192.168.5.2"));
        assert!(!card.contains("proxy_secret"));
        assert!(!card.contains("内网测试机"));
    }

    #[test]
    fn test_cross_platform_windows_and_unix_snippet_formats() {
        let mut host = RelayHost::new_template(1);
        host.codename = "silver-orbit-02".to_string();
        host.real_host = "172.16.99.88".to_string();
        host.real_user = "ubuntu_prod".to_string();
        host.agent_auth_mode = AgentAuthMode::DedicatedKey;

        let mut runtime = RelayRuntimeState::default();
        // 未启动状态必须拒绝导出配置
        assert!(render_agent_snippet(&host, &runtime, CopyFormat::AgentPromptCard).is_err());

        runtime.status = RelayStatus::Running {
            local_port: 60123,
            active_sessions: 1,
        };
        runtime.dedicated_key_path = Some(
            r"C:\Users\Admin\AppData\Local\AgentGate\agent_keys\silver-orbit-02_id_ed25519"
                .to_string(),
        );

        // 验证 Windows 平台下 NUL 设备与带反斜杠路径引用
        let win_card = render_agent_snippet_with_null_dev(
            &host,
            &runtime,
            CopyFormat::AgentPromptCard,
            "NUL",
        )
        .expect("win card");
        assert!(win_card.contains("UserKnownHostsFile=NUL"));
        assert!(win_card.contains(
            r#"ssh -i "C:\Users\Admin\AppData\Local\AgentGate\agent_keys\silver-orbit-02_id_ed25519""#
        ));
        assert!(!win_card.contains("172.16.99.88"));
        assert!(!win_card.contains("ubuntu_prod"));

        // 验证 Linux / macOS 平台下 /dev/null 与纯命令导出
        let unix_cmd = render_agent_snippet_with_null_dev(
            &host,
            &runtime,
            CopyFormat::SshCommandOnly,
            "/dev/null",
        )
        .expect("unix cmd");
        assert!(unix_cmd.contains("UserKnownHostsFile=/dev/null"));
        assert!(unix_cmd.contains("-p 60123 silver-orbit-02@127.0.0.1"));
    }
}
