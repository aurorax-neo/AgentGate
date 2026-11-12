use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use data_encoding::BASE64;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::models::ProxyConfig;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(12);

/// 校验目标主机名与代理凭据，阻断 CRLF 头部注入与控制字符（修复 [HIGH-03]）
fn validate_proxy_and_target_inputs(
    target_host: &str,
    proxy_host: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<()> {
    let th = target_host.trim();
    if th.is_empty()
        || th != target_host
        || th.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(anyhow!(
            "[阶段: 参数安全校验] 目标主机名包含非法空白或控制字符，已拒绝发起连接"
        ));
    }
    if let Some(ph) = proxy_host {
        let ph_trim = ph.trim();
        if ph_trim.is_empty()
            || ph_trim != ph
            || ph_trim.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(anyhow!(
                "[阶段: 参数安全校验] 代理服务器地址包含非法空白或控制字符"
            ));
        }
    }
    if let Some(u) = username
        && u.chars().any(|c| c.is_control())
    {
        return Err(anyhow!(
            "[阶段: 参数安全校验] 代理认证用户名包含非法控制字符"
        ));
    }
    if let Some(p) = password
        && p.chars().any(|c| c.is_control())
    {
        return Err(anyhow!(
            "[阶段: 参数安全校验] 代理认证密码包含非法控制字符"
        ));
    }
    Ok(())
}

/// 根据条目的代理配置建立到目标远端主机的底层 TCP 隧道
/// 注意：所有返回的错误信息均经过脱敏，不泄露真实远端 IP 给 Agent
pub async fn connect_via_proxy(
    proxy: &ProxyConfig,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    let stream = match proxy {
        ProxyConfig::None => {
            validate_proxy_and_target_inputs(target_host, None, None, None)?;
            connect_direct(target_host, target_port).await?
        }
        ProxyConfig::Socks5 {
            host,
            port,
            username,
            password,
        } => {
            validate_proxy_and_target_inputs(
                target_host,
                Some(host),
                username.as_deref(),
                password.as_deref(),
            )?;
            connect_socks5(
                host,
                *port,
                username.as_deref(),
                password.as_deref(),
                target_host,
                target_port,
            )
            .await?
        }
        ProxyConfig::HttpConnect {
            host,
            port,
            username,
            password,
        } => {
            validate_proxy_and_target_inputs(
                target_host,
                Some(host),
                username.as_deref(),
                password.as_deref(),
            )?;
            connect_http_tunnel(
                host,
                *port,
                username.as_deref(),
                password.as_deref(),
                target_host,
                target_port,
            )
            .await?
        }
    };

    let _ = stream.set_nodelay(true);
    Ok(stream)
}

async fn connect_direct(target_host: &str, target_port: u16) -> Result<TcpStream> {
    let started = Instant::now();
    timeout(CONNECT_TIMEOUT, TcpStream::connect((target_host, target_port)))
        .await
        .map_err(|_| {
            anyhow!(
                "[阶段: TCP直连] 连接上游目标端口 :{} 超时 (耗时 {}ms，目标不可达或防火墙丢包)",
                target_port,
                started.elapsed().as_millis()
            )
        })?
        .map_err(|e| {
            anyhow!(
                "[阶段: TCP直连] 无法连接上游目标端口 :{} (错误: {} / {}, 耗时 {}ms)",
                target_port,
                e.kind(),
                e,
                started.elapsed().as_millis()
            )
        })
}

async fn connect_socks5(
    proxy_host: &str,
    proxy_port: u16,
    username: Option<&str>,
    password: Option<&str>,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    timeout(CONNECT_TIMEOUT, async {
        let mut stream = TcpStream::connect((proxy_host, proxy_port))
            .await
            .with_context(|| format!("无法连接 SOCKS5 代理 {}:{}", proxy_host, proxy_port))?;

        let has_auth = username.is_some_and(|u| !u.is_empty());
        if has_auth {
            stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
        } else {
            stream.write_all(&[0x05, 0x01, 0x00]).await?;
        }

        let mut greeting_reply = [0u8; 2];
        stream.read_exact(&mut greeting_reply).await?;
        if greeting_reply[0] != 0x05 {
            return Err(anyhow!("SOCKS5 代理协议版本不匹配"));
        }

        match greeting_reply[1] {
            0x00 => {}
            0x02 => {
                let user = username.unwrap_or_default().as_bytes();
                let pass = password.unwrap_or_default().as_bytes();
                if user.len() > 255 || pass.len() > 255 {
                    return Err(anyhow!("SOCKS5 代理账号或密码长度超出限制"));
                }
                let mut auth_req = Vec::with_capacity(3 + user.len() + pass.len());
                auth_req.push(0x01);
                auth_req.push(user.len() as u8);
                auth_req.extend_from_slice(user);
                auth_req.push(pass.len() as u8);
                auth_req.extend_from_slice(pass);
                stream.write_all(&auth_req).await?;

                let mut auth_reply = [0u8; 2];
                stream.read_exact(&mut auth_reply).await?;
                if auth_reply[1] != 0x00 {
                    return Err(anyhow!("SOCKS5 代理用户名或密码认证失败"));
                }
            }
            0xFF => return Err(anyhow!("SOCKS5 代理拒绝了所有认证方式")),
            other => return Err(anyhow!("SOCKS5 代理返回未知认证方式: 0x{:02x}", other)),
        }

        let mut req = Vec::with_capacity(6 + target_host.len());
        req.extend_from_slice(&[0x05, 0x01, 0x00]);
        if let Ok(ipv4) = target_host.parse::<Ipv4Addr>() {
            req.push(0x01);
            req.extend_from_slice(&ipv4.octets());
        } else if let Ok(ipv6) = target_host.parse::<Ipv6Addr>() {
            req.push(0x04);
            req.extend_from_slice(&ipv6.octets());
        } else {
            let domain = target_host.as_bytes();
            if domain.len() > 255 {
                return Err(anyhow!("目标主机域名过长"));
            }
            req.push(0x03);
            req.push(domain.len() as u8);
            req.extend_from_slice(domain);
        }
        req.extend_from_slice(&target_port.to_be_bytes());
        stream.write_all(&req).await?;

        let mut resp_head = [0u8; 4];
        stream.read_exact(&mut resp_head).await?;
        if resp_head[0] != 0x05 {
            return Err(anyhow!("SOCKS5 响应版本异常"));
        }
        if resp_head[1] != 0x00 {
            return Err(anyhow!("SOCKS5 代理连接上游失败 (错误码: 0x{:02x})", resp_head[1]));
        }

        match resp_head[3] {
            0x01 => {
                let mut skip = [0u8; 6];
                stream.read_exact(&mut skip).await?;
            }
            0x04 => {
                let mut skip = [0u8; 18];
                stream.read_exact(&mut skip).await?;
            }
            0x03 => {
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await?;
                let mut skip = vec![0u8; (len_buf[0] as usize) + 2];
                stream.read_exact(&mut skip).await?;
            }
            other => return Err(anyhow!("SOCKS5 响应地址类型未知: 0x{:02x}", other)),
        }

        Ok(stream)
    })
    .await
    .map_err(|_| anyhow!("连接或握手 SOCKS5 代理超时"))?
}

async fn connect_http_tunnel(
    proxy_host: &str,
    proxy_port: u16,
    username: Option<&str>,
    password: Option<&str>,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    timeout(CONNECT_TIMEOUT, async {
        let mut stream = TcpStream::connect((proxy_host, proxy_port))
            .await
            .with_context(|| format!("无法连接 HTTP 代理 {}:{}", proxy_host, proxy_port))?;

        let auth_header = if let Some(user) = username.filter(|u| !u.is_empty()) {
            let pass = password.unwrap_or_default();
            let raw = format!("{}:{}", user, pass);
            let encoded = BASE64.encode(raw.as_bytes());
            format!("Proxy-Authorization: Basic {}\r\n", encoded)
        } else {
            String::new()
        };

        let connect_req = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n{}Proxy-Connection: keep-alive\r\n\r\n",
            target_host, target_port, target_host, target_port, auth_header
        );
        stream.write_all(connect_req.as_bytes()).await?;

        // 逐字节读取直到 \r\n\r\n，绝不吞掉后续 SSH 协议握手首包字节
        let mut header_bytes = Vec::with_capacity(256);
        let mut byte = [0u8; 1];
        while !header_bytes.ends_with(b"\r\n\r\n") {
            if header_bytes.len() > 8192 {
                return Err(anyhow!("HTTP CONNECT 响应头过长"));
            }
            let n = stream.read(&mut byte).await?;
            if n == 0 {
                return Err(anyhow!("HTTP 代理在完成握手前关闭了连接"));
            }
            header_bytes.push(byte[0]);
        }

        let header_str = String::from_utf8_lossy(&header_bytes);
        let status_line = header_str.lines().next().unwrap_or_default();
        let is_200 = status_line
            .split_whitespace()
            .nth(1)
            .is_some_and(|code| code == "200");
        if !is_200 {
            return Err(anyhow!("HTTP CONNECT 代理握手失败: {}", status_line));
        }

        Ok(stream)
    })
    .await
    .map_err(|_| anyhow!("连接或握手 HTTP 代理超时"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_socks5_and_http_connect_proxy_tunnels() {
        // 1. 启动模拟目标服务器
        let target_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
        let target_port = target_listener.local_addr().expect("target addr").port();

        tokio::spawn(async move {
            while let Ok((mut sock, _)) = target_listener.accept().await {
                tokio::spawn(async move {
                    let _ = sock.write_all(b"SSH-2.0-MockTarget\r\n").await;
                });
            }
        });

        // 2. 启动模拟 SOCKS5 代理服务器
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind socks");
        let socks_port = socks_listener.local_addr().expect("socks addr").port();
        tokio::spawn(async move {
            let (mut client, _) = socks_listener.accept().await.expect("accept socks");
            let mut greeting = [0u8; 3];
            client.read_exact(&mut greeting).await.expect("read greeting");
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            client.write_all(&[0x05, 0x00]).await.expect("write method");

            let mut req = [0u8; 10];
            client.read_exact(&mut req).await.expect("read connect req");
            assert_eq!(&req[..4], &[0x05, 0x01, 0x00, 0x01]);
            let port = u16::from_be_bytes([req[8], req[9]]);
            let mut upstream = TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("socks upstream");
            client
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .expect("write socks ok");
            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        });

        let mut socks_stream = connect_via_proxy(
            &ProxyConfig::Socks5 {
                host: "127.0.0.1".to_string(),
                port: socks_port,
                username: None,
                password: None,
            },
            "127.0.0.1",
            target_port,
        )
        .await
        .expect("connect via socks5");
        let mut banner = [0u8; 20];
        socks_stream
            .read_exact(&mut banner)
            .await
            .expect("read banner via socks5");
        assert_eq!(&banner, b"SSH-2.0-MockTarget\r\n");

        // 3. 启动模拟 HTTP CONNECT 代理服务器
        let http_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind http");
        let http_port = http_listener.local_addr().expect("http addr").port();
        tokio::spawn(async move {
            let (mut client, _) = http_listener.accept().await.expect("accept http");
            let mut req_buf = Vec::new();
            let mut b = [0u8; 1];
            while !req_buf.ends_with(b"\r\n\r\n") {
                client.read_exact(&mut b).await.expect("read http req");
                req_buf.push(b[0]);
            }
            let req_str = String::from_utf8_lossy(&req_buf);
            assert!(req_str.starts_with(&format!("CONNECT 127.0.0.1:{}", target_port)));
            let mut upstream = TcpStream::connect(("127.0.0.1", target_port))
                .await
                .expect("http upstream");
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .expect("write http 200");
            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        });

        let mut http_stream = connect_via_proxy(
            &ProxyConfig::HttpConnect {
                host: "127.0.0.1".to_string(),
                port: http_port,
                username: Some("agent".to_string()),
                password: Some("pass".to_string()),
            },
            "127.0.0.1",
            target_port,
        )
        .await
        .expect("connect via http connect");
        let mut banner2 = [0u8; 20];
        http_stream
            .read_exact(&mut banner2)
            .await
            .expect("read banner via http connect");
        assert_eq!(&banner2, b"SSH-2.0-MockTarget\r\n");
    }

    #[tokio::test]
    async fn test_socks5_username_password_auth_and_rejection() {
        let socks_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind socks auth");
        let socks_port = socks_listener.local_addr().expect("socks addr").port();

        tokio::spawn(async move {
            if let Ok((mut client, _)) = socks_listener.accept().await {
                let mut greeting = [0u8; 4];
                client.read_exact(&mut greeting).await.expect("greeting");
                // 选择 0x02 用户名密码认证
                client.write_all(&[0x05, 0x02]).await.expect("select 0x02");
                let mut ver = [0u8; 1];
                client.read_exact(&mut ver).await.expect("ver");
                let mut ulen = [0u8; 1];
                client.read_exact(&mut ulen).await.expect("ulen");
                let mut ubuf = vec![0u8; ulen[0] as usize];
                client.read_exact(&mut ubuf).await.expect("user");
                let mut plen = [0u8; 1];
                client.read_exact(&mut plen).await.expect("plen");
                let mut pbuf = vec![0u8; plen[0] as usize];
                client.read_exact(&mut pbuf).await.expect("pass");
                // 返回 0x01 认证失败
                let _ = client.write_all(&[0x01, 0x01]).await;
            }
        });

        let res = connect_via_proxy(
            &ProxyConfig::Socks5 {
                host: "127.0.0.1".to_string(),
                port: socks_port,
                username: Some("wrong_user".to_string()),
                password: Some("wrong_pass".to_string()),
            },
            "10.0.0.1",
            22,
        )
        .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_proxy_crlf_and_control_char_injection_rejected() {
        let bad_target = "10.0.0.1:22 HTTP/1.1\r\nX-Injected: pwned";
        let res_http = connect_via_proxy(
            &ProxyConfig::HttpConnect {
                host: "127.0.0.1".to_string(),
                port: 8080,
                username: None,
                password: None,
            },
            bad_target,
            22,
        )
        .await;
        assert!(res_http.is_err());

        let res_cred = connect_via_proxy(
            &ProxyConfig::HttpConnect {
                host: "127.0.0.1".to_string(),
                port: 8080,
                username: Some("admin\r\nInjected: 1".to_string()),
                password: Some("pass".to_string()),
            },
            "10.0.0.1",
            22,
        )
        .await;
        assert!(res_cred.is_err());
    }
}
