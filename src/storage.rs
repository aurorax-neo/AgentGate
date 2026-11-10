use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use rand::RngExt;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use russh::keys::ssh_key::{Algorithm, LineEnding, PrivateKey};
use serde::{Deserialize, Serialize};

use crate::models::RelayHost;

const VAULT_MAGIC: &[u8; 8] = b"AGTVLT01";
const NONCE_LEN: usize = 12;
const MASTER_KEY_LEN: usize = 32;

#[inline]
fn zeroize_slice(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultPayload {
    pub version: u32,
    pub hosts: Vec<RelayHost>,
}

/// 本机 AES-256-GCM 加密配置仓库与专用密钥管理器
#[derive(Debug, Clone)]
pub struct EncryptedStorage {
    base_dir: PathBuf,
}

impl EncryptedStorage {
    pub fn new_default() -> Result<Self> {
        if let Ok(custom_dir) = std::env::var("AGENTGATE_DATA_DIR")
            && !custom_dir.trim().is_empty()
        {
            return Self::new_in_dir(PathBuf::from(custom_dir));
        }
        let base = dirs::data_local_dir()
            .or_else(dirs::home_dir)
            .unwrap_or_else(|| PathBuf::from("."))
            .join("AgentGate");
        Self::new_in_dir(base)
    }

    pub fn new_in_dir(base_dir: impl Into<PathBuf>) -> Result<Self> {
        let base_dir = base_dir.into();
        fs::create_dir_all(&base_dir)
            .with_context(|| format!("创建应用数据目录失败: {}", base_dir.display()))?;
        let keys_dir = base_dir.join("agent_keys");
        fs::create_dir_all(&keys_dir)
            .with_context(|| format!("创建专用密钥目录失败: {}", keys_dir.display()))?;
        set_dir_permissions_0700(&base_dir)?;
        set_dir_permissions_0700(&keys_dir)?;
        Ok(Self { base_dir })
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    pub fn vault_file_path(&self) -> PathBuf {
        self.base_dir.join("vault.enc")
    }

    pub fn master_key_path(&self) -> PathBuf {
        self.base_dir.join("master.key")
    }

    pub fn agent_keys_dir(&self) -> PathBuf {
        self.base_dir.join("agent_keys")
    }

    /// 加载或初始化 256-bit 本机主密钥（权限 0600）
    fn load_or_create_master_key(&self) -> Result<[u8; MASTER_KEY_LEN]> {
        let key_path = self.master_key_path();
        if key_path.exists() {
            let mut bytes = fs::read(&key_path)
                .with_context(|| format!("读取本机主密钥失败: {}", key_path.display()))?;
            if bytes.len() != MASTER_KEY_LEN {
                zeroize_slice(&mut bytes);
                return Err(anyhow!(
                    "主密钥长度异常（期望 {} 字节，实际 {} 字节）",
                    MASTER_KEY_LEN,
                    bytes.len()
                ));
            }
            let mut key = [0u8; MASTER_KEY_LEN];
            key.copy_from_slice(&bytes);
            zeroize_slice(&mut bytes);
            return Ok(key);
        }

        let mut key = [0u8; MASTER_KEY_LEN];
        rand::rng().fill(&mut key);
        fs::write(&key_path, key)
            .with_context(|| format!("写入本机主密钥失败: {}", key_path.display()))?;
        set_file_permissions_0600(&key_path)?;
        Ok(key)
    }

    /// 使用 AES-256-GCM 加密保存全部主机配置到 vault.enc
    pub fn save_hosts(&self, hosts: &[RelayHost]) -> Result<()> {
        let mut key_bytes = self.load_or_create_master_key()?;
        let unbound_res = UnboundKey::new(&AES_256_GCM, &key_bytes);
        zeroize_slice(&mut key_bytes);
        let unbound_key = unbound_res.map_err(|_| anyhow!("初始化 AES-256-GCM 密钥失败"))?;
        let key = LessSafeKey::new(unbound_key);

        let payload = VaultPayload {
            version: 1,
            hosts: hosts.to_vec(),
        };
        let mut in_out =
            serde_json::to_vec(&payload).context("序列化主机配置失败")?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rng().fill(&mut nonce_bytes);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        key.seal_in_place_append_tag(nonce, Aad::from(VAULT_MAGIC), &mut in_out)
            .map_err(|_| anyhow!("AES-256-GCM 加密失败"))?;

        let mut file_bytes = Vec::with_capacity(VAULT_MAGIC.len() + NONCE_LEN + in_out.len());
        file_bytes.extend_from_slice(VAULT_MAGIC);
        file_bytes.extend_from_slice(&nonce_bytes);
        file_bytes.extend_from_slice(&in_out);

        let tmp_path = self.base_dir.join("vault.enc.tmp");
        fs::write(&tmp_path, &file_bytes)
            .with_context(|| format!("写入加密临时文件失败: {}", tmp_path.display()))?;
        set_file_permissions_0600(&tmp_path)?;
        fs::rename(&tmp_path, self.vault_file_path()).context("替换加密配置文件失败")?;
        Ok(())
    }

    /// 从 vault.enc 解密并加载主机配置
    pub fn load_hosts(&self) -> Result<Vec<RelayHost>> {
        let vault_path = self.vault_file_path();
        if !vault_path.exists() {
            return Ok(Vec::new());
        }

        let raw = fs::read(&vault_path)
            .with_context(|| format!("读取加密配置文件失败: {}", vault_path.display()))?;
        let header_len = VAULT_MAGIC.len() + NONCE_LEN;
        if raw.len() <= header_len + AES_256_GCM.tag_len() {
            return Err(anyhow!("加密仓库文件已损坏或长度不足"));
        }
        if &raw[..VAULT_MAGIC.len()] != VAULT_MAGIC {
            return Err(anyhow!("加密仓库文件头标识不匹配"));
        }

        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&raw[VAULT_MAGIC.len()..header_len]);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut key_bytes = self.load_or_create_master_key()?;
        let unbound_res = UnboundKey::new(&AES_256_GCM, &key_bytes);
        zeroize_slice(&mut key_bytes);
        let unbound_key = unbound_res.map_err(|_| anyhow!("初始化 AES-256-GCM 密钥失败"))?;
        let key = LessSafeKey::new(unbound_key);

        let mut ciphertext = raw[header_len..].to_vec();
        let plaintext = key
            .open_in_place(nonce, Aad::from(VAULT_MAGIC), &mut ciphertext)
            .map_err(|_| anyhow!("解密 vault.enc 失败：密文已被篡改或主密钥不匹配"))?;

        let parse_res: Result<VaultPayload> =
            serde_json::from_slice(plaintext).context("反序列化加密仓库内容失败");
        zeroize_slice(&mut ciphertext);
        let payload = parse_res?;
        Ok(payload.hosts)
    }

    /// 为指定代号确保生成或同步本机专用 Ed25519 密钥对，并落盘 0600 私钥文件供 Agent 使用
    pub fn ensure_dedicated_agent_key(
        &self,
        host: &mut RelayHost,
        force_rotate: bool,
    ) -> Result<(PathBuf, String)> {
        let need_generate = force_rotate || host.dedicated_key_openssh_pem.is_none();
        let private_key = if need_generate {
            let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
                .context("生成 Ed25519 专用密钥失败")?;
            let pem = key
                .to_openssh(LineEnding::LF)
                .context("导出 OpenSSH 私钥格式失败")?
                .to_string();
            host.dedicated_key_openssh_pem = Some(pem);
            key
        } else {
            let pem = host.dedicated_key_openssh_pem.as_deref().unwrap_or_default();
            PrivateKey::from_openssh(pem).or_else(|_| {
                let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
                    .context("重新生成 Ed25519 专用密钥失败")?;
                let new_pem = key
                    .to_openssh(LineEnding::LF)
                    .context("导出 OpenSSH 私钥格式失败")?
                    .to_string();
                host.dedicated_key_openssh_pem = Some(new_pem);
                Ok::<PrivateKey, anyhow::Error>(key)
            })?
        };

        let key_path = self.dedicated_key_path_for(&host.codename);
        if let Some(pem) = &host.dedicated_key_openssh_pem {
            fs::write(&key_path, pem.as_bytes())
                .with_context(|| format!("写入本地专用密钥文件失败: {}", key_path.display()))?;
            set_file_permissions_0600(&key_path)?;
        }

        let pubkey_openssh = private_key
            .public_key()
            .to_openssh()
            .context("导出专用公钥失败")?;
        Ok((key_path, pubkey_openssh))
    }

    pub fn dedicated_key_path_for(&self, codename: &str) -> PathBuf {
        let safe_name: String = codename
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.agent_keys_dir()
            .join(format!("{}_id_ed25519", safe_name))
    }

    pub fn remove_dedicated_key_file(&self, codename: &str) {
        let path = self.dedicated_key_path_for(codename);
        if path.exists() {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(unix)]
fn set_file_permissions_0600(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, perms)
        .with_context(|| format!("设置文件 0600 权限失败: {}", path.display()))
}

#[cfg(not(unix))]
fn set_file_permissions_0600(_path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let principal = std::env::var("USERNAME")
            .ok()
            .filter(|u| {
                !u.is_empty()
                    && !u
                        .chars()
                        .any(|c| matches!(c, ':' | '/' | '\\' | '"' | '\r' | '\n') || c.is_control())
            })
            .unwrap_or_else(|| "*S-1-5-32-544".to_string());
        let grant_arg = format!("{}:(F)", principal);
        let _ = std::process::Command::new("icacls")
            .arg(_path)
            .args(["/inheritance:r", "/grant:r", &grant_arg])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }
    Ok(())
}

#[cfg(unix)]
fn set_dir_permissions_0700(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o700);
    fs::set_permissions(path, perms)
        .with_context(|| format!("设置目录 0700 权限失败: {}", path.display()))
}

#[cfg(not(unix))]
fn set_dir_permissions_0700(_path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let principal = std::env::var("USERNAME")
            .ok()
            .filter(|u| {
                !u.is_empty()
                    && !u
                        .chars()
                        .any(|c| matches!(c, ':' | '/' | '\\' | '"' | '\r' | '\n') || c.is_control())
            })
            .unwrap_or_else(|| "*S-1-5-32-544".to_string());
        let grant_arg = format!("{}:(OI)(CI)(F)", principal);
        let _ = std::process::Command::new("icacls")
            .arg(_path)
            .args(["/inheritance:r", "/grant:r", &grant_arg])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AgentAuthMode, ProxyConfig, RealAuthConfig};
    use uuid::Uuid;

    #[test]
    fn test_aes256_gcm_vault_roundtrip_and_tamper_detection() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let storage = EncryptedStorage::new_in_dir(dir.path()).expect("init storage");

        let mut host = RelayHost {
            id: Uuid::new_v4(),
            codename: "prod-alpha-01".to_string(),
            label: "核心生产库".to_string(),
            real_host: "10.96.1.104".to_string(),
            real_port: 2222,
            real_user: "root".to_string(),
            real_auth: RealAuthConfig::Password {
                password: "SuperSecretRealPassword!2026".to_string(),
            },
            proxy: ProxyConfig::Socks5 {
                host: "127.0.0.1".to_string(),
                port: 7890,
                username: None,
                password: None,
            },
            agent_auth_mode: AgentAuthMode::DedicatedKey,
            dedicated_key_openssh_pem: None,
            pinned_host_key_openssh: None,
            created_at: "2026-11-10 10:00:00".to_string(),
            updated_at: "2026-11-10 10:00:00".to_string(),
        };

        let (key_path, pubkey) = storage
            .ensure_dedicated_agent_key(&mut host, false)
            .expect("generate dedicated key");
        assert!(key_path.exists());
        assert!(pubkey.starts_with("ssh-ed25519 "));

        storage
            .save_hosts(std::slice::from_ref(&host))
            .expect("save encrypted vault");

        // 确保密文文件中不包含明文真实 IP 和真实密码
        let raw_cipher = fs::read(storage.vault_file_path()).expect("read raw vault");
        let raw_lossy = String::from_utf8_lossy(&raw_cipher);
        assert!(!raw_lossy.contains("10.96.1.104"));
        assert!(!raw_lossy.contains("SuperSecretRealPassword!2026"));

        let loaded = storage.load_hosts().expect("load encrypted vault");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], host);

        // 篡改密文最后 1 个字节，必须触发认证标签校验失败
        let mut tampered = raw_cipher;
        let last = tampered.len() - 1;
        tampered[last] ^= 0x55;
        fs::write(storage.vault_file_path(), tampered).expect("write tampered vault");
        assert!(storage.load_hosts().is_err());
    }

    #[test]
    fn test_dedicated_ed25519_key_generation_rotation_and_cleanup() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let storage = EncryptedStorage::new_in_dir(dir.path()).expect("init storage");

        let mut host = RelayHost::new_template(0);
        host.codename = "onyx-bastion-09".to_string();

        let (path1, pub1) = storage
            .ensure_dedicated_agent_key(&mut host, false)
            .expect("initial keygen");
        assert!(path1.exists());
        assert!(pub1.starts_with("ssh-ed25519 "));

        // 非强制轮换时应保持同一公钥
        let (path2, pub2) = storage
            .ensure_dedicated_agent_key(&mut host, false)
            .expect("reuse key");
        assert_eq!(path1, path2);
        assert_eq!(pub1, pub2);

        // 强制轮换时必须生成全新 Ed25519 密钥对并覆盖磁盘文件
        let (_, pub3) = storage
            .ensure_dedicated_agent_key(&mut host, true)
            .expect("rotate key");
        assert_ne!(pub1, pub3);

        // 删除主机时同步清理专用密钥文件
        storage.remove_dedicated_key_file(&host.codename);
        assert!(!path1.exists());
    }
}
