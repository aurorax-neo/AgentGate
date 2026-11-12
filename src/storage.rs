use std::fs::{self, OpenOptions};
use std::io::Write;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use rand::RngExt;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::pbkdf2::{PBKDF2_HMAC_SHA256, derive};
use russh::keys::ssh_key::{Algorithm, LineEnding, PrivateKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::RelayHost;

const VAULT_MAGIC: &[u8; 8] = b"AGTVLT01";
const MASTER_KEY_SEAL_MAGIC: &[u8; 8] = b"AGTMK01\0";
const KEK_SALT_LEN: usize = 16;
const KEK_ITERATIONS: u32 = 100_000;
const NONCE_LEN: usize = 12;
const MASTER_KEY_LEN: usize = 32;

/// 进程内全局仓库写入互斥锁，防止多线程并发写入或覆盖临时文件（修复 [HIGH-05]）
static VAULT_SAVE_LOCK: Mutex<()> = Mutex::new(());

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
    use_os_keychain: bool,
    cached_master_key: Arc<Mutex<Option<[u8; MASTER_KEY_LEN]>>>,
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
        let mut storage = Self::new_in_dir(base)?;
        storage.use_os_keychain = true;
        Ok(storage)
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
        Ok(Self {
            base_dir,
            use_os_keychain: false,
            cached_master_key: Arc::new(Mutex::new(None)),
        })
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

    /// 派生与本机环境及仓库路径绑定的信封密钥加密密钥 (KEK)
    fn derive_envelope_kek(&self, salt: &[u8; KEK_SALT_LEN]) -> [u8; MASTER_KEY_LEN] {
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "agentgate-local-user".to_string());
        let canonical = self
            .base_dir
            .canonicalize()
            .unwrap_or_else(|_| self.base_dir.clone());
        let mut material = Vec::with_capacity(128);
        material.extend_from_slice(b"AgentGate::MasterKeyEnvelope::v1::");
        material.extend_from_slice(user.as_bytes());
        material.push(b':');
        material.extend_from_slice(canonical.to_string_lossy().as_bytes());

        let mut kek = [0u8; MASTER_KEY_LEN];
        derive(
            PBKDF2_HMAC_SHA256,
            NonZeroU32::new(KEK_ITERATIONS).expect("non-zero iterations"),
            salt,
            &material,
            &mut kek,
        );
        zeroize_slice(&mut material);
        kek
    }

    /// 使用 PBKDF2-HMAC-SHA256 + AES-256-GCM 封装 32 字节主密钥，杜绝裸明文 `master.key` 落盘（修复 [HIGH-01]）
    fn seal_master_key_envelope(&self, master_key: &[u8; MASTER_KEY_LEN]) -> Result<Vec<u8>> {
        let mut salt = [0u8; KEK_SALT_LEN];
        rand::rng().fill(&mut salt);
        let mut kek_bytes = self.derive_envelope_kek(&salt);
        let unbound_res = UnboundKey::new(&AES_256_GCM, &kek_bytes);
        zeroize_slice(&mut kek_bytes);
        let unbound = unbound_res.map_err(|_| anyhow!("初始化主密钥信封 KEK 失败"))?;
        let kek = LessSafeKey::new(unbound);

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rng().fill(&mut nonce_bytes);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = master_key.to_vec();
        kek.seal_in_place_append_tag(nonce, Aad::from(MASTER_KEY_SEAL_MAGIC), &mut in_out)
            .map_err(|_| anyhow!("封装主密钥信封失败"))?;

        let mut out =
            Vec::with_capacity(MASTER_KEY_SEAL_MAGIC.len() + KEK_SALT_LEN + NONCE_LEN + in_out.len());
        out.extend_from_slice(MASTER_KEY_SEAL_MAGIC);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&in_out);
        zeroize_slice(&mut in_out);
        Ok(out)
    }

    /// 解封 `AGTMK01\0` 信封格式的主密钥文件
    fn open_master_key_envelope(&self, raw: &[u8]) -> Result<[u8; MASTER_KEY_LEN]> {
        let header_len = MASTER_KEY_SEAL_MAGIC.len() + KEK_SALT_LEN + NONCE_LEN;
        if raw.len() != header_len + MASTER_KEY_LEN + AES_256_GCM.tag_len() {
            return Err(anyhow!("加密主密钥信封长度无效"));
        }
        let mut salt = [0u8; KEK_SALT_LEN];
        salt.copy_from_slice(&raw[MASTER_KEY_SEAL_MAGIC.len()..MASTER_KEY_SEAL_MAGIC.len() + KEK_SALT_LEN]);
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&raw[MASTER_KEY_SEAL_MAGIC.len() + KEK_SALT_LEN..header_len]);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut kek_bytes = self.derive_envelope_kek(&salt);
        let unbound_res = UnboundKey::new(&AES_256_GCM, &kek_bytes);
        zeroize_slice(&mut kek_bytes);
        let unbound = unbound_res.map_err(|_| anyhow!("初始化主密钥解封 KEK 失败"))?;
        let kek = LessSafeKey::new(unbound);

        let mut ciphertext = raw[header_len..].to_vec();
        let plain = kek
            .open_in_place(nonce, Aad::from(MASTER_KEY_SEAL_MAGIC), &mut ciphertext)
            .map_err(|_| anyhow!("解封本机主密钥失败：密钥文件已损坏或不属于当前环境"))?;
        let mut key = [0u8; MASTER_KEY_LEN];
        key.copy_from_slice(&plain[..MASTER_KEY_LEN]);
        zeroize_slice(&mut ciphertext);
        Ok(key)
    }

    /// 加载或初始化 256-bit 本机主密钥（支持系统钥匙串优先托管、PBKDF2+AES-GCM 信封落盘及旧版明文密钥无损自动升级）
    fn load_or_create_master_key(&self) -> Result<[u8; MASTER_KEY_LEN]> {
        if let Ok(guard) = self.cached_master_key.lock()
            && let Some(cached) = *guard
        {
            return Ok(cached);
        }

        if self.use_os_keychain
            && let Some(kc_key) = try_load_os_keychain_master_key()
        {
            if let Ok(mut guard) = self.cached_master_key.lock() {
                *guard = Some(kc_key);
            }
            return Ok(kc_key);
        }

        let key_path = self.master_key_path();
        if key_path.exists() {
            let mut bytes = fs::read(&key_path)
                .with_context(|| format!("读取本机主密钥失败: {}", key_path.display()))?;
            let key_res = if bytes.starts_with(MASTER_KEY_SEAL_MAGIC) {
                self.open_master_key_envelope(&bytes)
            } else if bytes.len() == MASTER_KEY_LEN {
                // 兼容旧版 32 字节裸主密钥并立即升级为加密信封格式
                let mut legacy_key = [0u8; MASTER_KEY_LEN];
                legacy_key.copy_from_slice(&bytes);
                if let Ok(sealed) = self.seal_master_key_envelope(&legacy_key) {
                    let _ = write_secret_file_0600(&key_path, &sealed);
                }
                Ok(legacy_key)
            } else {
                Err(anyhow!(
                    "主密钥格式或长度异常（实际 {} 字节）",
                    bytes.len()
                ))
            };
            zeroize_slice(&mut bytes);
            let key = key_res?;
            if self.use_os_keychain {
                let _ = try_store_os_keychain_master_key(&key);
            }
            if let Ok(mut guard) = self.cached_master_key.lock() {
                *guard = Some(key);
            }
            return Ok(key);
        }

        let mut key = [0u8; MASTER_KEY_LEN];
        rand::rng().fill(&mut key);
        let sealed = self.seal_master_key_envelope(&key)?;
        write_secret_file_0600(&key_path, &sealed)
            .with_context(|| format!("写入本机加密主密钥失败: {}", key_path.display()))?;
        if self.use_os_keychain {
            let _ = try_store_os_keychain_master_key(&key);
        }
        if let Ok(mut guard) = self.cached_master_key.lock() {
            *guard = Some(key);
        }
        Ok(key)
    }

    /// 使用 AES-256-GCM 加密保存全部主机配置到 vault.enc（带进程级并发互斥锁与随机临时文件原子替换）
    pub fn save_hosts(&self, hosts: &[RelayHost]) -> Result<()> {
        let _guard = VAULT_SAVE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

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

        let seal_res = key.seal_in_place_append_tag(nonce, Aad::from(VAULT_MAGIC), &mut in_out);
        if seal_res.is_err() {
            zeroize_slice(&mut in_out);
            return Err(anyhow!("AES-256-GCM 加密失败"));
        }

        let mut file_bytes = Vec::with_capacity(VAULT_MAGIC.len() + NONCE_LEN + in_out.len());
        file_bytes.extend_from_slice(VAULT_MAGIC);
        file_bytes.extend_from_slice(&nonce_bytes);
        file_bytes.extend_from_slice(&in_out);
        zeroize_slice(&mut in_out);

        let tmp_path = self
            .base_dir
            .join(format!("vault.enc.tmp.{}", Uuid::new_v4().simple()));
        write_secret_file_0600(&tmp_path, &file_bytes)
            .with_context(|| format!("写入加密临时文件失败: {}", tmp_path.display()))?;
        if let Err(err) = fs::rename(&tmp_path, self.vault_file_path()) {
            let _ = fs::remove_file(&tmp_path);
            return Err(err).context("替换加密配置文件失败");
        }
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

        let key_path = self.dedicated_key_path_for(&host.id, &host.codename);
        if let Some(pem) = &host.dedicated_key_openssh_pem {
            write_secret_file_0600(&key_path, pem.as_bytes())
                .with_context(|| format!("写入本地专用密钥文件失败: {}", key_path.display()))?;
        }

        let pubkey_openssh = private_key
            .public_key()
            .to_openssh()
            .context("导出专用公钥失败")?;
        Ok((key_path, pubkey_openssh))
    }

    /// 生成带 `host_id` 短标识的专用密钥路径，防止大小写不敏感文件系统上 `node-A` 与 `node-a` 互相覆盖或误删（修复 [MED-03]）
    pub fn dedicated_key_path_for(&self, host_id: &Uuid, codename: &str) -> PathBuf {
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
        let id_simple = host_id.simple().to_string();
        let short_id = &id_simple[..8];
        self.agent_keys_dir()
            .join(format!("{}_{}_id_ed25519", safe_name, short_id))
    }

    pub fn remove_dedicated_key_file(&self, host_id: &Uuid, codename: &str) {
        let path = self.dedicated_key_path_for(host_id, codename);
        if path.exists() {
            let _ = fs::remove_file(path);
        }
    }
}

/// 原子创建并写入 `0600` 权限敏感文件，杜绝先以默认 umask 落盘再 chmod 的权限时间窗（修复 [HIGH-05]）
fn write_secret_file_0600(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp_path = parent.join(format!(
        ".tmp.{}.{}",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("secret"),
        Uuid::new_v4().simple()
    ));

    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .with_context(|| format!("创建 0600 临时敏感文件失败: {}", tmp_path.display()))?
    };

    #[cfg(not(unix))]
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .with_context(|| format!("创建临时敏感文件失败: {}", tmp_path.display()))?;

    if let Err(err) = file.write_all(content).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&tmp_path);
        return Err(err).with_context(|| format!("写入临时敏感文件失败: {}", tmp_path.display()));
    }
    drop(file);
    set_file_permissions_0600(&tmp_path)?;
    if let Err(err) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err).with_context(|| format!("替换敏感文件失败: {}", path.display()));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn try_load_os_keychain_master_key() -> Option<[u8; MASTER_KEY_LEN]> {
    let output = std::process::Command::new("/usr/bin/security")
        .args([
            "find-generic-password",
            "-s",
            "io.agentgate.desktop.vault",
            "-a",
            "master-key-v1",
            "-w",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let encoded = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let mut decoded = data_encoding::BASE64.decode(encoded.as_bytes()).ok()?;
    if decoded.len() != MASTER_KEY_LEN {
        zeroize_slice(&mut decoded);
        return None;
    }
    let mut key = [0u8; MASTER_KEY_LEN];
    key.copy_from_slice(&decoded);
    zeroize_slice(&mut decoded);
    Some(key)
}

#[cfg(not(target_os = "macos"))]
fn try_load_os_keychain_master_key() -> Option<[u8; MASTER_KEY_LEN]> {
    None
}

#[cfg(target_os = "macos")]
fn try_store_os_keychain_master_key(key: &[u8; MASTER_KEY_LEN]) -> bool {
    let encoded = data_encoding::BASE64.encode(key);
    std::process::Command::new("/usr/bin/security")
        .args([
            "add-generic-password",
            "-U",
            "-s",
            "io.agentgate.desktop.vault",
            "-a",
            "master-key-v1",
            "-w",
            &encoded,
        ])
        .output()
        .is_ok_and(|o| o.status.success())
}

#[cfg(not(target_os = "macos"))]
fn try_store_os_keychain_master_key(_key: &[u8; MASTER_KEY_LEN]) -> bool {
    false
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
        match std::process::Command::new("icacls")
            .arg(_path)
            .args(["/inheritance:r", "/grant:r", &grant_arg])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
        {
            Ok(out) if !out.status.success() => {
                log::warn!(
                    "Windows icacls 设置文件 ACL 权限返回非零状态 ({}): {}",
                    out.status,
                    _path.display()
                );
            }
            Err(e) => {
                log::warn!("调用 Windows icacls 设置文件权限失败 ({}): {}", _path.display(), e);
            }
            _ => {}
        }
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
        match std::process::Command::new("icacls")
            .arg(_path)
            .args(["/inheritance:r", "/grant:r", &grant_arg])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
        {
            Ok(out) if !out.status.success() => {
                log::warn!(
                    "Windows icacls 设置目录 ACL 权限返回非零状态 ({}): {}",
                    out.status,
                    _path.display()
                );
            }
            Err(e) => {
                log::warn!("调用 Windows icacls 设置目录权限失败 ({}): {}", _path.display(), e);
            }
            _ => {}
        }
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
            local_bind_host: "127.0.0.1".to_string(),
            local_port: 52001,
            agent_password: RelayHost::generate_ephemeral_password(),
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
        storage.remove_dedicated_key_file(&host.id, &host.codename);
        assert!(!path1.exists());
    }

    #[test]
    fn test_master_key_envelope_encryption_and_legacy_migration() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let storage = EncryptedStorage::new_in_dir(dir.path()).expect("init storage");

        let host = RelayHost::new_template(0);
        storage
            .save_hosts(std::slice::from_ref(&host))
            .expect("save hosts");

        // 验证落盘的 master.key 采用 AGTMK01\0 信封加密而非裸 32 字节
        let mk_bytes = fs::read(storage.master_key_path()).expect("read master.key");
        assert!(mk_bytes.starts_with(MASTER_KEY_SEAL_MAGIC));
        assert_ne!(mk_bytes.len(), MASTER_KEY_LEN);

        // 模拟旧版 32 字节裸 master.key 升级迁移
        let dir2 = tempfile::tempdir().expect("create tempdir 2");
        let legacy_raw_key = [0x42u8; MASTER_KEY_LEN];
        fs::write(dir2.path().join("master.key"), legacy_raw_key).expect("write legacy key");
        let storage2 = EncryptedStorage::new_in_dir(dir2.path()).expect("init storage2");
        storage2
            .save_hosts(std::slice::from_ref(&host))
            .expect("save with migrated key");
        let upgraded_bytes = fs::read(storage2.master_key_path()).expect("read upgraded key");
        assert!(
            upgraded_bytes.starts_with(MASTER_KEY_SEAL_MAGIC),
            "legacy raw 32-byte master.key should be automatically upgraded to sealed envelope"
        );
        let loaded = storage2.load_hosts().expect("load after migration");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, host.id);
    }

    #[test]
    fn test_concurrent_save_hosts_and_case_collision_key_isolation() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let storage = EncryptedStorage::new_in_dir(dir.path()).expect("init storage");

        // 1. 验证大小写仅存差异的两个代号拥有独立密钥路径，互不覆盖或误删
        let mut host_upper = RelayHost::new_template(0);
        host_upper.codename = "Node-Collision".to_string();
        let mut host_lower = RelayHost::new_template(1);
        host_lower.codename = "node-collision".to_string();

        let (path_upper, pub_upper) = storage
            .ensure_dedicated_agent_key(&mut host_upper, false)
            .expect("key upper");
        let (path_lower, pub_lower) = storage
            .ensure_dedicated_agent_key(&mut host_lower, false)
            .expect("key lower");
        assert_ne!(path_upper, path_lower);
        assert_ne!(pub_upper, pub_lower);
        storage.remove_dedicated_key_file(&host_upper.id, &host_upper.codename);
        assert!(!path_upper.exists());
        assert!(
            path_lower.exists(),
            "removing upper-case host key must not delete lower-case host key on case-insensitive FS"
        );

        // 2. 验证多线程并发调用 save_hosts 时不会发生临时文件冲突或损坏仓库
        let mut handles = Vec::new();
        for i in 0..8 {
            let st = storage.clone();
            handles.push(std::thread::spawn(move || {
                let mut h = RelayHost::new_template(i);
                h.codename = format!("concurrent-node-{:02}", i);
                st.save_hosts(&[h]).expect("concurrent save_hosts");
            }));
        }
        for h in handles {
            h.join().expect("join thread");
        }
        let final_hosts = storage.load_hosts().expect("load after concurrent writes");
        assert_eq!(final_hosts.len(), 1);
    }
}
