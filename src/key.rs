use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::{CREDENTIAL_SEED_LEN, ServerIdentity};

const LEGACY_CREDENTIAL_SECRET_LEN: usize = 32;
const CREDENTIAL_MIGRATION_DOMAIN: &[u8] = b"\0etcat credential seed migration v2\0";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SavedKey {
    Server(SavedServerKey),
    Client(SavedClientKey),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedServerKey {
    pub identity: ServerIdentity,
    pub credential_secret: String,
    pub relay_id: String,
    #[serde(default)]
    pub fixed_relay: bool,
    pub gateway_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedClientKey {
    pub private_key: String,
}

pub fn key_dir() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("dev", "EasyTier", "etcat")
        .context("the operating system has no user configuration directory")?;
    Ok(dirs.config_dir().join("keys"))
}

pub fn named_key_path(name: &str) -> Result<PathBuf> {
    validate_key_name(name)?;
    Ok(key_dir()?.join(format!("{name}.private.json")))
}

pub fn validate_key_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        anyhow::bail!("key name must contain only ASCII letters, digits, '-' or '_'")
    }
    Ok(())
}

pub fn is_explicit_path(name: &str) -> bool {
    Path::new(name).components().count() > 1
}

pub fn key_path(name: &str) -> Result<PathBuf> {
    if is_explicit_path(name) {
        Ok(PathBuf::from(name))
    } else {
        named_key_path(name)
    }
}

pub fn load(name: &str) -> Result<SavedKey> {
    let path = key_path(name)?;
    let bytes =
        fs::read(&path).with_context(|| format!("failed to read key {}", path.display()))?;
    let mut key: SavedKey = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse key {}", path.display()))?;
    if let SavedKey::Server(server) = &mut key {
        server.credential_secret = normalize_credential_secret(&server.credential_secret)
            .with_context(|| format!("invalid server key {}", path.display()))?;
    }
    Ok(key)
}

fn normalize_credential_secret(secret: &str) -> Result<String> {
    let bytes = STANDARD
        .decode(secret)
        .context("credential secret is not valid base64")?;
    match bytes.len() {
        CREDENTIAL_SEED_LEN => Ok(STANDARD.encode(bytes)),
        LEGACY_CREDENTIAL_SECRET_LEN => {
            let mut hasher = Sha256::new();
            hasher.update(CREDENTIAL_MIGRATION_DOMAIN);
            hasher.update(bytes);
            Ok(STANDARD.encode(&hasher.finalize()[..CREDENTIAL_SEED_LEN]))
        }
        length => anyhow::bail!(
            "credential secret must contain {CREDENTIAL_SEED_LEN} bytes, or \
             {LEGACY_CREDENTIAL_SECRET_LEN} bytes for migration; found {length}"
        ),
    }
}

pub fn save(name: &str, key: &SavedKey, force: bool) -> Result<PathBuf> {
    let path = key_path(name)?;
    if path.exists() && !force {
        anyhow::bail!(
            "{} already exists; use --force to replace it",
            path.display()
        );
    }
    let parent = path.parent().context("key path has no parent directory")?;
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    let temporary = parent.join(format!(".etcat-key-{}.tmp", uuid::Uuid::new_v4()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("failed to create {}", temporary.display()))?;
    let bytes = serde_json::to_vec_pretty(key)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    if force && path.exists() {
        fs::remove_file(&path)?;
    }
    fs::rename(&temporary, &path)?;
    Ok(path)
}

pub fn delete(name: &str) -> Result<()> {
    if is_explicit_path(name) {
        anyhow::bail!("refusing to delete an explicit key path")
    }
    let path = named_key_path(name)?;
    fs::remove_file(&path).with_context(|| format!("failed to delete {}", path.display()))
}

pub fn list() -> Result<Vec<String>> {
    let directory = key_dir()?;
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut names = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_suffix(".private.json"))
                .map(ToOwned::to_owned)
        })
        .collect::<Vec<_>>();
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_names_without_path_traversal() {
        assert!(validate_key_name("client-default_2").is_ok());
        assert!(validate_key_name("../secret").is_err());
        assert!(validate_key_name("").is_err());
    }

    #[test]
    fn migrates_legacy_credential_secrets_deterministically() {
        let current = STANDARD.encode([7_u8; CREDENTIAL_SEED_LEN]);
        assert_eq!(normalize_credential_secret(&current).unwrap(), current);

        let legacy = STANDARD.encode([7_u8; LEGACY_CREDENTIAL_SECRET_LEN]);
        let migrated = normalize_credential_secret(&legacy).unwrap();
        assert_eq!(
            migrated, "ad4hp7Ygwq+BTF42cRUhPg==",
            "changing this value invalidates migrated persistent credentials"
        );
        assert_eq!(
            STANDARD.decode(migrated).unwrap().len(),
            CREDENTIAL_SEED_LEN
        );
        assert!(normalize_credential_secret(&STANDARD.encode([0_u8; 15])).is_err());
    }

    #[test]
    fn load_normalizes_a_legacy_server_key() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("legacy.private.json");
        let key = SavedKey::Server(SavedServerKey {
            identity: ServerIdentity::generate(),
            credential_secret: STANDARD.encode([9_u8; LEGACY_CREDENTIAL_SECRET_LEN]),
            relay_id: "test".to_owned(),
            fixed_relay: false,
            gateway_port: 49_152,
        });
        save(path.to_str().unwrap(), &key, false).unwrap();

        let SavedKey::Server(loaded) = load(path.to_str().unwrap()).unwrap() else {
            panic!("expected a server key")
        };
        assert_eq!(
            STANDARD.decode(loaded.credential_secret).unwrap().len(),
            CREDENTIAL_SEED_LEN
        );
    }
}
