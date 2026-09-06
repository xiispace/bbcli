//! Split local storage, gcx-style:
//!
//! - `config.yaml` — non-secret configuration (named contexts, the active
//!   context). Safe to copy, diff, and edit by hand.
//! - `tokens.json` — OAuth2 credentials only, keyed by server URL, guarded
//!   by an advisory exclusive lock (`fd-lock`) and chmod 0600. The lock is
//!   what lets multiple concurrent bbcli processes share one credential
//!   despite the server's single-use refresh-token rotation: see
//!   [`edit_tokens`].

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::future::Future;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use fd_lock::RwLock;
use serde::{Deserialize, Serialize};

/// One server's credentials. Expiry fields are unix seconds. The refresh
/// expiry is a local estimate: the server issues 30-day refresh tokens but
/// does not return its lifetime in the token response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Credentials {
    pub client_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
    pub refresh_expires_at: i64,
}

/// `tokens.json` — credentials only.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct TokenFile {
    pub servers: HashMap<String, Credentials>,
}

/// Config schema version this bbcli writes; older files parse fine.
pub const CONFIG_VERSION: u32 = 1;

/// `config.yaml` — contexts and the active one. No secrets.
///
/// ```yaml
/// version: 1
/// current-context: prod
/// contexts:
///   prod:
///     server: https://bytebase.example.com
/// ```
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct ConfigFile {
    #[serde(default)]
    pub version: u32,
    /// Name of the active context; empty means no global default.
    #[serde(default, rename = "current-context")]
    pub current_context: String,
    /// Named contexts; each references credentials by server URL and never
    /// stores or copies them.
    #[serde(default)]
    pub contexts: HashMap<String, ServerContext>,
}

/// One named context entry.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct ServerContext {
    pub server: String,
}

/// Normalizes a server base URL for use as the storage key. The storage
/// functions call this themselves; callers only need it for display.
pub fn normalize(server: &str) -> String {
    server.trim().trim_end_matches('/').to_string()
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn token_path() -> PathBuf {
    if let Ok(p) = std::env::var("BBCLI_TOKEN_FILE") {
        return PathBuf::from(p);
    }
    config_dir().join("tokens.json")
}

pub fn config_path() -> PathBuf {
    if let Ok(p) = std::env::var("BBCLI_CONFIG") {
        return PathBuf::from(p);
    }
    token_path().with_file_name("config.yaml")
}

/// gcx-style location: `~/.config/bbcli` (or `$XDG_CONFIG_HOME/bbcli` when
/// set); non-Unix falls back to the OS config dir.
fn config_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("bbcli");
        }
    }
    if let Some(home) = dirs::home_dir() {
        return home.join(".config").join("bbcli");
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("bbcli")
}

/// Loads the token file; missing file yields an empty one.
pub fn load() -> Result<TokenFile> {
    let data = match std::fs::read_to_string(token_path()) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(TokenFile::default()),
        Err(e) => return Err(e).context("failed to read token file"),
    };
    if data.trim().is_empty() {
        return Ok(TokenFile::default());
    }
    serde_json::from_str(&data).context("failed to parse token file")
}

/// Loads config.yaml; missing file yields an empty one.
pub fn load_config() -> Result<ConfigFile> {
    let data = match std::fs::read_to_string(config_path()) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ConfigFile::default()),
        Err(e) => return Err(e).context("failed to read config.yaml"),
    };
    if data.trim().is_empty() {
        return Ok(ConfigFile::default());
    }
    let cfg: ConfigFile = serde_yaml::from_str(&data).context("failed to parse config.yaml")?;
    if cfg.version > CONFIG_VERSION {
        anyhow::bail!(
            "config.yaml version {} is newer than this bbcli supports ({CONFIG_VERSION})",
            cfg.version
        );
    }
    Ok(cfg)
}

/// Shared "how to log in" tail for errors about missing credentials, so the
/// flag name lives in exactly one place.
pub fn login_hint(server: &str) -> String {
    format!("run `bbcli login --context {server}` first")
}

/// Runs `f` against the token file under an exclusive lock and writes the
/// (possibly modified) file back. The in-place rewrite while holding the
/// lock — rather than an atomic rename — is deliberate: renaming would move
/// the file out from under other processes' locks.
pub fn with_lock<T>(f: impl FnOnce(&mut TokenFile) -> Result<T>) -> Result<T> {
    locked_edit(&token_path(), true, parse_tokens, render_tokens, f)
}

/// Same protocol for config.yaml (not secret, but still guarded so
/// concurrent logins can't clobber each other's contexts).
pub fn with_config_lock<T>(f: impl FnOnce(&mut ConfigFile) -> Result<T>) -> Result<T> {
    locked_edit(&config_path(), false, parse_config, render_config, |cfg| {
        cfg.version = CONFIG_VERSION;
        f(cfg)
    })
}

/// Token-file editing with the exclusive lock held across `.await`s inside
/// `f`. Holding the lock across the whole read-modify-write sequence is what
/// makes concurrent refreshes safe: a racing bbcli process blocks here until
/// the winner's rotation is durable, then adopts the rotated token instead
/// of burning the now-dead single-use refresh token. `f` takes the parsed
/// file by value and returns it (possibly modified); the file is written
/// back only when it actually changed.
pub async fn edit_tokens<T, F, Fut>(f: F) -> Result<T>
where
    F: FnOnce(TokenFile) -> Fut,
    Fut: Future<Output = Result<(TokenFile, T)>>,
{
    let path = token_path();
    let file = open_file(&path, true)?;
    let mut lock = RwLock::new(file);
    let mut guard = take_lock(&mut lock, &path)?;
    let original = read_locked(&mut guard, &path, parse_tokens)?;
    let (value, out) = f(original.clone()).await?;
    if value != original {
        write_locked(&mut guard, &path, &render_tokens(&value)?)?;
    }
    Ok(out)
}

/// Opens (creating if needed) `path` for locked read-modify-write.
fn open_file(path: &Path, secret: bool) -> Result<std::fs::File> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).context("failed to create config directory")?;
    }
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    if secret {
        restrict_permissions(&file)?;
    }
    Ok(file)
}

/// Takes the exclusive lock on an opened file. The guard is returned to the
/// caller (not held here) so long critical sections — including ones that
/// span `.await`s — can own it in their own frame.
fn take_lock<'a>(
    lock: &'a mut RwLock<std::fs::File>,
    path: &Path,
) -> Result<fd_lock::RwLockWriteGuard<'a, std::fs::File>> {
    lock.write()
        .map_err(|e| anyhow::anyhow!("failed to lock {}: {e}", path.display()))
}

/// Reads and parses the locked file; an empty file (freshly created) is the
/// default, anything unparsable is an error rather than a silent reset.
fn read_locked<T>(
    guard: &mut fd_lock::RwLockWriteGuard<std::fs::File>,
    path: &Path,
    parse: fn(&[u8]) -> Result<T>,
) -> Result<T>
where
    T: for<'de> Deserialize<'de> + Default,
{
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut &mut **guard, &mut buf)
        .with_context(|| format!("failed to read {}", path.display()))?;
    if buf.is_empty() {
        Ok(T::default())
    } else {
        parse(&buf).with_context(|| format!("failed to parse {}", path.display()))
    }
}

/// Rewrites the locked file in place (seek 0, write, truncate).
fn write_locked(
    guard: &mut fd_lock::RwLockWriteGuard<std::fs::File>,
    path: &Path,
    data: &[u8],
) -> Result<()> {
    guard
        .seek(SeekFrom::Start(0))
        .with_context(|| format!("failed to seek {}", path.display()))?;
    guard
        .write_all(data)
        .with_context(|| format!("failed to write {}", path.display()))?;
    guard
        .set_len(data.len() as u64)
        .with_context(|| format!("failed to truncate {}", path.display()))?;
    Ok(())
}

/// Open-lock-parse-run-write for one file. The lock guard lives in this
/// frame for the whole critical section; `f` runs strictly between the parse
/// and the write-back.
fn locked_edit<T, U>(
    path: &Path,
    secret: bool,
    parse: fn(&[u8]) -> Result<T>,
    render: fn(&T) -> Result<Vec<u8>>,
    f: impl FnOnce(&mut T) -> Result<U>,
) -> Result<U>
where
    T: for<'de> Deserialize<'de> + Default,
{
    let mut lock = RwLock::new(open_file(path, secret)?);
    let mut guard = take_lock(&mut lock, path)?;
    let mut value = read_locked(&mut guard, path, parse)?;
    let out = f(&mut value)?;
    write_locked(&mut guard, path, &render(&value)?)?;
    Ok(out)
}

fn parse_tokens(buf: &[u8]) -> Result<TokenFile> {
    serde_json::from_slice(buf).context("failed to parse token file")
}

fn parse_config(buf: &[u8]) -> Result<ConfigFile> {
    serde_yaml::from_slice(buf).context("failed to parse config.yaml")
}

fn render_tokens(tf: &TokenFile) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec_pretty(tf)?)
}

fn render_config(cfg: &ConfigFile) -> Result<Vec<u8>> {
    Ok((serde_yaml::to_string(cfg)?.trim_end().to_string() + "\n").into_bytes())
}

#[cfg(unix)]
fn restrict_permissions(file: &std::fs::File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .context("failed to restrict token file permissions to 0600")
}

#[cfg(not(unix))]
fn restrict_permissions(_file: &std::fs::File) -> Result<()> {
    Ok(())
}

/// Stores credentials for `server` (normalized here) and activates its
/// context. `alias` names the context; unnamed logins land on "default"
/// (gcx semantics; the most recent login replaces it).
pub fn save_credentials(server: &str, creds: &Credentials, alias: Option<&str>) -> Result<()> {
    let key = normalize(server);
    with_lock(|tf| {
        tf.servers.insert(key.clone(), creds.clone());
        Ok(())
    })?;
    let name = alias.unwrap_or("default").to_string();
    with_config_lock(|cfg| {
        cfg.contexts.insert(
            name.clone(),
            ServerContext {
                server: key.clone(),
            },
        );
        cfg.current_context = name;
        Ok(())
    })
}

/// Resolves a context name to its server URL; a plain URL passes through.
pub fn resolve_alias(name_or_url: &str) -> Result<String> {
    let s = name_or_url.trim();
    if s.is_empty() {
        anyhow::bail!("empty server name");
    }
    if let Some(ctx) = load_config()?.contexts.get(s) {
        return Ok(normalize(&ctx.server));
    }
    Ok(normalize(s))
}

/// The global default server from an already-loaded config: the active
/// context's target. `None` when no context is active.
pub fn default_server_from(cfg: &ConfigFile) -> Option<String> {
    cfg.contexts
        .get(&cfg.current_context)
        .map(|c| normalize(&c.server))
}

pub fn get(server: &str) -> Result<Option<Credentials>> {
    Ok(load()?.servers.get(&normalize(server)).cloned())
}

/// Removes credentials for `server` (normalized here) plus every context
/// pointing at it, so no context references missing credentials. Returns
/// the removed credentials, if any.
pub fn remove(server: &str) -> Result<Option<Credentials>> {
    let key = normalize(server);
    let removed = with_lock(|tf| Ok(tf.servers.remove(&key)))?;
    with_config_lock(|cfg| {
        cfg.contexts.retain(|_, c| normalize(&c.server) != key);
        if !cfg.contexts.contains_key(&cfg.current_context) {
            cfg.current_context = String::new();
        }
        Ok(())
    })?;
    Ok(removed)
}

/// Switches the default server. Accepts a context name (makes it active) or
/// a logged-in URL (activates a context pointing at it, creating "default"
/// if none exists).
pub fn set_default(name_or_url: &str) -> Result<String> {
    let s = name_or_url.trim();
    let tf = load()?;
    with_config_lock(|cfg| {
        if let Some(ctx) = cfg.contexts.get(s).cloned() {
            let url = normalize(&ctx.server);
            cfg.current_context = s.to_string();
            return Ok(url);
        }
        let key = normalize(s);
        if !tf.servers.contains_key(&key) {
            anyhow::bail!("no credentials for {key}; {}", login_hint(&key));
        }
        let name = cfg
            .contexts
            .iter()
            .find(|(_, c)| normalize(&c.server) == key)
            .map(|(name, _)| name.clone())
            .unwrap_or_else(|| "default".to_string());
        cfg.contexts.insert(
            name.clone(),
            ServerContext {
                server: key.clone(),
            },
        );
        cfg.current_context = name;
        Ok(key)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These tests mutate process-global BBCLI_TOKEN_FILE/BBCLI_CONFIG; run
    /// them serially so they don't read each other's files.
    static FILE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn creds(id: &str) -> Credentials {
        Credentials {
            client_id: id.to_string(),
            access_token: format!("at-{id}"),
            refresh_token: format!("rt-{id}"),
            expires_at: 1000,
            refresh_expires_at: 2000,
        }
    }

    #[test]
    fn roundtrip_and_locking() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "bbcli-test-{}-{}.json",
            std::process::id(),
            line!()
        ));
        // Take the lock BEFORE touching the env var: set_var outside the
        // lock races the other test's save_credentials.
        let lock = FILE_LOCK.lock().unwrap();
        std::env::set_var("BBCLI_TOKEN_FILE", &path);
        std::env::remove_var("BBCLI_CONFIG");
        let _guard = (PathGuard(path.clone()), lock);

        assert!(load().unwrap().servers.is_empty());

        // Keys normalize inside the store, trailing slash or not.
        save_credentials("https://a.example.com", &creds("a"), None).unwrap();
        save_credentials("https://b.example.com/", &creds("b"), None).unwrap();

        // Unnamed logins share the "default" context; the latest wins.
        let tf = load().unwrap();
        assert_eq!(tf.servers.len(), 2);
        assert_eq!(
            default_server_from(&load_config().unwrap()).as_deref(),
            Some("https://b.example.com")
        );
        assert_eq!(
            get("https://a.example.com").unwrap().unwrap().client_id,
            "a"
        );
        assert!(get("https://missing").unwrap().is_none());

        // tokens.json stays credential-only (no config state leaks into it).
        let raw = std::fs::read_to_string(token_path()).unwrap();
        assert!(!raw.contains("context"), "{raw}");
    }

    #[test]
    fn contexts_aliases_and_defaults() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "bbcli-test-{}-{}.json",
            std::process::id(),
            line!()
        ));
        // Take the lock BEFORE touching the env var: set_var outside the
        // lock races the other test's save_credentials.
        let lock = FILE_LOCK.lock().unwrap();
        std::env::set_var("BBCLI_TOKEN_FILE", &path);
        std::env::remove_var("BBCLI_CONFIG");
        let _guard = (PathGuard(path.clone()), lock);

        // Named logins make their context active.
        save_credentials("https://a.example.com", &creds("a"), Some("prod")).unwrap();
        save_credentials("https://b.example.com", &creds("b"), Some("staging")).unwrap();
        assert_eq!(
            default_server_from(&load_config().unwrap()).as_deref(),
            Some("https://b.example.com")
        );

        // Aliases resolve anywhere a server is accepted; URLs pass through.
        assert_eq!(resolve_alias("prod").unwrap(), "https://a.example.com");
        assert_eq!(resolve_alias("staging").unwrap(), "https://b.example.com");
        assert_eq!(
            resolve_alias("https://b.example.com/").unwrap(),
            "https://b.example.com"
        );

        // config use by name activates that context; by URL activates the
        // context pointing at it (creating "default" if none).
        assert_eq!(set_default("prod").unwrap(), "https://a.example.com");
        assert_eq!(
            default_server_from(&load_config().unwrap()).as_deref(),
            Some("https://a.example.com")
        );
        assert_eq!(
            set_default("https://b.example.com").unwrap(),
            "https://b.example.com"
        );
        assert_eq!(load_config().unwrap().current_context, "staging");

        // Logging out drops contexts pointing at the removed server.
        remove("https://b.example.com").unwrap();
        let cfg = load_config().unwrap();
        assert!(!cfg.contexts.contains_key("staging"));
        assert_eq!(
            cfg.contexts.get("prod").map(|c| c.server.as_str()),
            Some("https://a.example.com")
        );
        assert_eq!(cfg.current_context, "");

        // Unknown names in set_default fall through to URL validation.
        assert!(set_default("nosuch").is_err());

        // A corrupt token file errors out instead of silently resetting.
        std::fs::write(token_path(), "{not json").unwrap();
        assert!(load().is_err());
    }

    #[tokio::test]
    async fn edit_tokens_writes_only_on_change() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "bbcli-test-{}-{}.json",
            std::process::id(),
            line!()
        ));
        let lock = FILE_LOCK.lock().unwrap();
        std::env::set_var("BBCLI_TOKEN_FILE", &path);
        std::env::remove_var("BBCLI_CONFIG");
        let _guard = (PathGuard(path.clone()), lock);

        save_credentials("https://a.example.com", &creds("a"), None).unwrap();
        let before = std::fs::read_to_string(token_path()).unwrap();

        // Read-only use (the closure may await, e.g. a network refresh that
        // turns out unnecessary) leaves the file untouched.
        edit_tokens(|tf| async {
            let n = tf.servers.len();
            Ok((tf, n))
        })
        .await
        .unwrap();

        assert_eq!(std::fs::read_to_string(token_path()).unwrap(), before);

        // A mutating use writes back.
        edit_tokens(|mut tf| async {
            tf.servers.remove("https://a.example.com");
            Ok((tf, ()))
        })
        .await
        .unwrap();
        assert!(load().unwrap().servers.is_empty());
    }

    #[test]
    fn normalize_trims_trailing_slash() {
        assert_eq!(normalize(" https://x.com/ "), "https://x.com");
        assert_eq!(normalize("https://x.com//"), "https://x.com");
    }

    struct PathGuard(std::path::PathBuf);
    impl Drop for PathGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::remove_file(self.0.with_file_name("config.yaml"));
        }
    }
}
