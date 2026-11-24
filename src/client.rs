//! Connect-protocol client for Bytebase's v1 API.
//!
//! Bytebase serves all v1 services as Connect handlers on the main HTTP port
//! (`backend/server/grpc_routes.go`): one endpoint speaks Connect JSON, gRPC,
//! and gRPC-Web. This client uses the Connect JSON form — a plain
//! `POST {server}/bytebase.v1.{Service}/{Method}` with a protojson body — so
//! no MCP session, no JSON-RPC envelope, one round trip per command.
//!
//! Refreshes run under the token file's exclusive lock, held across the
//! whole read-refresh-write sequence (see `store::edit_tokens`), which is
//! what lets concurrent bbcli processes share one credential despite the
//! server's single-use refresh-token rotation. The connect auth interceptor
//! accepts both `bb.user.access` and `bb.oauth2.access` audiences.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::oauth::OAuth2Client;
use crate::store::{self, Credentials, Grant};

/// Refresh this early before the access token's `exp` to avoid a 401 round
/// trip on the API call.
const REFRESH_MARGIN_SECS: i64 = 120;

pub struct ApiClient {
    oauth: OAuth2Client,
    /// HTTP client for API calls, shared with the OAuth endpoints (cloning
    /// a reqwest client is cheap — it shares the connection pool). It carries
    /// a connect timeout but no response deadline of its own.
    http: reqwest::Client,
    /// Optional deadline for a whole API call. Unset by default: SQL queries
    /// and rollouts can legitimately run for minutes, and a default that cuts
    /// them off would be worse than waiting. Unattended agents that need a
    /// bounded run set one explicitly (`--timeout`, `BBCLI_TIMEOUT`).
    timeout: Option<std::time::Duration>,
    /// Where the server came from (`--context flag`, `env BBCLI_SERVER`, a
    /// `.bbcli` file, the default context). Only used for the attribution
    /// line, but it lives here so every call site formats that line the same
    /// way instead of re-threading the provenance through each command.
    source: String,
    creds: Mutex<Credentials>,
}

impl ApiClient {
    /// Loads credentials for `server` from the shared token file. `source`
    /// names where the server came from, for the per-call attribution line.
    pub fn load(
        server: &str,
        source: &str,
        insecure: bool,
        timeout_secs: Option<u64>,
    ) -> Result<Self> {
        let key = store::normalize(server);
        let creds = store::get(server)?
            .ok_or_else(|| anyhow!("not logged in to {key}; {}", store::login_hint(&key)))?;
        let oauth = OAuth2Client::new(server, insecure)?;
        Ok(Self {
            http: oauth.http.clone(),
            timeout: timeout_secs.map(std::time::Duration::from_secs),
            source: source.to_string(),
            oauth,
            creds: Mutex::new(creds),
        })
    }

    /// The resolved server base URL, without a trailing slash.
    pub fn server(&self) -> &str {
        &self.oauth.server
    }

    /// `call`, preceded by the attribution line on stderr.
    ///
    /// The target is implicit (flag, env, `.bbcli` file, or the default
    /// context), and a multi-step agent run has no other cheap way to confirm
    /// it hit the environment it meant to. Every command that reaches the
    /// server goes through here — including each hop of a friendly subcommand,
    /// so the `api` escape hatch stays learnable from the trace — and stdout
    /// stays pure JSON for piping.
    pub async fn call_announced(&self, method: &str, args: &Value) -> Result<Value> {
        self.announce(method);
        self.call(method, args).await
    }

    /// The attribution line for `method`, without the call. For a poll loop,
    /// which announces its method once rather than once per tick.
    pub fn announce(&self, method: &str) {
        eprintln!(
            "{method} -> {} (source: {})",
            self.oauth.server, self.source
        );
    }

    /// Calls `Service/Method` (or `bytebase.v1.Service/Method`) with the given
    /// protojson object; returns the response message as JSON.
    pub async fn call(&self, method: &str, args: &Value) -> Result<Value> {
        let path = method_path(method)?;
        self.ensure_fresh().await?;
        let mut resp = self.post(&path, args).await?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            self.refresh()
                .await
                .context("refreshing access token after 401")?;
            resp = self.post(&path, args).await?;
        }
        let status = resp.status();
        let body = resp
            .text()
            .await
            .context("failed to read API response body")?;
        if !status.is_success() {
            bail!("{}", connect_error(status, &path, &body));
        }
        if body.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&body).with_context(|| format!("failed to parse response from {path}"))
    }

    /// Seconds until the in-memory access token expires (negative once
    /// past); reflects any refresh this client already performed.
    pub async fn access_expires_in(&self) -> i64 {
        self.creds.lock().await.expires_at - store::unix_now()
    }

    async fn post(&self, path: &str, args: &Value) -> Result<reqwest::Response> {
        let token = self.creds.lock().await.access_token.clone();
        let mut req = self
            .http
            .post(format!("{}{path}", self.oauth.server))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            // Required by the Connect protocol for JSON requests.
            .header("connect-protocol-version", "1")
            .bearer_auth(token)
            .body(serde_json::to_string(args)?);
        if let Some(t) = self.timeout {
            req = req.timeout(t);
        }
        req.send().await.map_err(|e| {
            // A client-side deadline says nothing about the server: the
            // statement or rollout may well still be running. Say so, or an
            // agent retries a change that already took effect.
            if e.is_timeout() {
                if let Some(t) = self.timeout {
                    return anyhow!(
                        "request to {path} exceeded the client timeout of {}s — \
                         the server may still be executing it; check its status \
                         before retrying",
                        t.as_secs()
                    );
                }
            }
            anyhow::Error::new(e).context(format!("request to {path} failed"))
        })
    }

    /// Refreshes the access token if it is within the expiry margin.
    async fn ensure_fresh(&self) -> Result<()> {
        let mut creds = self.creds.lock().await;
        if creds.expires_at - store::unix_now() < REFRESH_MARGIN_SECS {
            self.refresh_locked(&mut creds, false).await?;
        }
        Ok(())
    }

    /// Force-refreshes after a 401. Unlike the proactive path, local expiry
    /// is not consulted: a 401 means the access token is invalid regardless
    /// of its remaining lifetime (server secret rotation, revoked grant, ...).
    async fn refresh(&self) -> Result<()> {
        let mut creds = self.creds.lock().await;
        self.refresh_locked(&mut creds, true).await
    }

    /// The read-refresh-write sequence runs under the token file's exclusive
    /// lock, so concurrent bbcli processes serialize here: the loser blocks
    /// until the winner's rotation is durable, adopts the rotated token, and
    /// skips its own network refresh instead of burning the now-dead one.
    /// Lock order is always memory lock -> file lock, matching `login`'s
    /// writer. A service account has no rotation to race, but renewing under
    /// the same lock still means a successful re-login is shared: processes
    /// queued behind it adopt the new token instead of each logging in. A
    /// failed one is not shared — the file is unchanged, so the next process
    /// tries the same key again.
    async fn refresh_locked(&self, creds: &mut Credentials, force: bool) -> Result<()> {
        let key = self.oauth.server.clone();
        store::edit_tokens(move |mut tf| async move {
            if let Some(stored) = tf.servers.get(&key) {
                *creds = stored.clone();
            }
            if !force && creds.expires_at - store::unix_now() >= REFRESH_MARGIN_SECS {
                return Ok((tf, ())); // adopted token is fresh; file unchanged
            }
            let fresh = match &creds.grant {
                Grant::OAuth {
                    client_id,
                    refresh_token,
                    ..
                } => self.oauth.refresh(client_id, refresh_token).await?,
                Grant::ServiceAccount {
                    service_account,
                    service_key,
                } => service_account_login(&self.http, &key, service_account, service_key).await?,
            };
            tf.servers.insert(key, fresh.clone());
            *creds = fresh;
            Ok((tf, ()))
        })
        .await
    }
}

/// Exchanges a service account's key for an access token through
/// `AuthService/Login` — the same call the Bytebase UI makes, with the key in
/// the password field and `web: false` so the token comes back in the body
/// rather than as a cookie. The key never appears in an error: on failure
/// only the server's Connect error is surfaced.
pub async fn service_account_login(
    http: &reqwest::Client,
    server: &str,
    email: &str,
    key: &str,
) -> Result<Credentials> {
    const PATH: &str = "/bytebase.v1.AuthService/Login";
    let resp = http
        .post(format!("{server}{PATH}"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("connect-protocol-version", "1")
        // A login is a short request/response even when API calls on the
        // same client may run for minutes.
        .timeout(std::time::Duration::from_secs(30))
        .body(serde_json::to_string(
            &serde_json::json!({"email": email, "password": key, "web": false}),
        )?)
        .send()
        .await
        .with_context(|| format!("service account login for {email} failed"))?;
    let status = resp.status();
    let body = resp.text().await.context("failed to read login response")?;
    if !status.is_success() {
        bail!(
            "service account login for {email} failed: {}",
            connect_error_with(status, PATH, &body, service_account_hint)
        );
    }
    let v: Value = serde_json::from_str(&body).context("failed to parse login response")?;
    let Some(token) = v
        .get("token")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
    else {
        // Service accounts skip MFA server-side, so an empty token means the
        // email named an ordinary user, not a service account.
        bail!(
            "login for {email} returned no token — is it a service account? \
             Ordinary users log in with `bbcli login` (browser)"
        );
    };
    let now = store::unix_now();
    Ok(Credentials {
        access_token: token.to_string(),
        // The response carries no lifetime; the JWT's own `exp` is exact.
        // Bytebase issues service-account tokens for 1 hour
        // (`backend/api/auth/auth.go: apiTokenDuration`), the fallback should
        // the token ever stop being a readable JWT; a wrong guess only costs
        // a 401 and a re-login.
        expires_at: jwt_exp(token).unwrap_or(now + 3600),
        grant: Grant::ServiceAccount {
            service_account: email.to_string(),
            service_key: key.to_string(),
        },
    })
}

/// The `exp` claim of a JWT, read without verifying the signature — bbcli
/// only uses it to schedule renewal, never to trust the token.
fn jwt_exp(token: &str) -> Option<i64> {
    use base64::Engine;
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    serde_json::from_slice::<Value>(&bytes)
        .ok()?
        .get("exp")?
        .as_i64()
}

/// Renders a Connect error body into one actionable line.
///
/// A Connect error is `{"code": "permission_denied", "message": "...",
/// "details": [...]}`. Keeping only `message` throws away the two parts that
/// decide what to do next: `code` says whether to re-authenticate, fix the
/// request, or request access, and `details` names the resource that was
/// refused. Both are preserved here so the caller does not have to infer
/// intent from prose.
fn connect_error(status: reqwest::StatusCode, path: &str, body: &str) -> String {
    connect_error_with(status, path, body, recovery_hint)
}

/// `connect_error` with the hint table swapped. Used where the generic hint
/// would send the reader to the wrong fix.
fn connect_error_with(
    status: reqwest::StatusCode,
    path: &str,
    body: &str,
    hint: fn(Option<&str>) -> Option<&'static str>,
) -> String {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        // Not a Connect body at all (proxy HTML, empty 502, ...).
        let body = body.trim();
        return if body.is_empty() {
            format!("HTTP {status} from {path} (empty body)")
        } else {
            format!("HTTP {status} from {path}: {body}")
        };
    };
    let code = v.get("code").and_then(Value::as_str);
    let message = v
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("(no message)");
    let mut out = match code {
        Some(code) => format!("HTTP {status} from {path} [{code}]: {message}"),
        None => format!("HTTP {status} from {path}: {message}"),
    };
    if let Some(details) = v.get("details").filter(|d| !d.is_null()) {
        out.push_str(&format!("\n  details: {details}"));
    }
    if let Some(hint) = hint(code) {
        out.push_str(&format!("\n  {hint}"));
    }
    out
}

/// Maps a Connect code to the one action that resolves it, so a caller does
/// not retry a call that can never succeed as written.
fn recovery_hint(code: Option<&str>) -> Option<&'static str> {
    Some(match code? {
        "unauthenticated" => "credentials are not usable: run `bbcli login` again",
        "permission_denied" => {
            "the account lacks the required role: see `bbcli skill grant-permission`"
        }
        "not_found" => "the resource name does not exist — check its format with `bbcli search`",
        "invalid_argument" => {
            "the request fields are wrong: re-check with `bbcli search --operation-id <S/M>`"
        }
        "unimplemented" => {
            "this server does not serve that method; the embedded catalog may be newer or older \
             than the server (see `bbcli --version`)"
        }
        "deadline_exceeded" | "unavailable" => "transient server-side failure: retrying may work",
        _ => return None,
    })
}

/// Hints for a failed service-account login. The generic `unauthenticated`
/// hint says "run `bbcli login`", which here would be a trap: a browser login
/// stores the person's own credentials under the same server URL, silently
/// replacing the restricted identity with a broad one.
fn service_account_hint(code: Option<&str>) -> Option<&'static str> {
    match code {
        Some("unauthenticated") => Some(
            "the service key was rejected (rotated, or the account deleted): re-run \
             `bbcli login --service-account <email>` with a current key — not a browser login, \
             which would replace this identity with your own",
        ),
        Some("resource_exhausted") => Some(
            "too many failed logins for this account: wait for the lockout to pass, then log in \
             with a current key",
        ),
        _ => recovery_hint(code),
    }
}

/// Splits a method reference into (service, method), accepting
/// `Service/Method`, `Service.Method`, or the fully qualified
/// `bytebase.v1.Service/Method`.
pub fn parse_method(method: &str) -> Result<(&str, &str)> {
    let s = method.trim().trim_start_matches('/');
    let s = s.strip_prefix("bytebase.v1.").unwrap_or(s);
    let (service, m) = s.split_once(['/', '.']).ok_or_else(|| method_err(method))?;
    if service.is_empty() || m.is_empty() || m.contains(['/', '.']) {
        bail!("{}", method_err(method));
    }
    Ok((service, m))
}

/// Turns `SQLService/Query` (or `bytebase.v1.SQLService/Query`) into the
/// Connect path `/bytebase.v1.SQLService/Query`.
fn method_path(method: &str) -> Result<String> {
    let (service, m) = parse_method(method)?;
    Ok(format!("/bytebase.v1.{service}/{m}"))
}

fn method_err(method: &str) -> anyhow::Error {
    anyhow!("method must look like Service/Method, e.g. SQLService/Query (got {method:?})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renewal_is_scheduled_from_the_tokens_own_expiry() {
        use base64::Engine;
        let enc = |v: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
        let jwt = format!(
            "{}.{}.sig",
            enc(r#"{"alg":"HS256"}"#),
            enc(r#"{"exp":1700000000}"#)
        );
        assert_eq!(jwt_exp(&jwt), Some(1_700_000_000));
        // Not a JWT: no guess here — the caller falls back to the documented
        // lifetime instead.
        assert_eq!(jwt_exp("opaque-token"), None);
    }

    #[test]
    fn a_rejected_service_key_never_points_at_a_browser_login() {
        let body = r#"{"code": "unauthenticated", "message": "invalid email or password"}"#;
        let msg = connect_error_with(
            reqwest::StatusCode::UNAUTHORIZED,
            "/p",
            body,
            service_account_hint,
        );
        assert!(msg.contains("--service-account"), "{msg}");
        assert!(!msg.contains("run `bbcli login` again"), "{msg}");
    }

    #[test]
    fn method_path_forms() {
        assert_eq!(
            method_path("SQLService/Query").unwrap(),
            "/bytebase.v1.SQLService/Query"
        );
        assert_eq!(
            method_path("bytebase.v1.SQLService/Query").unwrap(),
            "/bytebase.v1.SQLService/Query"
        );
        assert_eq!(
            method_path(" /SQLService/Query ").unwrap(),
            "/bytebase.v1.SQLService/Query"
        );
        // The dot-separated form search prints for operationIds works too.
        assert_eq!(
            method_path("SQLService.Query").unwrap(),
            "/bytebase.v1.SQLService/Query"
        );
        assert!(method_path("SQLService").is_err());
        assert!(method_path("a/b/c").is_err());
        assert!(method_path("a.b.c").is_err());
    }
}
