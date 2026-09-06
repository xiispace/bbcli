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
use crate::store::{self, Credentials};

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
    creds: Mutex<Credentials>,
}

impl ApiClient {
    /// Loads credentials for `server` from the shared token file.
    pub fn load(server: &str, insecure: bool, timeout_secs: Option<u64>) -> Result<Self> {
        let key = store::normalize(server);
        let creds = store::get(server)?
            .ok_or_else(|| anyhow!("not logged in to {key}; {}", store::login_hint(&key)))?;
        let oauth = OAuth2Client::new(server, insecure)?;
        Ok(Self {
            http: oauth.http.clone(),
            timeout: timeout_secs.map(std::time::Duration::from_secs),
            oauth,
            creds: Mutex::new(creds),
        })
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
    /// writer.
    async fn refresh_locked(&self, creds: &mut Credentials, force: bool) -> Result<()> {
        let key = self.oauth.server.clone();
        store::edit_tokens(move |mut tf| async move {
            if let Some(stored) = tf.servers.get(&key) {
                *creds = stored.clone();
            }
            if !force && creds.expires_at - store::unix_now() >= REFRESH_MARGIN_SECS {
                return Ok((tf, ())); // adopted token is fresh; file unchanged
            }
            let fresh = self.oauth.refresh(creds).await?;
            tf.servers.insert(key, fresh.clone());
            *creds = fresh;
            Ok((tf, ()))
        })
        .await
    }
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
    if let Some(hint) = recovery_hint(code) {
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
