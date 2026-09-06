//! OAuth2 client for the Bytebase authorization server (`/api/oauth2`).
//!
//! Flow (matches `backend/api/oauth2`):
//!  1. RFC 7591 dynamic client registration as a public client
//!     (`token_endpoint_auth_method: none`).
//!  2. Authorization-code + PKCE (S256) via the system browser, with the
//!     redirect served by a loopback listener.
//!  3. Token exchange / refresh as `application/x-www-form-urlencoded` form
//!     posts carrying `client_id` (no secret, public client).

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::store::Credentials;

/// Refresh tokens are server-issued with a 30-day lifetime
/// (`backend/api/oauth2/oauth2.go: refreshTokenExpiry`), but the token
/// response does not carry it, so the expiry is tracked locally as an
/// estimate from issue time.
const REFRESH_TOKEN_LIFETIME_SECS: i64 = 30 * 24 * 3600;

/// Per-request timeout for the OAuth endpoints: short request/response
/// calls, unlike API calls that may run for minutes on the same client.
const OAUTH_TIMEOUT: Duration = Duration::from_secs(30);

pub struct OAuth2Client {
    /// HTTP client for the OAuth2 endpoints. No total timeout is set on the
    /// client — the same client is shared with API calls when this struct is
    /// embedded in an `ApiClient` — so each OAuth call sets its own.
    pub http: reqwest::Client,
    /// Server base URL, normalized (no trailing slash).
    pub server: String,
}

impl OAuth2Client {
    pub fn new(server: &str, insecure: bool) -> Result<Self> {
        // Fail fast on a server URL no HTTP client could use.
        reqwest::Url::parse(&crate::store::normalize(server))
            .with_context(|| format!("invalid server URL {server:?}"))?;
        let mut builder = reqwest::Client::builder().connect_timeout(Duration::from_secs(10));
        if insecure {
            builder = builder.danger_accept_invalid_certs(true);
        }
        Ok(Self {
            http: builder.build().context("failed to build HTTP client")?,
            server: crate::store::normalize(server),
        })
    }

    /// RFC 7591 dynamic client registration. Returns the assigned client_id.
    pub async fn register(&self, redirect_uri: &str) -> Result<String> {
        #[derive(serde::Serialize)]
        struct Req {
            client_name: &'static str,
            redirect_uris: Vec<String>,
            grant_types: Vec<&'static str>,
            token_endpoint_auth_method: &'static str,
        }
        #[derive(Deserialize)]
        struct Resp {
            client_id: String,
        }
        let resp = self
            .http
            .post(format!("{}/api/oauth2/register", self.server))
            .timeout(OAUTH_TIMEOUT)
            .json(&Req {
                client_name: "bbcli",
                redirect_uris: vec![redirect_uri.to_string()],
                grant_types: vec!["authorization_code", "refresh_token"],
                token_endpoint_auth_method: "none",
            })
            .send()
            .await
            .context("registration request failed")?;
        let resp = check(resp).await.context("client registration failed")?;
        let resp: Resp = resp
            .json()
            .await
            .context("failed to parse registration response")?;
        Ok(resp.client_id)
    }

    pub fn authorize_url(
        &self,
        client_id: &str,
        redirect_uri: &str,
        state: &str,
        code_challenge: &str,
    ) -> String {
        // Server URL was validated at construction, so parsing cannot fail.
        reqwest::Url::parse_with_params(
            &format!("{}/api/oauth2/authorize", self.server),
            &[
                ("response_type", "code"),
                ("client_id", client_id),
                ("redirect_uri", redirect_uri),
                ("state", state),
                ("code_challenge", code_challenge),
                ("code_challenge_method", "S256"),
            ],
        )
        .expect("server URL validated at construction")
        .to_string()
    }

    pub async fn exchange_code(
        &self,
        client_id: &str,
        redirect_uri: &str,
        code: &str,
        code_verifier: &str,
    ) -> Result<Credentials> {
        self.token_request(
            client_id,
            None,
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("code_verifier", code_verifier),
            ],
        )
        .await
    }

    /// Exchanges the (single-use) refresh token for a fresh token pair. On
    /// `invalid_grant` the only recovery is a new `login`.
    pub async fn refresh(&self, creds: &Credentials) -> Result<Credentials> {
        self.token_request(
            &creds.client_id,
            Some(&creds.refresh_token),
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", creds.refresh_token.as_str()),
            ],
        )
        .await
    }

    pub async fn revoke(&self, creds: &Credentials) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/api/oauth2/revoke", self.server))
            .timeout(OAUTH_TIMEOUT)
            .form(&[
                ("token", creds.refresh_token.as_str()),
                ("client_id", creds.client_id.as_str()),
            ])
            .send()
            .await
            .context("revoke request failed")?;
        check(resp).await.context("revoke failed")?;
        Ok(())
    }

    async fn token_request(
        &self,
        client_id: &str,
        // The server rotates refresh tokens on every use; keeping the old
        // one as a fallback only matters if a future server stops rotating.
        prev_refresh: Option<&str>,
        params: &[(&str, &str)],
    ) -> Result<Credentials> {
        #[derive(Deserialize)]
        struct Resp {
            access_token: String,
            expires_in: i64,
            #[serde(default)]
            refresh_token: Option<String>,
        }
        let mut form = vec![("client_id", client_id)];
        form.extend_from_slice(params);
        let resp = self
            .http
            .post(format!("{}/api/oauth2/token", self.server))
            .timeout(OAUTH_TIMEOUT)
            .form(&form)
            .send()
            .await
            .context("token request failed")?;
        let resp = check(resp)
            .await
            .context("token endpoint rejected the request")?;
        let r: Resp = resp
            .json()
            .await
            .context("failed to parse token response")?;

        let refresh_token = r
            .refresh_token
            .or_else(|| prev_refresh.map(str::to_string))
            .ok_or_else(|| anyhow!("token response carried no refresh token"))?;
        let now = crate::store::unix_now();
        Ok(Credentials {
            client_id: client_id.to_string(),
            access_token: r.access_token,
            refresh_token,
            expires_at: now + r.expires_in,
            refresh_expires_at: now + REFRESH_TOKEN_LIFETIME_SECS,
        })
    }
}

/// Returns `Err` with the status and body on non-2xx, so OAuth error payloads
/// (`{"error": ..., "error_description": ...}`) reach the user verbatim.
async fn check(resp: reqwest::Response) -> Result<reqwest::Response> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let body = resp.text().await.unwrap_or_default();
    bail!("HTTP {status}: {body}");
}

/// Generates a PKCE code_verifier / code_challenge (S256) pair.
pub fn pkce_pair() -> (String, String) {
    // 48 random bytes -> 64 base64url chars, within RFC 7636's 43..=128.
    let verifier = random_token(48);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

pub fn random_token(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    rand::rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// Waits for the OAuth2 redirect on a loopback listener and returns the
/// authorization code. Non-callback requests get a 404; error redirects and
/// state mismatches abort the login.
/// Waits for the authorization code, from whichever arrives first: the
/// loopback callback, or a redirect URL pasted on stdin.
///
/// The two paths exist because the browser is not always on this machine.
/// When it is, the callback lands on the listener and nothing is typed. When
/// it is not — an agent on a remote box, a container, a machine reached over
/// SSH — the browser redirects to `127.0.0.1:{port}` *there*, fails to
/// connect, and leaves the code in the address bar; pasting that URL back
/// completes the same exchange. Racing them means one `bbcli login` covers
/// both without the user having to declare which situation they are in.
///
/// Pasting is not a weaker flow: the PKCE verifier never leaves this process,
/// so the code alone cannot be redeemed, and `state` is checked identically
/// on both paths.
pub async fn wait_for_code(
    listener: TcpListener,
    expected_state: &str,
    redirect_uri: &str,
) -> Result<String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(600);
    // Reading stdin blocks, and in the common case — the browser is right
    // here, the callback arrives on the socket — nobody ever types a line, so
    // that read never returns. It therefore runs on a *detached* thread the
    // runtime does not track: `spawn_blocking` would be tidier, but dropping
    // the runtime waits for blocking tasks, and a task parked forever on
    // stdin would hang every successful login at exit. A detached thread is
    // simply abandoned when the process leaves.
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let _ = tx.send(read_pasted_line());
    });
    // Taken once it resolves: a oneshot receiver must not be polled again,
    // and after stdin is spent the listener is the only remaining source.
    let mut rx = Some(rx);
    loop {
        tokio::select! {
            received = async {
                match rx.as_mut() {
                    Some(rx) => rx.await,
                    None => std::future::pending().await,
                }
            } => {
                rx = None;
                let line = match received {
                    // Sender dropped without a value: stdin is unusable.
                    Err(_) => continue,
                    Ok(result) => result.context("failed to read the pasted URL")?,
                };
                let Some(line) = line else {
                    continue; // stdin closed; the callback is still coming
                };
                let params = parse_pasted(&line, redirect_uri)?;
                return match classify(&params, expected_state) {
                    Callback::Code(code) => Ok(code),
                    other => Err(other.into_error()),
                };
            }
            accepted = tokio::time::timeout_at(deadline, listener.accept()) => {
                let (mut stream, _) = accepted
                    .map_err(|_| anyhow!("timed out waiting for the authorization code"))??;

                let head = match read_http_head(&mut stream).await {
                    Ok(head) => head,
                    Err(_) => {
                        let _ = respond(&mut stream, "400 Bad Request", "Bad request", "").await;
                        continue;
                    }
                };
                // Request line "GET /callback?... HTTP/1.1": parse the target as an
                // absolute URL (the host is irrelevant) to get form-decoded pairs.
                let target = head
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default();
                let Ok(url) = reqwest::Url::parse(&format!("http://localhost{target}")) else {
                    let _ = respond(&mut stream, "400 Bad Request", "Bad request", "").await;
                    continue;
                };
                if url.path() != "/callback" {
                    let _ = respond(&mut stream, "404 Not Found", "Not found", "").await;
                    continue;
                }
                let params: HashMap<String, String> = url.query_pairs().into_owned().collect();

                return match classify(&params, expected_state) {
                    Callback::Code(code) => {
                        let _ = respond(
                            &mut stream,
                            "200 OK",
                            "Logged in",
                            "You can close this tab and return to the terminal.",
                        )
                        .await;
                        Ok(code)
                    }
                    Callback::Failed(err) => {
                        let _ = respond(&mut stream, "200 OK", "Authorization failed", &err).await;
                        Err(Callback::Failed(err).into_error())
                    }
                    Callback::StateMismatch => {
                        let _ = respond(&mut stream, "400 Bad Request", "State mismatch", "").await;
                        Err(Callback::StateMismatch.into_error())
                    }
                    Callback::MissingCode => {
                        let _ = respond(&mut stream, "400 Bad Request", "Missing code", "").await;
                        Err(Callback::MissingCode.into_error())
                    }
                };
            }
        }
    }
}

/// What the callback parameters turned out to be. Both the loopback listener
/// and the pasted URL run through this, so neither can drift into accepting
/// something the other rejects.
enum Callback {
    Code(String),
    /// The server refused: `error` (plus `error_description`).
    Failed(String),
    StateMismatch,
    MissingCode,
}

impl Callback {
    fn into_error(self) -> anyhow::Error {
        match self {
            Callback::Code(_) => anyhow!("not an error"),
            Callback::Failed(err) => anyhow!("authorization failed: {err}"),
            Callback::StateMismatch => anyhow!(
                "OAuth2 state mismatch — the pasted URL or callback belongs to a different \
                 login attempt; run `bbcli login` again and use the URL it prints"
            ),
            Callback::MissingCode => anyhow!("callback carried no authorization code"),
        }
    }
}

fn classify(params: &HashMap<String, String>, expected_state: &str) -> Callback {
    if let Some(err) = params.get("error") {
        let desc = params
            .get("error_description")
            .map(|d| format!(": {d}"))
            .unwrap_or_default();
        return Callback::Failed(format!("{err}{desc}"));
    }
    if params.get("state").map(String::as_str) != Some(expected_state) {
        return Callback::StateMismatch;
    }
    match params.get("code") {
        Some(code) => Callback::Code(code.clone()),
        None => Callback::MissingCode,
    }
}

/// Reads one line from stdin, or `None` at EOF.
fn read_pasted_line() -> Result<Option<String>> {
    use std::io::BufRead;
    let mut line = String::new();
    let n = std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("failed to read stdin")?;
    Ok((n > 0).then_some(line))
}

/// Turns a pasted redirect into callback parameters.
///
/// Accepts the whole URL from the address bar, or just its query string. A
/// bare code is rejected: without `state` there is nothing to bind the code
/// to this login attempt, and the whole URL is what the address bar holds
/// anyway — so asking for it costs the user nothing.
fn parse_pasted(line: &str, redirect_uri: &str) -> Result<HashMap<String, String>> {
    let text = line.trim();
    if text.is_empty() {
        bail!("no URL pasted");
    }
    let query = if let Ok(url) = reqwest::Url::parse(text) {
        url.query().unwrap_or_default().to_string()
    } else {
        text.trim_start_matches(['?', '&']).to_string()
    };
    let params: HashMap<String, String> =
        reqwest::Url::parse(&format!("http://localhost/?{query}"))
            .map(|u| u.query_pairs().into_owned().collect())
            .unwrap_or_default();
    // A bare code parses as a single valueless key, not an empty map, so
    // emptiness is not the test: the paste is only a redirect if it carries
    // the parameter the server actually sends back.
    if !params.contains_key("code") && !params.contains_key("error") {
        bail!(
            "pasted text is not a redirect URL. Copy the whole address the browser \
             failed to open — it looks like {redirect_uri}?code=...&state=... — not just the code"
        );
    }
    Ok(params)
}

/// Reads until the end of the HTTP request head (blank line). Only the head
/// is needed: the OAuth2 redirect is a GET with no body.
async fn read_http_head(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 64 * 1024 {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

async fn respond(stream: &mut TcpStream, status: &str, title: &str, body: &str) -> Result<()> {
    let html = format!(
        "<!DOCTYPE html><html><head><title>{title}</title></head>\
<body style=\"font-family:sans-serif;text-align:center;padding:3em\">\
<h2>{title}</h2><p>{body}</p></body></html>"
    );
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{html}",
        html.len()
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

pub fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let (program, args): (&str, Vec<&str>) = ("open", vec![url]);
    #[cfg(target_os = "windows")]
    let (program, args): (&str, Vec<&str>) = ("cmd", vec!["/c", "start", "", url]);
    #[cfg(all(unix, not(target_os = "macos")))]
    let (program, args): (&str, Vec<&str>) = ("xdg-open", vec![url]);
    let _ = std::process::Command::new(program).args(&args).spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    const REDIRECT: &str = "http://127.0.0.1:38123/callback";

    /// The address bar holds the whole URL, which is what we ask for.
    #[test]
    fn pasted_full_url_yields_code() {
        let params =
            parse_pasted(&format!("  {REDIRECT}?code=abc&state=xyz  \n"), REDIRECT).unwrap();
        match classify(&params, "xyz") {
            Callback::Code(code) => assert_eq!(code, "abc"),
            _ => panic!("expected a code"),
        }
    }

    /// Some users copy only the query part; accept it rather than fail on a
    /// difference that changes nothing about the checks that follow.
    #[test]
    fn pasted_bare_query_yields_code() {
        for text in ["?code=abc&state=xyz", "code=abc&state=xyz"] {
            let params = parse_pasted(text, REDIRECT).unwrap();
            match classify(&params, "xyz") {
                Callback::Code(code) => assert_eq!(code, "abc", "input {text:?}"),
                _ => panic!("expected a code for {text:?}"),
            }
        }
    }

    /// A bare code carries no `state`, so nothing binds it to this login
    /// attempt. Rejecting it is what keeps the pasted path as strong as the
    /// loopback one.
    #[test]
    fn pasted_bare_code_is_rejected() {
        let err = parse_pasted("4/0AeanS0abc", REDIRECT).unwrap_err().to_string();
        assert!(err.contains("not just the code"), "{err}");
    }

    /// Both paths run the same checks, so a mismatched state fails alike.
    #[test]
    fn pasted_state_mismatch_is_caught() {
        let params = parse_pasted(&format!("{REDIRECT}?code=abc&state=other"), REDIRECT).unwrap();
        assert!(matches!(
            classify(&params, "xyz"),
            Callback::StateMismatch
        ));
    }

    #[test]
    fn server_error_is_surfaced_with_its_description() {
        let params = parse_pasted(
            &format!("{REDIRECT}?error=access_denied&error_description=user+said+no"),
            REDIRECT,
        )
        .unwrap();
        let err = classify(&params, "xyz").into_error().to_string();
        assert!(err.contains("access_denied") && err.contains("user said no"), "{err}");
    }

    #[test]
    fn pkce_pair_shape() {
        let (verifier, challenge) = pkce_pair();
        assert!(
            (43..=128).contains(&verifier.len()),
            "verifier length {}",
            verifier.len()
        );
        assert_eq!(
            challenge,
            URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
        );
        // Deriving twice yields the same challenge; two draws differ.
        let (v2, c2) = pkce_pair();
        assert_ne!(verifier, v2);
        assert_ne!(challenge, c2);
    }

    #[test]
    fn authorize_url_encoding() {
        let client = OAuth2Client::new("https://bb.example.com/", false).unwrap();
        let url =
            client.authorize_url("bb_oauth_1", "http://127.0.0.1:1234/callback", "st", "ch%=");
        assert!(url.starts_with("https://bb.example.com/api/oauth2/authorize?"));
        assert!(url.contains("client_id=bb_oauth_1"));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A1234%2Fcallback"));
        assert!(url.contains("state=st"));
        assert!(url.contains("code_challenge=ch%25%3D"));
        assert!(url.contains("code_challenge_method=S256"));
    }

    #[test]
    fn rejects_unparsable_server_url() {
        assert!(OAuth2Client::new("not a url at all", false).is_err());
    }
}
