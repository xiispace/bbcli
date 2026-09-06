//! bbcli — CLI for a Bytebase server with OAuth2 auto-refresh.
//!
//! Calls the v1 API directly over the Connect JSON protocol (no MCP layer),
//! and ships an offline API catalog plus task guides embedded from the same
//! sources the MCP tools use. Designed to be driven by CLI agents (Claude
//! Code, ...) — pair with the agent skill in `skills/bytebase/SKILL.md`.

mod agent_skill;
mod change;
mod client;
mod oauth;
mod query;
mod resolve;
mod schema;
mod search;
mod store;

use anyhow::{anyhow, bail, Context, Result};
use clap::parser::ValueSource;
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use serde_json::Value;

use crate::client::ApiClient;
use crate::oauth::OAuth2Client;

/// Printed above every guide: the embedded guides were written for the MCP
/// tool syntax, so agents need the translation to bbcli commands.
const SKILL_SYNTAX_NOTE: &str = "\
Note: this guide uses MCP tool syntax. Equivalent bbcli commands:
  search_api(service=\"S\")                  -> bbcli search --service S
  search_api(operationId=\"S/M\")            -> bbcli search --operation-id S/M
  search_api(schema=\"T\")                   -> bbcli search --schema T
  call_api(operationId=\"S/M\", body={...})  -> bbcli api S/M --args '<same fields, as JSON>'
  query_database(database=, statement=, ...)
                                            -> bbcli query <database> '<statement>' \\
                                               [--instance I] [--project P] [--limit N]
  get_schema(database=, schema=, table=, include=)
                                            -> bbcli schema <database> [--schema S] [--table T] \\
                                               [--include summary|columns|details]
  propose_database_change(database=, sql=, title=, ...)
                                            -> bbcli change propose <database> --sql '...' \\
                                               --title '...' [--rollout] [--reason '...']
---- guide follows ----";

/// Task guides embedded from `backend/api/mcp/skills/` (same content the MCP
/// get_skill tool serves).
const SKILLS: &[(&str, &str)] = &[
    ("query", include_str!("../vendor/bytebase/skills/query.md")),
    (
        "database-change",
        include_str!("../vendor/bytebase/skills/database-change.md"),
    ),
    (
        "grant-permission",
        include_str!("../vendor/bytebase/skills/grant-permission.md"),
    ),
];

/// Binary version plus the Bytebase commit the embedded catalog and guides
/// were vendored from — the catalog only describes that API surface, so an
/// agent hitting an unknown method can tell whether the server is newer.
const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (API catalog: bytebase ",
    include_str!("../vendor/bytebase/COMMIT"),
    ")"
);

#[derive(Parser)]
#[command(
    name = "bbcli",
    version = VERSION,
    about = "CLI for a Bytebase server with OAuth2 auto-refresh",
    after_help = "Log in once with `bbcli login --context <url>`, then:\n  bbcli query employee 'SELECT 1'\n  bbcli schema employee\n  bbcli search --service SQLService\n  bbcli api SQLService/Query --args '{\"name\": \"instances/e1/databases/db\", \"statement\": \"SELECT 1\"}'"
)]
struct Cli {
    /// Context name or server base URL; the BBCLI_SERVER env sets the same
    /// slot (a URL, for CI) without persisting anything
    #[arg(long, global = true, env = "BBCLI_SERVER")]
    context: Option<String>,

    /// Accept invalid TLS certificates (self-signed deployments)
    #[arg(long, global = true)]
    insecure: bool,

    /// Fail an API call after this many seconds. Unset by default — queries
    /// and rollouts can run for minutes; set it to bound an unattended run
    #[arg(long, global = true, env = "BBCLI_TIMEOUT", value_name = "SECONDS")]
    timeout: Option<u64>,

    /// Print the authorization URL instead of opening a browser (headless)
    #[arg(long, global = true)]
    no_browser: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run one read-only SQL statement, resolving the database by name
    /// (mirrors the MCP query_database tool)
    Query {
        /// Database: a name, a substring of one, or the full
        /// instances/{instance}/databases/{database}
        database: String,
        /// The SQL statement — one statement per call. Quote it for the shell
        statement: Option<String>,
        /// Read the statement from a file, or "-" for stdin
        #[arg(long, conflicts_with = "statement")]
        file: Option<String>,
        /// Narrow resolution to one instance: an id or instances/{id}
        #[arg(long)]
        instance: Option<String>,
        /// Narrow resolution to one project: an id or projects/{id}
        #[arg(long)]
        project: Option<String>,
        /// Maximum rows to return; `truncated` in the output says whether
        /// there were more
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..))]
        limit: u32,
    },
    /// Inspect a database's schema: tables, columns, indexes, foreign keys
    /// (mirrors the MCP get_schema tool)
    Schema {
        /// Database: a name, a substring of one, or the full
        /// instances/{instance}/databases/{database}
        database: String,
        /// Narrow resolution to one instance: an id or instances/{id}
        #[arg(long)]
        instance: Option<String>,
        /// Narrow resolution to one project: an id or projects/{id}
        #[arg(long)]
        project: Option<String>,
        /// Limit to one schema (PostgreSQL, MSSQL, Oracle, ...); ignored with
        /// a note on engines without named schemas, such as MySQL
        #[arg(long)]
        schema: Option<String>,
        /// Drill into one table by name; implies --include details
        #[arg(long)]
        table: Option<String>,
        /// Detail per table [default: summary, or details with --table]
        #[arg(long, value_enum)]
        include: Option<schema::Include>,
    },
    /// Propose a database change through the review flow
    Change {
        #[command(subcommand)]
        action: ChangeAction,
    },
    /// Call a Bytebase API method, e.g. SQLService/Query
    Api {
        /// Method as Service/Method (or bytebase.v1.Service/Method)
        method: String,
        /// JSON object of request fields (find them with `bbcli search`)
        #[arg(long, default_value = "{}")]
        args: String,
        /// Read the JSON object from a file, or "-" for stdin (useful for
        /// large payloads such as base64 sheet content)
        #[arg(long)]
        args_file: Option<String>,
    },
    /// Search the embedded API catalog (offline; no server needed)
    Search {
        /// Browse all methods of one service, e.g. SQLService
        #[arg(long)]
        service: Option<String>,
        /// Show request/response schema of one operation, e.g. SQLService/Query
        #[arg(long)]
        operation_id: Option<String>,
        /// Show the definition of a message type, e.g. QueryRequest
        #[arg(long)]
        schema: Option<String>,
    },
    /// Show a bundled task guide (offline)
    Skill {
        /// Guide name: query | database-change | grant-permission
        name: Option<String>,
    },
    /// Install the agent skill (the SKILL.md that teaches an agent these
    /// commands) into the agent's skills directory
    InstallSkill {
        /// Where to write it (default: ~/.claude/skills/bytebase/SKILL.md).
        /// Project-level: --dest .claude/skills/bytebase/SKILL.md
        #[arg(long)]
        dest: Option<std::path::PathBuf>,
        /// Overwrite a copy that differs from the bundled skill
        #[arg(long)]
        force: bool,
    },
    /// Manage configuration (effective server, credential file)
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Authenticate via OAuth2 (browser) and store tokens locally
    Login {
        /// Name this server as a context (e.g. --as prod), usable with
        /// --context, BBCLI_SERVER, `config use`, and .bbcli files
        #[arg(long = "as")]
        r#as: Option<String>,
    },
    /// Show stored credentials and token expiry
    Status,
    /// Revoke and remove stored credentials
    Logout,
}

#[derive(Subcommand)]
enum ChangeAction {
    /// Create sheet -> plan -> plan checks -> issue for one database, and a
    /// rollout only with --rollout (mirrors the MCP propose_database_change
    /// tool). Nothing is approved on your behalf
    #[command(group(clap::ArgGroup::new("sql_source").required(true).args(["sql", "file"])))]
    Propose {
        /// Database: a name, a substring of one, or the full
        /// instances/{instance}/databases/{database}
        database: String,
        /// The SQL to apply, in plain text (DDL or DML)
        #[arg(long)]
        sql: Option<String>,
        /// Read the SQL from a file, or "-" for stdin
        #[arg(long, conflicts_with = "sql")]
        file: Option<String>,
        /// Title for the plan and the issue; what reviewers see first
        #[arg(long)]
        title: String,
        /// Narrow resolution to one instance: an id or instances/{id}
        #[arg(long)]
        instance: Option<String>,
        /// Narrow resolution to one project: an id or projects/{id}
        #[arg(long)]
        project: Option<String>,
        /// Also create the rollout, if plan checks and approval allow it;
        /// the output's rolloutDeferredReason says why not when they do not
        #[arg(long)]
        rollout: bool,
        /// Context or ticket reference; becomes the issue description
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Show the effective server (and where it comes from) plus all logged-in servers
    View,
    /// Switch the active context used when --context is not given
    Use {
        /// Context name or server base URL (must already be logged in)
        context: String,
    },
    /// Verify connectivity and credentials; exits non-zero if unusable
    Check,
    /// Print the credential file path
    Path,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // Die silently on SIGPIPE like a normal CLI (Rust ignores it by default,
    // which turns `bbcli ... | head` into a panic). Unix-only: Windows has no
    // SIGPIPE, and libc does not define it there, so an ungated call does not
    // compile for a Windows target.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL)
    };

    // Parse via raw matches so the flag-vs-env provenance of --context is
    // exact (clap records where a value came from) instead of reconstructed
    // by string-comparing the environment.
    let matches = Cli::command().get_matches();
    let context_from_env = matches.value_source("context") == Some(ValueSource::EnvVariable);
    let mut cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    // Taken out so the global flags stay borrowable while the subcommand runs.
    let Some(command) = cli.command.take() else {
        Cli::command().print_help()?;
        return Ok(());
    };
    match command {
        Command::Api {
            method,
            args,
            args_file,
        } => {
            let client = api_client(&cli, context_from_env)?;
            let args = read_args(&args, &args_file)?;
            // `call_announced` prints the `Method -> server (source: ...)`
            // line: the target is implicit (flag, env, .bbcli file, or the
            // global default), and a multi-step agent run has no other cheap
            // way to confirm it hit the environment it meant to. It goes to
            // stderr so stdout stays pure JSON for piping.
            let result = client.call_announced(&method, &args).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::Query {
            database,
            statement,
            file,
            instance,
            project,
            limit,
        } => {
            let client = api_client(&cli, context_from_env)?;
            // Validated here rather than with a required clap group: the
            // group makes the usage line read `<STATEMENT|--file> <DATABASE>`,
            // which tells an agent to put the SQL first.
            let statement = match (statement, &file) {
                (Some(s), _) => s,
                (None, Some(path)) => read_text(path)?,
                (None, None) => {
                    bail!("give the SQL statement after the database, or --file <path|->")
                }
            };
            let result = query::run(
                &client,
                &database,
                &statement,
                instance.as_deref(),
                project.as_deref(),
                limit,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::Schema {
            database,
            instance,
            project,
            schema,
            table,
            include,
        } => {
            let client = api_client(&cli, context_from_env)?;
            let result = schema::run(
                &client,
                &database,
                instance.as_deref(),
                project.as_deref(),
                schema.as_deref(),
                table.as_deref(),
                include,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::Change { action } => match action {
            ChangeAction::Propose {
                database,
                sql,
                file,
                title,
                instance,
                project,
                rollout,
                reason,
            } => {
                let client = api_client(&cli, context_from_env)?;
                let sql = match (sql, &file) {
                    (Some(s), _) => s,
                    (None, Some(path)) => read_text(path)?,
                    (None, None) => unreachable!("clap requires --file or --sql"),
                };
                let result = change::propose(
                    &client,
                    &database,
                    &sql,
                    &title,
                    instance.as_deref(),
                    project.as_deref(),
                    rollout,
                    reason.as_deref(),
                )
                .await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
        },
        Command::Search {
            service,
            operation_id,
            schema,
        } => search::run(operation_id, schema, service)?,
        Command::Skill { name } => match name {
            Some(name) => {
                let Some((_, content)) = SKILLS.iter().find(|(n, _)| *n == name) else {
                    bail!("no skill {name:?}; available: {}", skill_names().join(", "));
                };
                println!("{SKILL_SYNTAX_NOTE}\n\n{content}");
            }
            None => {
                println!("Guides (view with: bbcli skill <name>)\n");
                for (name, content) in SKILLS {
                    println!("  {name} — {}", skill_description(content));
                }
            }
        },
        Command::InstallSkill { dest, force } => {
            match agent_skill::install(dest, force)? {
                agent_skill::Installed::Written(path) => {
                    println!("Installed the bytebase skill to {}.", path.display())
                }
                agent_skill::Installed::Unchanged(path) => {
                    println!("{} is already up to date.", path.display())
                }
            }
            println!(
                "Re-run this after upgrading bbcli — the skill ships inside the binary, \
                 so that is what keeps the installed copy in sync."
            );
        }
        Command::Login { r#as } => {
            let server = cli
                .context
                .clone()
                .ok_or_else(|| anyhow!("--context (or BBCLI_SERVER) is required for login"))?;
            login(&server, r#as.as_deref(), cli.insecure, cli.no_browser).await?;
        }
        Command::Config { action } => match action {
            ConfigAction::View => config_view(cli.context.as_deref(), context_from_env)?,
            ConfigAction::Use { context } => {
                store::set_default(&context)?;
                println!("Active context set to {}.", context.trim());
            }
            ConfigAction::Check => {
                let (server, source) = resolve_server(cli.context.as_deref(), context_from_env)?;
                config_check(&server, &source, cli.insecure, cli.timeout).await?;
            }
            ConfigAction::Path => {
                println!("{}", store::config_path().display());
                println!("{}", store::token_path().display());
            }
        },
        Command::Status => status()?,
        Command::Logout => {
            let (server, _) = resolve_server(cli.context.as_deref(), context_from_env)?;
            logout(&server, cli.insecure).await?;
        }
    }
    Ok(())
}

/// Builds the client every server-touching command needs: resolve the target,
/// then load its credentials. The resolved source travels with the client so
/// each call announces where it went, `api` and the friendly subcommands alike.
fn api_client(cli: &Cli, context_from_env: bool) -> Result<ApiClient> {
    let (server, source) = resolve_server(cli.context.as_deref(), context_from_env)?;
    ApiClient::load(&server, &source, cli.insecure, cli.timeout)
}

/// Picks the server. Precedence: `--context`/`BBCLI_SERVER` (a context name or
/// URL) → a `.bbcli` file in this directory or an ancestor (gcx-style
/// repo configuration) → the global default (active context). Returns the
/// resolved URL and where it came from.
fn resolve_server(explicit: Option<&str>, from_env: bool) -> Result<(String, String)> {
    if let Some(s) = explicit.filter(|s| !s.trim().is_empty()) {
        let source = if from_env {
            "env BBCLI_SERVER"
        } else {
            "--context flag"
        };
        return Ok((store::resolve_alias(s)?, source.to_string()));
    }
    if let Some(s) = project_server_override() {
        return Ok((
            store::resolve_alias(&s)?,
            "project file (.bbcli)".to_string(),
        ));
    }
    let cfg = store::load_config()?;
    if let Some(url) = store::default_server_from(&cfg) {
        return Ok((url, format!("default (context {})", cfg.current_context)));
    }
    Err(anyhow!(
        "no server configured: pass --context (or set BBCLI_SERVER), or run `bbcli login --context <url>` first"
    ))
}

/// Reads the nearest `.bbcli` file (one line: a context name or URL),
/// walking up from the current directory — the bbcli equivalent of gcx's
/// repo-level `.gcx.yaml`.
fn project_server_override() -> Option<String> {
    std::env::current_dir()
        .ok()?
        .ancestors()
        .map(|dir| dir.join(".bbcli"))
        .find_map(|candidate| {
            let s = std::fs::read_to_string(candidate).ok()?;
            let s = s.trim();
            (!s.is_empty()).then(|| s.to_string())
        })
}

/// `bbcli config view`: effective server, its source, all contexts and
/// logged-in servers.
fn config_view(explicit: Option<&str>, from_env: bool) -> Result<()> {
    let cfg = store::load_config()?;
    let file = store::load()?;
    let (effective, source) = resolve_server(explicit, from_env).unwrap_or_else(|_| {
        (
            "-".to_string(),
            "none: run `bbcli login --context <url>`".to_string(),
        )
    });
    println!("Effective server: {effective} (source: {source})");
    println!("Config file:      {}", store::config_path().display());
    println!("Credential file:  {}", store::token_path().display());
    if !cfg.contexts.is_empty() {
        println!("Contexts:");
        let mut names: Vec<&String> = cfg.contexts.keys().collect();
        names.sort();
        for name in names {
            let active = if *name == cfg.current_context {
                "  [active]"
            } else {
                ""
            };
            println!("  {name} -> {}{active}", cfg.contexts[name].server);
        }
    }
    if file.servers.is_empty() {
        return Ok(());
    }
    let default_url = store::default_server_from(&cfg);
    println!("Logged-in servers:");
    let mut keys: Vec<&String> = file.servers.keys().collect();
    keys.sort();
    for key in keys {
        let default = if default_url.as_deref() == Some(key.as_str()) {
            "  [default]"
        } else {
            ""
        };
        println!("  {key}{default}");
    }
    Ok(())
}

/// `bbcli config check`: connectivity plus a credential round trip. Exits
/// non-zero when the configuration is unusable, so agents and CI can use it
/// as a gate before doing real work.
async fn config_check(
    server: &str,
    source: &str,
    insecure: bool,
    timeout: Option<u64>,
) -> Result<()> {
    let client = ApiClient::load(server, source, insecure, timeout)?;

    // Connectivity and version banner (auth-exempt endpoint).
    let info = client
        .call("ActuatorService/GetActuatorInfo", &serde_json::json!({}))
        .await
        .context("connectivity check failed")?;
    let version = info.get("version").and_then(Value::as_str).unwrap_or("?");

    // Authenticated round trip; exercises the 401-refresh path if needed.
    client
        .call(
            "SQLService/SearchQueryHistories",
            &serde_json::json!({"pageSize": 1}),
        )
        .await
        .context("credential check failed")?;

    let remaining = client.access_expires_in().await;
    println!("server:      {server} (source: {source})");
    println!("connectivity: ok (version {version})");
    println!(
        "credentials:  ok (access token valid for {}m)",
        remaining / 60
    );
    Ok(())
}

/// Reads a payload from a file, or from stdin for `-`. Shared by every
/// `--file` / `--args-file` flag so `-` means the same thing everywhere.
fn read_text(path: &str) -> Result<String> {
    use std::io::Read;
    if path == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .lock()
            .read_to_string(&mut buf)
            .context("failed to read from stdin")?;
        return Ok(buf);
    }
    std::fs::read_to_string(path).with_context(|| format!("failed to read {path}"))
}

/// Resolves request fields from --args / --args-file into a JSON object.
fn read_args(args: &str, args_file: &Option<String>) -> Result<Value> {
    let raw = match args_file {
        Some(path) => read_text(path)?,
        None => args.to_string(),
    };
    let value: Value =
        serde_json::from_str(&raw).context("request fields must be a JSON object")?;
    if !value.is_object() {
        bail!("request fields must be a JSON object, got: {raw}");
    }
    Ok(value)
}

fn skill_names() -> Vec<&'static str> {
    SKILLS.iter().map(|(n, _)| *n).collect()
}

/// First line of the frontmatter description.
fn skill_description(content: &str) -> String {
    content
        .lines()
        .find_map(|l| l.strip_prefix("description: "))
        .unwrap_or_default()
        .trim()
        .to_string()
}

async fn login(server: &str, alias: Option<&str>, insecure: bool, no_browser: bool) -> Result<()> {
    let client = OAuth2Client::new(server, insecure)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("failed to bind loopback callback listener")?;
    let port = listener
        .local_addr()
        .context("failed to get callback port")?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    let client_id = client.register(&redirect_uri).await?;
    let (verifier, challenge) = oauth::pkce_pair();
    let state = oauth::random_token(24);
    let url = client.authorize_url(&client_id, &redirect_uri, &state, &challenge);

    if no_browser {
        eprintln!("Open this URL to authorize:\n  {url}\n");
    } else {
        eprintln!("Opening browser for authorization:\n  {url}\n");
        oauth::open_browser(&url);
    }
    // The browser is not always on this machine. Say up front how to finish
    // the login when it is not, rather than leaving the user staring at a
    // failed redirect and assuming bbcli is broken.
    eprintln!(
        "If the browser is on another machine, open that URL there. The redirect to\n  \
         {redirect_uri}\n\
         will fail to load — that is expected. Copy the full address from the browser's\n\
         address bar and paste it here.\n\n\
         Waiting up to 10 minutes for the callback or a pasted URL..."
    );

    let code = oauth::wait_for_code(listener, &state, &redirect_uri).await?;
    let creds = client
        .exchange_code(&client_id, &redirect_uri, &code, &verifier)
        .await?;

    let key = store::normalize(server);
    store::save_credentials(server, &creds, alias)?;
    match alias {
        Some(name) => eprintln!(
            "Logged in to {key} as context {name} (client {client_id}); access token valid for {} minutes.",
            (creds.expires_at - store::unix_now()) / 60
        ),
        None => eprintln!(
            "Logged in to {key} (client {client_id}); access token valid for {} minutes.",
            (creds.expires_at - store::unix_now()) / 60
        ),
    }
    Ok(())
}

fn status() -> Result<()> {
    let file = store::load()?;
    if file.servers.is_empty() {
        println!("Not logged in to any server. Run `bbcli login --context <url>`.");
        return Ok(());
    }
    let default_url = store::default_server_from(&store::load_config()?);
    let now = store::unix_now();
    let mut entries: Vec<(&String, &store::Credentials)> = file.servers.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    for (key, c) in entries {
        let default = if default_url.as_deref() == Some(key.as_str()) {
            "  [default]"
        } else {
            ""
        };
        println!("{key}{default}");
        println!("  client_id:     {}", c.client_id);
        println!(
            "  access token:  {}",
            fmt_remaining(c.expires_at - now, Expired::Recoverable)
        );
        println!(
            "  refresh token: {}",
            fmt_remaining(c.refresh_expires_at - now, Expired::Terminal)
        );
    }
    Ok(())
}

/// What an expired token means for the user. An expired *access* token is
/// routine — the next call refreshes it. An expired *refresh* token is the
/// end of the grant: nothing recovers it but a new browser login, so the two
/// must never share a message.
enum Expired {
    Recoverable,
    Terminal,
}

fn fmt_remaining(secs: i64, expired: Expired) -> String {
    if secs <= 0 {
        return match expired {
            Expired::Recoverable => "expired (refreshes automatically on next use)",
            Expired::Terminal => "expired — run `bbcli login` again",
        }
        .to_string();
    }
    let (d, rem) = (secs / 86400, secs % 86400);
    let (h, m) = (rem / 3600, rem % 3600 / 60);
    if d > 0 {
        format!("expires in {d}d {h}h")
    } else if h > 0 {
        format!("expires in {h}h {m}m")
    } else {
        format!("expires in {m}m")
    }
}

async fn logout(server: &str, insecure: bool) -> Result<()> {
    let key = store::normalize(server);
    let Some(creds) = store::remove(server)? else {
        println!("No stored credentials for {key}.");
        return Ok(());
    };
    let client = OAuth2Client::new(server, insecure)?;
    if let Err(e) = client.revoke(&creds).await {
        println!("Logged out from {key} locally; server revoke failed ({e:#}).");
    } else {
        println!("Logged out from {key}.");
    }
    Ok(())
}
