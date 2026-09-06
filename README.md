# bbcli

A CLI for a Bytebase server with OAuth2 auto-refresh — built for CLI agents
(Claude Code, ...): pair it with the bundled agent skill and the agent drives
Bytebase through plain Bash commands, no MCP registration.

```
agent ──Bash──▶ bbcli api SQLService/Query ──Connect JSON + Bearer──▶ bytebase.v1 API
                       │
        OAuth2 login / auto-refresh / retry, one round trip per command
        bbcli search / bbcli skill — offline, embedded catalog & guides
```

## How it works

`bbcli api` speaks the [Connect JSON protocol](https://connectrpc.com/docs/protocol)
directly to Bytebase's v1 API (`POST {server}/bytebase.v1.{Service}/{Method}`).
Bytebase serves all v1 services as Connect handlers on its main HTTP port
(`backend/server/grpc_routes.go`), and the connect auth interceptor accepts the
same OAuth2 audience the `/mcp` endpoint does — so bbcli needs no MCP layer,
no session, one HTTP round trip per command.

`bbcli search` and `bbcli skill` are fully offline: the OpenAPI catalog and
the task guides are vendored under `vendor/bytebase/` (copied from
`backend/api/mcp/` in the Bytebase repo — the same sources the MCP
`search_api` / `get_skill` tools serve) and embedded into the binary at build
time. So the build needs nothing but this repository. `bbcli --version` and
`bbcli search` print the Bytebase commit the catalog came from; re-sync it
with `scripts/sync_vendor.sh /path/to/bytebase`.

## Why the credential handling exists

Bytebase OAuth2 access tokens live **1 hour** and refresh tokens are
**single-use** (rotated on every refresh). Concurrent clients sharing one
credential race the rotation and end up forced through browser re-logins.
bbcli sidesteps this:

- tokens live in one file guarded by an exclusive lock (`~/.config/bbcli/tokens.json`, `0600`);
- before refreshing, the process re-reads the file — if another process
  already rotated the token, it adopts the new one instead of burning a dead
  refresh token;
- expired access tokens are refreshed proactively (2-minute margin) and
  reactively (retry once after a 401).

## Install

Requires a Rust toolchain (1.75+); no other dependencies, and no network
access to a Bytebase repo — the catalog is vendored.

```bash
git clone https://github.com/xiispace/bbcli && cd bbcli
cargo build --release
install -m 755 target/release/bbcli /usr/local/bin/   # or anywhere on PATH
```

## Setup (for Claude Code and other agents)

Five steps from an empty machine to a first query:

1. **Verify the binary** — offline, so this works before any login:

   ```bash
   bbcli --version          # version + the Bytebase commit the catalog describes
   bbcli search             # lists every service
   ```

2. **Log in** once, naming the server as a context:

   ```bash
   bbcli login --context https://bytebase.example.com --as prod
   ```

   Opens a browser for OAuth2 consent. Add `--insecure` for self-signed TLS.

3. **Verify the connection** — exits non-zero if anything is unusable, so it
   works as an agent or CI gate:

   ```bash
   bbcli config check
   ```

4. **Install the agent skill** so the agent knows these commands exist:

   ```bash
   cp -r skills/bytebase ~/.claude/skills/      # user-level (Claude Code)
   cp -r skills/bytebase .claude/skills/        # or project-level
   ```

5. **Run the first query** — find a database, then read from it:

   ```bash
   bbcli skill query                            # the full flow, offline
   bbcli api DatabaseService/ListDatabases --args '{"parent": "workspaces/-"}'
   bbcli api SQLService/Query --args '{
     "name": "instances/<instance>/databases/<database>",
     "statement": "SELECT 1"
   }'
   ```

## Usage

```bash
bbcli search                                   # all services (offline)
bbcli search --service SQLService              # methods of one service
bbcli search --operation-id SQLService/Query   # request fields of a method
bbcli search --schema QueryRequest             # one message type

bbcli api SQLService/Query --args '{
  "name": "instances/e1/databases/db",
  "statement": "SELECT 1"
}'
bbcli api SheetService/CreateSheet --args-file - <<'JSON'   # large payloads via stdin
{"parent": "projects/p1", "sheet": {"title": "t", "content": "..."}}
JSON

bbcli skill query                              # bundled task guide
```

## Commands

| Command | Description |
|---|---|
| `api <Service/Method> [--args JSON \| --args-file F]` | Direct Connect call, prints the JSON response; non-2xx exits 1 with the server's message |
| `search [--service S \| --operation-id O \| --schema T]` | Offline API catalog (embedded OpenAPI spec) |
| `skill [name]` | Offline task guides (query, database-change, grant-permission) |
| `config view` | Show the effective server (and its source) plus all logged-in servers |
| `config use <name-or-url>` | Switch the active context (must already be logged in) |
| `config check` | Verify connectivity and credentials; exits non-zero if unusable — usable as an agent/CI gate |
| `config path` | Print the credential file path |
| `login [--as <name>]` | OAuth2 login: RFC 7591 dynamic client registration → browser consent (PKCE S256) → token exchange, via the loopback callback or a pasted redirect URL; `--as` names the server as a context |
| `status` | List stored credentials with access/refresh token expiry |
| `logout` | Revoke the refresh token server-side and remove local credentials (drops contexts pointing at it) |

## Logging in when the browser is elsewhere

A remote box, a container, a machine reached over SSH: the browser cannot
reach that host's `127.0.0.1`. No port forwarding needed — `bbcli login`
accepts the redirect by paste, and takes whichever arrives first:

```
$ bbcli login --context https://bytebase.example.com --as prod
Open this URL to authorize:
  https://bytebase.example.com/api/oauth2/authorize?...

If the browser is on another machine, open that URL there. The redirect to
  http://127.0.0.1:38123/callback
will fail to load — that is expected. Copy the full address from the browser's
address bar and paste it here.

Waiting up to 10 minutes for the callback or a pasted URL...
```

Open the URL in any browser, approve, and the browser lands on a page that
fails to load. That failure is the point: the authorization code is in the
address bar. Copy the whole address, paste it into the waiting prompt, done.

This is not a weaker flow. The PKCE `code_verifier` never leaves the host
running bbcli, so the pasted code cannot be redeemed by anyone who intercepts
it, and `state` is checked exactly as it is on the loopback path. A bare code
is rejected — paste the whole URL, which is what the address bar holds.

## Multiple servers (contexts)

Name each server at login, then address it by name anywhere a server is
accepted (`--context`, `BBCLI_SERVER`, `config use`, `.bbcli`):

```bash
bbcli login --context https://bytebase.example.com --as prod
bbcli login --context https://staging.example.com --as staging

bbcli config use prod                 # switch the global default
bbcli api SQLService/Query --context staging --args '{...}'
```

For per-project defaults, drop a `.bbcli` file (one line: a context
name or URL) at the project root — bbcli walks up from the working directory,
gcx-style:

```bash
echo staging > /path/to/project/.bbcli
cd /path/to/project && bbcli api SQLService/Query --args '{...}'   # hits staging
```

Selection precedence: `--context` flag → `BBCLI_SERVER` env → nearest
`.bbcli` file → the global default (active context, else the most
recent login). `bbcli config view` shows which one is in effect and lists all
contexts.

One credential per server URL: contexts are references, so two contexts on
the same URL share credentials (the later login overwrites the earlier).
Distinct identities on one server are not supported — point them at distinct
URLs/ports instead.

## Flags

| Flag | Applies to | Description |
|---|---|---|
| `--context <name-or-url>` | api/login/logout | Context name or server base URL; env `BBCLI_SERVER` (a URL, for CI); otherwise the `.bbcli` file or the active context |
| `--insecure` | all network | Accept invalid TLS certificates (self-signed deployments) |
| `--timeout <seconds>` | api/config check | Fail the call after N seconds; env `BBCLI_TIMEOUT`. Unset by default — a client timeout does **not** cancel server-side work, so check the resource's status before retrying |
| `--no-browser` | login | Print the authorization URL instead of opening a browser. Pasting the redirect works either way — see [Logging in when the browser is elsewhere](#logging-in-when-the-browser-is-elsewhere) |

## Storage

Two files side by side (gcx-style split of secrets from configuration):

- **`config.yaml`** — named contexts and the active one. No secrets; safe to
  copy, diff, and edit by hand. Override with `BBCLI_CONFIG`:

  ```yaml
  version: 1
  current-context: prod
  contexts:
    prod:
      server: https://bytebase.example.com
    staging:
      server: https://staging.example.com
  ```
- **`tokens.json`** — OAuth2 credentials only, keyed by server URL,
  permissions `0600`, guarded by an advisory file lock shared across bbcli
  processes. Override with `BBCLI_TOKEN_FILE`.

Locations (gcx-style, shown by `bbcli config path`): `~/.config/bbcli/` on
macOS and Linux (or `$XDG_CONFIG_HOME/bbcli/` when set); the OS config dir on
Windows. Refresh-token expiry is tracked locally as issue-time + 30 days (the
server does not return it in the token response).

## Errors

A failed `api` call exits non-zero and prints the Connect code, the server's
message, any `details`, and the action that resolves that code:

```
HTTP 403 Forbidden from /bytebase.v1.SQLService/Query [permission_denied]: ...
  the account lacks the required role: see `bbcli skill grant-permission`
```

The code is what decides the next step — `unauthenticated` means re-login,
`invalid_argument` means re-check the fields with `bbcli search`,
`permission_denied` means request access — so an agent never has to infer
intent from prose. stdout stays pure JSON; diagnostics and the resolved target
server go to stderr.

## Limitations

- **Login needs a browser somewhere, and a person at it.** The browser does
  not have to be on the same host (see below), but there is no unattended
  machine-identity flow — bbcli targets interactive agents, not CI.
- Unary RPCs only — Connect JSON streaming endpoints are not covered (rarely
  relevant for one-shot CLI commands).
- The embedded catalog is a vendored snapshot (`vendor/bytebase/`), not the
  live server's surface. `bbcli --version` names the commit; an
  `unimplemented` error means the server and the snapshot disagree. Re-sync
  with `scripts/sync_vendor.sh` and rebuild.
- Task guides are written in MCP tool syntax; `bbcli skill <name>` prints the
  MCP→bbcli translation above every guide rather than rewriting them, so they
  stay diffable against the upstream sources.

## Testing

```bash
cargo test                          # unit tests (method paths, catalog, token store, PKCE)
cargo build && python3 scripts/e2e_test.py   # end-to-end against a mock Connect server
```

The E2E script spins up an in-process mock of the OAuth2 endpoints and a
Connect endpoint, and verifies the full lifecycle: login (registration + PKCE
+ code exchange), `api` calls (args/args-file/error propagation),
401-triggered refresh and replay, cross-process refresh-token adoption, and
logout/revocation.

## License

bbcli is Apache-2.0 (`LICENSE`).

`vendor/bytebase/` is copied verbatim from
[bytebase/bytebase](https://github.com/bytebase/bytebase) and redistributed
under its MIT Expat license — see `vendor/bytebase/LICENSE` and
`vendor/bytebase/SOURCE.md` for the source paths and the synced commit.
