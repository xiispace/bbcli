#!/usr/bin/env python3
"""End-to-end test for bbcli against an in-process mock Bytebase server.

The mock speaks the Connect JSON protocol (POST /bytebase.v1.Svc/Method with
Bearer auth and connect-protocol-version), like the real server's connect
handlers. Covers, in order:
  1. login: RFC 7591 registration -> PKCE authorize redirect -> loopback
     callback -> authorization-code exchange -> token file written
  2. api: direct Connect call, args and --args-file, error propagation
  2a. friendly commands: query / schema / change propose -- database
      resolution (tiered, ambiguous, full resource name), row flattening and
      truncation, schema summary vs table drill-down, and the
      sheet->plan->checks->issue->rollout chain with its rollout gates
  2b. config: view / use / check / path
  2c. contexts: named logins (--as), alias resolution everywhere, project
      .bbcli files, and precedence between them
  3. 401 recovery: stale access token with far-future local expiry is
     refreshed reactively and the request replayed
  4. cross-process refresh adoption: a process holding a stale memory copy
     of a refresh token that another process already rotated must adopt the
     file's newer token instead of burning the dead one
  5. logout: server-side revoke + local removal

Usage: python3 scripts/e2e_test.py [path-to-bbcli]
"""

import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "target", "debug", "bbcli")
TOKEN_FILE = ""
MOCK_PORT = 0

def make_mock():
    """A mock Bytebase server with its own rotating credential state."""
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.state = {
        "access": None, "refresh": None, "n": 0, "refresh_calls": 0,
        # Approval the mock hands back from CreateIssue, and the sheet content
        # it last received -- the rollout gates and the base64 encoding are
        # asserted against these.
        "approval": "PENDING", "sheet_content": None,
    }
    return httpd


# --- Fixtures for the friendly commands (query / schema / change) ----------
#
# The workspace a listing must be parented to. `workspaces/-` resolves to it
# through GetWorkspace and is refused everywhere else, which is what the
# resolver's extra lookup exists for.
WORKSPACE = "workspaces/ws-test"
#
# Two databases whose short names both contain "emp", so "employee" resolves
# by the exact tier while "emp" is genuinely ambiguous.
DATABASES = [
    {
        "name": "instances/pg1/databases/employee",
        "project": "projects/hr",
        "instanceResource": {
            "name": "instances/pg1",
            "engine": "POSTGRES",
            # ADMIN first on purpose: the resolver must still pick READ_ONLY.
            "dataSources": [{"id": "admin", "type": "ADMIN"}, {"id": "ro", "type": "READ_ONLY"}],
        },
    },
    {
        "name": "instances/my1/databases/employee_archive",
        "project": "projects/hr",
        "instanceResource": {
            "name": "instances/my1",
            "engine": "MYSQL",
            "dataSources": [{"id": "admin", "type": "ADMIN"}],
        },
    },
]

TABLES = {
    "orders": {
        "name": "orders",
        # int64 on the wire may be a string; the CLI must emit a number.
        "rowCount": "42",
        "columns": [
            {"name": "id", "type": "int", "nullable": False},
            {"name": "total", "type": "numeric", "nullable": True, "default": "0"},
        ],
        "indexes": [{"name": "orders_pkey", "expressions": ["id"], "type": "btree",
                     "unique": True, "primary": True}],
        "foreignKeys": [{"name": "orders_user_fk", "columns": ["id"],
                         "referencedTable": "users", "referencedColumns": ["id"]}],
    },
    "users": {
        "name": "users",
        "rowCount": 7,
        "columns": [
            {"name": "id", "type": "int", "nullable": False},
            {"name": "email", "type": "text", "nullable": True},
        ],
    },
}


def cel_arg(filt, pattern):
    """The quoted argument of one CEL term, or None."""
    m = re.search(pattern, filt or "")
    return m.group(1) if m else None


def filter_databases(filt):
    """Substring on name plus exact instance/project, like the real server."""
    needle = cel_arg(filt, r'name\.contains\("([^"]*)"\)') or ""
    out = [d for d in DATABASES if needle in d["name"]]
    instance = cel_arg(filt, r'instance == "([^"]*)"')
    if instance:
        out = [d for d in out if d["instanceResource"]["name"] == instance]
    project = cel_arg(filt, r'project == "([^"]*)"')
    if project:
        out = [d for d in out if d["project"] == project]
    return out


def metadata_response(name, filt):
    table = cel_arg(filt, r'table == "([^"]*)"')
    tables = [t for t in TABLES.values() if table is None or t["name"] == table]
    return {"name": name, "schemas": [{
        "name": "public",
        "tables": tables,
        "views": [{"name": "v_orders"}],
    }]}


def query_rows(n):
    """n identical rows exercising the int64/string/timestamp variants."""
    return [{"values": [
        {"int64Value": "1"},
        {"stringValue": "a"},
        {"timestampValue": {"googleTimestamp": "2026-01-01T00:00:00Z", "accuracy": 6}},
    ]} for _ in range(n)]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _json(self, code, obj, headers=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/api/oauth2/authorize"):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            assert q["response_type"] == ["code"]
            assert q["code_challenge_method"] == ["S256"]
            redirect = q["redirect_uri"][0] + "?code=bb_code_test&state=" + q["state"][0]
            self.send_response(302)
            self.send_header("Location", redirect)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self._json(404, {"code": "not_found", "message": "not found"})

    def authed(self):
        return self.headers.get("Authorization") == f"Bearer {self.server.state['access']}"

    def require_auth(self):
        """Answers 401 and reports False when the bearer token is not current."""
        if self.authed():
            return True
        self._json(401, {"code": "unauthenticated", "message": "invalid token"})
        return False

    def do_POST(self):
        state = self.server.state
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        if self.path == "/api/oauth2/register":
            req = json.loads(body)
            assert req["client_name"], "client_name required"
            assert req["token_endpoint_auth_method"] == "none"
            assert set(req["grant_types"]) == {"authorization_code", "refresh_token"}
            assert all(u.startswith("http://127.0.0.1:") for u in req["redirect_uris"])
            self._json(201, {"client_id": "bb_oauth_test"})
        elif self.path == "/api/oauth2/token":
            form = dict(urllib.parse.parse_qsl(body))
            assert form["client_id"] == "bb_oauth_test", form
            state["n"] += 1
            if form["grant_type"] == "authorization_code":
                assert form["code"] == "bb_code_test", form
                assert 43 <= len(form.get("code_verifier", "")) <= 128, form
            elif form["grant_type"] == "refresh_token":
                state["refresh_calls"] += 1
                assert form["refresh_token"] == state["refresh"], (
                    f"stale refresh token: got {form['refresh_token']}, want {state['refresh']}"
                )
            else:
                raise AssertionError(form)
            state["access"] = f"at_{state['n']}"
            state["refresh"] = f"rt_{state['n']}"
            self._json(200, {
                "access_token": state["access"],
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": state["refresh"],
            })
        elif self.path == "/api/oauth2/revoke":
            form = dict(urllib.parse.parse_qsl(body))
            assert form["client_id"] == "bb_oauth_test", form
            if form.get("token") == state["refresh"]:
                state["access"] = None
                state["refresh"] = None
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/bytebase.v1.MockService/Echo":
            if not self.authed():
                self._json(401, {"code": "unauthenticated", "message": "invalid token"})
                return
            assert self.headers.get("Connect-Protocol-Version") == "1", "missing connect-protocol-version"
            assert "application/json" in self.headers.get("Content-Type", ""), self.headers
            msg = json.loads(body)
            if msg.get("fail"):
                self._json(400, {"code": "invalid_argument", "message": msg["fail"]})
                return
            self._json(200, {"echo": msg})
        elif self.path == "/bytebase.v1.ActuatorService/GetActuatorInfo":
            # auth-exempt health endpoint
            self._json(200, {"version": "mock-1"})
        elif self.path == "/bytebase.v1.SQLService/SearchQueryHistories":
            if not self.authed():
                self._json(401, {"code": "unauthenticated", "message": "invalid token"})
                return
            self._json(200, {"queryHistories": []})
        elif self.path == "/bytebase.v1.WorkspaceService/GetWorkspace":
            if not self.require_auth():
                return
            # Only the wildcard is answered: the real server accepts `-` here
            # and this is the one call that turns a credential into an id.
            assert json.loads(body).get("name") == "workspaces/-", body
            self._json(200, {"name": WORKSPACE, "title": "Test workspace"})
        elif self.path == "/bytebase.v1.DatabaseService/ListDatabases":
            if not self.require_auth():
                return
            msg = json.loads(body)
            # The concrete workspace, never the `-` wildcard: a real server
            # answers `permission_denied: workspace mismatch` for that here,
            # so accepting it in the mock would hide the bug.
            assert msg.get("parent") == WORKSPACE, msg
            self._json(200, {"databases": filter_databases(msg.get("filter", ""))})
        elif self.path == "/bytebase.v1.DatabaseService/GetDatabase":
            if not self.require_auth():
                return
            name = json.loads(body).get("name", "")
            match = next((d for d in DATABASES if d["name"] == name), None)
            if match is None:
                self._json(404, {"code": "not_found", "message": f"no database {name}"})
            else:
                self._json(200, match)
        elif self.path == "/bytebase.v1.SQLService/Query":
            if not self.require_auth():
                return
            msg = json.loads(body)
            if msg["name"] == "instances/pg1/databases/employee":
                assert msg.get("dataSourceId") == "ro", msg
            assert msg.get("limit"), f"the CLI must bound the result set: {msg}"
            if "bad" in msg["statement"]:
                # A failed statement inside a 200: the Connect call worked.
                self._json(200, {"results": [{"error": "syntax error near bad"}]})
                return
            self._json(200, {"results": [{
                "columnNames": ["id", "name", "ts"],
                "columnTypeNames": ["INT", "TEXT", "TIMESTAMP"],
                # Exactly as many rows as asked for, so the CLI's limit+1
                # request is what decides `truncated`.
                "rows": query_rows(msg["limit"]),
                "latency": "0.012s",
            }]})
        elif self.path == "/bytebase.v1.DatabaseService/GetDatabaseMetadata":
            if not self.require_auth():
                return
            msg = json.loads(body)
            assert msg["name"].endswith("/metadata"), msg
            if msg["name"].startswith("instances/my1/"):
                # MySQL has no named schemas, and the server matches
                # `schema == "x"` exactly -- the client must have dropped it.
                assert "schema ==" not in msg.get("filter", ""), msg
            self._json(200, metadata_response(msg["name"], msg.get("filter", "")))
        elif self.path == "/bytebase.v1.SheetService/CreateSheet":
            if not self.require_auth():
                return
            msg = json.loads(body)
            assert msg["parent"] == "projects/hr", msg
            state["sheet_content"] = base64.b64decode(
                msg["sheet"]["content"], validate=True
            ).decode()
            self._json(200, {"name": "projects/hr/sheets/1"})
        elif self.path == "/bytebase.v1.PlanService/CreatePlan":
            if not self.require_auth():
                return
            msg = json.loads(body)
            assert msg["parent"] == "projects/hr", msg
            spec = msg["plan"]["specs"][0]
            assert spec["changeDatabaseConfig"]["targets"] == [
                "instances/pg1/databases/employee"
            ], spec
            assert spec["changeDatabaseConfig"]["sheet"] == "projects/hr/sheets/1", spec
            self._json(200, {"name": "projects/hr/plans/1"})
        elif self.path == "/bytebase.v1.PlanService/RunPlanChecks":
            if not self.require_auth():
                return
            self._json(200, {})
        elif self.path == "/bytebase.v1.PlanService/GetPlanCheckRun":
            if not self.require_auth():
                return
            assert json.loads(body)["name"] == "projects/hr/plans/1/planCheckRun", body
            self._json(200, {"status": "DONE",
                             "results": [{"status": "SUCCESS", "title": "ok"},
                                         {"status": "WARNING", "title": "no index"}]})
        elif self.path == "/bytebase.v1.IssueService/CreateIssue":
            if not self.require_auth():
                return
            msg = json.loads(body)
            assert msg["issue"]["plan"] == "projects/hr/plans/1", msg
            assert msg["issue"]["type"] == "DATABASE_CHANGE", msg
            self._json(200, {"name": "projects/hr/issues/1",
                             "approvalStatus": state["approval"]})
        elif self.path == "/bytebase.v1.RolloutService/CreateRollout":
            if not self.require_auth():
                return
            # The parent of a rollout is the plan, not the project.
            assert json.loads(body)["parent"] == "projects/hr/plans/1", body
            self._json(200, {"name": "projects/hr/plans/1/rollout"})
        else:
            self._json(404, {"code": "not_found", "message": f"no such endpoint {self.path}"})


def env():
    e = os.environ.copy()
    e["BBCLI_TOKEN_FILE"] = TOKEN_FILE
    return e


def run_cli(*args, stdin=None, expect_fail=False):
    out = subprocess.run(
        [BIN, *args], input=stdin, capture_output=True, text=True,
        env=env(), timeout=30,
    )
    if not expect_fail:
        assert out.returncode == 0, f"bbcli {args} exited {out.returncode}: {out.stderr}"
    return out


def load_tokens():
    with open(TOKEN_FILE) as f:
        return json.load(f)["servers"][f"http://127.0.0.1:{MOCK_PORT}"]


def write_tokens(**over):
    with open(TOKEN_FILE) as f:
        d = json.load(f)
    d["servers"][f"http://127.0.0.1:{MOCK_PORT}"].update(over)
    with open(TOKEN_FILE, "w") as f:
        json.dump(d, f)


def step(name):
    print(f"== {name}")


def browser_login(base, *extra_args):
    """Runs `bbcli login` against base and emulates the browser consent."""
    login = subprocess.Popen(
        [BIN, "login", "--context", base, "--no-browser", *extra_args],
        stderr=subprocess.PIPE, text=True, env=env(),
    )
    url = None
    deadline = time.time() + 10
    while time.time() < deadline:
        line = login.stderr.readline()
        m = re.search(r"(https?://\S+)", line)
        if m:
            url = m.group(1)
            break
    assert url, "login never printed an authorization URL"
    urllib.request.urlopen(urllib.request.Request(url)).read()  # follows the 302 to the loopback callback
    assert login.wait(timeout=10) == 0, "login exited nonzero"


def paste_login(base, *extra_args):
    """Login with no reachable loopback: the redirect URL is pasted on stdin.

    Emulates the remote-host case -- the browser runs somewhere that cannot
    reach this process's 127.0.0.1 listener, so the code arrives by copy and
    paste instead of over the callback socket.
    """
    login = subprocess.Popen(
        [BIN, "login", "--context", base, "--no-browser", *extra_args],
        stdin=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env(),
    )
    url = None
    deadline = time.time() + 10
    while time.time() < deadline:
        line = login.stderr.readline()
        m = re.search(r"(https?://\S+authorize\S*)", line)
        if m:
            url = m.group(1)
            break
    assert url, "login never printed an authorization URL"

    # Follow the consent redirect WITHOUT letting it reach the loopback
    # listener -- exactly what a browser on another machine produces.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_a, **_kw):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    try:
        opener.open(urllib.request.Request(url))
        raise AssertionError("expected a 302 to the loopback callback")
    except urllib.error.HTTPError as e:
        redirect = e.headers["Location"]
    assert "code=" in redirect and "state=" in redirect, redirect

    out, err = login.communicate(redirect + "\n", timeout=10)
    assert login.returncode == 0, f"paste login exited {login.returncode}: {err}"
    return redirect


def main():
    global TOKEN_FILE, MOCK_PORT
    server = make_mock()
    MOCK_PORT = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{MOCK_PORT}"

    with tempfile.TemporaryDirectory() as tmp:
        TOKEN_FILE = os.path.join(tmp, "tokens.json")

        # --- 0) offline search & skills (no server involved) ---
        step("offline search & skills")
        out = run_cli("search").stdout
        assert "SQLService" in out, out
        out = run_cli("search", "--service", "SQLService").stdout
        assert "Query" in out, out
        out = run_cli("search", "--operation-id", "SQLService/Query").stdout
        assert "statement" in out and "camelCase" in out, out
        out = run_cli("skill", "query").stdout
        assert "## " in out, out[:200]
        print("   ok: catalog (list/browse/detail) and skill guide")

        # --- 1) login ---
        step("login")
        browser_login(base)
        c = load_tokens()
        assert c["client_id"] == "bb_oauth_test", c
        assert c["access_token"] == "at_1" and c["refresh_token"] == "rt_1", c
        assert c["expires_at"] > time.time(), c
        print("   ok: exchanged and stored at_1/rt_1")

        # --- 1b) headless login: browser on another machine ---
        step("login by pasting the redirect URL (no reachable loopback)")
        os.remove(TOKEN_FILE)
        redirect = paste_login(base)
        c = load_tokens()
        # The mock issues tokens sequentially, so pin the shape, not the value.
        assert c["client_id"] == "bb_oauth_test", c
        assert c["access_token"] and c["refresh_token"], c
        assert c["expires_at"] > time.time(), c
        # The same paste must not be replayable against a fresh login: its
        # state belongs to the attempt that is now over.
        os.remove(TOKEN_FILE)
        stale = subprocess.run(
            [BIN, "login", "--context", base, "--no-browser"],
            input=redirect + "\n", capture_output=True, text=True, env=env(), timeout=15,
        )
        assert stale.returncode != 0, stale.stdout
        assert "state mismatch" in stale.stderr.lower(), stale.stderr
        assert not os.path.exists(TOKEN_FILE), "a stale paste must not store credentials"
        browser_login(base)  # restore the credential the later steps expect
        print("   ok: pasted redirect completes login; stale paste rejected")

        # --- 2) api ---
        step("api (Connect JSON direct call)")
        out = run_cli("api", "MockService/Echo", "--args", '{"x": 1}').stdout
        assert json.loads(out) == {"echo": {"x": 1}}, out
        out = run_cli("api", "MockService/Echo", "--args-file", "-", stdin='{"y": "z"}').stdout
        assert json.loads(out) == {"echo": {"y": "z"}}, out
        # fully-qualified form is accepted too
        out = run_cli("api", "bytebase.v1.MockService/Echo").stdout
        assert json.loads(out) == {"echo": {}}, out
        # Server-side errors surface the connect code, the message, and the
        # one action that resolves that code -- an agent should not have to
        # infer from prose whether to re-login, fix fields, or ask for access.
        out = run_cli("api", "MockService/Echo", "--args", '{"fail": "boom"}', expect_fail=True)
        assert out.returncode != 0 and "boom" in out.stderr, (out.returncode, out.stderr)
        assert "[invalid_argument]" in out.stderr, out.stderr
        assert "bbcli search --operation-id" in out.stderr, out.stderr
        # Every api call names the server it resolved, on stderr only.
        assert f"-> {base}" in out.stderr, out.stderr
        ok = run_cli("api", "MockService/Echo", "--args", '{"x": 1}')
        assert ok.stdout.lstrip().startswith("{"), ok.stdout
        assert f"MockService/Echo -> {base}" in ok.stderr, ok.stderr
        print("   ok: echo, structured errors with recovery hint, target echo")

        # --- 2a) friendly commands: query / schema / change propose ---
        step("query (resolution, flattening, truncation)")
        # The exact tier wins over the substring one, so "employee" is not
        # ambiguous with "employee_archive"; READ_ONLY beats the ADMIN data
        # source listed before it; and asking for limit+1 is what makes
        # `truncated` a fact rather than a guess.
        out = run_cli("query", "employee", "SELECT 1", "--limit", "2")
        result = json.loads(out.stdout)
        assert result["database"] == "instances/pg1/databases/employee", result
        assert result["dataSourceId"] == "ro", result
        assert result["columns"] == ["id", "name", "ts"], result
        assert result["rows"] == [[1, "a", "2026-01-01T00:00:00Z"]] * 2, result
        assert result["rowCount"] == 2 and result["truncated"] is True, result
        assert result["latencyMs"] == 12, result
        # Every underlying call is attributable, exactly like `api`.
        assert f"DatabaseService/ListDatabases -> {base}" in out.stderr, out.stderr
        # The workspace lookup that precedes it is announced too, so the whole
        # chain stays reproducible with `api`.
        assert f"WorkspaceService/GetWorkspace -> {base}" in out.stderr, out.stderr
        assert f"SQLService/Query -> {base}" in out.stderr, out.stderr
        assert 'resolved "employee" ->' in out.stderr, out.stderr

        # Two databases match "emp": the CLI must list them, not choose. A
        # wrong pick here would run SQL against a database nobody named.
        out = run_cli("query", "emp", "SELECT 1", expect_fail=True)
        assert out.returncode != 0, out.stdout
        assert "[AMBIGUOUS_TARGET]" in out.stderr, out.stderr
        assert "instances/pg1/databases/employee" in out.stderr, out.stderr
        assert "instances/my1/databases/employee_archive" in out.stderr, out.stderr
        assert out.stdout == "", "a refusal must not print JSON to stdout"

        # ...and narrowing resolves the same ambiguous input.
        out = run_cli("query", "emp", "SELECT 1", "--instance", "pg1")
        assert json.loads(out.stdout)["database"] == "instances/pg1/databases/employee"

        # A full resource name is taken at its word: one GetDatabase, no listing.
        out = run_cli("query", "instances/pg1/databases/employee", "SELECT 1", "--limit", "1")
        assert json.loads(out.stdout)["rowCount"] == 1, out.stdout
        assert "DatabaseService/GetDatabase ->" in out.stderr, out.stderr
        assert "ListDatabases" not in out.stderr, out.stderr
        assert "GetWorkspace" not in out.stderr, "a full name needs no workspace lookup"

        # The statement can come from stdin, like --args-file does for `api`.
        out = run_cli("query", "employee", "--file", "-", "--limit", "1", stdin="SELECT 1\n")
        assert json.loads(out.stdout)["rowCount"] == 1, out.stdout

        # An error inside a 200 is a failure, not an empty result set.
        out = run_cli("query", "employee", "SELECT bad", expect_fail=True)
        assert out.returncode != 0, out.stdout
        assert "[QUERY_ERROR]" in out.stderr and "syntax error" in out.stderr, out.stderr
        assert out.stdout == "", out.stdout
        print("   ok: tiered resolution, ambiguity refused, flattening, truncation")

        step("schema (summary, drill-down, missing table)")
        out = run_cli("schema", "employee")
        result = json.loads(out.stdout)
        assert result["engine"] == "POSTGRES", result
        table = result["schemas"][0]["tables"][0]
        assert table["name"] == "orders", result
        assert table["rowCount"] == 42, "an int64 string must come back a number"
        assert table["columnCount"] == 2, table
        assert "columns" not in table, "summary must stay compact"
        assert result["schemas"][0]["views"] == ["v_orders"], result

        out = run_cli("schema", "employee", "--table", "orders")
        result = json.loads(out.stdout)
        assert "schemas" not in result, result
        assert result["table"]["columns"][0]["primaryKey"] is True, result
        assert result["table"]["foreignKeys"][0]["referencedTable"] == "users", result
        assert result["table"]["columns"][1]["default"] == "0", "--table implies details"

        out = run_cli("schema", "employee", "--table", "nope", expect_fail=True)
        assert out.returncode != 0, out.stdout
        assert "[TABLE_NOT_FOUND]" in out.stderr, out.stderr
        assert "run without --table" in out.stderr, out.stderr
        assert out.stdout == "", out.stdout

        # MySQL has no named schemas, so --schema is dropped (the mock asserts
        # it never reaches the wire) and the tables still come back. Keeping
        # the filter would return zero tables and read as an empty database.
        out = run_cli("schema", "employee_archive", "--schema", "public", "--include", "columns")
        assert "--schema ignored" in out.stderr and "MYSQL" in out.stderr, out.stderr
        result = json.loads(out.stdout)
        assert result["engine"] == "MYSQL", result
        assert result["schemas"][0]["tables"][0]["columns"][0]["name"] == "id", result
        assert "columnCount" not in result["schemas"][0]["tables"][0], result
        print("   ok: summary vs details, primary keys, TABLE_NOT_FOUND, schema drop")

        step("change propose (chain, rollout gates)")
        sql = "ALTER TABLE t ADD c int"
        out = run_cli("change", "propose", "employee", "--sql", sql, "--title", "add c")
        result = json.loads(out.stdout)
        assert result["sheet"] == "projects/hr/sheets/1", result
        assert result["plan"] == "projects/hr/plans/1", result
        assert result["issue"] == "projects/hr/issues/1", result
        assert server.state["sheet_content"] == sql, server.state["sheet_content"]
        # Successful checks are dropped; the warning is what an agent acts on.
        assert result["planChecks"]["summary"] == {"error": 0, "warning": 1}, result
        assert result["planChecks"]["results"] == [
            {"type": "WARNING", "message": "no index"}
        ], result
        # No --rollout: say so, and stop at the human rather than approving.
        assert result["rolloutDeferredReason"] == "NOT_REQUESTED", result
        assert result["nextAction"] == "AWAIT_HUMAN_APPROVAL", result
        assert result["rolloutCreated"] is False, result
        assert result["links"]["issue"] == f"{base}/projects/hr/issues/1", result
        assert "rollout" not in result["links"], result

        # Asked for, but the approval is still pending: deferred with the
        # reason, not attempted.
        result = json.loads(run_cli(
            "change", "propose", "employee", "--sql", sql, "--title", "add c", "--rollout",
        ).stdout)
        assert result["rolloutDeferredReason"] == "APPROVAL_PENDING", result
        assert result["rolloutCreated"] is False, result
        assert result["nextAction"] == "AWAIT_HUMAN_APPROVAL", result

        # Approved, checks clean: now the rollout is created and the agent is
        # sent to watch it.
        server.state["approval"] = "APPROVED"
        result = json.loads(run_cli(
            "change", "propose", "employee", "--sql", sql, "--title", "add c",
            "--rollout", "--reason", "TICKET-1",
        ).stdout)
        assert result["rolloutCreated"] is True, result
        assert result["rollout"] == "projects/hr/plans/1/rollout", result
        assert result["nextAction"] == "MONITOR_ROLLOUT", result
        assert "rolloutDeferredReason" not in result, result
        assert result["links"]["rollout"] == f"{base}/projects/hr/plans/1/rollout", result
        server.state["approval"] = "PENDING"
        print("   ok: sheet/plan/checks/issue chain, rollout gates, links")

        # --- 2b) config family ---
        step("config (view / use / check / path)")
        out = run_cli("config", "view").stdout
        assert f"Effective server: {base}" in out and "default" in out, out
        out = run_cli("config", "path").stdout.split()
        assert TOKEN_FILE in out, out
        assert any(p.endswith("config.yaml") for p in out), out
        out = run_cli("config", "use", base).stdout
        assert "Active context set to" in out, out
        # use on a not-logged-in server must fail without touching the default
        out = run_cli("config", "use", "https://other.example.com", expect_fail=True)
        assert out.returncode != 0 and "login" in out.stderr, out.stderr
        out = run_cli("config", "check").stdout
        assert "connectivity: ok (version mock-1)" in out, out
        assert "credentials:  ok" in out, out
        print("   ok: view/use/check/path, use rejects unknown servers")

        # --- 2c) contexts: named servers, aliases, project file ---
        step("contexts (--as, alias resolution, .bbcli)")
        server2 = make_mock()
        threading.Thread(target=server2.serve_forever, daemon=True).start()
        base2 = f"http://127.0.0.1:{server2.server_address[1]}"

        browser_login(base, "--as", "prod")
        browser_login(base2, "--as", "staging")
        out = run_cli("config", "view").stdout
        assert "prod -> " + base in out, out
        assert "staging -> " + base2 in out, out

        # Alias works for --context; lands on the second server's credentials.
        out = run_cli("api", "MockService/Echo", "--args", '{"x": 1}', "--context", "staging").stdout
        assert json.loads(out) == {"echo": {"x": 1}}, out

        # config use by name; a bare call then hits that server.
        run_cli("config", "use", "prod")
        out = run_cli("api", "MockService/Echo").stdout
        assert json.loads(out) == {"echo": {}}, out

        # Project-level .bbcli overrides the global default.
        projdir = os.path.join(tmp, "proj")
        os.makedirs(projdir, exist_ok=True)
        with open(os.path.join(projdir, ".bbcli"), "w") as f:
            f.write("staging\n")
        cwd = os.getcwd()
        os.chdir(projdir)
        try:
            out = run_cli("config", "view").stdout
            assert "project file (.bbcli)" in out, out
            out = run_cli("api", "MockService/Echo").stdout
            assert json.loads(out) == {"echo": {}}, out
            # ... but an explicit --context still wins.
            out = run_cli("api", "MockService/Echo", "--context", "prod").stdout
            assert json.loads(out) == {"echo": {}}, out
        finally:
            os.chdir(cwd)
        # Leave prod active for the following scenarios.
        print("   ok: named logins, aliases, project file, precedence")

        # --- 3) 401 recovery ---
        step("401 -> refresh -> replay")
        write_tokens(access_token="at_stale", expires_at=9999999999)
        out = run_cli("api", "MockService/Echo", "--args", '{"x": 1}').stdout
        assert json.loads(out) == {"echo": {"x": 1}}, out
        c = load_tokens()
        assert c["access_token"].startswith("at_") and c["refresh_token"] != "rt_stale", c
        assert c["access_token"] != "at_stale", c
        print("   ok: recovered and persisted rotated credentials")

        # --- 4) cross-process adoption ---
        step("adopt refresh token rotated by another process")
        write_tokens(expires_at=1)  # locally expired memory copy
        fifo = os.path.join(tmp, "in.fifo")
        os.mkfifo(fifo)
        out_path = os.path.join(tmp, "call.out")
        # The parent holds an O_RDWR fd as a keepalive writer (never blocks,
        # prevents EOF); the child gets a plain read end, so closing the
        # keepalive later terminates it. --args-file - makes the CLI block on
        # stdin AFTER loading credentials from the file — that gap is where
        # another process rotates the token.
        keepalive = os.open(fifo, os.O_RDWR)
        call = subprocess.Popen(
            [BIN, "api", "MockService/Echo", "--args-file", "-", "--context", base],
            stdin=os.open(fifo, os.O_RDONLY), stdout=open(out_path, "w"),
            stderr=subprocess.PIPE, text=True, env=env(),
        )
        time.sleep(0.5)  # CLI has loaded the (expired) at_2/rt_2, now waits on stdin

        # another process rotates the live refresh token and rewrites the file
        old_rt = load_tokens()["refresh_token"]
        req = urllib.request.Request(
            f"{base}/api/oauth2/token",
            data=f"grant_type=refresh_token&refresh_token={old_rt}&client_id=bb_oauth_test".encode(),
        )
        resp = json.loads(urllib.request.urlopen(req).read())
        assert resp["refresh_token"] != old_rt, resp
        write_tokens(access_token=resp["access_token"],
                     refresh_token=resp["refresh_token"],
                     expires_at=int(time.time()) + 3600)
        calls_before = server.state["refresh_calls"]

        os.write(keepalive, b'{"q": "y"}\n')
        os.close(keepalive)  # EOF after the line
        assert call.wait(timeout=10) == 0, call.stderr.read()
        result = json.loads(open(out_path).read())
        assert result == {"echo": {"q": "y"}}, result
        assert server.state["refresh_calls"] == calls_before, (
            "process burned the dead refresh token instead of adopting the file's"
        )
        print("   ok: adopted rt_3 from file, no wasted refresh call")

        # --- 5) logout ---
        step("logout (context-aware)")
        run_cli("logout")  # active context is prod -> server A
        assert server.state["refresh"] is None, "server did not revoke the refresh token"
        cfg = open(os.path.join(tmp, "config.yaml")).read()
        assert "prod:" not in cfg, "context not removed with its server"
        assert "staging:" in cfg, "unrelated context should survive"
        # tokens.json stays credentials-only throughout.
        assert list(json.load(open(TOKEN_FILE)).keys()) == ["servers"]
        run_cli("logout", "--context", "staging")
        assert server2.state["refresh"] is None
        assert not json.load(open(TOKEN_FILE))["servers"], "credentials not removed locally"
        print("   ok: revoked server-side, contexts and credentials cleaned")

    server.shutdown()
    print("\nALL E2E SCENARIOS PASSED")


if __name__ == "__main__":
    main()
