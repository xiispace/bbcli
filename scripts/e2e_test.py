#!/usr/bin/env python3
"""End-to-end test for bbcli against an in-process mock Bytebase server.

The mock speaks the Connect JSON protocol (POST /bytebase.v1.Svc/Method with
Bearer auth and connect-protocol-version), like the real server's connect
handlers. Covers, in order:
  1. login: RFC 7591 registration -> PKCE authorize redirect -> loopback
     callback -> authorization-code exchange -> token file written
  2. api: direct Connect call, args and --args-file, error propagation
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

import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "target", "debug", "bbcli")
TOKEN_FILE = ""
MOCK_PORT = 0

def make_mock():
    """A mock Bytebase server with its own rotating credential state."""
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.state = {"access": None, "refresh": None, "n": 0, "refresh_calls": 0}
    return httpd


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
