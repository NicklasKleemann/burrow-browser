"""scan_secrets, cors_check, exposure_check, tls_audit, session_audit.
Offline: a local HTTP server with deliberately bad behaviour, and a local TLS server with a
self-signed, soon-expiring certificate."""
import asyncio, datetime, http.server, os, ssl, sys, tempfile, threading
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # server.py is one folder up
import server

APP_JS = b"""const cfg = {region: "eu", apiKey: "abcd1234efgh5678", db: "db1.corp", host: "10.1.2.3"};
const aws = "FAKE_AWS";
const t = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
const env = {NUXT_ENV_SEARCH_API_KEY:"9c1e5b7a2f8d4e6b0a3c5d7e9f1b2a4c",NUXT_ENV_GATEWAY_CLIENT_ID_B2B:"1b2c3d4e-aaaa-4bbb-8ccc-123456789abc",
  NUXT_ENV_DATADOG_CLIENT_TOKEN:"pub0123456789abcdef0123456789abcdef",NUXT_ENV_TABLE_QUERY:"?sv=2019-12-12&ss=t&sp=r&sig=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789%3D",
  applicationId:"00000000-0000-0000-0000-000000000000"};
const noise = {key:"sliderOptions", RowKey:"3548c671-0000-4000-8000-2819abcceb06", AccessToken:"gig_access_token"}; x.apiKey=e.config.apiKey;
const mapUrl = "https://tiles.example.net/v1/style.json?token=Zm9vYmFyYmF6cXV4MTIzNDU2";
const db = "postgres://admin:S3cr3tPassw0rd@db1.internal:5432/app", demo = "postgres://user:password@localhost/db";
const store = "DefaultEndpointsProtocol=https;AccountName=acct;FAKE_AZURE";
const dsn = "https://4f9c2b7e8d1a3f5c6b0e9d2a7c4f1b3e@o12345.ingest.sentry.io/678";
const h = {Authorization: "Bearer Zx9QwErTy7UiOpAs4DfG"};
const gl = "FAKE_GITLAB", np = "FAKE_NPM", hf = "FAKE_HF";
var q="Xk92LmPq7RtZ4vBn8WcY3HsJ";
//# sourceMappingURL=app.js.map
"""
# Fake provider tokens are assembled here so the source never holds a token-shaped literal
# (GitHub push protection would block the repo).
for _mark, _token in {b"FAKE_AWS": b"AKIA" + b"ABCDEFGHIJKLMNOP",
                      b"FAKE_AZURE": b"AccountKey=" + b"Qm9ndXNLZXlGb3JUZXN0aW5nT25seTEyMzQ1Njc4OTA=",
                      b"FAKE_GITLAB": b"glpat" + b"-Ab3dEf6hIj9kLmN0pQrS",
                      b"FAKE_NPM": b"npm" + b"_Ab3dEf6hIj9kLmN0pQrStUvWxYz012345678",
                      b"FAKE_HF": b"hf" + b"_Ab3dEf6hIj9kLmN0pQrStUvWxYz01234"}.items():
    APP_JS = APP_JS.replace(_mark, _token)
logged_in = set()


class H(http.server.BaseHTTPRequestHandler):
    def reply(self, body=b"", status=200, ctype="text/html", headers=()):
        self.send_response(status)
        self.send_header("content-type", ctype)
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.do_GET()

    def do_GET(self):
        path, _, query = self.path.partition("?")
        cookies = dict(c.strip().split("=", 1) for c in self.headers.get("cookie", "").split(";") if "=" in c)
        origin = self.headers.get("origin")
        sid = cookies.get("sid")
        if path == "/app":
            return self.reply(b"<title>app</title><script src=/static/app.js></script>"
                              b"<script>window.appCfg = {svc: {apiSecret: ['Qz7', 'Lm2Vn9Bx4Kp8Rt'].join('')}}</script>")
        if path == "/static/app.js":
            return self.reply(APP_JS, ctype="application/javascript")
        if path == "/static/app.js.map":
            return self.reply(b'{"version":3,"sources":["src/a.ts","src/b.ts"],"mappings":""}', ctype="application/json")
        if path == "/.git/HEAD":
            return self.reply(b"ref: refs/heads/main\n", ctype="text/plain")
        if path == "/.env":
            return self.reply(b"DB_PASSWORD=hunter2\n", ctype="text/plain")
        if path == "/robots.txt":
            return self.reply(b"User-agent: *\nDisallow: /admin\nDisallow: /internal/\n", ctype="text/plain")
        if path == "/hidden":
            return self.reply(b"secret area")
        if path == "/api/data":  # reflects any Origin, with credentials
            return self.reply(b"{}", ctype="application/json", headers=[
                ("Access-Control-Allow-Origin", origin or "*"), ("Access-Control-Allow-Credentials", "true"),
                ("Access-Control-Allow-Methods", "GET, PUT, DELETE")] if origin else [])
        if path == "/api/safe":
            return self.reply(b"{}", ctype="application/json", headers=[
                ("Access-Control-Allow-Origin", "https://good.example"), ("Vary", "Origin")])
        if path == "/":  # hands out a session id before login
            return self.reply(b"<title>home</title>", headers=[] if sid else [("Set-Cookie", f"sid={os.urandom(6).hex()}; Path=/")])
        if path == "/login":  # vulnerable: keeps the pre-login id unless ?rotate
            if "rotate" in query:
                sid = os.urandom(6).hex()
            logged_in.add(sid)
            return self.reply(b"<title>in</title>", headers=[("Set-Cookie", f"sid={sid}; Path=/")])
        if path == "/logout":  # vulnerable: forgets the cookie in the browser, not on the server
            return self.reply(b"<title>out</title>", headers=[("Set-Cookie", "sid=; Path=/; Max-Age=0")])
        if path == "/account":
            return self.reply(b"Welcome back" if sid in logged_in else b"Please log in")
        return self.reply(b"not found", status=404, ctype="text/plain")

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
srv.handle_error = lambda *a: None  # tls_audit is pointed at this plain-HTTP port on purpose
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{srv.server_address[1]}"


def tls_server():
    """Self-signed localhost cert, valid 10 more days; TLS 1.2+ only."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=10, hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False).sign(key, hashes.SHA256()))
    d = tempfile.mkdtemp()
    open(f"{d}/c.pem", "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(f"{d}/k.pem", "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(f"{d}/c.pem", f"{d}/k.pem")
    s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    s.socket = ctx.wrap_socket(s.socket, server_side=True, do_handshake_on_connect=False)
    s.handle_error = lambda *a: None  # refused handshakes are the point; keep stderr quiet
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s.server_address[1]


async def main():
    # --- scan_secrets: keys in a bundle, redacted; downloadable source map ---
    await server.navigate(BASE + "/app")
    sc = (await server.scan_secrets())["result"]
    kinds = {f["kind"]: f for f in sc["findings"]}
    assert kinds["aws_access_key"]["severity"] == "high" and kinds["aws_access_key"]["value"] == "AKIA…MNOP", kinds
    assert kinds["aws_access_key"]["urls"] == [BASE + "/static/app.js"]
    assert {"jwt", "credential_assignment", "internal_host", "azure_sas_token", "datadog_client_token",
            "credential_in_url"} <= set(kinds), kinds
    for kind in ("url_credentials", "azure_storage_key", "sentry_dsn", "auth_header_literal", "gitlab_token",
                 "npm_token", "huggingface_token", "runtime_config"):
        assert kind in kinds, (kind, sorted(kinds))
    assert kinds["url_credentials"]["name"] == "admin" and kinds["url_credentials"]["severity"] == "high"
    assert kinds["runtime_config"]["name"] == "window.appCfg.svc.apiSecret", kinds["runtime_config"]
    assert not any(f.get("name") == "user" for f in sc["findings"]), "placeholder user:password reported"
    cand = [c for c in sc["candidates"] if c["value"] == "Xk92…3HsJ"]
    assert cand and "var q=" in cand[0]["context"] and cand[0]["length"] == 24, sc["candidates"]
    assert sc["candidates_total"] >= len(sc["candidates"])
    assert any(f["value"] == "AKIA" + "ABCDEFGHIJKLMNOP" for f in (await server.scan_secrets(reveal=True))["result"]["findings"]), "reveal"
    names = {f.get("name") for f in sc["findings"]}
    assert {"apiKey", "NUXT_ENV_SEARCH_API_KEY", "NUXT_ENV_GATEWAY_CLIENT_ID_B2B"} <= names, names
    values = " ".join(f["value"] for f in sc["findings"])
    for noise in ("slid", "3548", "gig_", "0000", ".con"):  # Vue keys, row keys, identifiers, placeholders, code
        assert noise not in values, (noise, sc["findings"])
    assert {f["value"] for f in sc["findings"] if f["kind"] == "internal_host"} == {"db1.corp", "10.1.2.3", "db1.internal"}
    assert sc["findings"][0]["severity"] == "high", "sorted by severity"
    assert sc["source_maps"][0]["sample_sources"] == ["src/a.ts", "src/b.ts"], sc["source_maps"]
    assert (await server.scan_secrets(check_source_maps=False))["result"]["source_maps"] == []

    # --- cors_check ---
    bad = (await server.cors_check(BASE + "/api/data"))["result"]
    issues = [f["issue"] for f in bad["findings"] if f["severity"] == "high"]
    assert any("untrusted.example with credentials" in i for i in issues), bad["findings"]
    assert any("null origin" in i for i in issues), bad["findings"]
    assert any("Vary" in f["issue"] for f in bad["findings"]), bad["findings"]
    assert any("PUT" in f["issue"] for f in bad["findings"] if f["severity"] == "info"), "preflight"
    assert (await server.cors_check(BASE + "/api/safe"))["result"]["findings"] == []

    # --- exposure_check ---
    ex = (await server.exposure_check(paths=["/hidden", "/nope"]))["result"]
    got = {f["path"]: f for f in ex["findings"]}
    assert got["/.git/HEAD"]["severity"] == "high" and got["/.env"]["severity"] == "high", got
    assert "/hidden" in got and "/nope" not in got and "/.git/config" not in got, got
    assert ex["robots_disallow"] == ["/admin", "/internal/"] and ex["security_txt"] is False, ex
    assert "hunter2" not in str(ex), "file contents must not be returned"

    # --- session_audit: fixation and logout invalidation on a vulnerable app, then a fixed login ---
    await server.navigate(BASE + "/")
    await server.session_audit("mark", "before")
    await server.navigate(BASE + "/login")
    cmp = await server.session_audit("compare", "before")
    assert cmp["result"]["unchanged"] == ["sid"] and "fixation" in cmp["findings"][0]["issue"], cmp
    await server.session_audit("mark", "authed")
    assert (await server.navigate(BASE + "/logout"))["title"] == "out"
    rep = await server.session_audit("replay", "authed", url=BASE + "/account", expect_text="Welcome back")
    assert rep["result"]["contains_expect_text"] and rep["findings"], rep
    await server.navigate(BASE + "/account")
    assert (await server.get_text())["result"] == "Please log in", "replay must not touch the session's own cookies"
    await server.navigate(BASE + "/")
    await server.session_audit("mark", "before")
    await server.navigate(BASE + "/login?rotate=1")
    cmp = await server.session_audit("compare", "before")
    assert cmp["findings"] == [] and cmp["result"]["changed"] == ["sid"], cmp
    try:
        await server.session_audit("compare", "never")
    except ValueError:
        pass
    else:
        raise AssertionError("compare without mark accepted")

    # --- tls_audit: self-signed, expiring, TLS 1.2+ only ---
    port = tls_server()
    t = (await server.tls_audit("localhost", port))["result"]
    issues = {f["issue"]: f["severity"] for f in t["findings"]}
    assert any("not trusted" in i and s == "high" for i, s in issues.items()), t
    assert "Certificate expires in 10 days" in issues, issues
    assert t["protocols"]["TLSv1_2"] == "accepted" and t["protocols"]["TLSv1"] != "accepted", t["protocols"]
    assert t["cert"]["san"] == ["localhost"] and t["cert"]["days_left"] == 10, t["cert"]
    assert not any("Accepts" in i for i in issues), issues
    assert "error" in (await server.tls_audit("localhost", srv.server_address[1]))["result"], "plain-HTTP port"
    print("ok | tls protocols", t["protocols"], "| weak", t["weak_ciphers"])
    await server._state["cm"].__aexit__(None, None, None)

asyncio.run(main())
