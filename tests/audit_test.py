"""snapshot, tabs (popups), route (mocks/failures/delays), security_headers, close_session.
Offline: serves its own pages from a local stdlib HTTP server."""
import asyncio, http.server, json, os, sys, tempfile, threading, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # server.py is one folder up
import server

HOME = b"""<title>home</title><h1>Orders</h1><button>Save</button><button></button>
<label>Email <input id=em value="a@b.c"></label>
<a id=pop href="/popup" target="_blank">open</a>
<button id=win onclick="window.open('/popup')">win</button><div id=out></div>
<button id=load onclick="fetch('/api/items').then(r => r.ok ? r.json() : Promise.reject(r.status))
  .then(j => out.textContent = 'items:' + j.length).catch(e => out.textContent = 'error:' + e)">load</button>"""
POPUP = b"""<title>popup</title><script>console.log('from popup')</script>
<button id=bye onclick="window.close()">close</button>"""
HOME_HEADERS = {"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
                "X-Powered-By": "PHP/8.1", "Set-Cookie": "session_id=abc; Path=/"}


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body, ctype, extra = {"/home": (HOME, "text/html", HOME_HEADERS), "/popup": (POPUP, "text/html", {}),
                              "/api/items": (b"[1,2,3]", "application/json", {})}.get(self.path, (b"ok", "text/plain", {}))
        self.send_response(200)
        self.send_header("content-type", ctype)
        for k, v in extra.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{srv.server_address[1]}"


async def out():
    return (await server.query("#out"))["result"]["items"][0]["text"]


async def main():
    await server.navigate(BASE + "/home")

    # --- snapshot: roles + names, usable as selectors, unlabeled controls visible ---
    snap = (await server.snapshot())["result"]
    for line in ('heading "Orders"', 'button "Save"', 'textbox "Email"'):
        assert line in snap, snap
    assert any(l.strip() == "- button" for l in snap.splitlines()), "unlabeled button should show bare"
    assert 'button "Save"' in (await server.snapshot("role=button[name='Save']"))["result"]

    # --- route: real, 500, empty, delay, abort, clear, offline ---
    await server.click("#load")
    assert await out() == "items:3"
    await server.route("/api/items", "fulfill", status=500)
    await server.click("#load")
    assert await out() == "error:500"
    rules = (await server.route("/api/items", "fulfill", body="[]"))["result"]
    assert len(rules) == 1 and rules[0]["hits"] == 0, rules  # same pattern replaces its rule
    await server.navigate(BASE + "/home")  # rules survive navigate
    await server.click("#load")
    assert await out() == "items:0"
    assert (await server.route())["result"][0]["hits"] == 1
    await server.route("/api/items", "delay", delay_ms=1500)
    t0 = time.monotonic()
    await server.click("#load")
    assert time.monotonic() - t0 >= 1.4 and await out() == "items:3", "delay"
    await server.route("/api/items", "abort")
    await server.click("#load")
    assert (await out()).startswith("error:"), await out()
    assert (await server.route(action="clear"))["result"] == []
    await server.click("#load")
    assert await out() == "items:3"
    await server.route("", "abort")  # offline
    try:
        await server.navigate(BASE + "/home")
    except Exception:
        pass
    else:
        raise AssertionError("offline navigate succeeded")
    await server.route(action="clear")
    try:
        await server.route("x", "explode")
    except ValueError:
        pass
    else:
        raise AssertionError("bad route action accepted")

    # --- tabs: target=_blank and window.open popups, switch, self-close, close ---
    await server.navigate(BASE + "/home")
    r = await server.click("#pop")
    assert r.get("new_tabs"), r
    t = (await server.tabs())["result"]
    assert len(t) == 2 and t[0]["current"] and not t[1]["current"], t
    t = (await server.tabs(switch=1))["result"]
    assert t[1]["current"], t
    await server.wait_for(load_state="load")
    assert (await server.get_text())["result"].strip() == "close", "tools act on switched tab"
    await server.tabs(close=1)  # closing the current tab falls back to the other
    t = (await server.tabs())["result"]
    assert len(t) == 1 and t[0]["current"] and t[0]["title"] == "home", t
    hinted = "new_tabs" in await server.click("#win")
    for _ in range(30):  # browser events can lag the popup by up to ~1 s
        if len((await server.tabs())["result"]) == 2 and any(
                e["text"] == "from popup" for e in (await server.console_logs())["result"]):
            break
        await asyncio.sleep(0.1)
    else:
        raise AssertionError("window.open popup or its console output not seen")
    assert any(r["url"].endswith("/popup") for r in (await server.requests())["result"]), "popup's first load logged"
    print("window.open reported in click result:", hinted)
    await server.tabs(switch=1)
    await server.click("#bye")  # the popup closes itself
    t = (await server.tabs())["result"]
    assert len(t) == 1 and t[0]["title"] == "home", t
    try:
        await server.tabs(switch=5)
    except IndexError:
        pass
    else:
        raise AssertionError("bad tab index accepted")

    # --- security_headers: live page, plus the pure audit on good/nonce headers ---
    await server.navigate(BASE + "/home")
    sh = (await server.security_headers())["result"]
    issues = " | ".join(f["issue"] for f in sh["findings"])
    for want in ("'unsafe-inline'", "embed the page in a frame", "plain HTTP", "nosniff", "x-powered-by: PHP/8.1",
                 "session_id looks like a credential but lacks HttpOnly"):
        assert want in issues, (want, issues)
    assert sh["headers"]["content-security-policy"].startswith("default-src"), sh["headers"]
    good = {"content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "strict-transport-security": "max-age=31536000", "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin", "permissions-policy": "camera=()", "server": "nginx"}
    assert server._audit_headers(good, True) == [], server._audit_headers(good, True)
    nonce = dict(good, **{"content-security-policy": "script-src 'unsafe-inline' 'nonce-abc'; frame-ancestors 'self'"})
    assert server._audit_headers(nonce, True) == [], "nonce neutralizes unsafe-inline"
    weak = dict(good, **{"strict-transport-security": "max-age=60", "content-security-policy": "script-src *"})
    assert {f["issue"] for f in server._audit_headers(weak, True)} >= {
        "HSTS max-age under 180 days", "CSP script-src allows any source via *"}

    # --- MCP shape for the new tools ---
    for tool, args in (("snapshot", {}), ("tabs", {}), ("route", {}), ("security_headers", {})):
        blocks = await server.mcp.call_tool(tool, args)
        assert len(blocks) == 1 and "result" in json.loads(blocks[0].text), tool

    # --- close_session: saves a running recording (mocks survive the recording swap), then starts fresh ---
    await server.navigate(BASE + "/home", session="c")
    await server.route("/api/items", "fulfill", body="[9]", session="c")
    har = os.path.join(tempfile.gettempdir(), "burrow-audit-test.har")
    await server.start_recording(har, session="c")
    await server.click("#load", session="c")
    assert (await server.query("#out", session="c"))["result"]["items"][0]["text"] == "items:1", "mock lost in recording"
    closed = await server.close_session(session="c")
    assert closed == {"result": "closed", "har": har} and os.path.getsize(har) > 0, closed
    assert (await server.route(session="c"))["result"] == [], "session state not forgotten"
    assert (await server.close_session(session="c"))["result"] == "closed"
    assert (await server.close_session(session="c"))["result"] == "no open session"
    assert (await server.tabs())["result"][0]["title"] == "home", "other session untouched"
    print("ok")
    await server._state["cm"].__aexit__(None, None, None)

asyncio.run(main())
