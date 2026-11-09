"""wait_for, form tools (hover/select_option/check/upload_file), dialogs, query, storage, plus
regressions: navigate on a page that never goes network-idle, and download sending set_browser_headers.
Offline: serves its own pages from a local stdlib HTTP server."""
import asyncio, http.server, json, os, sys, tempfile, threading, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server

APP = b"""<title>app</title><div class=spinner>loading</div>
<div id=menu>Menu<ul id=sub style="display:none"><li>Item</li></ul></div>
<select id=s><option value=a>Alpha</option><option value=b>Beta</option></select>
<input type=checkbox id=c><input type=radio name=r id=r1><input type=radio name=r id=r2>
<input type=file id=f multiple><input id=e value=pre><p class=err style="visibility:hidden">bad</p>
<button id=conf onclick="document.title = confirm('sure?') + ':' + prompt('name?', 'def')">c</button>
<button id=go onclick="history.pushState({}, '', '/app/done')">go</button>
<script>
menu.onmouseenter = () => sub.style.display = 'block';
f.onchange = () => document.title = [...f.files].map(x => x.name).join(',');
localStorage.setItem('access_token', 'x'); localStorage.setItem('theme', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig');
localStorage.setItem('lang', 'en'); sessionStorage.setItem('cart', '[1,2]');
const o = indexedDB.open('appdb', 1);
o.onupgradeneeded = () => o.result.createObjectStore('users', {keyPath: 'id'}).put({id: 1, name: 'ann'});
o.onsuccess = () => window.idb = true;
setTimeout(() => { document.querySelector('.spinner').remove();
  document.body.insertAdjacentHTML('beforeend', '<div id=result>Loaded 3 rows</div>'); window.ready = true; }, 2000);
</script>"""
seen = []


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        seen.append({k.lower(): v for k, v in self.headers.items()})
        if self.path == "/poll":
            time.sleep(30)  # a long poll that keeps the page from ever going network-idle
        self.send_response(200)
        self.send_header("content-type", "text/html")
        self.end_headers()
        self.wfile.write({"/app": APP, "/spa": b"<script>setInterval(() => fetch('/poll'), 300)</script>"}
                         .get(self.path, b"ok"))

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{srv.server_address[1]}"


async def main():
    # --- wait_for: the page isn't ready when navigate returns; waiting fixes the race ---
    await server.navigate(BASE + "/app")
    assert (await server.query(".spinner"))["result"]["count"] == 1, "spinner should still be there"
    assert (await server.query("#result"))["result"]["count"] == 0
    w = await server.wait_for(selector=".spinner", state="hidden")
    assert w["result"] and w["failed"] is None and w["elapsed_ms"] > 0, w
    assert (await server.wait_for(text="Loaded 3 rows", js="() => window.ready && window.idb"))["result"]
    miss = await server.wait_for(selector="#nope", timeout=300)
    assert miss["result"] is False and miss["failed"] == "selector", miss
    await server.click("#go")  # pushState route change, no navigation
    assert (await server.wait_for(url="/app/done", timeout=2000))["result"]
    try:
        await server.wait_for()
    except ValueError:
        pass
    else:
        raise AssertionError("wait_for with no condition accepted")

    # --- query: targeted asserts ---
    q = (await server.query("#e"))["result"]
    assert q["count"] == 1 and q["items"][0]["value"] == "pre" and q["items"][0]["visible"], q
    err = (await server.query(".err"))["result"]["items"][0]
    assert err["visible"] is False and err["text"] == "bad" and err["attrs"]["class"] == "err", err
    assert (await server.query("input", limit=2))["result"]["count"] > 2 == len((await server.query("input", limit=2))["result"]["items"])

    # --- hover / select_option / check / upload_file ---
    assert not (await server.query("#sub"))["result"]["items"][0]["visible"]
    await server.hover("#menu")
    assert (await server.query("#sub"))["result"]["items"][0]["visible"], "hover menu"
    assert (await server.select_option("#s", ["Beta"]))["result"] == ["b"], "select by label"
    assert (await server.select_option("#s", ["a"]))["result"] == ["a"], "select by value"
    await server.check("#c")
    await server.check("#r2")
    assert (await server.query("#c"))["result"]["items"][0]["checked"]
    assert (await server.query("#r2"))["result"]["items"][0]["checked"]
    await server.check("#c", checked=False)
    assert not (await server.query("#c"))["result"]["items"][0]["checked"]
    with tempfile.TemporaryDirectory() as d:
        files = [os.path.join(d, n) for n in ("a.txt", "b.txt")]
        for f in files:
            open(f, "w").write("x")
        up = await server.upload_file("#f", files)
        assert up["result"] == files and up["title"] == "a.txt,b.txt", up
        try:
            await server.upload_file("#f", [os.path.join(d, "missing.txt")])
        except FileNotFoundError:
            pass
        else:
            raise AssertionError("missing upload file accepted")

    # --- dialogs: dismissed + recorded by default, accepted on request ---
    assert (await server.click("#conf"))["title"] == "false:null", "dismiss policy"
    ds = (await server.dialogs())["result"]
    assert [(d["type"], d["message"], d["action"]) for d in ds] == [("confirm", "sure?", "dismiss"), ("prompt", "name?", "dismiss")], ds
    assert ds[1]["default_value"] == "def", ds
    assert (await server.dialogs("accept", "bob"))["policy"] == "accept"
    assert (await server.click("#conf"))["title"] == "true:bob", "accept policy"
    await server.dialogs("dismiss")

    # --- storage: local/session/IndexedDB, tokens flagged ---
    st = (await server.storage())["result"]
    assert st["origin"] == BASE and st["local"]["lang"] == "en" and st["session"]["cart"] == "[1,2]", st
    assert json.loads(st["indexeddb"]["appdb"]["stores"]["users"]["records"][0]) == {"id": 1, "name": "ann"}, st
    assert sorted(st["sensitive"]) == ["local:access_token", "local:theme"], st["sensitive"]  # key match, JWT value match
    assert set((await server.storage("session"))["result"]) == {"origin", "session", "sensitive"}

    # --- MCP shape: one JSON text block per tool, like a client sees it ---
    for tool, args in (("query", {"selector": "#e"}), ("storage", {}), ("dialogs", {}), ("wait_for", {"selector": "#e"})):
        blocks = await server.mcp.call_tool(tool, args)
        assert len(blocks) == 1 and "result" in json.loads(blocks[0].text), tool

    # --- dialog survives a navigate to an opaque origin; storage reports, doesn't crash ---
    await server.navigate("data:text/html,<script>alert('hello')</script>")
    assert (await server.dialogs())["result"][0]["message"] == "hello"
    assert "local_error" in (await server.storage("local"))["result"]

    # --- regression: download sends set_browser_headers headers (and navigate still does) ---
    await server.set_browser_headers({"X-Auth": "t0ken"})
    await server.navigate(BASE + "/page")
    assert seen[-1].get("x-auth") == "t0ken", seen[-1]
    await server.download(BASE + "/dl", os.path.join(tempfile.gettempdir(), "burrow-forms-test.bin"))
    assert seen[-1].get("x-auth") == "t0ken", "download dropped browser headers"
    await server.set_browser_headers({})
    await server.download(BASE + "/dl", os.path.join(tempfile.gettempdir(), "burrow-forms-test.bin"))
    assert "x-auth" not in seen[-1], "headers not cleared"

    # --- regression: a page that polls forever still navigates (used to raise after 30 s) ---
    t0 = time.monotonic()
    r = await server.navigate(BASE + "/spa")
    assert r["status"] == 200 and time.monotonic() - t0 < 20, r
    print("ok", round(time.monotonic() - t0, 1), "s spa navigate")
    await server._state["cm"].__aexit__(None, None, None)

asyncio.run(main())
