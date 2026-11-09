# /// script
# dependencies = ["mcp>=1.0,<2", "camoufox[geoip]"]
# ///
import asyncio, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # server.py is one folder up
import server
async def main():
    r = await server.navigate("https://example.com")
    assert r["status"] == 200, r
    assert any("iana" in l["href"] for l in (await server.links())["result"]), "links"
    assert any(q["type"] == "document" and q["status"] == 200 for q in (await server.requests())["result"]), "requests"
    assert (await server.evaluate("async () => document.title"))["result"] == r["title"], "evaluate"
    await server.evaluate("mw_probe = 42")  # page global, invisible to the isolated world
    assert (await server.evaluate("window.mw_probe"))["result"] == 42, "main world"
    assert (await server.evaluate("window.mw_probe", main_world=False))["result"] is None, "isolated world"
    form = "<input id=q><button onclick=\"document.title='clicked'\">go</button><script>q.onkeydown=e=>{if(e.key=='Enter')document.title=q.value}</script>"
    await server.navigate("data:text/html," + form)
    await server.type_text("#q", "abc")
    assert (await server.press("Enter"))["title"] == "abc", "type_text + press"
    assert (await server.click("button"))["title"] == "clicked", "click"
    for tool in ("get_text", "get_html", "links", "requests"):  # same shape as a client sees it
        blocks = await server.mcp.call_tool(tool, {})
        assert len(blocks) == 1 and "result" in json.loads(blocks[0].text), tool
    await server.navigate("https://example.com")
    q = [r for r in (await server.requests(type="document", details=True))["result"] if r["status"] in (200, 304)]
    # A repeat load may be a 304, which has no content-type, so only check headers were captured.
    assert q and q[0]["response_headers"] and q[0]["request_headers"], "requests details"
    assert "response_headers" not in (await server.requests())["result"][0], "requests brief"
    await server.evaluate("document.cookie = 'smoke=1; path=/'")
    har = "/tmp/burrow-browser-smoke.har"
    await server.start_recording(har)
    assert "smoke=1" in (await server.evaluate("document.cookie"))["result"], "cookie lost on start_recording"
    await server.evaluate("async () => (await fetch('/?probe=1')).status")
    saved = await server.stop_recording()
    entries = json.load(open(har))["log"]["entries"]
    assert any("probe=1" in e["request"]["url"] and e["response"]["content"].get("text") for e in entries), "har body"
    assert "smoke=1" in (await server.evaluate("document.cookie"))["result"], "cookie lost on stop_recording"
    print("har", saved, len(entries), "entries")
    d = await server.download("https://example.com", "/tmp/burrow-browser-smoke.html")
    assert d["status"] == 200 and d["bytes"] > 0, d
    print("ok", r, d)
    await server._state["cm"].__aexit__(None, None, None)
asyncio.run(main())
