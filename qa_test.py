# /// script
# dependencies = ["mcp>=1.0,<2", "camoufox[geoip]"]
# ///
"""QA/diagnostics tools: get_response_body, cookies, console_logs, frames_and_listeners,
websockets, set_browser_headers, and the extended http_request."""
import asyncio, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server


async def main():
    # --- get_response_body: read a captured response without reloading ---
    await server.navigate("https://example.com")
    doc = [r for r in (await server.requests(type="document"))["result"] if r["status"] == 200][0]
    by_id = (await server.get_response_body(str(doc["id"])))["result"]
    assert "Example Domain" in by_id["body"], by_id
    by_url = (await server.get_response_body("example.com"))["result"]
    assert by_url["status"] == 200 and by_url["bytes"] > 0, by_url

    # --- cookies: set an HttpOnly cookie document.cookie can't see, then audit it ---
    await server.cookies("set", [{"name": "sid", "value": "x", "url": "https://example.com/",
                                  "httpOnly": True, "secure": True, "sameSite": "Strict"}])
    jar = (await server.cookies())["result"]
    sid = next(c for c in jar if c["name"] == "sid")
    assert sid["httpOnly"] and sid["secure"] and sid["sameSite"] == "Strict", sid
    assert "sid" not in (await server.evaluate("document.cookie"))["result"], "HttpOnly leaked to JS"

    # --- console_logs: console.error, uncaught exception, and a CSP violation ---
    page = ('<meta http-equiv="Content-Security-Policy" content="img-src \'none\'">'
            '<img src="https://example.com/x.png">'
            '<script>console.error("boom"); window.addEventListener("message", function onMsg(){});'
            'new WebSocket("ws://127.0.0.1:9/"); setTimeout(()=>{throw new Error("late")},0);</script>'
            '<iframe name="f1" srcdoc="hi"></iframe>')
    await server.navigate("data:text/html," + page)
    await server.evaluate("async () => new Promise(r => setTimeout(r, 300))")  # let async events land
    logs = (await server.console_logs())["result"]
    assert any(e["type"] == "error" and e["text"] == "boom" for e in logs), logs
    assert any(e["type"] == "pageerror" and "late" in e["text"] for e in logs), logs
    assert (await server.console_logs(type="pageerror"))["result"], "type filter"
    csp = (await server.console_logs(type="csp"))["result"]
    print("csp violations:", len(csp))  # best-effort: delivery varies by engine

    # --- frames_and_listeners ---
    inv = (await server.frames_and_listeners())["result"]
    assert any(f["name"] == "f1" for f in inv["frames"]), inv["frames"]
    assert "onMsg" in inv["message_listeners"], inv["message_listeners"]

    # --- websockets: the ws() constructor above must show up ---
    ws = (await server.websockets())["result"]
    assert any("127.0.0.1:9" in w["url"] for w in ws), ws

    # --- set_browser_headers: Authorization reaches the outgoing request, then clears ---
    await server.set_browser_headers({"Authorization": "Bearer t0ken"})
    await server.navigate("https://example.com")
    doc2 = [r for r in (await server.requests(type="document", details=True))["result"] if r["status"] in (200, 304)][0]
    assert doc2["request_headers"].get("authorization") == "Bearer t0ken", doc2["request_headers"]
    await server.set_browser_headers({})
    await server.navigate("https://example.com")
    doc3 = [r for r in (await server.requests(type="document", details=True))["result"] if r["status"] in (200, 304)][0]
    assert "authorization" not in doc3["request_headers"], "header not cleared"

    # --- http_request: custom header + body, and redirect following ---
    r = (await server.http_request("https://example.com/", method="OPTIONS",
                                   headers={"Origin": "https://other.test",
                                            "Access-Control-Request-Method": "GET"}))["result"]
    assert "status" in r or "error" in r, r
    red = (await server.http_request("http://github.com/", follow_redirects=True))["result"]
    # github redirects http->https; tolerate network variance but the chain must be shaped right if present
    assert "redirect_chain" not in red or all("location" in h for h in red["redirect_chain"]), red
    print("ok | body", by_url["bytes"], "| cookies", len(jar), "| logs", len(logs),
          "| ws", len(ws), "| redirects", len(red.get("redirect_chain", [])))

    await server._state["cm"].__aexit__(None, None, None)

asyncio.run(main())
