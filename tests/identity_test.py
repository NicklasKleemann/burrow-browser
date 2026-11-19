"""set_identity (per-session fingerprint and emulation) and browser_settings (browser-wide Camoufox
options). Offline: serves its own page with an image, an animation and a button."""
import asyncio, base64, http.server, os, sys, tempfile, threading
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # server.py is one folder up
import server

PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
PAGE = b"""<title>id</title><style>@keyframes grow { to { width: 300px } } #box { width: 10px; height: 10px;
animation: grow 5s 1 forwards }</style><div id=box></div><img id=img src=/pic.png>
<button id=b onclick="document.title='clicked'">b</button>"""
seen = []


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        seen.append({k.lower(): v for k, v in self.headers.items()})
        png = self.path == "/pic.png"
        self.send_response(200)
        self.send_header("content-type", "image/png" if png else "text/html")
        self.end_headers()
        self.wfile.write(PNG if png else PAGE)

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
URL = f"http://127.0.0.1:{srv.server_address[1]}/page"
PROBE = """() => ({ua: navigator.userAgent, platform: navigator.platform, lang: navigator.language,
  tz: Intl.DateTimeFormat().resolvedOptions().timeZone, w: innerWidth, h: innerHeight,
  dark: matchMedia('(prefers-color-scheme: dark)').matches,
  reduce: matchMedia('(prefers-reduced-motion: reduce)').matches,
  rtc: typeof RTCPeerConnection, img: document.getElementById('img').naturalWidth,
  anim: document.getAnimations().map(a => a.effect.getComputedTiming().duration), cookie: document.cookie})"""
GEO = """() => new Promise(ok => navigator.geolocation.getCurrentPosition(
  p => ok([p.coords.latitude, p.coords.longitude]), e => ok('error ' + e.code), {timeout: 5000}))"""


async def probe(session=""):
    await server.wait_for(load_state="load", session=session)
    return (await server.evaluate(PROBE, session=session))["result"]


async def raises(coro, kind):
    try:
        await coro
    except kind:
        return
    raise AssertionError(f"expected {kind.__name__}")


async def main():
    await server.navigate(URL)
    await server.evaluate("document.cookie = 'keep=1; path=/'")
    base = await probe()
    assert base["img"] == 1 and base["rtc"] == "function" and base["anim"] == [5000], base

    # --- set_identity: everything at once, cookies kept ---
    r = (await server.set_identity(os="macos", locale="da-DK", timezone="Asia/Tokyo", viewport_width=390,
                                   viewport_height=844, color_scheme="dark", reduced_motion="reduce",
                                   latitude=55.68, longitude=12.57))["result"]
    assert r["identity_id"] and "Macintosh" in r["user_agent"] and r["platform"] == "MacIntel", r
    p = await probe()
    assert (p["platform"], p["lang"], p["tz"], p["w"], p["dark"], p["reduce"]) == \
           ("MacIntel", "da-DK", "Asia/Tokyo", 390, True, True), p
    assert "Macintosh" in p["ua"] and p["cookie"] == "keep=1", p
    assert (await server.evaluate(GEO))["result"] == [55.68, 12.57]
    await server.navigate(URL)
    assert seen[-2]["accept-language"].startswith("da"), seen[-2]  # [-1] is the image

    # --- other sessions keep the browser-wide identity ---
    await server.navigate(URL, session="other")
    o = await probe("other")
    assert o["tz"] != "Asia/Tokyo" and o["w"] != 390, o

    # --- partial update keeps the fingerprint; rotate draws a new one ---
    first = r["identity_id"]
    r2 = (await server.set_identity(viewport_width=1280, viewport_height=800))["result"]
    p = await probe()
    assert r2["identity_id"] == first and p["w"] == 1280 and p["platform"] == "MacIntel" and p["lang"] == "da-DK", (r2, p)
    r3 = (await server.set_identity(rotate=True))["result"]
    assert r3["identity_id"] != first and r3["platform"] == "MacIntel" and r3["timezone"] == "Asia/Tokyo", r3
    await raises(server.set_identity(os="beos"), ValueError)
    await raises(server.set_identity(latitude=1.0), ValueError)

    # --- the identity survives a recording's context swaps; changing it while recording is refused ---
    har = os.path.join(tempfile.gettempdir(), "burrow-identity-test.har")
    await server.start_recording(har)
    assert (await probe())["tz"] == "Asia/Tokyo"
    await raises(server.set_identity(rotate=True), RuntimeError)
    await raises(server.browser_settings(block_images=True), RuntimeError)
    assert server._LAUNCH["block_images"] is False, "refused change must roll back"
    await server.stop_recording()
    assert (await probe())["tz"] == "Asia/Tokyo"

    assert (await server.set_identity(reset=True))["result"]["identity_id"] is None
    p = await probe()
    assert p["tz"] != "Asia/Tokyo" and p["w"] != 1280 and p["cookie"] == "keep=1", p

    # --- browser_settings: report, then change; sessions keep cookies and page ---
    assert (await server.browser_settings())["result"] == {
        "humanize": False, "adblock": True, "instant_animations": False, "block_images": False,
        "block_webrtc": False, "geoip": False}
    s = await server.browser_settings(instant_animations=True, block_images=True, block_webrtc=True)
    assert s["restarted_sessions"] == ["default", "other"], s
    p = await probe()
    assert p["img"] == 0 and p["rtc"] == "undefined" and p["anim"] == [0], p
    assert p["cookie"] == "keep=1" and (await server.evaluate("location.href"))["result"] == URL, p
    assert (await probe("other"))["img"] == 0, "other session restarted too"
    await server.browser_settings(humanize=True)
    assert (await server.click("#b"))["title"] == "clicked", "click with humanize"
    await server.browser_settings(humanize=False, instant_animations=False, block_images=False, block_webrtc=False)
    assert (await probe())["img"] == 1
    print("ok | identity", first, "->", r3["identity_id"])
    await server._state["cm"].__aexit__(None, None, None)

asyncio.run(main())
