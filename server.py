# /// script
# requires-python = ">=3.11"
# dependencies = ["mcp>=1.0,<2", "camoufox[geoip]", "cryptography"]
# ///
"""burrow-browser: MCP server for Camoufox, a debloated headless Firefox fork
built for scraping and AI agents.

BURROW_BROWSER_OUTPUT_DIR is where relative paths for screenshots, downloads and recordings
go (default: the working directory). Point it at a folder the agent can read when the server
runs somewhere else, e.g. in its own sandbox.

BURROW_BROWSER_REQUIRE_SESSION=1 makes every tool's session argument mandatory, for hosts
like Claude Science that share one server process between agents.

Logging is off by default. Enable it with:
  BURROW_BROWSER_LOG_LEVEL  DEBUG | INFO | WARNING | ERROR
  BURROW_BROWSER_LOG_FILE   optional path; otherwise logs go to stderr

  DEBUG    every network response, browser console messages
  INFO     navigations and downloads with status, size and timing
  WARNING  HTTP errors (>= 400) on documents and downloads, failed requests,
           uncaught page errors
Logs never go to stdout, which carries the MCP stdio transport.
"""
import asyncio
import collections
import datetime
import json
import math
import secrets
import contextvars
import hashlib
import http.client
import logging
import os
import pathlib
import re
import socket
import ssl as ssl_mod
import time
from urllib.parse import unquote, urljoin, urlsplit

from camoufox import DefaultAddons
from camoufox.async_api import AsyncCamoufox
from camoufox.fingerprints import generate_context_fingerprint
from mcp.server.fastmcp import FastMCP
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

log = logging.getLogger("burrow-browser")
_level = os.environ.get("BURROW_BROWSER_LOG_LEVEL")
if _level:
    _file = os.environ.get("BURROW_BROWSER_LOG_FILE")
    _handler = logging.FileHandler(_file) if _file else logging.StreamHandler()  # StreamHandler = stderr
    _handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(_handler)
    log.setLevel(_level.upper())
    log.propagate = False  # mcp installs its own root handler; avoid duplicate lines
else:
    log.disabled = True

# What agents read about burrow-browser as a whole (sent as the MCP server instructions).
# Each tool's own description is the docstring of its function below (search for @mcp.tool).
INSTRUCTIONS = (
    "Debloated headless Firefox fork. "
    "Use it to open and read web pages that need a real browser (JavaScript rendering, cookies, "
    "multi-page listings), extract their links, and download the documents they link to. "
    "One page is kept open across calls: navigate first, then read it with get_text, get_html or links, "
    "interact with it using click, type_text, press, hover, select_option, check and upload_file, wait "
    "for async content with wait_for (selector/text visible or hidden, URL change, JS condition), list "
    "the network requests it made with requests, record full traffic to a HAR file with start_recording "
    "and stop_recording (relative file paths resolve against the server's output folder; results give the"
    " absolute path), or run JavaScript in it with evaluate. "
    "For QA and diagnostics: get_response_body reads a captured response's body (by request id or url) "
    "without reloading, cookies lists or sets cookies including HttpOnly flags, console_logs returns "
    "console messages, page exceptions and CSP violations, frames_and_listeners inventories iframes, "
    "service workers and message listeners, websockets lists realtime connections, and "
    "set_browser_headers sets persistent headers (e.g. "
    "Authorization) for navigating staging environments. "
    "query inspects matching elements (count, text, value, visible, attributes) for assertions, dialogs "
    "lists alert/confirm/prompt dialogs (auto-dismissed so they never block; set accept to accept them), "
    "and storage reads localStorage, sessionStorage and IndexedDB, flagging token-like keys. "
    "snapshot returns the accessibility tree (roles and names; compact, gives stable role= selectors), "
    "tabs lists and switches popups and new tabs, route mocks, fails or delays matching requests to test "
    "error states, security_headers audits CSP/HSTS/framing/cookie flags, and close_session frees a "
    "session when your task is done. "
    "browser_settings turns browser-wide Camoufox options on or off (human-like mouse movement, ad "
    "blocking, instant animations, image and WebRTC blocking, geoip), and set_identity gives one session "
    "its own OS, locale, timezone, geolocation, viewport, color scheme or a fresh random fingerprint. "
    "Security review (the operator points this server to do a full security assessment): "
    "scan_secrets lists API keys, tokens and downloadable source maps in the code a page loaded; "
    "cors_check, exposure_check, tls_audit and session_audit check a site's CORS, public files, TLS and "
    "login/logout session handling by sending their own requests. "
    "Separately, http_request makes one raw HTTP(S) call with the connection IP, Host header and TLS SNI "
    "set independently (DNS/vhost/origin testing, like curl --resolve). "
    "get_text, get_html, links, requests, evaluate and screenshot all return {'result': <value>}. "
    "Every tool takes an optional session name; each session has its own page, cookies, request log and "
    "recording. "
    "When other agents may use this browser at the same time (Claude Science shares one burrow-browser "
    "between all its sessions), pass the same unique session name, e.g. "
    "your task name, on every call. "
    "If a result lists blocked_hosts, the network proxy refused those domains. "
    "When the page itself failed, ask for access to the page's domain (in Claude Science, call "
    "request_network_access(domain=...)) and retry. "
    "When the page loaded, blocked_hosts are third-party resources (ads, widgets): only request one if "
    "content you need is missing."
)
mcp = FastMCP("burrow-browser", log_level=(_level or "WARNING").upper(), instructions=INSTRUCTIONS)
_state = {"cm": None, "browser": None}  # one browser process, shared by all sessions
_launch_lock = asyncio.Lock()


def _new_session():
    # ponytail: fixed cap on recorded requests; make it configurable if long sessions need more.
    return {"page": None, "blocked": set(), "requests": collections.deque(maxlen=2000), "lost": False, "har": None,
            "req_seq": 0, "console": collections.deque(maxlen=500), "websockets": collections.deque(maxlen=200),
            "extra_headers": None, "dialogs": collections.deque(maxlen=100), "dialog_policy": "dismiss",
            "prompt_text": "", "routes": {}, "opened": [], "inflight": 0,
            "cookie_marks": {}, "identity": None}


_sessions = collections.defaultdict(_new_session)
_PER_PAGE_LOGS = ("requests", "console", "websockets", "dialogs")  # cleared on every navigate
_current = contextvars.ContextVar("session", default="default")
# Claude Science sets this: its sessions share one server process, so an unnamed session
# would let two agents drive the same page.
_REQUIRE_SESSION = bool(os.environ.get("BURROW_BROWSER_REQUIRE_SESSION"))
_OUTPUT_DIR = pathlib.Path(os.environ.get("BURROW_BROWSER_OUTPUT_DIR") or ".")


def _env_flag(name, default):
    v = os.environ.get(f"BURROW_BROWSER_{name}")
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


# Browser-wide Camoufox options. Env vars set the defaults; browser_settings changes them at runtime.
_LAUNCH = {
    "humanize": _env_flag("HUMANIZE", False),               # human-like mouse paths for clicks/hovers
    "adblock": _env_flag("ADBLOCK", True),                  # uBlock Origin, a Camoufox default add-on
    "instant_animations": _env_flag("INSTANT_ANIMATIONS", False),  # CSS/Web animations finish at once
    "block_images": _env_flag("BLOCK_IMAGES", False),
    "block_webrtc": _env_flag("BLOCK_WEBRTC", False),       # no WebRTC, so it can't reveal the local IP
    "geoip": _env_flag("GEOIP", False),                     # timezone/locale/location from the exit IP
}


def _out(path: str) -> pathlib.Path:
    """Absolute path for an output file, relative paths under the output dir; creates the folder."""
    full = (_OUTPUT_DIR / path).resolve()
    full.parent.mkdir(parents=True, exist_ok=True)
    return full


def _use(session: str):
    """Make session the one the rest of this tool call works on."""
    if not session and _REQUIRE_SESSION:
        raise ValueError("Pass session=<a unique name for your task>: other agents share this browser.")
    _current.set(session or "default")


def _s() -> dict:
    return _sessions[_current.get()]

# Use the proxy from the environment, which Firefox otherwise ignores.
_PROXY = next((os.environ[v] for v in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy") if os.environ.get(v)), None)
_NO_PROXY = os.environ.get("NO_PROXY") or os.environ.get("no_proxy")


def _playwright_proxy():
    """Proxy env var -> Playwright proxy dict.

    Playwright ignores credentials inside `server`, so they go in username/password,
    and localhost becomes 127.0.0.1 because Firefox may try ::1 first while the
    proxy listens on IPv4 only.
    """
    if not _PROXY:
        return None
    u = urlsplit(_PROXY if "://" in _PROXY else f"http://{_PROXY}")
    host = "127.0.0.1" if u.hostname == "localhost" else u.hostname
    proxy = {"server": f"{u.scheme}://{host}" + (f":{u.port}" if u.port else "")}
    if u.username:
        proxy["username"] = unquote(u.username)
        proxy["password"] = unquote(u.password or "")
    if _NO_PROXY:
        proxy["bypass"] = _NO_PROXY
    return proxy


def _proxy_refused(error: str) -> bool:
    """True if a request failed because the proxy refused it (e.g. a domain allowlist)."""
    e = error.lower()
    return "ns_error_proxy" in e or (_PROXY is not None and ("tunnel" in e or "proxy" in e or " 403" in e))


def _proxy_block_response(headers) -> bool:
    """True if a response is the proxy's own refusal rather than the site's (Claude Science marks these)."""
    return "blocked-by-allowlist" in headers.get("x-proxy-error", "") or "x-operon-blocked-host" in headers


def _on_failed(sess, req):
    sess["inflight"] -= 1
    err = req.failure or ""
    log.warning("request failed: %s %s", req.url, err)
    sess["req_seq"] += 1
    sess["requests"].append({"id": sess["req_seq"], "method": req.method, "url": req.url, "type": req.resource_type,
                               "status": None, "error": err,
                               "request_headers": req.headers, "post_data": req.post_data})
    if _proxy_refused(err):
        sess["blocked"].add(urlsplit(req.url).hostname)


def _blocked_result(url) -> dict:
    """Result for a request the proxy refused before it reached the site."""
    return {"status": None, "error": "blocked by network proxy", "blocked_hosts": [urlsplit(url).hostname]}


def _take_blocked() -> dict:
    blocked, _s()["blocked"] = sorted(h for h in _s()["blocked"] if h), set()
    return {"blocked_hosts": blocked} if blocked else {}

_EVALUATE_TIMEOUT = 60  # seconds
_INPUT_TIMEOUT = 10_000  # milliseconds

# Response headers worth recording next to an HTTP error.
_ERROR_HEADERS = ("server", "cf-mitigated", "retry-after", "x-cache")


def _on_response(sess, r):
    _log_response(r.status, r.url, r.headers, r.request.resource_type)
    sess["req_seq"] += 1
    sess["requests"].append({
        "id": sess["req_seq"], "method": r.request.method, "url": r.url, "type": r.request.resource_type,
        "status": r.status, "content_type": r.headers.get("content-type"),
        "request_headers": r.request.headers, "post_data": r.request.post_data, "response_headers": r.headers,
        "_resp": r,  # kept for get_response_body; stripped from requests() output, dropped on next navigate
    })


def _log_response(status, url, headers, kind):
    log.debug("%s %s %s", status, kind, url)
    if status >= 400 and kind in ("document", "download"):
        extra = " ".join(f"{h}={headers[h]}" for h in _ERROR_HEADERS if h in headers)
        log.warning("HTTP %s on %s %s %s", status, kind, url, extra)


def _on_console(sess, m):
    log.debug("console.%s: %s", m.type, m.text)
    loc = m.location or {}
    sess["console"].append({"type": m.type, "text": m.text, "location": loc.get("url")})


async def _on_dialog(sess, d):
    """Record an alert/confirm/prompt/beforeunload and answer it per the session's policy. A dialog
    left unanswered blocks the page, so this must always accept or dismiss."""
    accept = sess["dialog_policy"] == "accept"
    sess["dialogs"].append({"type": d.type, "message": d.message, "default_value": d.default_value,
                            "action": "accept" if accept else "dismiss"})
    log.info("dialog %s %r -> %s", d.type, d.message, "accept" if accept else "dismiss")
    try:
        await (d.accept(sess["prompt_text"]) if accept and d.type == "prompt" else d.accept() if accept else d.dismiss())
    except Exception as e:  # page closed meanwhile
        log.warning("dialog answer failed: %s", e)


def _on_websocket(sess, ws):
    rec = {"url": ws.url, "state": "open", "sent": 0, "received": 0, "detail": None}
    sess["websockets"].append(rec)
    ws.on("framesent", lambda p: rec.update(sent=rec["sent"] + 1))
    ws.on("framereceived", lambda p: rec.update(received=rec["received"] + 1))
    ws.on("close", lambda *a: rec.update(state="closed"))
    ws.on("socketerror", lambda e: rec.update(state="error", detail=str(e)))


# Runs at document_start in Playwright's isolated world. The CSP listener works there (DOM events
# are shared across worlds); the addEventListener wrapper must patch the page's MAIN world, which we
# reach by injecting a <script> element (its code runs in the main world). Read __burrow_listeners
# back with a main-world (mw:) evaluate. It also counts the page's pending fetch/XHR calls in
# __burrow_pending, for _settled: Playwright's network events for them can arrive ~1 s late.
# ponytail: catches only addEventListener('message', ...), not onmessage= assignments or listeners on
# other targets; add CDP instrumentation if that gap matters.
_INIT_SCRIPT = r"""
document.addEventListener('securitypolicyviolation', e =>
  console.error('[CSP] ' + e.violatedDirective + ' blocked ' + e.blockedURI));
(() => {
  const code = "(function(){if(window.__burrow_lw)return;window.__burrow_lw=1;window.__burrow_listeners=[];"
    + "var o=window.addEventListener;window.addEventListener=function(t){if(t==='message'){try{"
    + "window.__burrow_listeners.push((arguments[1]&&arguments[1].name)||'anonymous')}catch(e){}}"
    + "return o.apply(this,arguments)};"
    + "window.__burrow_pending=0;var done=function(){window.__burrow_pending--};"
    + "var f=window.fetch;if(f)window.fetch=function(){window.__burrow_pending++;"
    + "try{var p=f.apply(this,arguments)}catch(e){done();throw e}p.then(done,done);return p};"
    + "var x=XMLHttpRequest.prototype.send;XMLHttpRequest.prototype.send=function(){"
    + "window.__burrow_pending++;this.addEventListener('loadend',done);return x.apply(this,arguments)};})();";
  const s = document.createElement('script');
  s.textContent = code;
  (document.head || document.documentElement || document).appendChild(s);
  s.remove();
})();
"""


async def _browser(force_relaunch=False):
    """The shared browser, relaunched if it died. A relaunch loses every session's page.
    force_relaunch: the caller saw it die, though is_connected() can still say True for a moment."""
    async with _launch_lock:
        if _state["cm"] is not None and (force_relaunch or not _state["browser"].is_connected()):
            log.warning("browser lost, relaunching")
            cm, _state["cm"] = _state["cm"], None
            for sess in _sessions.values():
                if sess["page"] is not None:
                    sess.update(page=None, lost=True, har=None)
            try:
                await cm.__aexit__(None, None, None)
            except Exception as e:
                log.warning("closing lost browser failed: %s", e)
        if _state["cm"] is None:
            # Allowlist proxies read the TLS SNI to check the host; Firefox's ECH (and its
            # GREASE placeholder) makes them reset the tunnel, so turn ECH off behind a proxy.
            prefs = {"security.tls.ech.grease_probability": 0, "network.dns.echconfig.enabled": False} if _PROXY else {}
            # ponytail: some launches of Camoufox 156.0.1-beta.36 die on their first page ("Exiting due to
            # channel error"; 2-35% in tests, sometimes several in a row, not tied to the random fingerprint).
            # Open a throwaway page to prove the launch, relaunch with backoff if it dies. Drop this once a
            # Camoufox build fixes it.
            for attempt in range(6):
                if attempt:
                    await asyncio.sleep(attempt * 0.5)
                cm = AsyncCamoufox(
                    headless=True, proxy=_playwright_proxy(), firefox_user_prefs=prefs, main_world_eval=True,
                    humanize=_LAUNCH["humanize"], block_images=_LAUNCH["block_images"],
                    block_webrtc=_LAUNCH["block_webrtc"], geoip=_LAUNCH["geoip"],
                    exclude_addons=[] if _LAUNCH["adblock"] else [DefaultAddons.UBO],
                    config={"instantAnimations": True} if _LAUNCH["instant_animations"] else None)
                browser = await cm.__aenter__()
                try:
                    probe = await browser.new_context()
                    await probe.new_page()
                    await probe.close()
                    break
                except Exception as e:
                    log.warning("new browser died on its first page (launch %d), relaunching: %s", attempt + 1, e)
                    try:
                        await cm.__aexit__(None, None, None)
                    except Exception:
                        pass
                    if attempt == 5:
                        raise
            _state["cm"], _state["browser"] = cm, browser
    return _state["browser"]


async def _page(fresh=False):
    """This session's page, opening one if needed. After a crash a new page is opened only
    for fresh=True callers: the rest need a page that no longer exists."""
    sess = _s()
    await _browser()
    if sess["page"] is not None and sess["page"].is_closed():
        alive = [p for p in sess["page"].context.pages if not p.is_closed()]
        if alive:  # a popup or tab closed itself (e.g. after an OAuth login): carry on in the newest other tab
            sess["page"] = alive[-1]
        else:
            log.warning("page of session %s lost", _current.get())
            sess.update(page=None, lost=True, har=None)
    if sess["lost"] and not fresh:
        raise RuntimeError("The browser crashed and the page is gone. Call navigate to continue; cookies were reset.")
    # ponytail: blind retry with backoff. Right after a browser crash a relaunched Camoufox can die on its
    # first page (cause not pinned down; fine with ~2 s between); find the cause if 3 tries ever aren't enough.
    for attempt in range(3):
        if sess["page"] is not None:
            break
        try:
            await _new_page()
        except Exception as e:  # the browser died after _browser() checked it: relaunch and retry
            if "has been closed" not in str(e) or attempt == 2:
                raise
            log.warning("browser gone while opening a page, relaunching (try %d): %s", attempt + 2, e)
            await asyncio.sleep(attempt + 0.5)
            await _browser(force_relaunch=True)
    return sess["page"]


async def _new_page(storage_state=None, har=None):
    """Open this session's page in a new context, optionally with cookies carried over and recording to a HAR file."""
    sess = _s()
    har_opts = {"record_har_path": har, "record_har_content": "embed"} if har else {}
    ident = sess["identity"]  # set_identity: this session's fingerprint and emulation, if any
    context = await (await _browser()).new_context(storage_state=storage_state,
                                                   extra_http_headers=sess["extra_headers"],
                                                   **(ident["opts"] if ident else {}), **har_opts)
    if ident:  # before ours, so the identity is in place before any page script runs
        await context.add_init_script(ident["init"])
    sess["inflight"] = 0  # requests of the old context will never report finishing
    # Context-level events cover every tab, including a popup's first load, which happens before
    # the popup's page object exists.
    context.on("request", lambda r: sess.update(inflight=sess["inflight"] + 1))
    context.on("requestfinished", lambda r: sess.update(inflight=sess["inflight"] - 1))
    context.on("response", lambda r: _on_response(sess, r))
    context.on("requestfailed", lambda r: _on_failed(sess, r))
    context.on("console", lambda m: _on_console(sess, m))
    context.on("weberror", lambda e: (log.warning("page error: %s", e.error),
                                      sess["console"].append({"type": "pageerror", "text": str(e.error), "location": None})))
    context.on("dialog", lambda d: _on_dialog(sess, d))
    context.on("page", lambda p: _wire(sess, p))
    await context.add_init_script(_INIT_SCRIPT)
    for spec in sess["routes"].values():  # carry mocks across recording context swaps
        await context.route(spec["_match"], spec["_handle"])
    sess["page"] = await context.new_page()


def _wire(sess, page):
    """Track a new tab: its websockets (a page-only event) and, for new_tabs, that it opened."""
    page.on("websocket", lambda ws: _on_websocket(sess, ws))
    sess["opened"].append(page)


def _take_opened() -> dict:
    """Tabs opened since the last check other than the current one, i.e. popups and target=_blank links."""
    sess = _s()
    new, sess["opened"] = [p for p in sess["opened"] if p is not sess["page"] and not p.is_closed()], []
    return {"new_tabs": [p.url for p in new]} if new else {}


async def _switch_context(har=None) -> str:
    """Replace the page's context, keeping cookies and storage and reopening the current URL.
    Closing the old context is what writes its HAR file."""
    old = await _page()
    url, storage = old.url, await old.context.storage_state()
    await _new_page(storage, har)
    await old.context.close()
    if url.startswith("http"):
        try:
            await _s()["page"].goto(url, wait_until="domcontentloaded")
        except Exception as e:  # the context swap itself succeeded; the agent can navigate again
            log.warning("reloading %s after context switch failed: %s", url, e)
    return url


@mcp.tool()
async def navigate(url: str, session: str = "") -> dict:
    """Open a URL in the headless browser and wait for it to finish loading, including JavaScript.

    Use for pages that need a real browser. The page stays open for get_text, get_html,
    links and screenshot. Returns HTTP status, final URL after redirects, and page title.
    """
    _use(session)
    page = await _page(fresh=True)
    _s()["lost"] = False
    for k in _PER_PAGE_LOGS:
        _s()[k].clear()
    t0 = time.monotonic()
    try:
        try:
            resp = await page.goto(url, wait_until="domcontentloaded")
        except Exception as e:
            # Just after a crash the dead page can still look open. Open a fresh one (relaunching the
            # browser if it's gone too, see _page) and try once more.
            if "has been closed" not in str(e):
                raise
            log.warning("page gone during navigate, reopening: %s", e)
            _s().update(page=None, har=None)
            page = await _page(fresh=True)
            resp = await page.goto(url, wait_until="domcontentloaded")
    except Exception as e:
        if not _proxy_refused(str(e)):
            raise
        _s()["blocked"].add(urlsplit(url).hostname)
        log.warning("navigate %s blocked by proxy: %s", url, e)
        return {"status": None, "error": "blocked by network proxy", **_take_blocked()}
    status = resp.status if resp else None
    settled = await _settled(page)  # gives up on pages that poll or stream instead of failing them
    log.info("navigate %s -> %s %s (%.1fs)", url, status, page.url, time.monotonic() - t0)
    return {"status": status, **settled}


@mcp.tool()
async def get_text(session: str = "") -> dict:
    """Visible text of the page opened by navigate, as {"result": text}. Best for reading content and listings."""
    _use(session)
    return {"result": await (await _page()).inner_text("body")}


@mcp.tool()
async def get_html(session: str = "") -> dict:
    """Full rendered HTML (DOM after JavaScript) of the page opened by navigate, as {"result": html}. Use when you need markup or attributes."""
    _use(session)
    return {"result": await (await _page()).content()}


@mcp.tool()
async def links(contains: str = "", session: str = "") -> dict:
    """All links on the page opened by navigate as {"result": [{text, href}, ...]}, with absolute URLs.

    Pass contains to keep only hrefs containing that substring (e.g. ".pdf", "/reports/").
    Use to find pagination, detail pages and document links.
    """
    _use(session)
    page = await _page()
    found = await page.eval_on_selector_all(
        "a[href]", "els => els.map(a => ({text: a.innerText.trim(), href: a.href}))"
    )
    # Always a dict: FastMCP 1.x sends each list item as its own text block, and one shape
    # across tools stops agents guessing wrong.
    return {"result": [l for l in found if contains in l["href"]]}


@mcp.tool()
async def requests(contains: str = "", type: str = "", details: bool = False, session: str = "") -> dict:
    """Network requests made by the page since the last navigate, including XHR/fetch calls made by JavaScript.

    Returns {"result": [...]}. Each entry: method, url, resource type (document, script, xhr, fetch, image, ...), status and
    content_type, or status None with error for failed requests. Filter with contains (substring of
    the url) and type (e.g. "xhr", "fetch"). Use to find the API endpoints a page loads its data from.
    details=True adds request_headers, post_data and response_headers; filter first, they are large.
    Each entry has an id; pass it (or the url) to get_response_body to read the response payload.
    """
    _use(session)
    brief = ("request_headers", "post_data", "response_headers")
    return {"result": [
        {k: v for k, v in r.items() if not k.startswith("_") and (details or k not in brief)}
        for r in _s()["requests"] if contains in r["url"] and (not type or r["type"] == type)
    ]}


@mcp.tool()
async def start_recording(path: str, session: str = "") -> dict:
    """Record all network traffic, with full request and response bodies, to a HAR file at path.

    Cookies and the current page carry over: the page is reloaded in a recording context, so
    that reload is the first thing recorded. Then navigate, click, type_text and press as usual, and
    call stop_recording to write the file. HAR files open in browser DevTools and HAR tools.
    The file holds cookies and auth headers from the traffic: keep it out of git and shared folders.
    Code written from a capture should read cookies, tokens and keys from environment variables
    or a git-ignored file, never hardcode them.
    """
    _use(session)
    if _s()["har"]:
        raise RuntimeError(f"Already recording to {_s()['har']}; call stop_recording first.")
    path = str(_out(path))
    await _switch_context(har=path)
    _s()["har"] = path
    log.info("recording to %s", path)
    return {"result": path}


@mcp.tool()
async def stop_recording(session: str = "") -> dict:
    """Stop recording and write the HAR file. Returns {"result": path, "bytes": size}. Cookies and the page carry over."""
    _use(session)
    path = _s()["har"]
    if not path:
        raise RuntimeError("Not recording; call start_recording first.")
    _s()["har"] = None
    await _switch_context()
    size = pathlib.Path(path).stat().st_size
    log.info("recording saved to %s (%d bytes)", path, size)
    return {"result": path, "bytes": size}


@mcp.tool()
async def evaluate(expression: str, main_world: bool = True, session: str = "") -> dict:
    """Run JavaScript in the page opened by navigate and return {"result": <value as JSON>}.

    expression is a JS expression or function source, e.g. "document.title",
    "() => location.href", or "async () => (await fetch('/api/x')).json()".
    Promises are awaited, for at most 60 seconds. Values that can't be serialized (DOM nodes, functions) come back as null.
    The script runs in the page's own JavaScript context, so it can read page variables
    (e.g. window.__NEXT_DATA__) and dispatch events to page handlers, and the page can observe it.
    main_world=False uses an isolated world, which shares the DOM but not the page's globals.
    Don't dispatch events there: a synthetic keypress sent into a jQuery handler crashes the tab.
    Prefer click, type_text and press for user input.
    """
    _use(session)
    page = await _page()
    return {"result": await asyncio.wait_for(page.evaluate(("mw:" if main_world else "") + expression), _EVALUATE_TIMEOUT)}


async def _page_pending(page) -> int:
    """fetch/XHR calls the page has started but not finished (counted by _INIT_SCRIPT)."""
    try:
        return await page.evaluate("mw:window.__burrow_pending || 0")
    except Exception:  # mid-navigation, no document to ask yet: not settled
        return 1


_QUIET = 0.5  # seconds without in-flight requests that count as settled, like Playwright's networkidle


async def _settled(page) -> dict:
    """Let the page finish reacting to an input (the XHR/fetch calls it triggers), then report where it
    ended up. Playwright's networkidle can't do this: once a page has reached it, it returns at once and
    doesn't wait for requests an input starts. Pages that poll or stream are given up on after
    _INPUT_TIMEOUT; use wait_for for a specific result."""
    sess, deadline, quiet_since = _s(), time.monotonic() + _INPUT_TIMEOUT / 1000, None
    while time.monotonic() < deadline and not page.is_closed():  # an input may close a popup
        if sess["inflight"] > 0 or await _page_pending(page):
            quiet_since = None
        elif quiet_since is None:
            quiet_since = time.monotonic()
        elif time.monotonic() - quiet_since >= _QUIET:
            break
        await asyncio.sleep(0.05)
    else:
        log.info("page still busy after input: %s (%d requests in flight)", page.url, sess["inflight"])
    if page.is_closed():
        page = await _page()  # the input closed this tab; report the one now current
    return {"final_url": page.url, "title": await page.title(), **_take_blocked(), **_take_opened()}


async def _act(session, action) -> dict:
    """Run one user input on this session's page, then report where the page settled."""
    _use(session)
    page = await _page()
    try:
        extra = await action(page)
    except Exception:
        if not page.is_closed():
            raise
        extra = None  # the input closed its own tab (e.g. a popup's window.close()); _settled moves on
    return {**(extra or {}), **await _settled(page)}


@mcp.tool()
async def click(selector: str, session: str = "") -> dict:
    """Click an element with a real mouse click, then wait for the page to settle.

    selector is a CSS selector or Playwright selector, e.g. "#search", "text=Next".
    Returns the final URL and title. Follow with requests to see what the click loaded.
    """
    return await _act(session, lambda p: p.click(selector, timeout=_INPUT_TIMEOUT))


@mcp.tool()
async def type_text(selector: str, text: str, session: str = "") -> dict:
    """Replace the content of an input with text, typed as real keystrokes so typeaheads fire."""
    async def typing(page):
        field = page.locator(selector)
        await field.fill("", timeout=_INPUT_TIMEOUT)
        await field.press_sequentially(text, timeout=_INPUT_TIMEOUT)
    return await _act(session, typing)


@mcp.tool()
async def press(key: str, selector: str = "", session: str = "") -> dict:
    """Press a key, e.g. "Enter", "Escape", "ArrowDown", in the focused element or in selector if given."""
    return await _act(session, lambda p: p.press(selector, key, timeout=_INPUT_TIMEOUT) if selector
                      else p.keyboard.press(key))


@mcp.tool()
async def hover(selector: str, session: str = "") -> dict:
    """Move the mouse over an element (opens hover menus and tooltips), then wait for the page to settle."""
    return await _act(session, lambda p: p.hover(selector, timeout=_INPUT_TIMEOUT))


@mcp.tool()
async def select_option(selector: str, values: list[str], session: str = "") -> dict:
    """Choose options in a <select>. Each entry of values matches an option's value or its visible label.

    A single-select takes the first match; a <select multiple> selects every match.
    Returns {"result": [selected option values], final_url, title}.
    """
    async def choose(page):
        return {"result": await page.select_option(selector, values, timeout=_INPUT_TIMEOUT)}
    return await _act(session, choose)


@mcp.tool()
async def check(selector: str, checked: bool = True, session: str = "") -> dict:
    """Check (or with checked=False uncheck) a checkbox or radio button by clicking it like a user.
    Fails if the element doesn't end up in the requested state, e.g. a disabled box or a script undoing it."""
    return await _act(session, lambda p: p.set_checked(selector, checked, timeout=_INPUT_TIMEOUT))


@mcp.tool()
async def upload_file(selector: str, paths: list[str], session: str = "") -> dict:
    """Set the files of an <input type=file> (selector) to paths, as if the user picked them.

    Relative paths resolve against the server's output folder. Pass [] to clear the selection.
    The input's change event fires; submit the form with click or press afterwards.
    """
    files = [str((_OUTPUT_DIR / f).resolve()) for f in paths]
    missing = [f for f in files if not os.path.isfile(f)]
    if missing:
        raise FileNotFoundError(f"Not files: {missing}")
    async def pick(page):
        await page.set_input_files(selector, files, timeout=_INPUT_TIMEOUT)
        return {"result": files}
    return await _act(session, pick)


@mcp.tool()
async def screenshot(path: str, session: str = "") -> dict:
    """Save a full-page PNG screenshot of the page opened by navigate to path, returned as {"result": absolute path}. Use to check layout or what actually rendered."""
    _use(session)
    path = str(_out(path))
    await (await _page()).screenshot(path=path, full_page=True)
    return {"result": path}


@mcp.tool()
async def download(url: str, dest: str, session: str = "") -> dict:
    """Download a file (PDF, xlsx, HTML, ...) to dest exactly as served, using the browser's cookies.

    Use for document links found with links. Returns HTTP status, final URL, content type, size and the absolute path written.
    """
    _use(session)
    page = await _page(fresh=True)
    t0 = time.monotonic()
    try:
        resp = await page.context.request.get(url, headers=_s()["extra_headers"])
    except Exception as e:
        if not _proxy_refused(str(e)):
            raise
        log.warning("download %s blocked by proxy: %s", url, e)
        return _blocked_result(url)
    if _proxy_block_response(resp.headers):
        log.warning("download %s blocked by proxy allowlist", url)
        return _blocked_result(url)
    body = await resp.body()
    dest = _out(dest)
    dest.write_bytes(body)
    _log_response(resp.status, resp.url, resp.headers, "download")
    log.info("download %s -> %s %d bytes to %s (%.1fs)", url, resp.status, len(body), dest, time.monotonic() - t0)
    return {
        "status": resp.status,
        "final_url": resp.url,
        "content_type": resp.headers.get("content-type"),
        "bytes": len(body),
        "path": str(dest),
    }


def _cert_summary(der: bytes) -> dict:
    """Subject, issuer and SAN of a DER cert, for checking which host an IP actually serves."""
    try:
        from cryptography import x509
        c = x509.load_der_x509_certificate(der)
        try:
            san = [n.value for n in c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
        except x509.ExtensionNotFound:
            san = []
        return {"subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(),
                "san": san, "not_after": c.not_valid_after_utc.isoformat()}
    except Exception as e:  # cryptography missing, or an unparseable cert
        return {"error": f"{type(e).__name__}: {e}"}


class _ProxyRefused(Exception):
    """The configured proxy declined the CONNECT tunnel (e.g. host not on an allowlist)."""
    def __init__(self, status):
        self.status = status
        super().__init__(f"proxy refused CONNECT (status {status})")


def _proxy_parts():
    """(host, port, Proxy-Authorization value or None) for the configured proxy, or None if direct."""
    if not _PROXY:
        return None
    u = urlsplit(_PROXY if "://" in _PROXY else f"http://{_PROXY}")
    host = "127.0.0.1" if u.hostname == "localhost" else u.hostname
    auth = None
    if u.username:
        import base64
        raw = f"{unquote(u.username)}:{unquote(u.password or '')}".encode()
        auth = "Basic " + base64.b64encode(raw).decode()
    return host, u.port or 8080, auth


def _connect_sock(connect, port, timeout):
    """A TCP socket to connect:port. Direct when no proxy is set; otherwise tunnelled through the proxy
    with HTTP CONNECT. The proxy resolves the host, so an IP pinned in connect isn't honoured and an
    allowlist proxy refuses a host it doesn't allow (raised as _ProxyRefused); Host and SNI, set on the
    tunnelled socket afterwards, still work. Plain-HTTP (port 80) may be refused by a CONNECT-only proxy."""
    proxy = _proxy_parts()
    if proxy is None:
        return socket.create_connection((connect, port), timeout=timeout)
    phost, pport, pauth = proxy
    sock = socket.create_connection((phost, pport), timeout=timeout)
    try:
        req = f"CONNECT {connect}:{port} HTTP/1.1\r\nHost: {connect}:{port}\r\n"
        if pauth:
            req += f"Proxy-Authorization: {pauth}\r\n"
        sock.sendall((req + "\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        line = buf.split(b"\r\n", 1)[0].split(b" ")
        status = int(line[1]) if len(line) > 1 and line[1].isdigit() else 0
        if status != 200:
            raise _ProxyRefused(status)
        return sock
    except Exception:
        sock.close()
        raise


def _one_request(method, url, connect_ip, host_header, sni, max_bytes, headers, body) -> dict:
    """One HTTP(S) request with the connection target, Host header and TLS SNI set independently.

    Blocking; call it in a thread. Connection, TLS and HTTP errors come back in the dict, not raised,
    because a failed handshake (e.g. no-SNI to a CDN) is itself the test result.
    """
    u = urlsplit(url)
    https = u.scheme != "http"
    port = u.port or (443 if https else 80)
    url_host = u.hostname
    connect = connect_ip or url_host
    host_hdr = host_header or (url_host if not u.port else f"{url_host}:{u.port}")
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    server_name = None if sni == "none" or not https else (sni or host_hdr.split(":")[0])
    out = {"requested": {"url": url, "connect_ip": connect, "port": port, "host_header": host_hdr,
                         "sni": "(none)" if https and sni == "none" else server_name}}
    sock = None
    if _PROXY:
        out["requested"]["via_proxy"] = True  # the proxy resolves connect; peer_ip is unknown
    try:
        sock = _connect_sock(connect, port, 20)
        if not _PROXY:
            out["peer_ip"] = sock.getpeername()[0]
        if https:
            ctx = ssl_mod.SSLContext(ssl_mod.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl_mod.CERT_NONE  # the point is to inspect mismatched hosts/IPs
            sock = ctx.wrap_socket(sock, server_hostname=server_name)
            out["tls"] = {"version": sock.version(), "cipher": sock.cipher()[0], "sni_sent": server_name,
                          "cert": _cert_summary(sock.getpeercert(binary_form=True))}
        conn = http.client.HTTPConnection(connect, port, timeout=20)
        conn.sock = sock
        # Caller headers override the defaults (case-insensitively), so Host/UA/Accept can be set too.
        given = {k.lower() for k in headers or {}}
        defaults = {"Host": host_hdr, "Connection": "close", "User-Agent": "burrow-browser", "Accept": "*/*"}
        hdrs = {**{k: v for k, v in defaults.items() if k.lower() not in given}, **(headers or {})}
        conn.request(method, path, body=(body or None), headers=hdrs)
        resp = conn.getresponse()
        data = resp.read(max_bytes)
        out.update(status=resp.status, reason=resp.reason, headers=dict(resp.getheaders()),
                   body_bytes=len(data), body=data.decode("utf-8", "replace"))
    except _ProxyRefused as e:
        out.update(error=f"blocked by network proxy: {e}", blocked_hosts=[connect])
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    return out


def _raw_request(method, url, connect_ip, host_header, sni, max_bytes, headers, body, follow_redirects) -> dict:
    """First hop with the caller's connect_ip/host_header/sni overrides, then follow Location by DNS."""
    out = _one_request(method, url, connect_ip, host_header, sni, max_bytes, headers, body)
    if not follow_redirects:
        return out
    chain, hop = [], out
    # ponytail: overrides apply to the first hop only; later hops resolve the Location host by DNS.
    for _ in range(5):
        loc = {k.lower(): v for k, v in hop.get("headers", {}).items()}.get("location")
        if hop.get("status") not in (301, 302, 303, 307, 308) or not loc:
            break
        chain.append({"status": hop["status"], "location": loc})
        url = urljoin(url, loc)
        if hop["status"] == 303:
            method, body = "GET", ""
        hop = _one_request(method, url, "", "", "", max_bytes, headers, body)
    if chain:
        out = hop
        out["redirect_chain"] = chain
    return out


@mcp.tool()
async def http_request(url: str, connect_ip: str = "", host_header: str = "", sni: str = "",
                       method: str = "GET", max_bytes: int = 200_000,
                       headers: dict | None = None, body: str = "", follow_redirects: bool = False,
                       record: bool = False, session: str = "") -> dict:
    """One raw HTTP(S) request with the connection IP, Host header and TLS SNI set independently.

    For DNS/vhost testing, like curl --resolve / --connect-to / -H Host, plus CORS-preflight,
    cache-control and redirect-chain checks. Not a browser call: no JavaScript or cookies. Returns
    {"result": {...}} with peer_ip, tls (version, cipher, sni_sent, cert subject/issuer/SAN), status,
    headers and body. Errors (e.g. a refused TLS handshake) come back in the result, not as a failure.
      connect_ip  TCP target; default resolves the URL host via DNS. Set it to reach a specific
                  origin/alternate host while keeping the URL's Host and SNI.
      host_header Host header; default the URL host. Set it to the connect IP or another name to
                  check the default vhost / alternate-host routing.
      sni         TLS server name; default the Host header's host. "none" omits SNI.
      headers     extra request headers; override the defaults (e.g. Origin, Access-Control-Request-Method
                  for a CORS preflight with method=OPTIONS, or Cache-Control).
      body        request body sent as-is; set a Content-Type header for it yourself.
      follow_redirects  follow up to 5 3xx hops by DNS (connect_ip/host_header/sni apply to the first
                  hop only), adding a redirect_chain of {status, location} to the final result.
      record      add this response to the session's request log (as a "fetch" entry) so a later
                  scan_secrets / get_response_body sees it, for probing an endpoint the page didn't call.
    Certificates are fetched but NOT validated, so a cert that doesn't match the host still returns.
    Behind a network proxy (Claude Science) the request is tunnelled through it with HTTP CONNECT:
    host_header, sni, headers and TLS/cert inspection all work, but the proxy resolves the host, so
    connect_ip can't pin an IP (an IP or a host the allowlist doesn't allow comes back as
    blocked_hosts) and there's no peer_ip. https works; plain http:// may be refused by the proxy.
    """
    _use(session)
    result = await asyncio.to_thread(_raw_request, method, url, connect_ip, host_header, sni, max_bytes,
                                     headers, body, follow_redirects)
    log.info("http_request %s connect=%s host=%s -> %s", url, connect_ip or "(dns)", host_header or "(url)",
             result.get("status") or result.get("error"))
    if record and "status" in result:
        sess = _s()
        sess["req_seq"] += 1
        sess["requests"].append({
            "id": sess["req_seq"], "method": method, "url": result.get("final_url", url), "type": "fetch",
            "status": result["status"], "content_type": (result.get("headers") or {}).get("content-type"),
            "request_headers": headers or {}, "post_data": body or None,
            "response_headers": result.get("headers") or {}, "_body": result.get("body", ""),
        })
    return {"result": result}


@mcp.tool()
async def get_response_body(url_or_id: str, max_bytes: int = 2_000_000, session: str = "") -> dict:
    """Body of a response already captured by requests(), as {"result": {url, status, content_type, bytes, truncated, body}}.

    Pass an entry's id (from requests()) or a substring of its url; the most recent match wins.
    Reads the payload from the live browser without reloading the page: use it to check an API
    response against a schema, or check a script/JSON for build metadata or env values.
    The body is held only until the next navigate (which clears captures); after that it is gone
    and this returns an error in the result. For a persistent copy of all bodies, use start_recording.
    """
    _use(session)
    kept = [r for r in _s()["requests"] if "_resp" in r or "_body" in r]
    match = None
    if url_or_id.isdigit():
        match = next((r for r in kept if r.get("id") == int(url_or_id)), None)
    if match is None:
        match = next((r for r in reversed(kept) if url_or_id in r["url"]), None)
    if match is None:
        raise ValueError(f"No captured response matches {url_or_id!r}; call requests() to list ids and urls.")
    if "_body" in match:  # recorded by http_request(record=True); text, not bytes
        text = match["_body"]
        return {"result": {"url": match["url"], "status": match["status"], "content_type": match.get("content_type"),
                           "bytes": len(text.encode("utf-8", "replace")), "truncated": len(text) > max_bytes,
                           "body": text[:max_bytes]}}
    try:
        data = await match["_resp"].body()
    except Exception as e:
        return {"result": {"url": match["url"], "status": match["status"],
                           "error": f"body unavailable ({type(e).__name__}: {e}); it is kept only until the next navigate."}}
    return {"result": {"url": match["url"], "status": match["status"], "content_type": match.get("content_type"),
                       "bytes": len(data), "truncated": len(data) > max_bytes,
                       "body": data[:max_bytes].decode("utf-8", "replace")}}


@mcp.tool()
async def cookies(action: str = "list", data: list | None = None, session: str = "") -> dict:
    """Read or set the browser context's cookies, including HttpOnly ones document.cookie can't see.

    action="list" (default) returns {"result": [{name, value, domain, path, httpOnly, secure, sameSite, expires}, ...]}
    for auditing session-cookie flags. action="set" adds the cookies in data (a list of such dicts;
    each needs url, or domain+path) and returns the updated list. action="clear" removes all and returns [].
    """
    _use(session)
    ctx = (await _page()).context
    if action == "list":
        return {"result": await ctx.cookies()}
    if action == "set":
        if not data:
            raise ValueError("Pass data=[{name, value, url | domain+path, httpOnly?, secure?, sameSite?, expires?}]")
        await ctx.add_cookies(data)
        return {"result": await ctx.cookies()}
    if action == "clear":
        await ctx.clear_cookies()
        return {"result": []}
    raise ValueError(f"Unknown action {action!r}; use list, set or clear.")


@mcp.tool()
async def set_browser_headers(headers: dict, session: str = "") -> dict:
    """Set persistent extra HTTP headers (e.g. Authorization) for this session's navigate and XHR calls.

    Headers survive across navigations and recording toggles. Pass {} to clear them. Use to reach a
    staging/UAT environment behind Basic Auth or an access token. SECURITY: these headers are sent to
    EVERY host the page requests, including third parties and cross-origin resources, so an Authorization
    header is sent to them as well. Only set credentials when navigating.
    """
    _use(session)
    # ponytail: sent to all hosts, no per-origin scoping; add an allowed-origins filter if a token must not leak.
    _s()["extra_headers"] = dict(headers) or None
    await (await _page()).context.set_extra_http_headers(headers or {})
    return {"result": {"headers": headers or {}}}


@mcp.tool()
async def console_logs(type: str = "", session: str = "") -> dict:
    """Browser console messages, uncaught page exceptions and CSP violations since the last navigate.

    Returns {"result": [{type, text, location}, ...]}. type is the console level (log, info, warning,
    error) or "pageerror" for uncaught exceptions; CSP violations arrive as error entries whose text
    starts with "[CSP]". Filter with type (a level, "pageerror", or "csp" for CSP violations only).
    Use to surface broken CSP directives, missing assets and runtime JS/React errors in a regression run.
    """
    _use(session)
    logs = list(_s()["console"])
    if type == "csp":
        logs = [e for e in logs if e["text"].startswith("[CSP]")]
    elif type:
        logs = [e for e in logs if e["type"] == type]
    return {"result": logs}


@mcp.tool()
async def frames_and_listeners(session: str = "") -> dict:
    """Inventory of the page's iframes, service workers and window 'message' listeners.

    Returns {"result": {frames: [{url, name}], service_workers: [{scope, scriptURL}], message_listeners: [name, ...]}}.
    Use to check embedded components and cross-window handlers against frame-ancestors and origin rules.
    message_listeners only lists handlers added via window.addEventListener('message', ...) after page
    load; onmessage= assignments and listeners on other targets are not captured.
    """
    _use(session)
    page = await _page()
    frames = [{"url": f.url, "name": f.name} for f in page.frames]
    # main world (mw: prefix, as the evaluate tool uses): the init script's state and the page's own
    # addEventListener both live there, not in Playwright's isolated world.
    sw = await page.evaluate("""mw:async () => {
        if (!navigator.serviceWorker || !navigator.serviceWorker.getRegistrations) return [];
        try {
            const rs = await navigator.serviceWorker.getRegistrations();
            return rs.map(r => ({scope: r.scope, scriptURL: (r.active || r.installing || r.waiting || {}).scriptURL || null}));
        } catch (e) { return []; }
    }""")
    listeners = await page.evaluate("mw:() => window.__burrow_listeners || []")
    return {"result": {"frames": frames, "service_workers": sw, "message_listeners": listeners}}


@mcp.tool()
async def websockets(contains: str = "", session: str = "") -> dict:
    """WebSocket connections opened by the page since the last navigate, with frame counts.

    Returns {"result": [{url, state, sent, received, detail}, ...]}; state is open, closed or error,
    sent/received are frame counts (not payloads). Filter with contains (substring of the url).
    EventSource/SSE streams are plain requests: find them in requests() by content-type text/event-stream.
    """
    _use(session)
    return {"result": [w for w in _s()["websockets"] if contains in w["url"]]}


async def _poll_js(page, js, timeout):
    """Poll a JS condition in the page's main world until truthy. page.wait_for_function can't be used:
    it runs in Playwright's isolated world (Camoufox's mw: prefix doesn't apply), blind to page globals."""
    deadline = time.monotonic() + timeout / 1000
    while not await page.evaluate("mw:" + js):
        if time.monotonic() > deadline:
            raise PlaywrightTimeoutError(f"js condition not met in {timeout} ms")
        await asyncio.sleep(0.1)


@mcp.tool()
async def wait_for(selector: str = "", text: str = "", url: str = "", js: str = "", state: str = "visible",
                   load_state: str = "", timeout: int = 10_000, session: str = "") -> dict:
    """Wait until the page reaches a condition, instead of racing an async (SPA) page.

    Give one or more conditions; each must hold, checked in this order, each with up to timeout ms:
      selector    a CSS/Playwright selector reaches state (first match).
      text        an element containing this text reaches state.
      state       for selector/text: visible (default), hidden, attached or detached.
                  "Spinner gone" = selector=".spinner", state="hidden".
      url         the page URL contains this substring (also catches pushState route changes).
      js          a JS expression or function, run in the page's main world, becomes truthy,
                  e.g. "() => window.app && window.app.ready".
      load_state  load, domcontentloaded or networkidle.
    A timeout is a result, not an error: returns {"result": true|false, "failed": <condition or None>,
    "elapsed_ms", final_url, title}.
    """
    _use(session)
    page = await _page()
    waits = []
    if selector:
        waits.append(("selector", lambda: page.locator(selector).first.wait_for(state=state, timeout=timeout)))
    if text:
        waits.append(("text", lambda: page.get_by_text(text).first.wait_for(state=state, timeout=timeout)))
    if url:
        waits.append(("url", lambda: page.wait_for_url(lambda u: url in u, wait_until="commit", timeout=timeout)))
    if js:
        waits.append(("js", lambda: _poll_js(page, js, timeout)))
    if load_state:
        waits.append(("load_state", lambda: page.wait_for_load_state(load_state, timeout=timeout)))
    if not waits:
        raise ValueError("Pass at least one of selector, text, url, js or load_state.")
    t0, failed = time.monotonic(), None
    for name, wait in waits:
        try:
            await wait()
        except PlaywrightTimeoutError:
            failed = name
            break
    return {"result": failed is None, "failed": failed, "elapsed_ms": round((time.monotonic() - t0) * 1000),
            "final_url": page.url, "title": await page.title(), **_take_blocked()}


@mcp.tool()
async def dialogs(action: str = "", prompt_text: str = "", session: str = "") -> dict:
    """alert/confirm/prompt/beforeunload dialogs the page opened since the last navigate.

    Every dialog is answered automatically so it can't block the page, and recorded here as
    {"result": [{type, message, default_value, action}, ...]}. Dialogs are dismissed by default
    (confirm() returns false). Pass action="accept" before triggering one to accept instead
    (confirm() returns true, prompt() returns prompt_text), or action="dismiss" to go back.
    The policy lasts for the session.
    """
    _use(session)
    if action:
        if action not in ("accept", "dismiss"):
            raise ValueError(f"Unknown action {action!r}; use accept or dismiss.")
        _s().update(dialog_policy=action, prompt_text=prompt_text)
    return {"result": list(_s()["dialogs"]), "policy": _s()["dialog_policy"]}


_QUERY_JS = """(els, limit) => els.slice(0, limit).map(e => {
    const r = e.getBoundingClientRect();
    return {tag: e.tagName.toLowerCase(), text: (e.innerText || e.textContent || '').trim().slice(0, 1000),
            value: 'value' in e && typeof e.value === 'string' ? e.value : null,
            checked: 'checked' in e ? e.checked : null, disabled: 'disabled' in e ? e.disabled : null,
            visible: r.width > 0 && r.height > 0 && getComputedStyle(e).visibility !== 'hidden',
            attrs: Object.fromEntries([...e.attributes].map(a => [a.name, a.value]))};
})"""


@mcp.tool()
async def query(selector: str, limit: int = 20, session: str = "") -> dict:
    """Inspect the elements matching a CSS/Playwright selector, for targeted assertions.

    Returns {"result": {count, items: [{tag, text, value, checked, disabled, visible, attrs}, ...]}}
    for the first limit matches; count is the total. value is an input's current value, checked a
    checkbox/radio state (null where not applicable). visible uses Playwright's rule: non-empty box and
    not visibility:hidden. Doesn't wait: count 0 means absent right now (use wait_for to wait).
    E.g. query(".error-banner") -> is it visible? query("#email") -> its value.
    """
    _use(session)
    loc = (await _page()).locator(selector)
    return {"result": {"count": await loc.count(), "items": await loc.evaluate_all(_QUERY_JS, limit)}}


# ponytail: values capped at 4000 chars and 50 records per IndexedDB store; raise if audits need full dumps.
_STORAGE_JS = r"""async kind => {
  const cap = v => { const s = typeof v === 'string' ? v : JSON.stringify(v); return s && s.length > 4000 ? s.slice(0, 4000) + '…' : s; };
  const web = st => { const o = {}; for (let i = 0; i < st.length; i++) { const k = st.key(i); o[k] = cap(st.getItem(k)); } return o; };
  const out = {origin: location.origin};
  for (const [area, get] of [['local', () => localStorage], ['session', () => sessionStorage]])
    if (kind === 'all' || kind === area) try { out[area] = web(get()); } catch (e) { out[area + '_error'] = String(e); }
  if (kind === 'all' || kind === 'indexeddb') {
    const req = p => new Promise((ok, no) => { p.onsuccess = () => ok(p.result); p.onerror = () => no(p.error); });
    try {
      out.indexeddb = {};
      for (const {name, version} of await indexedDB.databases()) {
        const db = await req(indexedDB.open(name));
        const stores = {};
        for (const s of db.objectStoreNames) {
          const st = db.transaction(s, 'readonly').objectStore(s);
          stores[s] = {count: await req(st.count()), records: (await req(st.getAll(null, 50))).map(cap)};
        }
        db.close();
        out.indexeddb[name] = {version, stores};
      }
    } catch (e) { delete out.indexeddb; out.indexeddb_error = String(e); }
  }
  return out;
}"""
_SENSITIVE = re.compile(r"token|auth|jwt|bearer|session|secret|passw|api.?key|credential", re.I)
_JWT = re.compile(r"eyJ[\w-]{5,}\.eyJ[\w-]{5,}\.")


@mcp.tool()
async def storage(kind: str = "all", session: str = "") -> dict:
    """Read the current page origin's web storage: kind = local, session, indexeddb or all (default).

    Returns {"result": {origin, local: {key: value}, session: {...}, indexeddb: {db: {version, stores:
    {store: {count, records}}}}, sensitive: [...]}}; an area the page may not access (e.g. an opaque
    data: origin) comes back as <area>_error instead. sensitive lists "local:<key>" / "session:<key>"
    entries whose key looks like a credential or whose value holds a JWT: a token in web storage is
    readable by every script running on the origin, unlike an HttpOnly cookie (see cookies).
    Long values are truncated to 4000 chars and IndexedDB stores to 50 records. Main frame origin only.
    """
    _use(session)
    if kind not in ("all", "local", "session", "indexeddb"):
        raise ValueError(f"Unknown kind {kind!r}; use local, session, indexeddb or all.")
    page = await _page()
    out = await asyncio.wait_for(page.evaluate(_STORAGE_JS, kind), _EVALUATE_TIMEOUT)
    out["sensitive"] = [f"{area}:{k}" for area in ("local", "session") for k, v in out.get(area, {}).items()
                        if _SENSITIVE.search(k) or _JWT.search(v or "")]
    return {"result": out}


@mcp.tool()
async def snapshot(selector: str = "body", session: str = "") -> dict:
    """Accessibility tree of the page (or of the first element matching selector) as YAML, {"result": text}.

    Lines look like `- heading "Orders" [level=1]`, `- button "Save"`, `- textbox "Email": a@b.c`,
    `- checkbox "Remember me" [checked]`. Much smaller than get_html and, unlike get_text, it keeps
    structure and roles. Turn a line into a stable selector: role=button[name="Save"].
    Doubles as an accessibility check: a bare `- button` or `- textbox` with no name is unlabeled.
    """
    _use(session)
    return {"result": await (await _page()).locator(selector).first.aria_snapshot(timeout=_INPUT_TIMEOUT)}


@mcp.tool()
async def tabs(switch: int = -1, close: int = -1, session: str = "") -> dict:
    """List this session's tabs; switch=<index> makes one current, close=<index> closes one.

    Popups (window.open, OAuth/payment windows) and target=_blank links open new tabs; click and
    other inputs report them as new_tabs, best-effort: a slow popup may only show up here. Every other tool works on the current tab. If the current
    tab closes itself, the newest remaining tab becomes current. Returns {"result": [{index, url,
    title, current}, ...]} after the change. Their traffic and console output land in the same logs.
    start_recording/stop_recording keep only the current tab.
    """
    _use(session)
    sess = _s()
    pages = (await _page()).context.pages
    for i in (switch, close):
        if i >= len(pages):
            raise IndexError(f"No tab {i}; there are {len(pages)}.")
    if switch >= 0:
        sess["page"] = pages[switch]
        await pages[switch].bring_to_front()
    if close >= 0:
        await pages[close].close()
    page = await _page()  # falls back to another tab if the current one was closed
    return {"result": [{"index": i, "url": p.url, "title": await p.title(), "current": p is page}
                       for i, p in enumerate(page.context.pages)]}


def _route_handler(spec):
    async def handle(route):
        spec["hits"] += 1
        if spec["delay_ms"]:
            await asyncio.sleep(spec["delay_ms"] / 1000)
        if spec["action"] == "abort":
            await route.abort()
        elif spec["action"] == "fulfill":
            await route.fulfill(status=spec["status"], body=spec["_body"], content_type=spec["content_type"],
                                headers=spec["_headers"])
        else:
            await route.continue_()
    return handle


@mcp.tool()
async def route(pattern: str = "", action: str = "list", status: int = 200, body: str = "",
                content_type: str = "application/json", headers: dict | None = None, delay_ms: int = 0,
                session: str = "") -> dict:
    """Intercept requests whose URL contains pattern, to test how the page copes with failure.

    action:
      fulfill  answer with status, body, content_type and headers instead of the real server,
               e.g. status=500, or body="[]" for an empty list. For a cross-origin API add
               headers={"Access-Control-Allow-Origin": "*"} or the browser blocks the mock.
      abort    fail the request like a network error. pattern="" aborts everything = offline.
      delay    let the request through after delay_ms (slow API; check spinners and timeouts).
               delay_ms also delays fulfill and abort.
      clear    remove the rule for pattern, or every rule if pattern is "".
      list     (default) show the rules.
    Rules apply to all tabs of the session and survive navigate; setting a pattern again replaces
    its rule. Returns {"result": [{pattern, action, status, delay_ms, hits}, ...]}; hits counts the
    requests a rule caught, so 0 means the pattern didn't match. The page is not reloaded:
    navigate or click afterwards. Requests served by a service worker are not intercepted.
    """
    _use(session)
    sess = _s()
    ctx = (await _page()).context
    if action not in ("list", "clear", "fulfill", "abort", "delay"):
        raise ValueError(f"Unknown action {action!r}; use fulfill, abort, delay, clear or list.")
    if action != "list":
        for key in [k for k in sess["routes"] if k == pattern or (action == "clear" and not pattern)]:
            old = sess["routes"].pop(key)
            await ctx.unroute(old["_match"], old["_handle"])
    if action in ("fulfill", "abort", "delay"):
        spec = {"pattern": pattern, "action": action, "status": status, "content_type": content_type,
                "delay_ms": delay_ms, "hits": 0, "_body": body, "_headers": headers,
                "_match": lambda url: pattern in url}
        spec["_handle"] = _route_handler(spec)
        sess["routes"][pattern] = spec
        await ctx.route(spec["_match"], spec["_handle"])
    return {"result": [{k: v for k, v in r.items() if not k.startswith("_")} for r in sess["routes"].values()]}


def _audit_headers(h: dict, https: bool) -> list:
    """Findings for a document's response headers (lower-case names). Pure, so it is easy to test."""
    found = []
    add = lambda severity, issue: found.append({"severity": severity, "issue": issue})
    csp = {d.split()[0].lower(): d.split()[1:] for d in h.get("content-security-policy", "").split(";") if d.split()}
    if not csp:
        add("medium", "No Content-Security-Policy header" +
            (" (only Content-Security-Policy-Report-Only, which enforces nothing)"
             if "content-security-policy-report-only" in h else ""))
    else:
        scripts = csp.get("script-src", csp.get("default-src"))
        if scripts is None:
            add("medium", "CSP has neither script-src nor default-src: scripts are unrestricted")
        else:
            # A nonce or hash makes CSP2+ browsers ignore 'unsafe-inline'.
            if "'unsafe-inline'" in scripts and not any(x.startswith(("'nonce-", "'sha")) for x in scripts):
                add("medium", "CSP script-src allows 'unsafe-inline': inline scripts are not restricted")
            if "'unsafe-eval'" in scripts:
                add("low", "CSP script-src allows 'unsafe-eval'")
            wide = [x for x in scripts if x in ("*", "http:", "https:", "data:")]
            if wide:
                add("medium", f"CSP script-src allows any source via {' '.join(wide)}")
    if "frame-ancestors" not in csp and "x-frame-options" not in h:
        add("medium", "Neither X-Frame-Options nor CSP frame-ancestors: other sites can embed the page in a frame")
    if not https:
        add("medium", "Served over plain HTTP")
    elif "strict-transport-security" not in h:
        add("medium", "No Strict-Transport-Security header")
    else:
        age = re.search(r"max-age=(\d+)", h["strict-transport-security"])
        if not age or int(age[1]) < 15_552_000:
            add("low", "HSTS max-age under 180 days")
    if h.get("x-content-type-options", "").lower() != "nosniff":
        add("low", "No X-Content-Type-Options: nosniff")
    if h.get("referrer-policy", "").lower() in ("unsafe-url", "no-referrer-when-downgrade"):
        add("low", f"Referrer-Policy {h['referrer-policy']} sends full URLs to other sites")
    if "permissions-policy" not in h:
        add("info", "No Permissions-Policy header")
    if h.get("access-control-allow-origin") == "*":
        add("info", "Access-Control-Allow-Origin: * lets any site read this response")
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        if name in h and (name != "server" or re.search(r"\d", h[name])):
            add("low", f"{name}: {h[name]} discloses software/version")
    return found


_AUDITED = ("content-security-policy", "content-security-policy-report-only", "strict-transport-security",
            "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy",
            "cross-origin-opener-policy", "cross-origin-embedder-policy", "cross-origin-resource-policy",
            "access-control-allow-origin", "access-control-allow-credentials", "server", "x-powered-by")


@mcp.tool()
async def security_headers(session: str = "") -> dict:
    """Audit the current page's security response headers and its cookies' flags.

    Uses the document response captured at the last navigate (no extra request). Returns {"result":
    {url, status, headers: {<security header>: value}, findings: [{severity, issue}, ...]}} with
    severity high/medium/low/info. Checks CSP (missing, unsafe-inline/eval, wildcard script sources),
    framing protection, HSTS, nosniff, Referrer-Policy, Permissions-Policy, CORS wildcard, version
    disclosure, and cookies missing Secure / HttpOnly (token-like names) / SameSite=None without Secure.
    A <meta> CSP isn't seen. A 304 response may lack headers: navigate again or clear the cache.
    These are heuristics for triage, not a verdict.
    """
    _use(session)
    page = await _page()
    target = page.url.split("#")[0]
    docs = [r for r in _s()["requests"] if r["type"] == "document" and r.get("response_headers") is not None]
    doc = next((r for r in reversed(docs) if r["url"].split("#")[0] == target), docs[-1] if docs else None)
    if doc is None:
        raise RuntimeError("No document response captured; call navigate first.")
    h, https = doc["response_headers"], doc["url"].startswith("https:")
    findings = _audit_headers(h, https)
    for c in await page.context.cookies(doc["url"]):
        name = c["name"]
        if https and not c["secure"]:
            findings.append({"severity": "medium", "issue": f"cookie {name} lacks Secure"})
        if not c["httpOnly"] and _SENSITIVE.search(name):
            findings.append({"severity": "medium", "issue": f"cookie {name} looks like a credential but lacks HttpOnly"})
        if c.get("sameSite") == "None" and not c["secure"]:
            findings.append({"severity": "medium", "issue": f"cookie {name} is SameSite=None without Secure"})
    return {"result": {"url": doc["url"], "status": doc["status"], "headers": {k: h[k] for k in _AUDITED if k in h},
                       "findings": findings}}


@mcp.tool()
async def close_session(session: str = "") -> dict:
    """Close this session's tabs and forget its cookies, logs, mocks and headers; the name can be reused fresh.

    Call when your task is done so a shared browser doesn't fill up with idle pages. A recording in
    progress is saved first: the result then includes {"har": path}.
    """
    _use(session)
    sess = _sessions.pop(_current.get(), None)
    if sess is None or sess["page"] is None:
        return {"result": "no open session"}
    try:
        await sess["page"].context.close()  # also writes a HAR being recorded
    except Exception as e:  # the browser died meanwhile
        log.warning("closing session %s failed: %s", _current.get(), e)
    return {"result": "closed", **({"har": sess["har"]} if sess["har"] else {})}


async def _relaunch_keeping_sessions() -> list:
    """Restart the browser with the current _LAUNCH options. Each session keeps its cookies, storage
    and current URL; extra tabs and in-page state are lost. Refused while any session records."""
    recording = sorted(n for n, s in _sessions.items() if s["har"])
    if recording:
        raise RuntimeError(f"Stop recording first; sessions recording: {', '.join(recording)}.")
    saved = {}
    for name, sess in list(_sessions.items()):
        page = sess["page"]
        if page is not None and not page.is_closed():
            try:
                saved[name] = (page.url, await page.context.storage_state())
            except Exception as e:
                log.warning("couldn't save session %s before restart: %s", name, e)
    await _browser(force_relaunch=True)
    for name, (url, storage) in saved.items():
        token = _current.set(name)
        try:
            _s()["lost"] = False
            await _new_page(storage)
            if url.startswith("http"):
                try:
                    await _s()["page"].goto(url, wait_until="domcontentloaded")
                except Exception as e:
                    log.warning("reopening %s for session %s failed: %s", url, name, e)
        finally:
            _current.reset(token)
    return sorted(saved)


@mcp.tool()
async def browser_settings(humanize: bool | None = None, adblock: bool | None = None,
                           instant_animations: bool | None = None, block_images: bool | None = None,
                           block_webrtc: bool | None = None, geoip: bool | None = None,
                           session: str = "") -> dict:
    """Turn browser-wide Camoufox options on or off; with no arguments, show the current settings.

      humanize            move the mouse along human-like paths for click and hover (slower)
      adblock             uBlock Origin ad and tracker blocking, on by default; turn it off to check ad slots
      instant_animations  CSS and Web Animations finish at once, for steadier screenshots and waits
                          (a page can tell: getComputedTiming() reports a 0 duration)
      block_images        don't load images, for faster text-only runs
      block_webrtc        disable WebRTC, so it can't reveal the machine's local IP (useful behind a proxy)
      geoip               set timezone, locale and geolocation from the browser's exit IP (the proxy's,
                          if one is set); looks the IP up once at launch, so that lookup must be reachable
    Changing any of them restarts the browser for every session: cookies, storage and each session's
    current page carry over, extra tabs close and in-page state is lost. Not possible while a session
    is recording. For per-session settings (OS, locale, viewport, dark mode, ...) use set_identity.
    Returns {"result": {<option>: on/off, ...}, "restarted_sessions": [...]}.
    """
    _use(session)
    asked = {"humanize": humanize, "adblock": adblock, "instant_animations": instant_animations,
             "block_images": block_images, "block_webrtc": block_webrtc, "geoip": geoip}
    changes = {k: v for k, v in asked.items() if v is not None and v != _LAUNCH[k]}
    if not changes:
        return {"result": dict(_LAUNCH)}
    before = dict(_LAUNCH)
    _LAUNCH.update(changes)
    try:
        restarted = await _relaunch_keeping_sessions()
    except Exception:
        _LAUNCH.update(before)  # e.g. a session is recording, or the geoip lookup failed
        raise
    log.info("browser settings changed: %s", changes)
    return {"result": dict(_LAUNCH), "restarted_sessions": restarted}


def _identity_params(given: dict) -> dict:
    """Drop the arguments set_identity's caller left out, and validate the rest."""
    out = {k: v for k, v in given.items() if v is not None and v != "" and not (k.startswith("viewport") and v == 0)}
    choices = {"os": ("windows", "macos", "linux"), "color_scheme": ("light", "dark", "no-preference"),
               "reduced_motion": ("reduce", "no-preference")}
    for key, allowed in choices.items():
        if key in out and out[key] not in allowed:
            raise ValueError(f"{key} must be one of {', '.join(allowed)}.")
    for a, b in (("latitude", "longitude"), ("viewport_width", "viewport_height")):
        if (a in given and given[a] not in (None, 0, "")) != (b in given and given[b] not in (None, 0, "")):
            raise ValueError(f"Pass {a} and {b} together.")
    return out


@mcp.tool()
async def set_identity(os: str = "", locale: str = "", timezone: str = "", latitude: float | None = None,
                       longitude: float | None = None, viewport_width: int = 0, viewport_height: int = 0,
                       color_scheme: str = "", reduced_motion: str = "", rotate: bool = False,
                       reset: bool = False, session: str = "") -> dict:
    """Give this session its own browser identity, to see how a site looks and behaves for different
    visitors. Other sessions are unaffected; cookies and the current page carry over.

      os                   windows, macos or linux: user agent, platform, fonts, screen and WebGL to match
      locale               e.g. "da-DK": navigator.language and the Accept-Language header
      timezone             IANA name, e.g. "Europe/Copenhagen": what Date and Intl report
      latitude, longitude  the position navigator.geolocation returns (permission is granted)
      viewport_width, viewport_height  page size in CSS pixels, e.g. 390 x 844 for a phone-sized layout
      color_scheme         light, dark or no-preference (prefers-color-scheme)
      reduced_motion       reduce or no-preference (prefers-reduced-motion)
      rotate               draw a new random fingerprint, keeping the settings above
      reset                drop this session's identity and use the browser-wide one again
    Arguments you leave out keep their current value. A session without an identity uses the
    fingerprint Camoufox picked at launch, shared by all sessions. Not possible while recording.
    Returns {"result": {identity_id, user_agent, platform, <settings>}}; identity_id changes whenever
    the fingerprint does.
    """
    _use(session)
    sess = _s()
    if sess["har"]:
        raise RuntimeError("Stop recording first: changing the identity replaces the browser context.")
    if reset:
        sess["identity"] = None
    else:
        prev = sess["identity"] or {"params": {}}
        params = {**prev["params"], **_identity_params({
            "os": os, "locale": locale, "timezone": timezone, "latitude": latitude, "longitude": longitude,
            "viewport_width": viewport_width, "viewport_height": viewport_height,
            "color_scheme": color_scheme, "reduced_motion": reduced_motion})}
        if rotate or "init" not in prev or any(params.get(k) != prev["params"].get(k)
                                                for k in ("os", "locale", "timezone")):
            ff = (await _browser()).version.split(".", 1)[0]
            fp = await asyncio.to_thread(generate_context_fingerprint, os=params.get("os"), ff_version=ff,
                                         timezone=params.get("timezone"), locale=params.get("locale"))
            init, base = fp["init_script"], fp["context_options"]
            platform = fp["config"].get("navigator.platform")
        else:
            init, base, platform = prev["init"], prev["base"], prev["platform"]
        opts = dict(base)
        if "viewport_width" in params:
            opts["viewport"] = {"width": params["viewport_width"], "height": params["viewport_height"]}
        if "latitude" in params:
            opts.update(geolocation={"latitude": params["latitude"], "longitude": params["longitude"]},
                        permissions=["geolocation"])
        for key in ("color_scheme", "reduced_motion"):
            if key in params:
                opts[key] = params[key]
        sess["identity"] = {"params": params, "init": init, "base": base, "opts": opts, "platform": platform,
                            "id": hashlib.sha1(init.encode()).hexdigest()[:10]}
    if sess["page"] is not None and not sess["page"].is_closed():
        await _switch_context()  # a context's options are fixed, so swap it, keeping cookies and URL
    ident = sess["identity"]
    if ident is None:
        return {"result": {"identity_id": None, "note": "using the browser-wide identity"}}
    return {"result": {"identity_id": ident["id"], "user_agent": ident["opts"].get("user_agent"),
                       "platform": ident["platform"], **ident["params"]}}


def _redact(v: str) -> str:
    return v[:4] + "…" + v[-4:] if len(v) > 12 else v[:2] + "…"


_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
# A key/variable/JSON-path name this strong means the value is a real secret, not a public id: bump to high.
_STRONG_NAME = re.compile(r"(?i)(private|secret|passw|master|hmac|signing|\bsas\b|bearer|credential|netaxept|connection[_-]?string)")
# A name credential-ish enough to trust a short value under it (relaxes the digit/length heuristic).
_NAME_IS_CRED = re.compile(r"(?i)(api[_-]?key|apikey|[_-]key$|\bkey\b|token|secret|passw|credential|bearer|\bsas\b|signature|\bsig\b|dsn|\bmac\b|private|hmac)")
# A JSON/storage key worth flagging its string value even with no quotes around it.
_JSON_KEY_CRED_RE = re.compile(r"(?i)(private|secret|passw|hmac|signing|master|netaxept|connection[_-]?string|api[_-]?key|apikey|token|credential|bearer|salt|signature|\bsig\b|\bmac\b|webhook|key$)")
# An outgoing request header whose value is (or carries) a credential.
_CRED_HEADER_RE = re.compile(r"(?i)^(authorization|x-api-key|api-?key|ocp-apim-subscription-key|subscription-key|x-algolia-api-key|x-algolia-application-id|x-auth-token|x-access-token|x-amz-security-token|signature)$")
_AUTH_SCHEME_RE = re.compile(r"(?i)^(?:Bearer|Basic|APIKey|Token|Digest)\s+(\S+)")


# (kind, severity, pattern), most specific first: a value is reported once, under the first kind that
# matches it. The value is the (?P<v>) group if present, else the whole match; (?P<name>) is the
# variable, header or URL user it belongs to.
_SECRET_PATTERNS = [(k, sev, re.compile(rx)) for k, sev, rx in [
    ("private_key", "high", r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
    ("aws_access_key", "high", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("azure_storage_key", "high", r"AccountKey=(?P<v>[A-Za-z0-9+/=]{40,})"),
    ("stripe_secret_key", "high", r"\b[sr]k_live_[0-9A-Za-z]{20,}\b"),
    ("github_token", "high", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"),
    ("gitlab_token", "high", r"\bglpat-[A-Za-z0-9_\-]{20,}"),
    ("npm_token", "high", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("shopify_token", "high", r"\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b"),
    ("sendgrid_key", "high", r"\bSG\.[\w-]{16,32}\.[\w-]{16,64}\b"),
    ("twilio_api_key", "high", r"\bSK[0-9a-fA-F]{32}\b"),
    ("huggingface_token", "high", r"\bhf_[A-Za-z0-9]{30,}\b"),
    ("slack_token", "high", r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    ("slack_webhook", "high", r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"),
    ("google_oauth_secret", "high", r"\bGOCSPX-[\w-]{20,}"),
    ("mapbox_secret_token", "high", r"\bsk\.eyJ[\w-]{10,}\.[\w-]{10,}"),
    ("ai_api_key", "high", r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{32,}"),
    ("url_credentials", "high", r"\b[a-z][a-z0-9+.-]{1,20}://(?P<name>[^\s:/@\"'<>{}$`]{1,64}):(?P<v>[^\s:/@\"'<>{}$`]{3,128})@[\w.-]+"),
    ("auth_header_literal", "high", r"[\"'`](?P<name>Bearer|Basic|Token)\s+(?P<v>[A-Za-z0-9_\-+/=.~]{12,})[\"'`]"),
    ("azure_sas_token", "medium", r"""(?i)(?:(?P<name>[\w$-]+)["']?\s*[:=]\s*["']\??)?(?P<v>sv=\d{4}-\d\d-\d\d&[^"'\s]*?sig=[A-Za-z0-9%+/=]{20,})"""),
    ("jwt", "medium", r"\beyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,}"),
    # Application Insights: a GUID, bare or inside a ConnectionString=InstrumentationKey=<guid>;Ingestion...
    ("app_insights_key", "medium", r"(?i)InstrumentationKey=(?P<v>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"),
    # A GUID assigned to a key/token/secret/guid/id-named field (JS or unquoted config), e.g. App Insights.
    ("guid_under_cred_name", "low", r"""(?i)(?P<name>[\w$-]{0,40}?(?:instrumentationkey|key|token|secret|guid|id))["']?\s*[:=]\s*["']?(?P<v>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b"""),
    ("twilio_account_sid", "low", r"\bAC[0-9a-fA-F]{32}\b"),
    # Browser keys for Maps etc. are public by design; only a risk if unrestricted in the Google console.
    ("google_api_key", "low", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    # Client-side keys that are public by design; listed so an audit sees them all.
    ("sentry_dsn", "info", r"https://(?P<v>[0-9a-f]{32})@[\w.-]*sentry[\w.-]*/\d+"),
    ("mapbox_public_token", "info", r"\bpk\.eyJ[\w-]{10,}\.[\w-]{10,}"),
    ("datadog_client_token", "info", r"\bpub[0-9a-f]{32}\b"),
    ("stripe_publishable_key", "info", r"\bpk_live_[0-9A-Za-z]{20,}\b"),
    # A credential-named variable assigned a literal. Catches build-time env blocks (NUXT_ENV_*,
    # NEXT_PUBLIC_*, VITE_*, REACT_APP_*) and config objects; _plausible drops identifiers.
    ("credential_assignment", "low",
     r"""(?i)(?P<name>[\w$-]*(?:[_-]?key|apikey|secret|token|passw(?:or)?d|credentials?|bearer|client[_-]?id|app(?:lication)?[_-]?id|dsn|signature|\bsig|sas)[\w$]{0,24})["']?\s*[:=]\s*["'](?P<v>[A-Za-z0-9][A-Za-z0-9_\-+/=.%~]{5,})["']"""),
    ("credential_in_url", "low",
     r"""[?&](?P<name>api_?key|apikey|key|token|access_token|auth|client_id)=(?P<v>[A-Za-z0-9_\-%.~]{16,})"""),
    ("internal_host", "info", r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|[a-z0-9.-]+\.(?:internal|corp|intranet|lan))\b"),
]]
_REDACT_EXEMPT = {"internal_host"}
_PLACEHOLDERS = {"password", "passwd", "secret", "changeme", "example", "username", "user", "pass", "xxxxxxxx"}


def _plausible(kind: str, v: str, name: str = "") -> bool:
    """Drop placeholders and, for name-based kinds, identifiers that only look like values."""
    if len(set(v)) < 5 or v.lower() in _PLACEHOLDERS:  # 00000000-..., "password"
        return False
    if name and _NAME_IS_CRED.search(name):
        # the key name is credential-ish, so trust a short value (e.g. data-api-key="LCWZyk")
        return len(v) >= 6
    if kind in ("credential_assignment", "runtime_config", "json_field", "browser_storage"):
        # a digit, or long and mixed case (skips "gig_access_token", "sliderOptions")
        return bool(re.search(r"\d", v)) or (len(v) >= 16 and bool(re.search(r"[a-z]", v)) and bool(re.search(r"[A-Z]", v)))
    return True


_SOURCEMAP_RE = re.compile(r"[#@]\s*sourceMappingURL=(\S+)\s*(?:\*/)?\s*$")
_LITERAL = re.compile(r"""(?<![\w$])["'`]([A-Za-z0-9_\-+/=.~]{16,200})["'`]""")
_PROP = re.compile(r"""["']?([\w$@-]+)["']?\s*[:=]\s*$""")
_ID_PROP = re.compile(r"(?i)(?:^|[_@-])?(?:id|ids|uuid|guid|hash|filename|code|version|rowkey|partitionkey|etag|nonce|integrity|sha\d*|md5)$")


def _entropy(s: str) -> float:
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in collections.Counter(s).values())


def _is_candidate(v: str, before: str) -> bool:
    """A random-looking string literal that no pattern named. Tuned on real bundles: drops alphabet
    tables, file names, paths, readable identifiers, UPPER_SNAKE constants, hostnames and *Id values."""
    if not re.search(r"\d", v) or not re.search(r"[A-Za-z]", v) or re.search(r"abcdef|ABCDEF|0123456|456789", v):
        return False
    if re.search(r"\.(?:m?js|css|png|svg|jpe?g|gif|webp|woff2?|ttf|json|html?)$|\.[a-z]{2,6}$", v):
        return False
    if re.fullmatch(r"[A-Z0-9_]+", v) and "_" in v:
        return False
    if "/" in v and not (re.search(r"[A-Z]", v) and re.search(r"[a-z]", v) and len(v) >= 30):
        return False
    if sum(map(len, re.findall(r"[a-z]{4,}|[A-Z][a-z]{3,}", v))) / len(v) > 0.3:
        return False
    prop = _PROP.search(before)
    if prop and _ID_PROP.search(prop.group(1)) and not re.search(r"(?i)client|app", prop.group(1)):
        return False
    return _entropy(v) >= 3.5


# Walks the page's own globals (window minus what a blank window has) for credential-named strings:
# catches config assembled at runtime, which no bundle scan can see.
_RUNTIME_JS = r"""() => {
  const NAME = /api.?key|apikey|secret|token|passw|credential|client.?id|app(lication)?.?id|dsn|bearer/i;
  const f = document.createElement('iframe'); f.style.display = 'none'; document.documentElement.appendChild(f);
  const builtin = new Set(Object.getOwnPropertyNames(f.contentWindow)); f.remove();
  const out = [], seen = new WeakSet();
  const walk = (o, path, depth, b) => {
    if (!o || typeof o !== 'object' || seen.has(o) || depth > 10 || --b.n < 0) return;
    if (o instanceof Node || o === window) return;
    seen.add(o);
    let keys; try { keys = Object.keys(o); } catch (e) { return; }
    for (const k of keys.slice(0, 500)) {
      let v; try { v = o[k]; } catch (e) { continue; }
      if (typeof v === 'string') { if (NAME.test(k) && v.length >= 8 && v.length <= 2000 && !/\s/.test(v)) out.push([path + '.' + k, v]); }
      else if (v && typeof v === 'object') walk(v, path + '.' + k, depth + 1, b);
    }
  };
  // Known config roots first, each with its own budget, so a big framework object can't starve them.
  const PRI = ['__NEXT_DATA__', '__NUXT__', '__INITIAL_STATE__', 'staticSettings', 'digitalData', 'dataLayer', '__APP_CONFIG__', '__ENV__', 'env', 'config', 'runtimeConfig'];
  for (const g of PRI) { try { if (window[g] && typeof window[g] === 'object') walk(window[g], 'window.' + g, 0, {n: 8000}); } catch (e) {} }
  const budget = {n: 20000};
  for (const g of Object.getOwnPropertyNames(window)) {
    if (builtin.has(g) || PRI.includes(g)) continue;
    let v; try { v = window[g]; } catch (e) { continue; }
    if (typeof v === 'string') { if (NAME.test(g) && v.length >= 8) out.push(['window.' + g, v]); }
    else walk(v, 'window.' + g, 0, budget);
  }
  const storage = [];
  for (const [label, store] of [['localStorage', window.localStorage], ['sessionStorage', window.sessionStorage]]) {
    try { for (let i = 0; i < store.length; i++) { const k = store.key(i); storage.push([label + '.' + k, store.getItem(k)]); } } catch (e) {}
  }
  return {globals: out.slice(0, 500), storage: storage.slice(0, 300)};
}"""


async def _fetch_json(ctx, url):
    """GET url with the browser's cookies; the parsed JSON body, or None."""
    try:
        resp = await ctx.request.get(url, max_redirects=0)
        return json.loads(await resp.body()) if resp.status == 200 else None
    except Exception:
        return None


@mcp.tool()
async def scan_secrets(check_source_maps: bool = True, candidates: bool = True, max_candidates: int = 50,
                       reveal: bool = False, out_path: str = "", group: bool = True, session: str = "") -> dict:
    """List API keys, tokens and other credentials in what the page loaded since the last navigate.

    Sources: documents, scripts, stylesheets and XHR/fetch responses captured since navigate (response
    bodies are also parsed as JSON and walked by key, including JSON strings nested inside JSON, so a
    secret under any field name is flagged by its path); outgoing request headers (Authorization,
    X-Api-Key, Ocp-Apim-Subscription-Key, ...), request URLs and POST bodies; the page's service
    worker scripts; the page's live JS globals; and localStorage/sessionStorage. Code the page never
    loaded (lazy chunks) isn't seen: click/scroll to load it first.
    findings, by pattern (most specific first, each value once), with severity:
      high: private keys, AWS, Azure storage, Stripe secret, GitHub, GitLab, npm, Shopify, SendGrid,
            Twilio, Hugging Face, Slack, Google OAuth secret, Mapbox secret, OpenAI/Anthropic keys,
            user:password@ in URLs/connection strings, hard-coded "Bearer/Basic …" headers.
      medium: Azure SAS tokens, JWTs, Application Insights InstrumentationKey (bare or in a
            ConnectionString).  low: Google API keys, Twilio SIDs, credential-named assignments (incl.
            env blocks like NUXT_ENV_*/NEXT_PUBLIC_*/VITE_*, reported with name), keys in URL query
            strings, runtime_config (credential-named live globals), GUIDs under a key/token/secret/id name.
      info: public-by-design client keys (Sentry DSN, Mapbox pk, Datadog RUM, Stripe pk), internal hosts.
    candidates: random-looking string literals in code that no pattern named (minified variables),
      highest entropy first, each with the preceding code as context (usually reveals the variable).
      Expect noise (content IDs, hashes): judge each by its context and shape.
    check_source_maps fetches each script's sourceMappingURL (one GET per map) and reports maps
    anyone can download, since they expose the original source.
    A value is reported once, under its most severe match; a value under a name containing private,
    secret, password, hmac, signing, sas, bearer or credential is raised to high (so a real leaked key
    isn't buried among public config). name is the variable, header, URL parameter or JSON path.
    Values are redacted (first4…last4) unless reveal=True, which returns them in full for a responsible
    disclosure. Pattern hits are leads: confirm a key is live and secret before reporting.
    out_path writes the full result as JSON to that file (relative paths resolve against the server's
    output folder; the file records whether values are redacted), to attach to a disclosure.
    Each finding carries a short context snippet (the surrounding code) so the value can be judged in
    situ without fetching the script. group=True (default) collapses repeats: hits sharing a name and
    source become one entry with a count and up to three sample values (one minified Babel pattern can
    yield hundreds of identical name=key hits); group=False returns every hit individually.
    Returns {"result": {scanned, findings: [{kind, severity, name?, urls, context?, value | (count,
    samples)}], candidates: [{value, length, entropy, context, url}], candidates_total, source_maps,
    written?}}.
    """
    _use(session)
    page = await _page()
    ctx = page.context
    show = (lambda v: v) if reveal else _redact
    sources = []  # (url, is_code, text)
    for r in list(_s()["requests"]):
        if r["type"] not in ("document", "script", "stylesheet", "xhr", "fetch", "other"):
            continue
        if "_body" in r:  # recorded by http_request(record=True); already text
            text = r["_body"]
        elif "_resp" in r:
            try:
                text = (await r["_resp"].body())[:10_000_000].decode("utf-8", "replace")
            except Exception:
                continue
        else:
            continue
        sources.append((r["url"], r["type"] in ("document", "script"), text, r.get("response_headers") or {}))
    try:  # service worker scripts don't show up in the page's request log
        # Isolated world (not mw:) on purpose: in the main world, Angular's Zone.js replaces Promise,
        # so an awaited value comes back as a {__zone_symbol__...} wrapper instead of the array.
        sw_urls = await page.evaluate("""async () => navigator.serviceWorker ? (await navigator.serviceWorker
            .getRegistrations()).map(r => (r.active || r.installing || r.waiting || {}).scriptURL).filter(Boolean) : []""")
    except Exception:
        sw_urls = []
    if not isinstance(sw_urls, list):
        sw_urls = []
    for url in sw_urls[:5]:
        try:
            resp = await ctx.request.get(url)
            sources.append((url, True, (await resp.body())[:10_000_000].decode("utf-8", "replace"), {}))
        except Exception:
            pass

    found, maps, cands = {}, {}, {}

    def add(kind, sev, value, url, name=None, context=""):
        if not value or len(value) > 8192 or not _plausible(kind, value, name or ""):
            return
        if name and _STRONG_NAME.search(name) and _SEV_ORDER.get(sev, 9) > _SEV_ORDER["high"]:
            sev = "high"  # a private/secret/password-named value is not a public id
        hit = found.setdefault(value, {"kind": kind, "severity": sev,
                                       "value": value if kind in _REDACT_EXEMPT else show(value), "urls": []})
        if _SEV_ORDER[sev] < _SEV_ORDER[hit["severity"]]:  # same value under two kinds: keep the worse
            hit["kind"], hit["severity"] = kind, sev
        if name and "name" not in hit:
            hit["name"] = name
        if context and "context" not in hit:  # a snippet so the reviewer sees the value in situ
            hit["context"] = context if kind in _REDACT_EXEMPT else context.replace(value, hit["value"])
        if url not in hit["urls"] and len(hit["urls"]) < 5:
            hit["urls"].append(url)

    def add_candidate(value, context, url):
        if candidates and value not in cands and value not in found and _is_candidate(value, ""):
            cands[value] = {"value": show(value), "length": len(value), "entropy": round(_entropy(value), 2),
                            "context": context[:80].replace("\n", " "), "url": url}

    def scan_patterns(url, text):
        for kind, sev, rx in _SECRET_PATTERNS:
            for m in rx.finditer(text):
                snip = text[max(0, m.start() - 45):m.end() + 25].replace("\n", " ").strip()
                add(kind, sev, m.group("v") if "v" in rx.groupindex else m.group(0), url,
                    m.group("name") if "name" in rx.groupindex else None, context=snip[:120])

    def walk_json(node, path, url, depth=0):
        """Flag credential-named keys and high-entropy values by JSON path, recursing into
        nested objects and into strings that are themselves JSON (double-serialised payloads)."""
        if depth > 8:
            return
        items = node.items() if isinstance(node, dict) else enumerate(node[:200]) if isinstance(node, list) else ()
        for k, v in items:
            p = f"{path}.{k}" if path else str(k)
            if isinstance(v, (dict, list)):
                walk_json(v, p, url, depth + 1)
            elif isinstance(v, str):
                s = v.strip()
                if s[:1] in "{[" and len(s) >= 2:
                    try:
                        walk_json(json.loads(s), p, url, depth + 1)
                        continue
                    except Exception:
                        pass
                if _JSON_KEY_CRED_RE.search(str(k)):
                    add("json_field", "high" if _STRONG_NAME.search(str(k)) else "low", v, url, p)
                else:
                    add_candidate(v, p, url)

    def maybe_json(url, text):
        s = text.lstrip()
        if s[:1] not in "{[":
            return
        try:
            walk_json(json.loads(s), "", url)
        except Exception:
            pass

    def scan_headers(hdrs, url):
        for k, v in (hdrs or {}).items():
            if not v or len(v) > 4096:
                continue
            if _CRED_HEADER_RE.match(k):
                m = _AUTH_SCHEME_RE.match(v)
                token = m.group(1) if m else v
                sev = "high" if re.search(r"(?i)author|secret|security-token", k) else "medium"
                add("request_header", sev, token, url, name=k)

    # Request side: outgoing headers, the request URL, and POST bodies (gap: these carry keys too).
    for r in list(_s()["requests"]):
        ru = r["url"]
        scan_headers(r.get("request_headers"), ru)
        scan_patterns(ru, ru)
        pd = r.get("post_data")
        if pd:
            scan_patterns(ru, pd[:1_000_000])
            maybe_json(ru, pd[:1_000_000])

    for url, is_code, text, hdrs in sources:
        scan_patterns(url, text)
        maybe_json(url, text)  # serialised API responses: structural + entropy by JSON path
        if is_code and candidates:
            for m in _LITERAL.finditer(text):
                v = m.group(1)
                if v not in cands and _is_candidate(v, text[max(0, m.start() - 40):m.start()]):
                    cands[v] = {"value": show(v), "length": len(v), "entropy": round(_entropy(v), 2),
                                "context": text[max(0, m.start() - 40):m.start()].replace("\n", " "), "url": url}
        if url.split("?")[0].endswith((".js", ".mjs")) or (is_code and "javascript" in hdrs.get("content-type", "")):
            ref = hdrs.get("sourcemap") or hdrs.get("x-sourcemap")
            if not ref and (m := _SOURCEMAP_RE.search(text[-1000:])):
                ref = m.group(1)
            if ref:
                maps.setdefault(url if ref.startswith("data:") else urljoin(url, ref), url)
    try:
        runtime = await page.evaluate("mw:" + _RUNTIME_JS)
    except Exception:
        runtime = {}
    for path, value in runtime.get("globals", []):
        add("runtime_config", "high" if _STRONG_NAME.search(path) else "low", value, page.url, path)
    for key, value in runtime.get("storage", []):  # localStorage/sessionStorage, often JSON blobs
        if not value:
            continue
        scan_patterns(page.url, value[:1_000_000])
        maybe_json(page.url, value[:1_000_000])
        if value.strip()[:1] not in "{[" and _NAME_IS_CRED.search(key) and " " not in value and len(value) <= 500:
            add("browser_storage", "high" if _STRONG_NAME.search(key) else "medium", value, page.url, key)

    source_maps = []
    if check_source_maps:
        # ponytail: first 20 maps only; raise if a bundle splits into more chunks than that.
        for map_url, script in list(maps.items())[:20]:
            if map_url == script:
                source_maps.append({"script": script, "map": "inline", "severity": "low",
                                    "issue": "inline source map embeds the original source"})
                continue
            data = await _fetch_json(ctx, map_url)
            if isinstance(data, dict) and isinstance(data.get("sources"), list):
                source_maps.append({"script": script, "map": map_url, "severity": "medium",
                                    "issue": f"source map publicly downloadable: {len(data['sources'])} original files",
                                    "sample_sources": data["sources"][:10]})
    ranked = sorted((c for v, c in cands.items() if v not in found), key=lambda c: -c["entropy"])
    # Collapse repeats: many hits share a name+source (e.g. Babel {key:"method"} patterns). Group them into
    # one entry with a count and up to three sample values. group=False returns every hit individually.
    if group:
        buckets = {}
        for f in found.values():
            buckets.setdefault((f.get("name", ""), f["kind"], f["urls"][0] if f["urls"] else ""), []).append(f)
        findings = []
        for members in buckets.values():
            if len(members) == 1:
                findings.append(members[0])
                continue
            worst = min(members, key=lambda m: _SEV_ORDER[m["severity"]])
            e = {"kind": worst["kind"], "severity": worst["severity"], "name": worst.get("name"),
                 "urls": worst["urls"], "count": len(members), "samples": [m["value"] for m in members[:3]]}
            if worst.get("context"):
                e["context"] = worst["context"]
            if e["name"] is None:
                del e["name"]
            findings.append(e)
    else:
        findings = list(found.values())
    findings.sort(key=lambda f: _SEV_ORDER[f["severity"]])
    result = {"scanned": len(sources), "findings": findings,
              "candidates": ranked[:max_candidates], "candidates_total": len(ranked), "source_maps": source_maps}
    if out_path:
        report = {"url": page.url, "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  "redacted": not reveal, **result}
        dest = _out(out_path)
        dest.write_text(json.dumps(report, indent=2, ensure_ascii=False))
        result["written"] = str(dest)
    return {"result": result}


# API endpoints named in JS bundles: a URL-ish value assigned to a *Url/*Endpoint/*Api name, an
# http/fetch/axios call target, and the keys a page serialises into browser storage.
_ENDPOINT_ASSIGN_RE = re.compile(
    r"""(?P<name>[\w$]*(?:Url|Endpoint|Api|Origin|Uri|Path|Route|Host))\s*[:=]\s*[`"'](?P<url>(?:https?://|\$\{[^}]+\}|/)[^`"'\s]{2,200})[`"']""")
_HTTP_CALL_RE = re.compile(
    r"""(?<![\w$])(?:this\.)?(?:http|axios|fetch|\$http|httpClient)\s*(?:\.\s*(?P<method>get|post|put|delete|patch))?\s*\(\s*[`"'](?P<target>(?:https?://|\$\{[^}]+\}|/)[^`"'\s)]{2,200})[`"']""")
_STORAGE_SINK_RE = re.compile(
    r"""(?P<store>local|session)Storage\.setItem\(\s*[`"']?(?P<key>[\w.$@/-]{1,80})""")
# A quoted/backtick string literal that itself looks like an API path, under ANY variable name
# (e.g. o=`/rest-api/1/1/${t}/search`). A Python-side marker test keeps only the API-ish ones.
_PATH_LIT_RE = re.compile(r"""[`"'](?P<url>(?:https?://|/)[^`"'\s]{1,200})[`"']""")
_API_MARKER = re.compile(r"""(?i)/(?:rest-?api|api|appresource|graphql|gql|odata|rpc)(?:/|\b)|/download/|\.json(?:$|[?#])""")
# A URL passed as a query-parameter value, e.g. ...drugservice.json?...&url=http://host:9003/TLV-drug-api/drugs/
_QPARAM_URL_RE = re.compile(r"""[?&][\w.$-]{1,40}=(?P<url>https?://[^"'`\s&]{6,200})""")
# A simple string-literal assignment, to resolve `base + "method"` concatenations across a scope.
_STR_ASSIGN_RE = re.compile(r"""(?:^|[;,{(\s])(?P<v>[\w$]{1,40})\s*=\s*[`"'](?P<val>(?:https?://|/)[^`"'\s]{2,200})[`"']""")
# A base (literal path or a resolved base variable) with a method segment appended, e.g.
# "...TLV-drug-api/drugs/" + "getDrugDecisions"  or  base + "getDrugPrices".
_CONCAT_RE = re.compile(r"""(?:[`"'](?P<base>(?:https?://|/)[^`"'\s]{1,200})[`"']|(?P<var>[\w$]{1,40}))\s*\+\s*[`"'](?P<seg>[\w./${}%-]{1,80})[`"']""")
# A <script type="application/json"> config block (Sitevision app_props etc.) carrying endpoint keys.
_JSON_SCRIPT_RE = re.compile(r"""<script[^>]*type=["']application/json["'][^>]*>(?P<body>.*?)</script>""", re.I | re.S)
_CONFIG_KEY_RE = re.compile(r"(?i)(?:uri|url|route|endpoint)$")


def _walk_config(node, depth=0):
    """Yield (key, string-value) for keys ending in Uri/Url/Route/Endpoint, recursing into a parsed
    application/json config block."""
    if depth > 6:
        return
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, str) and v and _CONFIG_KEY_RE.search(str(k)) and len(v) <= 300:
                yield (str(k), v)
            elif isinstance(v, (dict, list)):
                yield from _walk_config(v, depth + 1)
    elif isinstance(node, list):
        for v in node[:200]:
            if isinstance(v, (dict, list)):
                yield from _walk_config(v, depth + 1)


@mcp.tool()
async def scan_endpoints(max_results: int = 300, session: str = "") -> dict:
    """List API endpoints named in the JavaScript the page has already loaded, firing no requests.

    Passive inventory, for mapping the API surface. Reads the
    document and script bodies captured since the last navigate (and service worker scripts) and
    extracts, by regex:
      endpoints, by kind:
        assign  - URL/path assigned to a *Url/*Endpoint/*Api/*Origin/*Uri/*Path/*Route name.
        call    - target of http/fetch/axios .get/.post/...; method when the call names one.
        path    - any string/template literal that looks like an API path (/rest-api/, /api/,
                  /appresource/, *.json, /download/, graphql, ...) whatever variable holds it,
                  e.g. o=`/rest-api/1/1/${t}/search`.
        qparam  - a full URL carried as a query-parameter value, e.g. ...?...&url=http://host:9003/api/.
        append  - a method/segment literal concatenated onto a base path or base variable, e.g.
                  "...drug-api/drugs/" + "getDrugDecisions"; base is the left side it attaches to.
        config  - a *Uri/*Url/*Route/*Endpoint key inside a <script type="application/json"> block
                  (Sitevision app_props etc.: baseRouteUri, baseViewUri, baseResourceUri).
        observed- an XHR/fetch the page actually fired since navigate (from the request log),
                  deduped against the code findings, so one scan gives the full map.
      Many assign/path/append entries never fire on the landing page; they sit in the bundle until a
      flow (login, checkout) runs. Values keep template placeholders like ${apiOrigin}/Order.
      storage_sinks: keys the code writes to localStorage/sessionStorage (where tokens/payloads land).
    Lazy chunks the page never loaded aren't seen: navigate/click to load them first, then scan.
    Returns {"result": {scanned, endpoints: [{kind, name?, method?, base?, url, source}], storage_sinks:
    [{store, key, source}]}}. It only reports what the code contains; it does not call anything.
    """
    _use(session)
    page = await _page()
    ctx = page.context
    texts = []  # (url, code)
    for r in list(_s()["requests"]):
        if r["type"] not in ("document", "script"):
            continue
        if "_body" in r:
            texts.append((r["url"], r["_body"]))
        elif "_resp" in r:
            try:
                texts.append((r["url"], (await r["_resp"].body())[:10_000_000].decode("utf-8", "replace")))
            except Exception:
                pass
    try:
        # Isolated world (not mw:) on purpose: in the main world, Angular's Zone.js replaces Promise,
        # so an awaited value comes back as a {__zone_symbol__...} wrapper instead of the array.
        sw_urls = await page.evaluate("""async () => navigator.serviceWorker ? (await navigator.serviceWorker
            .getRegistrations()).map(r => (r.active || r.installing || r.waiting || {}).scriptURL).filter(Boolean) : []""")
    except Exception:
        sw_urls = []
    if not isinstance(sw_urls, list):
        sw_urls = []
    for url in sw_urls[:5]:
        try:
            resp = await ctx.request.get(url)
            texts.append((url, (await resp.body())[:10_000_000].decode("utf-8", "replace")))
        except Exception:
            pass

    endpoints, sinks, seen = [], [], set()

    def add_ep(kind, url, src, **extra):
        if not url or ("", url) in seen:
            return
        seen.add(("", url))  # dedup a url across kinds so a path and its call don't both list
        endpoints.append({"kind": kind, "url": url, "source": src, **extra})

    assigns = {}  # simple `var = "url"` map, for resolving base+method concatenations
    for src, code in texts:
        for m in _STR_ASSIGN_RE.finditer(code):
            assigns.setdefault(m.group("v"), m.group("val"))
    for src, code in texts:
        for m in _ENDPOINT_ASSIGN_RE.finditer(code):
            add_ep("assign", m.group("url"), src, name=m.group("name"))
        for m in _HTTP_CALL_RE.finditer(code):
            add_ep("call", m.group("target"), src, method=m.group("method"))
        # API-looking literals under any variable name, plus URLs embedded as query-parameter values.
        for m in _PATH_LIT_RE.finditer(code):
            u = m.group("url")
            if _API_MARKER.search(u):
                add_ep("path", u, src)
            for qm in _QPARAM_URL_RE.finditer(u):
                add_ep("qparam", qm.group("url"), src)
        # Method/segment literals appended onto a base literal or a resolved base variable.
        for m in _CONCAT_RE.finditer(code):
            base = m.group("base") or assigns.get(m.group("var") or "")
            if base and base[:1] in "/h" and _API_MARKER.search(base + m.group("seg")):
                add_ep("append", base.rstrip("/") + "/" + m.group("seg").lstrip("/"), src,
                       base=base, name=m.group("var") or None)
        # Endpoints declared in application/json config blocks (keys ending Uri/Url/Route/Endpoint).
        for jm in _JSON_SCRIPT_RE.finditer(code):
            try:
                data = json.loads(jm.group("body").strip())
            except Exception:
                continue
            for name, val in _walk_config(data):
                add_ep("config", val, src, name=name)
        for m in _STORAGE_SINK_RE.finditer(code):
            key = ("sink", m.group("store"), m.group("key"))
            if key not in seen:
                seen.add(key)
                sinks.append({"store": m.group("store"), "key": m.group("key"), "source": src})
    # Merge traffic actually observed since navigate (XHR/fetch), deduped against the code findings.
    for r in list(_s()["requests"]):
        if r["type"] in ("xhr", "fetch"):
            add_ep("observed", r["url"], "observed", method=r.get("method"))
    return {"result": {"scanned": len(texts), "endpoints": endpoints[:max_results], "storage_sinks": sinks[:max_results]}}


@mcp.tool()
async def cors_check(url: str = "", method: str = "GET", session: str = "") -> dict:
    """Check which origins an endpoint's CORS policy lets read its responses.

    An active check that sends its own requests;
    url defaults to the current page. Sends method with Origin set to an unrelated site, "null",
    names that start or end like the host (checks that an allowlist matches whole origins) and the
    http:// variant, plus one preflight, using the browser's cookies (CORS settings matter most on
    logged-in endpoints). Reports an Access-Control-Allow-Origin that repeats an unlisted origin,
    rated higher with Access-Control-Allow-Credentials: true (other sites could then read responses
    made with the user's cookies), and one sent without Vary: Origin (shared caches may then serve
    it to other origins). Returns {"result": {url, checks: [...], findings: [...]}}.
    """
    _use(session)
    page = await _page()
    url = url or page.url
    u = urlsplit(url)
    host = u.hostname
    origins = ["https://untrusted.example", "null", f"https://{host}.untrusted.example", f"https://not{host}"]
    if u.scheme == "https":
        origins.append(f"http://{host}")
    checks, findings = [], []

    async def send(origin, m, extra=None):
        try:
            resp = await page.context.request.fetch(url, method=m, headers={"Origin": origin, **(extra or {})},
                                                    max_redirects=0)
        except Exception as e:
            checks.append({"origin": origin, "method": m, "error": str(e)})
            return None
        h = resp.headers
        rec = {"origin": origin, "method": m, "status": resp.status,
               "allow_origin": h.get("access-control-allow-origin"),
               "allow_credentials": h.get("access-control-allow-credentials"), "vary": h.get("vary")}
        if extra:
            rec.update(allow_methods=h.get("access-control-allow-methods"),
                       allow_headers=h.get("access-control-allow-headers"))
        checks.append(rec)
        return rec

    for origin in origins:
        rec = await send(origin, method)
        if not rec or not rec["allow_origin"]:
            continue
        creds = (rec["allow_credentials"] or "").lower() == "true"
        if rec["allow_origin"] == origin:
            what = {"null": "the null origin (sandboxed iframes, file: pages)",
                    f"http://{host}": "the unencrypted http:// origin"}.get(origin, f"unlisted origin {origin}")
            findings.append({"severity": "high" if creds else "medium",
                             "issue": f"Allows {what}" + (" with credentials: it can read responses made with users' cookies"
                                                          if creds else "")})
            if "origin" not in (rec["vary"] or "").lower():
                findings.append({"severity": "low", "issue": f"Repeats Origin {origin} without Vary: Origin, so shared caches may serve it to other origins"})
        elif rec["allow_origin"] == "*" and not any(f["issue"].startswith("Wildcard") for f in findings):
            findings.append({"severity": "info", "issue": "Wildcard Access-Control-Allow-Origin: * (fine for public data only)"
                             + ("; with Allow-Credentials: true, which browsers reject" if creds else "")})
    pre = await send("https://untrusted.example", "OPTIONS", {"Access-Control-Request-Method": "PUT",
                                                         "Access-Control-Request-Headers": "authorization,content-type"})
    if pre and pre["allow_origin"] in ("https://untrusted.example", "*") and pre.get("allow_methods"):
        findings.append({"severity": "info", "issue": f"Preflight from an unlisted origin allows methods "
                         f"{pre['allow_methods']} and headers {pre.get('allow_headers')}"})
    return {"result": {"url": url, "checks": checks, "findings": findings}}


# (path, what, severity, signature on the response body). A finding needs the signature, so a site
# answering 200 to every path (soft 404) isn't flagged.
_EXPOSURES = [
    ("/.git/HEAD", "git repository (source code and history downloadable)", "high", rb"^ref: refs/|^[0-9a-f]{40}\s*$"),
    ("/.git/config", "git config (remote URLs, sometimes credentials)", "high", rb"\[core\]"),
    ("/.env", "environment file (typically secrets)", "high", rb"(?m)^[A-Z][A-Z0-9_]*=\S"),
    ("/.svn/wc.db", "svn working copy", "high", rb"^SQLite format 3"),
    ("/.htpasswd", "password file", "high", rb"(?m)^[\w.-]+:(?:\$|\{SHA\})"),
    ("/actuator/env", "Spring Boot actuator env (config and secrets)", "high", rb'"propertySources"'),
    ("/server-status", "Apache server-status (live requests and client IPs)", "medium", rb"Apache Server Status"),
    ("/phpinfo.php", "phpinfo page", "medium", rb"phpinfo\(\)|<title>PHP \d"),
    ("/.DS_Store", "macOS folder index (lists files)", "low", rb"^\x00\x00\x00\x01Bud1"),
    ("/crossdomain.xml", "Flash cross-domain policy allowing every domain", "low", rb'allow-access-from\s+domain="\*"'),
    ("/swagger.json", "API description", "info", rb'"(?:swagger|openapi)"\s*:'),
    ("/openapi.json", "API description", "info", rb'"(?:swagger|openapi)"\s*:'),
    ("/v3/api-docs", "API description", "info", rb'"(?:swagger|openapi)"\s*:'),
]


@mcp.tool()
async def exposure_check(base_url: str = "", paths: list[str] | None = None, session: str = "") -> dict:
    """Check that common private files (.git, .env, config and status pages) aren't publicly reachable.

    An active check that sends its own requests;
    Checks the origin of base_url (default: the current page) for .git, .env, .svn, .htpasswd, Spring
    actuator, server-status, phpinfo, .DS_Store, crossdomain.xml and OpenAPI docs, ~16 GET requests with
    the browser's cookies and no redirects followed. A path counts as exposed only when its body
    matches that file's format. Also reads robots.txt (its Disallow entries list areas kept out of search) and
    security.txt. paths adds your own paths, reported as exposed when they answer 200 unlike a random
    nonexistent path. File contents aren't returned.
    Returns {"result": {origin, findings: [{path, severity, issue, status}], robots_disallow, security_txt, checked}}.
    """
    _use(session)
    page = await _page()
    u = urlsplit(base_url or page.url)
    if u.scheme not in ("http", "https"):
        raise ValueError("Navigate to an http(s) page first or pass base_url.")
    origin = f"{u.scheme}://{u.netloc}"

    async def get(path):
        try:
            resp = await page.context.request.get(origin + path, max_redirects=0)
            return resp.status, await resp.body()
        except Exception as e:
            return None, str(e).encode()

    extra = list(paths or [])
    targets = [p for p, *_ in _EXPOSURES] + ["/robots.txt", "/.well-known/security.txt",
                                             f"/burrow-{secrets.token_hex(6)}"] + extra
    results = dict(zip(targets, await asyncio.gather(*(get(p) for p in targets))))
    findings = []
    for path, what, sev, sig in _EXPOSURES:
        status, body = results[path]
        if status == 200 and re.search(sig, body[:65536]):
            findings.append({"path": path, "severity": sev, "issue": f"Exposed: {what}", "status": status})
    baseline = results[targets[-1 - len(extra)]]
    for path in extra:
        status, body = results[path]
        if status == 200 and (baseline[0] != 200 or len(body) != len(baseline[1])):
            findings.append({"path": path, "severity": "info", "issue": "Answers 200 (a nonexistent path doesn't)",
                             "status": status})
    status, body = results["/robots.txt"]
    disallow = re.findall(r"(?im)^\s*disallow:\s*(\S+)", body.decode("utf-8", "replace")) if status == 200 else []
    status, body = results["/.well-known/security.txt"]
    has_sec = status == 200 and bool(re.search(rb"(?im)^contact:", body))
    if not has_sec:
        findings.append({"path": "/.well-known/security.txt", "severity": "info",
                         "issue": "No security.txt: no published contact for reporting security issues", "status": status})
    return {"result": {"origin": origin, "findings": findings, "robots_disallow": disallow[:50],
                       "security_txt": has_sec, "checked": len(targets)}}


# Cipher groups a server should refuse, tried with TLS 1.2 at most. @SECLEVEL=0 lets the local OpenSSL offer them.
_WEAK_CIPHERS = [("RC4", "high"), ("NULL:eNULL:aNULL", "high"), ("EXPORT", "high"), ("3DES", "medium"),
                 ("kRSA", "low")]  # kRSA: static RSA key exchange, no forward secrecy
_LOCAL_LIMITS = ("NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE", "NO_CIPHER_MATCH", "No cipher can be selected")


def _tls_try(connect, port, sni, version=None, ciphers=None, verify=False):
    """One handshake. Returns ("accepted", details) or ("refused" | "untestable", reason);
    untestable = the local OpenSSL can't offer that protocol/cipher, so the server was never asked."""
    try:
        if verify:
            ctx = ssl_mod.create_default_context()
        else:
            ctx = ssl_mod.SSLContext(ssl_mod.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl_mod.CERT_NONE
        if ciphers or version:
            ctx.set_ciphers((ciphers or "DEFAULT") + ":@SECLEVEL=0")
        if version:
            ctx.minimum_version = ctx.maximum_version = version
        elif ciphers:
            ctx.maximum_version = ssl_mod.TLSVersion.TLSv1_2  # TLS 1.3 suites can't be restricted this way
    except (ssl_mod.SSLError, ValueError) as e:
        return "untestable", str(e)
    try:
        with _connect_sock(connect, port, 10) as raw, ctx.wrap_socket(raw, server_hostname=sni) as tls:
            return "accepted", {"version": tls.version(), "cipher": tls.cipher()[0],
                                "der": tls.getpeercert(binary_form=True)}
    except _ProxyRefused as e:
        return "blocked", f"blocked by network proxy: {e}"
    except ssl_mod.SSLCertVerificationError as e:
        return "refused", e.verify_message or str(e)
    except ssl_mod.SSLError as e:
        return ("untestable" if any(x in str(e) for x in _LOCAL_LIMITS) else "refused"), (e.reason or str(e))
    except OSError as e:
        return "refused", f"{type(e).__name__}: {e}"


def _tls_audit(host, port, connect_ip) -> dict:
    connect = connect_ip or host
    status, base = _tls_try(connect, port, host)
    if status == "blocked":
        return {"host": host, "port": port, "error": base, "blocked_hosts": [connect]}
    if status != "accepted":
        return {"host": host, "port": port, "error": f"TLS handshake failed: {base}"}
    cert = _cert_summary(base["der"])
    findings = []
    trust, why = _tls_try(connect, port, host, verify=True)
    if trust != "accepted":
        findings.append({"severity": "high", "issue": f"Certificate not trusted for {host}: {why}"})
    if "not_after" in cert:
        days = (datetime.datetime.fromisoformat(cert["not_after"]) - datetime.datetime.now(datetime.UTC)).days
        cert["days_left"] = days
        if 0 <= days < 30:
            findings.append({"severity": "low", "issue": f"Certificate expires in {days} days"})
    protocols = {}
    for name in ("TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3"):
        st, detail = _tls_try(connect, port, host, version=getattr(ssl_mod.TLSVersion, name))
        protocols[name] = st
        if st == "accepted" and name in ("TLSv1", "TLSv1_1"):
            findings.append({"severity": "medium", "issue": f"Accepts deprecated {name.replace('_', '.')}"})
    if protocols["TLSv1_3"] == "refused":
        findings.append({"severity": "info", "issue": "No TLS 1.3"})
    weak = {}
    for group, sev in _WEAK_CIPHERS:
        st, detail = _tls_try(connect, port, host, ciphers=group)
        weak[group] = st if st != "accepted" else f"accepted ({detail['cipher']})"
        if st == "accepted":
            findings.append({"severity": sev, "issue": f"Accepts weak cipher {detail['cipher']} ({group})"})
    return {"host": host, "port": port, "negotiated": {"version": base["version"], "cipher": base["cipher"]},
            "cert": cert, "protocols": protocols, "weak_ciphers": weak, "findings": findings}


@mcp.tool()
async def tls_audit(host: str = "", port: int = 443, connect_ip: str = "", session: str = "") -> dict:
    """Audit a server's TLS: certificate trust, name and expiry, accepted protocol versions, weak ciphers.

    host (or a URL) defaults to the current page's host; connect_ip reaches a specific origin/edge
    while sending host as SNI. Makes ~11 TLS handshakes, no HTTP. "untestable" means this machine's
    OpenSSL can't offer that protocol/cipher, so the server's answer is unknown (not a pass).
    Returns {"result": {host, port, negotiated, cert: {subject, issuer, san, not_after, days_left},
    protocols: {TLSv1..TLSv1_3: accepted|refused|untestable}, weak_ciphers, findings}}.
    Behind a network proxy (Claude Science) each handshake is tunnelled through it with HTTP CONNECT,
    so the results are the server's own; connect_ip can't pin an IP there (the proxy resolves the host).
    """
    _use(session)
    if not host:
        host = (await _page()).url
    if "://" in host:
        u = urlsplit(host)
        host, port = u.hostname, u.port or (443 if u.scheme == "https" else port)
    return {"result": await asyncio.to_thread(_tls_audit, host, port, connect_ip)}


_SESSION_COOKIE = re.compile(r"sess|sid|auth|token|jwt|login", re.I)


@mcp.tool()
async def session_audit(action: str, label: str = "before", url: str = "", expect_text: str = "",
                        session: str = "") -> dict:
    """Test session handling around login and logout: fixation and logout invalidation.

    action="mark"    remember the current cookies under label.
    action="compare" diff the current cookies against label's. A session-like cookie (name has sess,
                     sid, auth, token, jwt or login) that keeps its value across login is reported:
                     the session ID should change at login so one issued beforehand can't carry over.
    action="replay"  send label's cookies from a clean browser context to url (default: current page)
                     and report status, final_url and whether the body contains expect_text. Mark
                     while logged in, log out, then replay: still logged in = logout doesn't
                     invalidate the session server-side.
    Typical run: navigate to the login page, mark "before"; log in with type_text/click; compare
    "before"; mark "authed"; log out; replay "authed" with url=<account page>, expect_text=<text only
    a logged-in user sees>. Returns {"result": {...}, "findings": [...]}.
    """
    _use(session)
    sess, page = _s(), await _page()
    if action == "mark":
        sess["cookie_marks"][label] = await page.context.cookies()
        return {"result": {"label": label, "cookies": [c["name"] for c in sess["cookie_marks"][label]]}, "findings": []}
    if label not in sess["cookie_marks"]:
        raise ValueError(f"No cookies marked as {label!r}; call session_audit('mark', label={label!r}) first.")
    marked = sess["cookie_marks"][label]
    if action == "compare":
        key = lambda c: (c["name"], c["domain"], c["path"])
        before, now = {key(c): c["value"] for c in marked}, {key(c): c["value"] for c in await page.context.cookies()}
        same = [k[0] for k in before if k in now and now[k] == before[k]]
        findings = [{"severity": "high", "issue": f"Session ID not renewed: cookie {n} kept its value since {label!r}; "
                     "the server should issue a new session ID at login (session fixation)"} for n in same if _SESSION_COOKIE.search(n)]
        return {"result": {"unchanged": same, "changed": [k[0] for k in before if k in now and now[k] != before[k]],
                           "added": [k[0] for k in now if k not in before],
                           "removed": [k[0] for k in before if k not in now]}, "findings": findings}
    if action == "replay":
        url = url or page.url
        ctx = await (await _browser()).new_context()
        try:
            await ctx.add_cookies(marked)
            resp = await ctx.request.get(url)
            body = (await resp.body()).decode("utf-8", "replace")
        finally:
            await ctx.close()
        hit = bool(expect_text) and expect_text in body
        findings = [{"severity": "high", "issue": f"Cookies marked {label!r} still reach logged-in content at {url}: "
                     "the session wasn't invalidated server-side"}] if hit else []
        return {"result": {"url": url, "status": resp.status, "final_url": resp.url, "bytes": len(body),
                           "contains_expect_text": hit if expect_text else None}, "findings": findings}
    raise ValueError(f"Unknown action {action!r}; use mark, compare or replay.")


if __name__ == "__main__":
    mcp.run()
