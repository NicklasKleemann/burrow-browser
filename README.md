# burrow-browser

An MCP server that gives AI agents a real headless browser for reading web pages, testing web apps and diagnosing what a page actually does. It runs [Camoufox](https://camoufox.com), a Firefox build made for automation, through Playwright.

Agents use it to:

- open pages that need JavaScript, cookies or a login, and read their text, HTML, links or accessibility tree
- fill in and submit forms, wait for async content, and check the result
- see every network request a page makes, read response bodies, and record traffic to a HAR file
- collect console errors, CSP violations, dialogs, websockets and storage contents
- mock or fail API calls to test error states
- review a site's security configuration: headers, cookie flags, CORS, TLS, exposed files and keys shipped in its JavaScript

One file, `server.py`. Every tool returns JSON.

## Install

Requires Python 3.11+.

With [uv](https://docs.astral.sh/uv/), the dependencies are declared inline in `server.py`:

```sh
git clone https://github.com/NicklasKleemann/burrow-browser.git
cd burrow-browser
uv run --script server.py   # first run installs dependencies; stop it with Ctrl+C
uvx camoufox fetch          # downloads the browser (once)
```

Or with a virtualenv:

```sh
python -m venv .venv
.venv/bin/pip install "mcp>=1.0,<2" "camoufox[geoip]" cryptography
.venv/bin/python -m camoufox fetch
```

## Connect it to an agent

Claude Code:

```sh
claude mcp add burrow-browser -- /path/to/burrow-browser/.venv/bin/python /path/to/burrow-browser/server.py
# or, with uv:
claude mcp add burrow-browser -- uv run --script /path/to/burrow-browser/server.py
```

Any other MCP client, as a stdio server:

```json
{
  "mcpServers": {
    "burrow-browser": {
      "command": "/path/to/burrow-browser/.venv/bin/python",
      "args": ["/path/to/burrow-browser/server.py"]
    }
  }
}
```

## Tools

**Browse and read**

| Tool | What it does |
|---|---|
| `navigate` | Open a URL and wait for it to load, JavaScript included |
| `get_text`, `get_html` | Visible text, or the rendered DOM |
| `links` | All links with absolute URLs, optionally filtered |
| `snapshot` | Accessibility tree as YAML: compact, and gives stable `role=` selectors |
| `screenshot` | Full-page PNG |
| `download` | Save a file exactly as served, with the browser's cookies |
| `tabs` | List, switch to or close tabs, including popups |

**Interact and wait**

| Tool | What it does |
|---|---|
| `click`, `type_text`, `press`, `hover` | Real mouse and keyboard input; each waits for the requests it triggers to finish |
| `select_option`, `check`, `upload_file` | Dropdowns, checkboxes and radios, file inputs |
| `wait_for` | Wait for a selector or text to appear or disappear, a URL change, a JS condition or a load state |
| `dialogs` | alert/confirm/prompt dialogs, answered automatically so they never block the page |
| `evaluate` | Run JavaScript in the page |

**Inspect and assert**

| Tool | What it does |
|---|---|
| `query` | Count, text, value, checked, visible and attributes of matching elements |
| `requests`, `get_response_body` | Network log since the last navigate, and any captured response body |
| `start_recording`, `stop_recording` | Record all traffic to a HAR file |
| `console_logs` | Console messages, uncaught exceptions, CSP violations |
| `cookies`, `storage` | Cookies with their flags; localStorage, sessionStorage and IndexedDB |
| `frames_and_listeners`, `websockets` | iframes, service workers, `message` listeners, websocket connections |
| `route` | Mock, fail or delay matching requests to test error and loading states |
| `set_browser_headers` | Persistent headers, e.g. for a staging site behind auth |

**Security review**

These check how a site is configured and report findings with a severity, for the site's owners and testers.

| Tool | What it checks |
|---|---|
| `security_headers` | CSP, HSTS, framing, nosniff, Referrer-Policy, version disclosure, cookie flags |
| `scan_secrets` | API keys, tokens and source maps in the JavaScript a page loaded |
| `cors_check` | Which origins the CORS policy lets read responses |
| `exposure_check` | Whether files like `.git`, `.env` or status pages are publicly reachable |
| `tls_audit` | Certificate trust and expiry, protocol versions, weak ciphers |
| `session_audit` | Whether the session ID changes at login and stops working after logout |

**Networking**

| Tool | What it does |
|---|---|
| `http_request` | One raw HTTP(S) request with the connection IP, Host header and TLS SNI set independently, like `curl --resolve` |

**Sessions**

Every tool takes an optional `session` name. Each session has its own tabs, cookies, logs, mocks and recording, so several agents can share one server. `close_session` frees one.

## Configuration

| Variable | Effect |
|---|---|
| `BURROW_BROWSER_OUTPUT_DIR` | Where relative paths for screenshots, downloads and recordings go (default: working directory) |
| `BURROW_BROWSER_REQUIRE_SESSION=1` | Make the `session` argument mandatory, for servers shared between agents |
| `BURROW_BROWSER_LOG_LEVEL` | `DEBUG`, `INFO`, `WARNING` or `ERROR`; logging is off by default |
| `BURROW_BROWSER_LOG_FILE` | Log to this file instead of stderr |
| `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` | Route the browser, `http_request` and `tls_audit` through a proxy |

Behind a proxy, `http_request` and `tls_audit` tunnel through it, so the Host header and SNI still work, but the proxy picks the IP, so `connect_ip` can't pin one.

## Tests

Each `*_test.py` is a plain script; run it with the server's Python:

```sh
for t in *_test.py; do .venv/bin/python "$t" || echo "FAILED: $t"; done
```

`forms_test`, `audit_test`, `security_test` and `tunnel_test` run against local servers they start themselves. `smoke_test`, `qa_test`, `session_test`, `http_test`, `crash_test` and `proxy_test` need internet access.
