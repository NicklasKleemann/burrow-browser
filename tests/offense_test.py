"""page_audit, inject_probe, content_discovery, forbidden_bypass, http_methods, graphql_introspection.
A single local fixture exhibits each issue; no third-party site is touched. All payloads are read-only."""
import asyncio, json, os, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs
sys.path.insert(0, "/home/nicklas/Documents/Github/burrow-browser")
import server

OTHER = 0  # a closed port, filled in once the baseline port is known (external, un-loadable subresource)

INTROSPECTION = json.dumps({"data": {"__schema": {"queryType": {"name": "Query"},
                            "types": [{"name": "User", "kind": "OBJECT"}, {"name": "Query", "kind": "OBJECT"},
                                      {"name": "__Type", "kind": "OBJECT"}]}}})


def landing():
    return (f'<!doctype html><title>fix</title>'
            f'<script>window.jQuery={{fn:{{jquery:"3.1.0"}}}};</script>'
            f'<script src="http://127.0.0.1:{OTHER}/ext.js"></script>'       # external (other port), no integrity
            f'<script src="/jquery-3.1.0.min.js"></script>'                   # versioned, same-origin (for from_urls)
            f'<form action="http://127.0.0.1:{OTHER}/post"><input name=x></form>'
            f'<body>ok</body>').encode()


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, body, ct="text/html", extra=None):
        self.send_response(code); self.send_header("content-type", ct)
        self.send_header("content-length", str(len(body)))
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(body)

    def do_GET(self):
        u = urlsplit(self.path); path = u.path
        if path == "/":
            return self._send(200, landing())
        if path == "/search":
            q = parse_qs(u.query).get("q", [""])[0]; low = q.lower()
            if "etc/passwd" in low:
                body = "root:x:0:0:root:/root:/bin/bash"
            elif "win.ini" in low:
                body = "[extensions]\nmci=1"
            elif "'" in q or '"' in q:
                body = "You have an error in your SQL syntax; check the manual that corresponds"
            else:
                body = ("results: " + q).replace("{{7*7}}", "49").replace("${7*7}", "49").replace("<%=7*7%>", "49")
                if ";id" in q or "|id" in q or "`id`" in q:
                    body += " uid=0(root) gid=0(root) groups=0(root)"
            return self._send(200, body.encode())
        if path == "/go":
            nxt = parse_qs(u.query).get("next", [""])[0]
            return self._send(302, b"", extra={"Location": nxt})
        if path == "/admin":
            ok = self.headers.get("X-Forwarded-For") == "127.0.0.1"
            return self._send(200 if ok else 403, b"admin ok" if ok else b"forbidden")
        if path == "/backup.zip":
            return self._send(200, b"PK\x03\x04backupcontents", ct="application/zip")
        if path == "/robots.txt":
            return self._send(200, b"User-agent: *\nDisallow: /admin\n", ct="text/plain")
        if path == "/jquery-3.1.0.min.js":
            return self._send(200, b"var x=1;", ct="application/javascript")
        return self._send(404, b"nope")

    def do_OPTIONS(self):
        self._send(200, b"", extra={"Allow": "GET, POST, PUT, OPTIONS, TRACE"})

    def do_TRACE(self):
        self._send(200, b"TRACE")

    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", 0)))
        if urlsplit(self.path).path == "/graphql":
            return self._send(200, INTROSPECTION.encode(), ct="application/json")
        return self._send(404, b"nope")


async def main():
    global OTHER
    srv = HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    OTHER = port + 1  # almost certainly closed; the <script>/<form> point here but never need to load
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}/"
    os.environ.pop("HTTPS_PROXY", None)

    # page_audit: library globals, missing SRI, versioned script, insecure form
    await server.navigate(base)
    await asyncio.sleep(0.5)
    pa = (await server.page_audit())["result"]
    assert pa["libraries"]["globals"].get("jQuery") == "3.1.0", pa["libraries"]
    assert any(e["tag"] == "script" for e in pa["missing_sri"]), ("missing SRI", pa["missing_sri"])
    assert any(l["name"].lower().startswith("jquery") for l in pa["libraries"]["from_urls"]), pa["libraries"]["from_urls"]
    assert any("http" in f["issue"].lower() for f in pa["findings"]), pa["findings"]

    # inject_probe on /search: sqli, traversal, ssti, cmdi, xss
    await server.navigate(base + "search?q=hi")
    inj = (await server.inject_probe())["result"]
    hit_kinds = {f["kind"] for f in inj["findings"]}
    for k in ("sqli", "traversal", "ssti", "cmdi", "xss"):
        assert k in hit_kinds, (k, "not detected", inj["findings"])

    # inject_probe redirect kind on /go?next= (pass the URL; don't navigate or the 302 is followed)
    red = (await server.inject_probe(url=base + "go?next=start", kinds=["redirect"]))["result"]
    assert any(f["kind"] == "redirect" for f in red["findings"]), ("open redirect", red)

    # content_discovery: finds backup.zip (200) and admin (403 protected)
    cd = (await server.content_discovery(base_url=base))["result"]
    paths = {f["path"]: f for f in cd["findings"]}
    assert "/backup.zip" in paths and paths["/backup.zip"]["status"] == 200, cd["findings"]
    assert "/admin" in paths and paths["/admin"]["status"] == 403, cd["findings"]

    # forbidden_bypass: /admin 403 -> 200 with X-Forwarded-For
    fb = (await server.forbidden_bypass(url=base + "admin"))["result"]
    assert fb["baseline_status"] == 403 and fb["findings"], fb
    assert any("X-Forwarded-For" in f["trick"] for f in fb["findings"]), fb["findings"]

    # http_methods: OPTIONS advertises TRACE/PUT
    hm = (await server.http_methods(url=base))["result"]
    assert "TRACE" in (hm["allow"] or "") and hm["findings"], hm

    # graphql_introspection
    gi = (await server.graphql_introspection(url=base + "graphql"))["result"]
    assert gi["introspection_enabled"] and "User" in gi["types"], gi

    print("ok | page_audit, inject_probe(5+redirect), content_discovery, forbidden_bypass, http_methods, graphql")
    srv.shutdown()
    await server._state["cm"].__aexit__(None, None, None)

asyncio.run(main())
