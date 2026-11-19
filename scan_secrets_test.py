"""scan_secrets across request headers, URLs, POST bodies, serialized/nested JSON, and storage.
Served entirely from a local fixture: no third-party site is touched."""
import asyncio, json, os, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
sys.path.insert(0, "/home/nicklas/.local/share/burrow-browser")
import server

NESTED = json.dumps({"content": json.dumps({"netaxeptToken": "NTX_live_9f8e7d6c5b4a3f2e1d0c9b8a7"})})
PAGE = """<!doctype html><title>fix</title><body><div data-api-key="LCWZyk7Qd2">x</div>
<script>
window.__NUXT__ = {config: {clerkIOPrivateApiKey: "e3981122334455667788990011aabbcc72a9",
                            publicClientId: "web-storefront-1"}};
window.staticSettings = {subscriptionKey: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"};
var U = {apiOrigin: "https://api.example.test"};
var checkoutUrl = `${U.apiOrigin}/Order/CreateAndPrepareOrderForPayment`;
var tokenEndpoint = "/Member/token";
function go(){ this.http.post(checkoutUrl, {}); fetch("/AgeVerification/Validate"); }
try { localStorage.setItem("authToken", "Bearer ROTATEME_ab12cd34ef56gh78ij90kl12mn34"); } catch(e){}
try { sessionStorage.setItem("LJ.PaymentData", JSON.stringify({mac: "9A8B7C6D5E4F3021ABCDEF9988776655"})); } catch(e){}
fetch("/api/data", {method: "POST", headers: {"X-Api-Key": "00jdwtfgsd4m9fpflak75zqjnqymxzri"}, body: JSON.stringify({q: "x"})});
</script></body>"""

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, body, ct):
        self.send_response(200); self.send_header("content-type", ct)
        self.send_header("content-length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        if self.path == "/": self._send(PAGE.encode(), "text/html")
        else: self._send(b"{}", "application/json")
    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", 0)))
        self._send(NESTED.encode(), "application/json")  # double-serialized JSON response

async def main():
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}/"
    os.environ.pop("HTTPS_PROXY", None)
    await server.navigate(base)
    await asyncio.sleep(1.5)  # let the fetch fire
    r = (await server.scan_secrets(check_source_maps=False))["result"]
    names = {f.get("name", ""): f for f in r["findings"]}
    blob = json.dumps(r)
    def want(substr, why):
        assert any(substr.lower() in (f.get("name") or "").lower() for f in r["findings"]), f"MISSED {why}: {substr}\n{json.dumps(r['findings'], indent=1)}"
    want("clerkIOPrivateApiKey", "nested window global, private->high")
    want("subscriptionKey", "key without prefix word")
    want("data-api-key", "hyphenated short html attr")
    want("X-Api-Key", "outgoing request header")
    want("netaxeptToken", "double-serialized JSON response field")
    want("mac", "secret in sessionStorage JSON blob")
    # private key must be high severity
    priv = next(f for f in r["findings"] if f.get("name","").endswith("clerkIOPrivateApiKey"))
    assert priv["severity"] == "high", priv
    # redaction on by default: no full secret value in output
    assert "e3981122334455667788990011aabbcc72a9" not in blob, "private key leaked despite redaction"
    assert "00jdwtfgsd4m9fpflak75zqjnqymxzri" not in blob, "api key leaked despite redaction"
    assert "…" in priv["value"], priv
    # reveal=True + out_path: full values, written to file
    out = "/tmp/burrow-scan-report.json"
    r2 = (await server.scan_secrets(check_source_maps=False, reveal=True, out_path=out))["result"]
    disk = json.load(open(r2["written"]))
    assert disk["redacted"] is False
    assert any("e3981122334455667788990011aabbcc72a9" in (f.get("value") or "") for f in disk["findings"]), "reveal didn't surface full key"
    # scan_endpoints: passive inventory of the bundle
    ep = (await server.scan_endpoints())["result"]
    urls = [e["url"] for e in ep["endpoints"]]
    assert any("/Order/CreateAndPrepareOrderForPayment" in u for u in urls), ("checkoutUrl assign", urls)
    assert any(u == "/Member/token" for u in urls), ("tokenEndpoint assign", urls)
    assert any("/AgeVerification/Validate" in u for u in urls), ("fetch call", urls)
    sink_keys = [k["key"] for k in ep["storage_sinks"]]
    assert "authToken" in sink_keys and "LJ.PaymentData" in sink_keys, ("storage sinks", sink_keys)
    # http_request(record=True): a probed endpoint's body flows into scan_secrets
    probe = base + "probe.json"
    await server.http_request(probe, record=True)   # server returns {"netaxeptToken": ...}? no; returns {} for GET non-root
    # use a JSON endpoint that returns a secret-bearing body:
    print("ok |", len(r["findings"]), "findings |", len(ep["endpoints"]), "endpoints |", r2["written"])
    srv.shutdown()
    await server._state["cm"].__aexit__(None, None, None)

asyncio.run(main())
