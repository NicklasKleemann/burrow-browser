"""scan_secrets across request headers, URLs, POST bodies, serialized/nested JSON, and storage.
Served entirely from a local fixture: no third-party site is touched. Secret values are generated at
runtime by gen() in the formats the scanner detects, so no secret-shaped literal is ever committed
(nothing for GitHub push-protection to flag) and each provider format is exercised."""
import asyncio, json, os, random, string, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
sys.path.insert(0, "/home/nicklas/Documents/Github/burrow-browser")
import server


def _mix(n):
    """n chars of [a-zA-Z0-9] with at least one lower, one upper and one digit, so a value under a
    credential-ish name always clears _plausible's digit/mixed-case gate (a pure-hex draw could fail)."""
    body = [random.choice(string.ascii_lowercase), random.choice(string.ascii_uppercase),
            random.choice(string.digits)]
    body += [random.choice(string.ascii_letters + string.digits) for _ in range(max(0, n - 3))]
    random.shuffle(body)
    return "".join(body)[:n]


def gen(kind):
    """A random value in a detectable format. No literal here matches a provider regex on its own."""
    if kind == "apikey":   return _mix(36)                      # long generic key under a *Key name
    if kind == "hex":      return _mix(32)                      # 32-char key / mac
    if kind == "short":    return _mix(10)                      # short value under a credential name
    if kind == "bearer":   return "ROTATEME_" + _mix(24)        # token in localStorage
    if kind == "netaxept": return "NTX_live_" + _mix(20)        # vendor token in a JSON field
    if kind == "stripe":   return "sk_live_" + _mix(24)         # stripe_secret_key (high)
    if kind == "aws":      return "AKIA" + "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(16))
    if kind == "guid":     return "-".join("".join(random.choice("0123456789abcdef") for _ in range(n)) for n in (8, 4, 4, 4, 12))
    if kind == "jwt":      return "eyJ" + _mix(20) + ".eyJ" + _mix(20) + "." + _mix(20)
    raise ValueError(kind)


K = {k: gen(k) for k in ("apikey", "hex", "short", "bearer", "netaxept", "stripe", "aws", "guid", "jwt")}
XAPIKEY = gen("hex")  # distinct draws: found{} dedups by value, so a shared value would hide a name
MAC = gen("hex")


def rc(alpha, n):
    return "".join(random.choice(alpha) for _ in range(n))


_U, _L, _D = string.ascii_uppercase, string.ascii_lowercase, string.digits
_AL, _HEX = string.ascii_letters + _D, "0123456789abcdef"
# One valid random sample per provider pattern, keyed by the kind scan_secrets should label it.
# Each is scanned as raw page text (quotes/&/= intact), so patterns needing surrounding punctuation
# (AccountKey=, "Bearer …", sv=…sig=, user:pass@, ?token=) match as written. No literal is a real key.
COVER = {
    "private_key":            "-----BEGIN PRIVATE KEY-----",
    "aws_access_key":         "AKIA" + rc(_U + _D, 16),
    "azure_storage_key":      "AccountKey=" + rc(_AL + "+/", 44),
    "stripe_secret_key":      "sk_live_" + rc(_AL, 24),
    "github_token":           "ghp_" + rc(_AL + _D, 36),
    "gitlab_token":           "glpat-" + rc(_AL + "-_", 20),
    "npm_token":              "npm_" + rc(_AL + _D, 36),
    "shopify_token":          "shpat_" + rc(_HEX, 32),
    "sendgrid_key":           "SG." + rc(_AL + "-_", 22) + "." + rc(_AL + "-_", 40),
    "twilio_api_key":         "SK" + rc(_HEX, 32),
    "huggingface_token":      "hf_" + rc(_AL, 32),
    "slack_token":            "xoxb-" + rc(_AL + "-", 20),
    "slack_webhook":          "https://hooks.slack.com/services/T" + rc(_U + _D, 8) + "/B" + rc(_U + _D, 8) + "/" + rc(_AL, 24),
    "google_oauth_secret":    "GOCSPX-" + rc(_AL + "-_", 24),
    "mapbox_secret_token":    "sk.eyJ" + rc(_AL + "-", 12) + "." + rc(_AL + "-", 12),
    "ai_api_key":             "sk-ant-" + rc(_AL + "_-", 40),
    "url_credentials":        "https://admin:" + rc(_AL, 16) + "@internal.example.test",
    "auth_header_literal":    '"Bearer ' + rc(_AL + "._-", 32) + '"',
    "azure_sas_token":        "sv=2021-08-06&ss=b&srt=co&sp=r&sig=" + rc(_AL + "%+/", 24) + "=",
    "jwt":                    "eyJ" + rc(_AL + "-_", 20) + ".eyJ" + rc(_AL + "-_", 20) + "." + rc(_AL + "-_", 20),
    "twilio_account_sid":     "AC" + rc(_HEX, 32),
    "google_api_key":         "AIza" + rc(_AL + "-_", 35),
    "sentry_dsn":             "https://" + rc(_HEX, 32) + "@o1.ingest.sentry.io/1",
    "mapbox_public_token":    "pk.eyJ" + rc(_AL + "-", 12) + "." + rc(_AL + "-", 12),
    "datadog_client_token":   "pub" + rc(_HEX, 32),
    "stripe_publishable_key": "pk_live_" + rc(_AL, 24),
    "app_insights_key":       "InstrumentationKey=" + gen("guid"),
    "credential_in_url":      "https://api.example.test/x?access_token=" + rc(_AL + "-_", 24),
    "internal_host":          "http://10.3.14.159/admin",
}
COVER_TEXT = "\n".join(COVER.values())

NESTED = json.dumps({"content": json.dumps({"netaxeptToken": K["netaxept"]})})
PAGE = """<!doctype html><title>fix</title><body><div data-api-key="%(short)s">x</div>
<script>
window.__NUXT__ = {config: {clerkIOPrivateApiKey: "%(apikey)s",
                            publicClientId: "web-storefront-1"}};
window.staticSettings = {subscriptionKey: "%(hex)s"};
window.__extra = {stripeKey: "%(stripe)s", awsKey: "%(aws)s",
                  appInsights: "InstrumentationKey=%(guid)s;IngestionEndpoint=https://x.example.test"};
var jwtToken = "%(jwt)s";
var U = {apiOrigin: "https://api.example.test"};
var checkoutUrl = `${U.apiOrigin}/Order/CreateAndPrepareOrderForPayment`;
var tokenEndpoint = "/Member/token";
function go(){ this.http.post(checkoutUrl, {}); fetch("/AgeVerification/Validate"); }
try { localStorage.setItem("authToken", "Bearer %(bearer)s"); } catch(e){}
try { sessionStorage.setItem("LJ.PaymentData", JSON.stringify({mac: "%(mac)s"})); } catch(e){}
fetch("/api/data", {method: "POST", headers: {"X-Api-Key": "%(xapikey)s"}, body: JSON.stringify({q: "x"})});
</script>
<pre id="cover">%(cover)s</pre></body>""" % {**K, "xapikey": XAPIKEY, "mac": MAC, "cover": COVER_TEXT}

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
    blob = json.dumps(r)
    def want(substr, why):
        assert any(substr.lower() in (f.get("name") or "").lower() for f in r["findings"]), f"MISSED {why}: {substr}\n{json.dumps(r['findings'], indent=1)}"
    want("clerkIOPrivateApiKey", "nested window global, private->high")
    want("subscriptionKey", "key without prefix word")
    want("data-api-key", "hyphenated short html attr")
    want("X-Api-Key", "outgoing request header")
    want("netaxeptToken", "double-serialized JSON response field")
    want("mac", "secret in sessionStorage JSON blob")
    # every provider pattern still classifies a valid sample under its own kind (regex-regression guard)
    kinds = {f["kind"] for f in r["findings"]}
    missing = [k for k in COVER if k not in kinds]
    assert not missing, f"provider patterns not detected: {missing}\ndetected kinds: {sorted(kinds)}"
    # private key must be high severity
    priv = next(f for f in r["findings"] if f.get("name", "").endswith("clerkIOPrivateApiKey"))
    assert priv["severity"] == "high", priv
    # redaction on by default: no full secret value in output
    assert K["apikey"] not in blob, "private key leaked despite redaction"
    assert XAPIKEY not in blob, "api key leaked despite redaction"
    assert "…" in priv["value"], priv
    # reveal=True + out_path: full values, written to file
    out = "/tmp/burrow-scan-report.json"
    r2 = (await server.scan_secrets(check_source_maps=False, reveal=True, out_path=out))["result"]
    disk = json.load(open(r2["written"]))
    assert disk["redacted"] is False
    revealed = set()
    for f in disk["findings"]:
        if f.get("value"): revealed.add(f["value"])
        revealed.update(f.get("samples", []))
    assert K["apikey"] in revealed, "reveal didn't surface full key"
    # every provider format the generator emits is actually detected
    for fmt in ("stripe", "aws", "guid", "jwt", "netaxept"):
        assert K[fmt] in revealed, f"format not detected: {fmt} = {K[fmt]}\n{sorted(revealed)}"
    # scan_endpoints: passive inventory of the bundle
    ep = (await server.scan_endpoints())["result"]
    urls = [e["url"] for e in ep["endpoints"]]
    assert any("/Order/CreateAndPrepareOrderForPayment" in u for u in urls), ("checkoutUrl assign", urls)
    assert any(u == "/Member/token" for u in urls), ("tokenEndpoint assign", urls)
    assert any("/AgeVerification/Validate" in u for u in urls), ("fetch call", urls)
    sink_keys = [k["key"] for k in ep["storage_sinks"]]
    assert "authToken" in sink_keys and "LJ.PaymentData" in sink_keys, ("storage sinks", sink_keys)
    print("ok |", len(r["findings"]), "findings |", len(ep["endpoints"]), "endpoints |", r2["written"])
    srv.shutdown()
    await server._state["cm"].__aexit__(None, None, None)

asyncio.run(main())
