# /// script
# dependencies = ["mcp>=1.0,<2", "camoufox[geoip]"]
# ///
"""Check that a proxy refusing CONNECT (like an allowlist proxy) surfaces as blocked_hosts."""
import asyncio, os, socketserver, sys, threading

class Refuse(socketserver.StreamRequestHandler):
    def handle(self):
        self.rfile.readline()
        self.wfile.write(b"HTTP/1.1 403 Forbidden\r\nX-Proxy-Error: blocked-by-allowlist\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")

from camoufox.fpgen_model import ensure_fpgen_model
ensure_fpgen_model()  # fetch the model before the refusing proxy is switched on

srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Refuse)
threading.Thread(target=srv.serve_forever, daemon=True).start()
os.environ["HTTPS_PROXY"] = f"http://127.0.0.1:{srv.server_address[1]}"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server

async def main():
    r = await server.navigate("https://example.com")
    assert r.get("blocked_hosts") == ["example.com"], r
    d = await server.download("https://example.com/x.pdf", "/tmp/burrow-proxy-test.bin")
    assert d.get("blocked_hosts") == ["example.com"], d
    print("ok", r, d)
    await server._state["cm"].__aexit__(None, None, None)

asyncio.run(main())
