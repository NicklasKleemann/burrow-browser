"""http_request: connection IP, Host header and SNI controlled independently."""
import asyncio, os, socket, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server


async def main():
    ip = socket.gethostbyname("example.com")
    # normal: host + matching SNI, cert should mention example.com
    r = (await server.http_request("https://example.com/"))["result"]
    assert r["status"] in (200, 301, 302), r
    assert r["peer_ip"] == r["requested"]["connect_ip"] or r["peer_ip"], r
    assert any("example" in n for n in r["tls"]["cert"].get("san", [])), r["tls"]["cert"]

    # connect by IP, keep Host + SNI: still works, same cert
    r2 = (await server.http_request("https://example.com/", connect_ip=ip))["result"]
    assert r2["status"] in (200, 301, 302), r2
    assert r2["peer_ip"] == ip, r2

    # default-vhost probe: Host=IP, no SNI. Cloudflare refuses the handshake; capture that as data.
    r3 = (await server.http_request("https://example.com/", connect_ip=ip, host_header=ip, sni="none"))["result"]
    assert "error" in r3 or "status" in r3, r3  # either answers, but must not raise
    assert r3["requested"]["sni"] == "(none)", r3

    # plain HTTP alternate-host header
    r4 = (await server.http_request("http://example.com/", host_header="alt.example.net"))["result"]
    assert "status" in r4 or "error" in r4, r4
    # tls_audit on a public host: trusted cert, modern protocols. (example.com, behind Cloudflare,
    # also still accepts TLS 1.0/1.1, confirmed with openssl s_client, so those findings are real.)
    t = (await server.tls_audit("https://example.com/"))["result"]
    assert not [f for f in t["findings"] if f["severity"] == "high"], t["findings"]
    assert "accepted" in (t["protocols"]["TLSv1_2"], t["protocols"]["TLSv1_3"]) and t["cert"]["days_left"] > 0, t
    print("ok", r["status"], "| ip", ip, "| default-vhost:", r3.get("error") or r3.get("status"))

asyncio.run(main())
