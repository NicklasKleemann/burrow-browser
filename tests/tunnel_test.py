"""http_request and tls_audit behind a CONNECT proxy, like Claude Science's allowlist proxy.
Offline: a local proxy (needs auth, allows only "localhost") in front of a local HTTPS server that
reports the Host header and SNI it received."""
import asyncio, base64, datetime, http.server, os, select, socket, socketserver, ssl, sys, tempfile, threading

seen = {}


def https_server():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False).sign(key, hashes.SHA256()))
    d = tempfile.mkdtemp()
    open(f"{d}/c.pem", "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(f"{d}/k.pem", "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(f"{d}/c.pem", f"{d}/k.pem")
    ctx.sni_callback = lambda sock, server_name, c: seen.__setitem__("sni", server_name)

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(f"host={self.headers.get('host')}".encode())

        def log_message(self, *a):
            pass

    s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    s.socket = ctx.wrap_socket(s.socket, server_side=True)
    s.handle_error = lambda *a: None  # tls_audit's refused handshakes are expected
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s.server_address[1]


AUTH = "Basic " + base64.b64encode(b"agent:s3cret").decode()


class Proxy(socketserver.StreamRequestHandler):
    def handle(self):
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self.connection.recv(4096)
            if not chunk:
                return
            head += chunk
        lines = head.decode("latin-1").split("\r\n")
        target = lines[0].split(" ")[1]
        host, port = target.rsplit(":", 1)
        hdrs = {l.split(":", 1)[0].lower(): l.split(":", 1)[1].strip() for l in lines[1:] if ":" in l}
        seen.setdefault("connects", []).append(target)
        if hdrs.get("proxy-authorization") != AUTH:
            self.connection.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
            return
        if host != "localhost":  # allowlist by hostname: IP literals and other hosts are refused
            self.connection.sendall(b"HTTP/1.1 403 Forbidden\r\nX-Proxy-Error: blocked-by-allowlist\r\nContent-Length: 0\r\n\r\n")
            return
        up = socket.create_connection(("127.0.0.1", int(port)))
        self.connection.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        socks = [self.connection, up]
        try:
            while True:
                r, _, _ = select.select(socks, [], [], 10)
                if not r:
                    return
                for s in r:
                    data = s.recv(65536)
                    if not data:
                        return
                    (up if s is self.connection else self.connection).sendall(data)
        except OSError:
            pass
        finally:
            up.close()


proxy = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Proxy)
proxy.daemon_threads = True
threading.Thread(target=proxy.serve_forever, daemon=True).start()
os.environ["HTTPS_PROXY"] = f"http://agent:s3cret@127.0.0.1:{proxy.server_address[1]}"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # server.py is one folder up
import server  # reads the proxy from the environment at import


async def main():
    port = https_server()
    url = f"https://localhost:{port}/"

    # Host header and SNI are still ours through the tunnel
    r = (await server.http_request(url, host_header="vhost.test", sni="sni.test"))["result"]
    assert r.get("status") == 200 and r["body"] == "host=vhost.test", r
    assert r["requested"]["via_proxy"] and "peer_ip" not in r, r
    assert r["tls"]["sni_sent"] == "sni.test" and seen["sni"] == "sni.test", (r["tls"], seen)
    assert r["tls"]["cert"]["san"] == ["localhost"], r["tls"]["cert"]
    assert seen["connects"][-1] == f"localhost:{port}"

    # an IP pinned via connect_ip, or a host off the allowlist, comes back as blocked_hosts
    pinned = (await server.http_request(url, connect_ip="127.0.0.1"))["result"]
    assert pinned["blocked_hosts"] == ["127.0.0.1"] and "blocked by network proxy" in pinned["error"], pinned
    off = (await server.http_request("https://blocked.example/"))["result"]
    assert off["blocked_hosts"] == ["blocked.example"] and "status" not in off, off

    # tls_audit runs its handshakes through the tunnel
    t = (await server.tls_audit("localhost", port))["result"]
    assert "error" not in t and t["cert"]["san"] == ["localhost"], t
    assert t["protocols"]["TLSv1_2"] == "accepted" or t["protocols"]["TLSv1_3"] == "accepted", t["protocols"]
    assert any("not trusted" in f["issue"] for f in t["findings"]), "self-signed cert must still be flagged"
    blocked = (await server.tls_audit("blocked.example"))["result"]
    assert blocked["blocked_hosts"] == ["blocked.example"] and "blocked by network proxy" in blocked["error"], blocked
    print("ok | connects:", len(seen["connects"]), "| protocols", t["protocols"])

asyncio.run(main())
