"""Crash the browser's content process, then check that burrow-browser recovers."""
import asyncio, os, signal, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server


def descendants(pid):
    kids = subprocess.run(["pgrep", "-P", str(pid)], capture_output=True, text=True).stdout.split()
    return [k for c in kids for k in [int(c), *descendants(c)]]


def crash(kind):
    """SIGKILL our own browser processes: the tab processes, or the main browser. SIGSEGV doesn't kill them."""
    procs = {p: open(f"/proc/{p}/cmdline").read().split("\0") for p in descendants(os.getpid())}
    hit = [p for p, c in procs.items() if "camoufox/browsers" in c[0] and (" tab" in " ".join(c) if kind == "tab" else "-contentproc" not in c)]
    assert hit, f"no {kind} process"
    for p in hit:
        os.kill(p, signal.SIGKILL)


async def main():
    for mark in ("tab", "browser"):
        r = await server.navigate("https://example.com")
        assert r["status"] in (200, 304), r
        crash(mark)
        await asyncio.sleep(2)
        try:
            (await server.get_text())["result"]
        except Exception as e:
            assert "Call navigate" in str(e), e
        else:
            raise AssertionError("get_text returned a dead page")
        assert (await server.requests())["result"], "request log lost"
        r = await server.navigate("https://example.com")
        assert r["status"] in (200, 304), r
        assert "domain" in (await server.get_text())["result"]
        print("recovered from", mark)
    # navigate the instant the browser dies, before is_connected() notices: must relaunch, not fail
    for _ in range(3):
        crash("browser")
        r = await server.navigate("https://example.com")
        assert r["status"] in (200, 304), r
    print("recovered from immediate navigate x3")
    await server._state["cm"].__aexit__(None, None, None)

asyncio.run(main())
