"""Two agents sharing one server: their sessions must not touch each other's page or cookies."""
import asyncio, os, sys
os.environ["BURROW_BROWSER_REQUIRE_SESSION"] = "1"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server


async def agent(name, url, cookie):
    await server.navigate(url, session=name)
    await server.evaluate(f"document.cookie = '{cookie}; path=/'", session=name)
    await asyncio.sleep(1)  # let the other agent navigate in between
    title = (await server.evaluate("document.title", session=name))["result"]
    return title, (await server.evaluate("document.cookie", session=name))["result"]


async def main():
    try:
        await server.navigate("https://example.com")
    except ValueError as e:
        assert "session=" in str(e)
    else:
        raise AssertionError("unnamed session allowed")
    a, b = await asyncio.gather(agent("dk", "https://example.com", "who=dk"),
                                agent("se", "https://example.org", "who=se"))
    print(a, b)
    assert a[1] == "who=dk" and b[1] == "who=se", "cookies leaked between sessions"
    assert (await server.requests(session="dk"))["result"][0]["url"].startswith("https://example.com"), "dk log"
    assert (await server.requests(session="se"))["result"][0]["url"].startswith("https://example.org"), "se log"
    await server.start_recording("/tmp/burrow-browser-session.har", session="dk")
    try:
        await server.stop_recording(session="se")
    except RuntimeError:
        pass
    else:
        raise AssertionError("se stopped dk's recording")
    assert (await server.stop_recording(session="dk"))["bytes"] > 0
    print("ok")
    await server._state["cm"].__aexit__(None, None, None)

asyncio.run(main())
