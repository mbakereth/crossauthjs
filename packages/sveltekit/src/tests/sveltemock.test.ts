import { MockRequestEvent, MockResolver, MockCookies } from './sveltemocks';
import { SvelteKitSessionServer } from '../sveltekitsession';
import { InMemoryKeyStorage } from '@crossauth/backend';

test('SvelteMocks.Request', async () => {

    const request = new Request("http://ex.com/test", {method: "POST", body: "This is the body"});
    expect(request.body).not.toBe(null)
    if (request.body) expect(await (new Response(request.body).text())).toBe("This is the body");
});

test('SvelteMocks.MockRequestEvent', async () => {

    const request = new Request("http://ex.com/test", {method: "POST", body: "This is the body"});
    const requestEvent = new MockRequestEvent("1", request, {"param1": "value1"});
    expect(requestEvent.route.id).toBe("1");
    expect(requestEvent.params["param1"]).toBe("value1");

});

test('SvelteMocks.MockCookies', async () => {
    const cookies = new MockCookies({
        "cookie1": {value: "value1", opts: {maxAge: 120, domain: "http://example1.com"}},
        "cookie2": {value: "value&2", opts: {maxAge: 140, domain: "http://example2.com"}},
    });

    // get cookie
    let value1 = await cookies.get("cookie1")
    expect(value1).toBe("value1");
    let value2 = await cookies.get("cookie2")
    expect(value2).toBe("value&2");

    // get all
    let values = await cookies.getAll();
    expect(values.length).toBe(2);

    // set cookie
    await cookies.set("cookie1", "value3", {maxAge: 120, domain: "http://example3.com", path: "/"});
    value1 = await cookies.get("cookie1");
    expect(value1).toBe("value3");
    await cookies.delete("cookie1", {path: "/"});
    value1 = await cookies.get("cookie1");
    expect(value1).toBe(undefined);
});

test('SvelteMocks.hook', async () => {
    const request = new Request("http://ex.com/test", {method: "POST", body: "This is the body"});
    const requestEvent = new MockRequestEvent("1", request, {"param1": "value1"});
    const keyStorage = new InMemoryKeyStorage();

    const session = new SvelteKitSessionServer(keyStorage);
    const handle = session.sessionHook;
    const resolver = new MockResolver("Response");
    const resp = await handle({event: requestEvent, resolve: resolver.mockResolve});
    const cookies = resp.headers.getSetCookie();
    expect(cookies.length).toBe(1);
    expect(cookies[0]).toContain("TESTCOOKIE=");
});

