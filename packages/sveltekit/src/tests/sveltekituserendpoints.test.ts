import { MockRequestEvent } from './sveltemocks';
import { test, expect } from 'vitest';
import {  makeServer, getCsrfToken } from './testshared';

test('SvelteKitUserEndpoints.login', async () => {
    const { server, resolver, handle } = await makeServer();
    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);

    const postRequest = new Request("http://ex.com/test", {
        method: "POST",
        body: "csrfToken="+csrfToken+"&username=bob&password=bobPass123",
        headers: { 
            "cookie": "CSRFTOKEN="+csrfCookieValue,
            "content-type": "application/x-www-form-urlencoded",
        }});
    let event = new MockRequestEvent("1", postRequest, {"param1": "value1"});
    event.locals.csrfToken = csrfToken;

    const ret = await server.sessionServer?.login(event);
    expect(ret?.user?.username).toBe("bob");
    expect(event.cookies.get("SESSIONID")).toBeDefined();
});

test('SvelteKitUserEndpoints.logout', async () => {
    const { server, resolver, handle } = await makeServer();
    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);

    let postRequest = new Request("http://ex.com/test", {
        method: "POST",
        body: "csrfToken="+csrfToken+"&username=bob&password=bobPass123",
        headers: { 
            "cookie": "CSRFTOKEN="+csrfCookieValue,
            "content-type": "application/x-www-form-urlencoded",
        }});
    let event = new MockRequestEvent("1", postRequest, {"param1": "value1"});
    event.locals.csrfToken = csrfToken;

    let ret = await server.sessionServer?.login(event);
    expect(ret?.user?.username).toBe("bob");
    expect(event.cookies.get("SESSIONID")).toBeDefined();

    postRequest = new Request("http://ex.com/test", {
        method: "POST",
        body: "csrfToken="+csrfToken+"&username=bob&password=bobPass123",
        headers: { 
            "cookie": "CSRFTOKEN="+csrfCookieValue,
            "content-type": "application/x-www-form-urlencoded",
        }});
    event = new MockRequestEvent("1", postRequest, {"param1": "value1"});
    event.locals.csrfToken = csrfToken;

    ret = await server.sessionServer?.logout(event);
    expect(ret?.user).toBeUndefined();
    expect(event.cookies.get("SESSIONID")).toBeUndefined();
});
