import { MockRequestEvent } from './sveltemocks';
import { SvelteKitServer } from '../sveltekitserver';
import type { MockResolver } from './sveltemocks';
import { test, expect } from 'vitest';
import {  makeServer, getCookies } from './testshared';
import type { Handle } from '@sveltejs/kit';

async function getCsrfToken(server : SvelteKitServer, resolver : MockResolver, handle : Handle ) {
    const getRequest = new Request("http://ex.com/test", {method: "GET"});
    let event = new MockRequestEvent("1", getRequest, {"param1": "value1"});

    const resp = await handle({event: event, resolve: resolver.mockResolve});
    /*const cookieNames = resp.headers.getSetCookie().map((el) => el.split("=")[0]);
    expect(cookieNames.length).toBe(2);
    expect(["TESTCOOKIE", "CSRFTOKEN"]).toContain(cookieNames[0]);*/
    const cookies = getCookies(resp);
    expect(cookies["CSRFTOKEN"]).toBeDefined();
    let csrfValid = false;
    try {
        server.sessionServer?.sessionManager.validateCsrfCookie(cookies["CSRFTOKEN"]);
        csrfValid = true;
    } catch (e) {
        console.log(e);
    }
    expect(csrfValid).toBe(true);
    expect(event.locals.csrfToken).toBeDefined();
    return {
        csrfToken: event.locals.csrfToken,
        csrfCookieValue: cookies["CSRFTOKEN"]
    };
}

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
