import { MockRequestEvent } from './sveltemocks';
import { JsonOrFormData } from '../utils';
import { test, expect } from 'vitest';
import { createSession, makeServer, getCookies, login, loginFactor2, getCsrfToken} from './testshared';
import { SessionCookie } from '@crossauth/backend';

test('SvelteSessionHooks.hookWithGetNotLoggedIn', async () => {
    const { server, resolver, handle } = await makeServer();

    const getRequest = new Request("http://ex.com/test", {method: "GET"});
    let event = new MockRequestEvent("1", getRequest, {"param1": "value1"});

    const resp = await handle({event: event, resolve: resolver.mockResolve});
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

    csrfValid = false;
    try {
        server.sessionServer?.sessionManager.validateDoubleSubmitCsrfToken(cookies["CSRFTOKEN"], event.locals.csrfToken);
    } catch (e) {
        console.log(e);
    }
});

test('SvelteSessionHooks.hookWithPostNotLoggedIn', async () => {
    const { resolver, handle } = await makeServer();

    const postRequest = new Request("http://ex.com/test", {method: "POST", body: "This is the body"});
    let event = new MockRequestEvent("1", postRequest, {"param1": "value1"});

    const resp = await handle({event: event, resolve: resolver.mockResolve});
    const cookies = getCookies(resp);
    expect(cookies["CSRFTOKEN"]).toBeUndefined();
});

test('SvelteMocks.hookGetThenPost', async () => {
    const { server, resolver, handle } = await makeServer();

    const getRequest = new Request("http://ex.com/test", {method: "GET"});
    let event = new MockRequestEvent("1", getRequest, {"param1": "value1"});

    let resp = await handle({event: event, resolve: resolver.mockResolve});
    const cookies = getCookies(resp);
    expect(cookies["CSRFTOKEN"]).toBeDefined();
    const postRequest = new Request("http://ex.com/test", {
        method: "POST",
        body: "csrfToken="+event.locals.csrfToken,
        headers: { 
            "cookie": "CSRFTOKEN="+cookies["CSRFTOKEN"],
            "content-type": "application/x-www-form-urlencoded",
        }});
    event = new MockRequestEvent("1", postRequest, {"param1": "value1"});
    resp = await handle({event: event, resolve: resolver.mockResolve});
    let csrfValid = false;
    try {
        server.sessionServer?.sessionManager.validateCsrfCookie(cookies["CSRFTOKEN"]);
        csrfValid = true;
    } catch (e) {
        console.log(e);
    }
    expect(csrfValid).toBe(true);
    expect(event.locals.csrfToken).toBeDefined();

    csrfValid = false;
    try {
        server.sessionServer?.sessionManager.validateDoubleSubmitCsrfToken(cookies["CSRFTOKEN"], event.locals.csrfToken);
        csrfValid = true;
    } catch (e) {
        console.log(e);
    }
});

test('SvelteSessionHooks.formBody', async () => {
    const postRequest = new Request("http://ex.com/test", {
        method: "POST",
        body: "param1=value1&param%262=value+2",
        headers: { 
            "content-type": "application/x-www-form-urlencoded",
        }});
    const event = new MockRequestEvent("1", postRequest, {});
    const data = new JsonOrFormData();
    await data.loadData(event);
    let keys = [...data.keys()];
    expect(keys.length).toBe(2);
    expect(["param1","param&2"]).toContain(keys[0]);
    expect(["param1","param&2"]).toContain(keys[1]);
    expect(data.get("param1")).toBe("value1");
    expect(data.get("param&2")).toBe("value 2");
    expect(data.get("X")).toBeUndefined();
    const obj = data.toObject();
    expect(obj["param1"]).toBe("value1");
});

test('SvelteSessionHooks.jsonBody', async () => {
    const body = JSON.stringify({"param1": "value1", "param&2": "value 2"});
    const postRequest = new Request("http://ex.com/test", {
        method: "POST",
        body: body,
        headers: { 
            "content-type": "application/json",
        }});
    const event = new MockRequestEvent("1", postRequest, {});
    const data = new JsonOrFormData();
    await data.loadData(event);
    let keys = [...data.keys()];
    expect(keys.length).toBe(2);
    expect(["param1","param&2"]).toContain(keys[0]);
    expect(["param1","param&2"]).toContain(keys[1]);
    expect(data.get("param1")).toBe("value1");
    expect(data.get("param&2")).toBe("value 2");
    expect(data.get("X")).toBeUndefined();
});

test('SvelteSessionHooks.hookWithGetIsLoggedIn', async () => {
    const { server, resolver, handle, userStorage, keyStorage } = await makeServer();
    const sessionKey = await createSession("bob", userStorage, keyStorage);

    const getRequest = new Request("http://ex.com/test", {
        method: "GET", headers: { 
            "cookie": sessionKey.cookie.name + "=" + sessionKey.cookie.value,
    }});
    let event = new MockRequestEvent("1", getRequest, {"param1": "value1"});

    const resp = await handle({event: event, resolve: resolver.mockResolve});
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
    expect(event.locals.user).toBeDefined();
    expect(event.locals.user?.username).toBe("bob");

    csrfValid = false;
    try {
        server.sessionServer?.sessionManager.validateDoubleSubmitCsrfToken(cookies["CSRFTOKEN"], event.locals.csrfToken);
    } catch (e) {
        console.log(e);
    }
});

test('SvelteSessionHooks.loginProtectedNotLoggedIn', async () => {
    const { server, resolver, handle } = await makeServer();

    let getRequest = new Request("http://ex.com/account", {method: "GET"});
    let event = new MockRequestEvent("1", getRequest, {"param1": "value1"});

    let resp = await handle({event: event, resolve: resolver.mockResolve});
    expect(resp.status).toBe(302);
    expect(resp.headers.get('location')).toBe("/");

    // log in
    let {event: loginEvent} = await login(server, resolver, handle);

    // try again now that we are logged in
    event.request = getRequest;
    resp = await handle({event: loginEvent, resolve: resolver.mockResolve});
    expect(resp.status).toBe(200);

});


test('SvelteSessionHooks.login2FA', async () => {
    const { server, resolver, handle } = await makeServer();

    // log in
    let resp = await login(server, resolver, handle, "alice", "alicePass123");
    const loginEvent = resp.event;
    const sessionCookie = loginEvent.cookies.get("SESSIONID");
    let ret = resp.ret;
    expect(ret?.factor2Required).toBe(true);
    const sessionId = server.sessionServer?.sessionManager.getSessionId(sessionCookie??"");
    resp = await loginFactor2(server, resolver, handle, sessionCookie??"", sessionId??"");
    ret = resp.ret;
    expect(ret?.success).toBe(true);
    expect(ret?.user?.username).toBe("alice");
});

test('SvelteSessionHooks.visitPage2FA', async () => {
    const { server, resolver, handle } = await makeServer();

    // log in
    let resp = await login(server, resolver, handle, "alice", "alicePass123");
    let loginEvent = resp.event;
    let sessionCookieValue = loginEvent.cookies.get("SESSIONID");
    let ret = resp.ret;
    expect(ret?.factor2Required).toBe(true);
    let sessionId = server.sessionServer?.sessionManager.getSessionId(sessionCookieValue??"");
    resp = await loginFactor2(server, resolver, handle, sessionCookieValue??"", sessionId??"");
    loginEvent = resp.event;
    ret = resp.ret;
    expect(ret?.success).toBe(true);
    expect(ret?.user?.username).toBe("alice");

    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);

    // visit factor2-protected page
    let postRequest = new Request("http://ex.com/factor2protected", {
        method: "POST",
        body: "csrfToken="+csrfToken+"&param1=value1",
        headers: { 
            "cookie": "CSRFTOKEN="+csrfCookieValue,
            "content-type": "application/x-www-form-urlencoded",
        }});
    let event = new MockRequestEvent("1", postRequest, {});
    event.locals.csrfToken = csrfToken;
    event.locals.user = ret?.user;
    sessionCookieValue = loginEvent.cookies.get("SESSIONID");
    event.cookies.set("SESSIONID", sessionCookieValue??"", {path: "/"});
    //sessionId = loginEvent.locals.sessionId;
    sessionId = server.sessionServer?.sessionManager.getSessionId(sessionCookieValue??"");
    event.locals.sessionId = sessionId;
    let resp1 = await handle({event: event, resolve: resolver.mockResolve});
    expect(resp1.status).toBe(302);
    expect(resp1.headers.get("location")).toBe("/factor2/");

    // submit factor2
    postRequest = new Request("http://ex.com/factor2protected", {
        method: "POST",
        body: "csrfToken="+csrfToken+"&otp=0000",
        headers: [ 
            ["cookie", "CSRFTOKEN="+csrfCookieValue],
            ["cookie", "SESSIONID="+sessionCookieValue],
            ["content-type", "application/x-www-form-urlencoded"],
        ]});
    event = new MockRequestEvent("1", postRequest, {});
    resp1 = await handle({event: event, resolve: resolver.mockResolve});
    expect(resp1.status).toBe(200);

});
