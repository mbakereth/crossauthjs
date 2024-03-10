import { MockRequestEvent, MockResolver } from './sveltemocks';
import { JsonOrFormData } from '../utils';
import { SvelteKitServer } from '../sveltekitserver';
import { SvelteKitSessionServer } from '../sveltekitsession';
import { InMemoryKeyStorage, InMemoryUserStorage, LocalPasswordAuthenticator } from '@crossauth/backend';
import { test, expect } from 'vitest';

function makeServer() {
    const keyStorage = new InMemoryKeyStorage();
    const userStorage = new InMemoryUserStorage();
    const authenticator = new LocalPasswordAuthenticator(userStorage);

    const server = new SvelteKitServer(userStorage, {
        session: {
            keyStorage: keyStorage,
            authenticators: {
                password: authenticator
            }
        }}, {secret: "ABCDEFG"});   
    const handle = server.hooks;
    const resolver = new MockResolver("Response");

    return {server, resolver, handle, keyStorage, userStorage, authenticator};
}
function getCookies(resp : Response) {
    const cookieHeaders = resp.headers.getSetCookie();
    let cookies : {[key:string]:string} = {};
    for (let cookie of cookieHeaders) {
        const parts = cookie.split("=", 2);
        const semiColon = parts[1].indexOf(";");
        if (semiColon > -1) {
            const value = parts[1].substring(0, semiColon).trim();
            if (value.length > 0) cookies[parts[0]] = value;
        }
    }
    return cookies;
}
test('SvelteSessionHooks.hookWithGetNotLoggedIn', async () => {
    const { server, resolver, handle } = makeServer();

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

    csrfValid = false;
    try {
        server.sessionServer?.sessionManager.validateDoubleSubmitCsrfToken(cookies["CSRFTOKEN"], event.locals.csrfToken);
    } catch (e) {
        console.log(e);
    }
});

test('SvelteSessionHooks.hookWithPostNotLoggedIn', async () => {
    const { resolver, handle } = makeServer();

    const postRequest = new Request("http://ex.com/test", {method: "POST", body: "This is the body"});
    let event = new MockRequestEvent("1", postRequest, {"param1": "value1"});

    const resp = await handle({event: event, resolve: resolver.mockResolve});
    const cookies = getCookies(resp);
    expect(cookies["CSRFTOKEN"]).toBeUndefined();
});

test('SvelteMocks.hookGetThenPost', async () => {
    const { server, resolver, handle } = makeServer();

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

test('SvelteSessionHooks.cloneJsonResponse', async () => {
    const response = new Response(
        JSON.stringify({"param1": "value1", "param2" : "value2"}),
        {status: 200, statusText: "OK", headers: {'content-type': 'application/json'}}
    );
    const newResponse = SvelteKitSessionServer.responseWithNewBody(
        response,
        {"param3": "value3"}
    );
    const newBody = await newResponse.json();
    expect(newBody.param3).toBe("value3");
    expect(newBody.param1).toBeUndefined();
    expect(newResponse.headers.get('content-type')).toBe("application/json");
});

test('SvelteSessionHooks.cloneFormResponse', async () => {
    const response = new Response(
        "param1=value1&param2=value2",
        {status: 200, statusText: "OK", headers: {'content-type': 'application/x-www-form-urlencoded'}}
    );
    const newResponse = SvelteKitSessionServer.responseWithNewBody(
        response,
        {"param3": "value3"}
    );
    const newBody = await newResponse.formData();
    expect(newBody.get("param3")).toBe("value3");
    expect(newBody.get("param1")).toBeNull();
    expect(newResponse.headers.get('content-type')).toBe("application/x-www-form-urlencoded");
});
