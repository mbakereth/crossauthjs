import { MockRequestEvent } from './sveltemocks';
import { test, expect } from 'vitest';
import {  makeServer, getCsrfToken, login } from './testshared';

export var passwordResetData :  {token : string, extraData: {[key:string]: any}};

test('SvelteKitOAuthServer.authorizeRedirectsToLogin', async () => {
    const { server } = await makeServer(true, false, true);

    const redirect = encodeURIComponent("http://example.com/redirect")

    // authorize get endpoint
    let getRequest = new Request(`http://server.com/authorize?response_type=code&client_id=ABC&redirect_uri=${redirect}&scope=read+write&state=ABC123`, {
        method: "GET",
        });
    let event = new MockRequestEvent("1", getRequest, {});
    let authServer = server.oAuthAuthServer;
    let redirectTo : string|undefined = undefined;
    try {
        await authServer?.authorizeEndpoint.load(event);
    } catch (e) {
        
        redirectTo = "location" in Object(e) ?  Object(e).location : undefined;
    }
    expect(redirectTo).toContain("/login");

});

test('SvelteKitOAuthServer.getAccessTokenWhileLoggedIn', async () => {
    const { server, resolver, handle } = await makeServer(true, false, true);

    // log in
    let resp = await login(server, resolver, handle);
    const user = resp.event.locals.user;
    let loginEvent = resp.event;
    loginEvent = resp.event;
    
    let sessionCookieValue = loginEvent.cookies.get("SESSIONID");

    // authorize get endpoint
    const redirect = encodeURIComponent("http://example.com/redirect");

    let getRequest = new Request(`http://server.com/authorize?response_type=code&client_id=ABC&redirect_uri=${redirect}&scope=read+write&state=ABC123`, {
        method: "GET",
        headers: [
            ["cookie", "SESSIONID="+sessionCookieValue],
        ] 
        });
    let event = new MockRequestEvent("1", getRequest, {});
    event.locals.user = user;
    let authServer = server.oAuthAuthServer;
    if (!authServer) throw new Error("No auth server");
    let redirectTo : string|undefined = undefined;
    try {
        const resp = await authServer?.authorizeEndpoint.load(event);
        expect(resp?.success).toBe(true);
        expect(resp?.authorizationNeeded).toBeDefined();
        expect(resp?.authorizationNeeded?.user?.username).toBe("bob");
    } catch (e) {
        redirectTo = "location" in Object(e) ?  Object(e).location : undefined;
    }
    expect(redirectTo).toBeUndefined();
    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);
    let sessionId = server.sessionServer?.sessionManager.getSessionId(sessionCookieValue??"");

    // authorize
    let postRequest = new Request("http://ex.com/authorize", {
        method: "POST",
        body:  "csrfToken=" + csrfToken + "&" +
            "response_type=code&" +
            "client_id=ABC&" +
            "redirect_uri=" + redirect + "&" +
            "scope=read+write&" +
            "state=ABC123&" +
            "authorized=true",
        headers: [
            ["cookie", "CSRFTOKEN="+csrfCookieValue],
            ["cookie", "SESSIONID="+sessionCookieValue],
            ["content-type", "application/x-www-form-urlencoded"],
        ] 
        });
        event = new MockRequestEvent("1", postRequest, {});
        event.locals.user = user;
        event.locals.csrfToken = csrfToken;
        event.locals.sessionId = sessionId;
        try {
            await authServer?.authorizeEndpoint.actions.default(event);
        } catch (e) {
            redirectTo = "location" in Object(e) ?  Object(e).location : undefined;
        }
        expect(redirectTo).toContain("http://example.com/redirect");
        const redirectUrl = new URL(redirectTo??"");
        let code = redirectUrl.searchParams.get("code");

        // token
        postRequest = new Request("http://ex.com/token", {
            method: "POST",
            body: JSON.stringify({
                grant_type: "authorization_code",
                client_id : "ABC",
                client_secret: "DEF",
                scope: "read write",
                code: code,
            }),
            headers: [
                ["content-type", "application/json"],
            ] 
                });
        event = new MockRequestEvent("1", postRequest, {});
        let access_token : string|undefined = undefined;
        try {
            const resp = await authServer.tokenEndpoint.post(event);
            access_token = (await resp.json()).access_token;
        } catch (e) {
            redirectTo = "location" in Object(e) ?  Object(e).location : undefined;
            console.log("Error", e);
        }
        expect(access_token).toBeDefined();
    
    
});

/*
test('SvelteKitOAuthServer.getAccessTokenAlreadyAuthorized', async () => {
    const { server, resolver, handle, userStorage } = await makeServer(true, false, true);

    // log in
    let resp = await login(server, resolver, handle);
    const user = resp.event.locals.user;
    let loginEvent = resp.event;
    loginEvent = resp.event;
    const {csrfCookieValue} = await getCsrfToken(server, resolver, handle);
    
    let sessionCookieValue = loginEvent.cookies.get("SESSIONID");

    // authorize get endpoint
    const redirect = encodeURIComponent("http://example.com/redirect");

    let getRequest = new Request(`http://server.com/authorize?response_type=code&client_id=ABC&redirect_uri=${redirect}&scope=read+write&state=ABC123`, {
        method: "GET",
        headers: [
            ["cookie", "SESSIONID="+sessionCookieValue],
        ] 
        });
    let event = new MockRequestEvent("1", getRequest, {});
    event.locals.user = user;
    let authServer = server.oAuthAuthServer;
    let redirectTo : string|undefined = undefined;
    try {
        const resp = await authServer?.authorizeEndpoint.load(event);
        expect(resp?.success).toBe(true);
        expect(resp?.authorizationNeeded).toBeDefined();
        expect(resp?.authorizationNeeded?.user?.username).toBe("bob");
    } catch (e) {
        redirectTo = "location" in Object(e) ?  Object(e).location : undefined;
    }
    expect(redirectTo).toBeUndefined();

});
*/