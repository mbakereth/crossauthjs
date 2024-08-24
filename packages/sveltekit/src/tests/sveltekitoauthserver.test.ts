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
        expect(resp?.ok).toBe(true);
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
        }
        expect(access_token).toBeDefined();
    
    
});

test('SvelteKitOAuthServer.alreadyAuthorized', async () => {
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
        expect(resp?.ok).toBe(true);
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
        expect(code).toBeDefined();


        // second authorize request
        event = new MockRequestEvent("1", getRequest, {});
        event.locals.user = user;
        redirectTo = undefined;
        try {
            await authServer?.authorizeEndpoint.load(event);
        } catch (e) {
            redirectTo = "location" in Object(e) ?  Object(e).location : undefined;
        }
        expect(redirectTo).toContain("http://example.com/redirect");
    
    
});

test('SvelteKitOAuthServer.notAuthorized', async () => {
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
        expect(resp?.ok).toBe(true);
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
            "authorized=false",
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
        const url = new URL(redirectTo??"");
        expect(url.searchParams.get("error")).toBe("access_denied");
    
});

test('SvelteKitOAuthServer.oidcConfiguration', async () => {
    const { server } = await makeServer(true, false, true);

    let getRequest = new Request(`http://server.com/oidc-configuration`, {
        method: "GET",
        });
    let event = new MockRequestEvent("1", getRequest, {});
    let authServer = server.oAuthAuthServer;
    const resp =await authServer?.oidcConfigurationEndpoint.get(event);
    expect(resp?.status).toBe(200);
    const body = await resp?.json();
    expect(body?.authorization_endpoint).toBe("http://localhost:3000/oauth/authorize");
    expect(body?.token_endpoint).toBe("http://localhost:3000/oauth/token");
    expect(body?.jwks_uri).toBe("http://localhost:3000/oauth/jwks");
});

test('SvelteKitOAuthServer.jwks', async () => {
    const { server } = await makeServer(true, false, true);

    let getRequest = new Request(`http://server.com/jwks`, {
        method: "GET",
        });
    let event = new MockRequestEvent("1", getRequest, {});
    let authServer = server.oAuthAuthServer;
    const resp =await authServer?.jwksGetEndpoint.get(event);
    expect(resp?.status).toBe(200);
    const body = await resp?.json();
    expect(body.keys).toBeDefined();
    expect(body.keys.length).toBe(1);
});

test('SvelteKitOAuthServer.getCsrfTokenJson', async () => {
    const { server } = await makeServer(true, false, true);

    let getRequest = new Request(`http://server.com/getcsrftoken`, {
        method: "GET",
        });
    let event = new MockRequestEvent("1", getRequest, {});
    let authServer = server.oAuthAuthServer;
    const resp =await authServer?.getCsrfTokenEndpoint.get(event);
    expect(resp?.status).toBe(200);
    const body = await resp?.json();
    expect(body.ok).toBe(false);
});

test('SvelteKitOAuthServer.getCsrfTokenCookie', async () => {
    const { server } = await makeServer(true, false, true, false, {refreshTokenType: "cookie"});

    let getRequest = new Request(`http://server.com/getcsrftoken`, {
        method: "GET",
        });
    let event = new MockRequestEvent("1", getRequest, {});
    let authServer = server.oAuthAuthServer;
    const resp =await authServer?.getCsrfTokenEndpoint.get(event);
    expect(resp?.status).toBe(200);
    const body = await resp?.json();
    expect(body.ok).toBe(true);
    expect(body.csrfToken).toBeDefined();
});

test('SvelteKitOAuthServer.mfa', async () => {
    const { server, resolver, handle } = await makeServer(true, false, true);

    // log in
    await login(server, resolver, handle);
    

    // authorize get endpoint
    let authServer = server.oAuthAuthServer;
    if (!authServer) throw new Error("No auth server");

    // token
    let postRequest = new Request("http://ex.com/token", {
        method: "POST",
        body: JSON.stringify({
            grant_type: "password",
            client_id : "ABC",
            client_secret: "DEF",
            scope: "read write",
            username: "alice",
            password: "alicePass123",
            state: "ABCDEF",
        }),
        headers: [
            ["content-type", "application/json"],
        ] 
    });
    let event = new MockRequestEvent("1", postRequest, {});
    const resp2 = await authServer.tokenEndpoint.post(event);
    const body2 = await resp2.json();
    expect(body2.error).toBe("mfa_required");
    const mfa_token = body2.mfa_token ?? "";

    // authenticators
    let getRequest = new Request(`http://server.com/authenticators`, {
        method: "GET",
        headers: {
            'authorization': "Bearer " + mfa_token,
        },
        });
    event = new MockRequestEvent("1", getRequest, {});
    const resp3 = await authServer.mfaAuthenticatorsEndpoint.get(event);
    const body3 = await resp3.json();
    expect(Array.isArray(body3)).toBe(true);
    expect(body3.length).toBe(1);

    // challenge
    postRequest = new Request("http://ex.com/mfachallenge", {
        method: "POST",
        body: JSON.stringify({
            mfa_token: mfa_token,
            client_id : "ABC",
            client_secret: "DEF",
            authenticator_id: "dummyFactor2",
            challenge_type: "oob",
        }),
        headers: [
            ["content-type", "application/json"],
        ] 
    });
    event = new MockRequestEvent("1", postRequest, {});
    const resp4 = await authServer.mfaChallengeEndpoint.post(event);
    const body4 = await resp4.json();
    expect(body4.challenge_type).toBe("oob");
    expect(body4.oob_code).toBeDefined();
    const oob_code = body4.oob_code;
    const oob = "0000";

    // OOB
    postRequest = new Request("http://ex.com/token", {
        method: "POST",
        body: JSON.stringify({
            grant_type: "http://auth0.com/oauth/grant-type/mfa-oob",
            client_id : "ABC",
            scope: "read write",
            client_secret: "DEF",
            mfa_token: mfa_token,
            oob_code: oob_code,
            binding_code: oob
    }),
    headers: [
        ["content-type", "application/json"],
    ] 
});
    event = new MockRequestEvent("1", postRequest, {});
    const resp5 = await authServer.tokenEndpoint.post(event);
    const body5 = await resp5.json();
    expect(body5.access_token).toBeDefined();
    
});
