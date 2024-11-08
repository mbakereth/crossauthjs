// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { MockRequestEvent } from './sveltemocks';
import { CrossauthError, ErrorCode } from '@crossauth/common';
import {  makeServer, getAccessToken, oidcConfiguration, getCsrfToken } from './testshared';
import createFetchMock from 'vitest-fetch-mock';

let fetchMocker = createFetchMock(vi);
fetchMocker.enableMocks();

beforeAll(async () => {
    fetchMocker.doMock();
});

afterEach(async () => {
    vi.restoreAllMocks();
});

export async function oauthLogin (options = {}) {
    const {server, keyStorage, userStorage, clientStorage} = await makeServer(true, false, true, true, {tokenResponseType: "saveInSessionAndReturn", enableCsrfProtection: false, ...options});
    const {authServer} = await getAccessToken();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // @ts-ignore
    //fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, body: JSON.parse(request.body.toString())})});
    fetchMocker.mockResponseOnce(async (request) => {
        // call token with password flow
        const body = JSON.parse(request.body?.toString() ?? "{}");
        const firstTokenResponse = await authServer.tokenEndpoint({
            grantType: body.grant_type, 
            client_id : body.client_id, 
            scope : body.scope, 
            client_secret : body.client_secret,
            username: body.username,
            password: body.password,
        });
        return new Response(JSON.stringify(firstTokenResponse), {headers: {"content-type": "application/json"}});
    });

    // password flow post endpoint
    let postRequest = new Request(`http://server.com/passwordFlowFlow`, {
        method: "POST",
        body: JSON.stringify({
            scope: "read write",
            username: "bob",
            password: "bobPass123",
         }),
         headers: {"content-type": "application/json"},
    });
    let event = new MockRequestEvent("1", postRequest, {});
    if (server.oAuthClient == undefined) throw new Error("server.oAuthClient is undefined");
    const resp = await server.oAuthClient?.passwordFlowEndpoint.post(event);
    if (!resp || !(resp instanceof Response)) throw "Resp is not an object";
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.access_token).toBeDefined();
    expect(body.refresh_token).toBeDefined();
    const access_token = body.access_token;
    const refresh_token = body.refresh_token;

    let sessionCookieValue = event.cookies.get("SESSIONID");
    let sessionId = server.sessionServer?.sessionManager.getSessionId(sessionCookieValue??"");


    return {server, authServer, sessionCookieValue, sessionId, access_token, refresh_token, keyStorage, userStorage, clientStorage};
};

////////////////////////////////////////////////////////////////////////
// Tests

test('SvelteKitClient.authzcodeflowLoginNotNeeded_get', async () => {
    const {authServer} = await getAccessToken();

    const {server} = await makeServer(true, false, false, true);

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // authorizationCodeFlow get endpoint
    let getRequest = new Request(`http://server.com/authorizationCodeFlow?scope=read+write`, {
        method: "GET",
        });
    let event = new MockRequestEvent("1", getRequest, {});
    let location : string|undefined = undefined;
    try {
        await server.oAuthClient?.authorizationCodeFlowEndpoint.get(event);
    } catch (e : any) {
        expect(e.location).toBeDefined();
        location = e.location;
    }
    expect(location).toContain("http://server.com/authorize");
    const url = new URL(location??"");
    expect(url.searchParams.get("scope")).not.toBe(null);
    expect(url.searchParams.get("state")).not.toBe(null);
    expect(url.searchParams.get("redirect_uri")).not.toBe(null);
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("client_id")).toBe("ABC");
    
    const state = url.searchParams.get("state") ?? "";
    const scope = url.searchParams.get("scope") ?? "";
    const redirect_uri = url.searchParams.get("redirect_uri") ?? "";
    const {code, state: returnedState, error} = await authServer.authorizeGetEndpoint({
        responseType: "code", 
        client_id: "ABC", 
        redirect_uri: redirect_uri??"",
        scope: scope,
        state: state??""
    });
    expect(error).toBeUndefined();
    expect(returnedState).toBe(state);
    expect(code).toBeDefined();

});

test('SvelteKitClient.authzcodeflowLoginNotNeeded_load', async () => {
    const {server} = await makeServer(true, false, false, true, {tokenResponseType: "sendInPage"});

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // authorizationCodeFlow get endpoint
    let getRequest = new Request(`http://server.com/authorizationCodeFlow?scope=read+write`, {
        method: "GET",
        });
    let event = new MockRequestEvent("1", getRequest, {});
    let location : string|undefined = undefined;
    try {
        await server.oAuthClient?.authorizationCodeFlowEndpoint.load(event);
    } catch (e : any) {
        expect(e.location).toBeDefined();
        location = e.location;
    }
    expect(location).toContain("http://server.com/authorize");
    const url = new URL(location??"");
    expect(url.searchParams.get("scope")).not.toBe(null);
    expect(url.searchParams.get("state")).not.toBe(null);
    expect(url.searchParams.get("redirect_uri")).not.toBe(null);
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("client_id")).toBe("ABC");


});

test('SvelteKitClient.clientCredentials_post', async () => {
    const {authServer} = await getAccessToken();

    const {server} = await makeServer(true, false, false, true);

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, body: JSON.parse(request.body.toString())})});

    // clientCredentialsFlow post endpoint
    let postRequest = new Request(`http://server.com/clientCredentialsFlow`, {
        method: "POST",
        body: JSON.stringify({
            scope: "read write",
         }),
         headers: {"content-type": "application/json"},
    });
    let event = new MockRequestEvent("1", postRequest, {});
    const resp = await server.oAuthClient?.clientCredentialsFlowEndpoint.post(event);
    if (!(resp instanceof Response)) throw new CrossauthError(ErrorCode.Configuration, "Expected Response");
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.body.grant_type).toBe("client_credentials");
    expect(body.body.client_secret).toBe("DEF");

    const resp2 = await authServer.tokenEndpoint({
        grantType: body.body.grant_type, 
        client_id : body.body.client_id, 
        scope : body.body.scope, 
        client_secret : body.body.client_secret,
    });
    expect(resp2.error).toBeUndefined();
    expect(resp2.access_token).toBeDefined();

});

test('SvelteKitClient.clientCredentials_action', async () => {

    const {server} = await makeServer(true, false, false, true, {tokenResponseType: "sendInPage"});

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, body: JSON.parse(request.body.toString())})});

    // clientCredentialsFlow post endpoint
    let postRequest = new Request(`http://server.com/clientCredentialsFlow`, {
        method: "POST",
        body: JSON.stringify({
            scope: "read write",
         }),
        headers: {"content-type": "application/json"},
    });
    let event = new MockRequestEvent("1", postRequest, {});
    const resp = await server.oAuthClient?.clientCredentialsFlowEndpoint.actions.default(event);
    expect(typeof resp).toBe("object");
    if (typeof resp == "object") {
        const url = ("url" in resp)  ? resp.url : undefined;
        expect(url).toBe("http://server.com/token");
        const body : {[key:string]:any}= ("body" in resp)  ? (resp.body ?? {}) : {};
        expect(body.grant_type).toBe("client_credentials");
        expect(body.client_secret).toBe("DEF");
    }
});

test('SvelteKitClient.refreshTokenFlow_post', async () => {
    const {authServer, refresh_token} = await getAccessToken();

    const {server, resolver, handle} = await makeServer(true, false, false, true);

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, body: JSON.parse(request.body.toString())})});

    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);
    // clientCredentialsFlow post endpoint
    let postRequest = new Request(`http://server.com/refreshTokenFlow`, {
        method: "POST",
        body: JSON.stringify({
            refresh_token: refresh_token,
            csrfToken,
         }),
         headers: [
            ["cookie", "CSRFTOKEN="+csrfCookieValue],
            ["content-type", "application/json"],
        ] 
        });
    let event = new MockRequestEvent("1", postRequest, {});
    event.locals.csrfToken = csrfToken;
    if (!server.oAuthClient) throw new CrossauthError(ErrorCode.Configuration, "No auth client");
    const resp = await server.oAuthClient?.refreshTokenFlowEndpoint.post(event);
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.body.grant_type).toBe("refresh_token");
    expect(body.body.client_secret).toBe("DEF");

    const resp2 = await authServer.tokenEndpoint({
        grantType: body.body.grant_type, 
        client_id : body.body.client_id, 
        scope : body.body.scope, 
        client_secret : body.body.client_secret,
        refreshToken : refresh_token,
    });
    expect(resp2.error).toBeUndefined();
    expect(resp2.access_token).toBeDefined();

});

test('SvelteKitClient.refreshTokenFlow_action', async () => {
    const {refresh_token} = await getAccessToken();

    const {server, resolver, handle} = await makeServer(true, false, false, true, {tokenResponseType: "sendInPage"});
    const {csrfToken} = await getCsrfToken(server, resolver, handle);

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, body: JSON.parse(request.body.toString())})});

    // refresh token flow post endpoint
    let postRequest = new Request(`http://server.com/refreshTokenFlow`, {
        method: "POST",
        body: JSON.stringify({
            refresh_token: refresh_token,
         }),
         headers: {"content-type": "application/json"},
        });
    let event = new MockRequestEvent("1", postRequest, {});
    event.locals.csrfToken = csrfToken;
    if (!server.oAuthClient) throw new CrossauthError(ErrorCode.Configuration, "No auth client");
    const resp = await server.oAuthClient?.refreshTokenFlowEndpoint.actions.default(event);
    const url = ("url" in resp)  ? resp.url : undefined;
    expect(url).toBe("http://server.com/token");
    const body : {[key:string]:any}= ("body" in resp)  ? (resp.body ?? {}) : {};
    expect(body.grant_type).toBe("refresh_token");
    expect(body.client_secret).toBe("DEF");

});

test('SvelteKitClient.passwordFlow_post', async () => {
    const {authServer} = await getAccessToken();

    const {server} = await makeServer(true, false, false, true, {enableCsrfProtection: false});

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, body: JSON.parse(request.body.toString())})});

    // password flow post endpoint
    let postRequest = new Request(`http://server.com/passwordFlowFlow`, {
        method: "POST",
        body: JSON.stringify({
            scope: "read write",
            username: "bob",
            password: "bobPass123",
         }),
         headers: {"content-type": "application/json"},
    });
    let event = new MockRequestEvent("1", postRequest, {});
    if (server.oAuthClient == undefined) throw new Error("server.oAuthClient is undefined");
    const resp = await server.oAuthClient?.passwordFlowEndpoint.post(event);
    if (!resp || !(resp instanceof Response)) throw "Resp is not an object";
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.body.grant_type).toBe("password");
    expect(body.body.client_secret).toBe("DEF");

    const resp2 = await authServer.tokenEndpoint({
        grantType: body.body.grant_type, 
        client_id : body.body.client_id, 
        scope : body.body.scope, 
        client_secret : body.body.client_secret,
        username: body.body.username,
        password: body.body.password,
    });
    expect(resp2.error).toBeUndefined();
    expect(resp2.access_token).toBeDefined();

});

test('SvelteKitClient.passwordFlow_action', async () => {

    const {server} = await makeServer(true, false, false, true, {tokenResponseType: "sendInPage", enableCsrfProtection: false});

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, body: JSON.parse(request.body.toString())})});

    // password flow post endpoint
    let postRequest = new Request(`http://server.com/passwordFlowFlow`, {
        method: "POST",
        body: JSON.stringify({
            scope: "read write",
            username: "bob",
            password: "bobPass123",
         }),
         headers: {"content-type": "application/json"},
    });
    let event = new MockRequestEvent("1", postRequest, {});
    if (!server.oAuthClient) throw new CrossauthError(ErrorCode.Configuration, "No auth client");
    const resp = await server.oAuthClient?.passwordFlowEndpoint.actions.password(event);
    const url = ("url" in resp)  ? resp.url : undefined;
    expect(url).toBe("http://server.com/token");
    const body : {[key:string]:any}= ("body" in resp)  ? (resp.body ?? {}) : {};
    expect(body.grant_type).toBe("password");
    expect(body.client_secret).toBe("DEF");
    expect(body.username).toBe("bob");
    expect(body.password).toBe("bobPass123");

});

test('SvelteKitClient.passwordMfaFlow_post', async () => {
    const {authServer} = await getAccessToken();

    const {server} = await makeServer(true, false, false, true, {enableCsrfProtection: false});

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, body: JSON.parse(request.body.toString())})});

    // password flow post endpoint
    let postRequest = new Request(`http://server.com/passwordFlowFlow`, {
        method: "POST",
        body: JSON.stringify({
            scope: "read write",
            username: "alice",
            password: "alicePass123",
         }),
         headers: {"content-type": "application/json"},
    });
    let event = new MockRequestEvent("1", postRequest, {});
    if (server.oAuthClient == undefined) throw new Error("server.oAuthClient is undefined");
    const resp = await server.oAuthClient?.passwordFlowEndpoint.post(event);
    if (!resp || !(resp instanceof Response)) throw "Resp is not an object";
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.body.grant_type).toBe("password");
    expect(body.body.client_secret).toBe("DEF");

    // call token with password flow
    const firstTokenResponse = await authServer.tokenEndpoint({
        grantType: body.body.grant_type, 
        client_id : body.body.client_id, 
        scope : body.body.scope, 
        client_secret : body.body.client_secret,
        username: body.body.username,
        password: body.body.password,
    });
    expect(firstTokenResponse.error).toBe("mfa_required");
    expect(firstTokenResponse.mfa_token).toBeDefined();

    // call mfaAuthenticators to select factor2 method
    fetchMocker.mockResponseOnce((_req) => {
        return JSON.stringify(firstTokenResponse)});
    const authenticatorsResponse = 
        await authServer.mfaAuthenticatorsEndpoint(firstTokenResponse.mfa_token??"");
    expect(authenticatorsResponse.authenticators?.length).toBe(1);
    let authenticators = authenticatorsResponse.authenticators;
    if (!authenticators) throw Error("No authenticators returned");
    expect(authenticators[0].id).toBe("dummyFactor2");

    const challengeResponse = await authServer.mfaChallengeEndpoint(
        firstTokenResponse.mfa_token??"",
        "ABC",
        "DEF",
        "oob",
        "dummyFactor2",
    );
    expect(challengeResponse.challenge_type).toBe("oob");
    expect(challengeResponse.binding_method).toBe("prompt");
    expect(challengeResponse.oob_code).toBeDefined();
    fetchMocker.mockResponseOnce((_req) => {
        return JSON.stringify(authenticatorsResponse.authenticators)});
    fetchMocker.mockResponseOnce((_req) => {
        return JSON.stringify({
            challenge_type: "oob",
            oob_code: challengeResponse.oob_code,
            binding_method: "prompt"
        })});

    // password flow again.  This time it should trigger MFA completion
    postRequest = new Request(`http://server.com/passwordFlow`, {
        method: "POST",
        body: JSON.stringify({
            scope: "read write",
            username: "alice",
            password: "alicePass123",
         }),
         headers: {"content-type": "application/json"},
    });
    event = new MockRequestEvent("1", postRequest, {});
    if (server.oAuthClient == undefined) throw new Error("server.oAuthClient is undefined");
    const password2Resp = await server.oAuthClient?.passwordFlowEndpoint.post(event);
    if (!password2Resp || !(password2Resp instanceof Response)) throw "Resp is not an object";
    expect(password2Resp.status).toBe(200);
    const password2Body = await password2Resp.json();
    expect(password2Body.ok).toBe(true);
    expect(password2Body.challenge_type).toBe("oob");
    const oobCode = password2Body.oob_code;

    // Call passwordoob to completre MFA
    const {access_token, expires_in} =
    await authServer.tokenEndpoint({
        grantType: "http://auth0.com/oauth/grant-type/mfa-oob",
        client_id : "ABC",
        scope: "read write",
        client_secret: "DEF",
        mfaToken: firstTokenResponse.mfa_token,
        oobCode: oobCode,
        bindingCode: "0000",
    });
    expect(access_token).toBeDefined();
    expect(expires_in).toBeDefined();
});


test('SvelteKitClient.refreshIfExpired_post', async () => {

    // login using password flow
    const {authServer, refresh_token, server, sessionId, sessionCookieValue} = await oauthLogin();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // Refresh token flow
    // @ts-ignore
    //fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, body: JSON.parse(request.body.toString())})});
    fetchMocker.mockResponseOnce(async (request) => {
        // call token with refresj tolken flow 
        const body = JSON.parse(request.body?.toString() ?? "{}");
        const resp2 = await authServer.tokenEndpoint({
            grantType: body.grant_type, 
            client_id : body.client_id, 
            scope : body.scope, 
            client_secret : body.client_secret,
            refreshToken : refresh_token,
        });
        return new Response(JSON.stringify(resp2), {headers: {"content-type": "application/json"}});
    });
   // if (server.oAuthClient) server.oAuthClient["receiveTokenFn"] = receiveFn_post;

    // refresh token if expired post endpoint
    let postRequest = new Request(`http://server.com/refreshTokenIfExpired`, {
        method: "POST",
        body: JSON.stringify({
            refresh_token: refresh_token,
         }),
         headers: {"content-type": "application/json", "cookie": "SESSIONID="+sessionCookieValue},
        });
    let event = new MockRequestEvent("1", postRequest, {});
    event.locals.sessionId = sessionId;

    // expire token
    const oauthData = await server.sessionServer?.getSessionData(event, "oauth");
    expect(oauthData).toBeDefined();
    if (!oauthData) throw new Error("oauthData not defined");
    oauthData.expires_in = 0;
    oauthData.expires_at = Date.now() - 10000;
    await server.sessionServer?.updateSessionData(event, "oauth", oauthData);
    
    if (!server.oAuthClient) throw new CrossauthError(ErrorCode.Configuration, "No auth client");
    const resp = await server.oAuthClient?.refreshTokensIfExpiredEndpoint.post(event);
    expect(resp).toBeDefined();
    if (!resp || !(resp instanceof Response)) throw Error("Response undefined");
    const body = await resp.json();
    expect(body.access_token).toBeDefined();

});

test('SvelteKitClient.refreshIfNotExpired_post', async () => {

    // login using password flow
    const {authServer, refresh_token, server, sessionId, sessionCookieValue} = await oauthLogin();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // Refresh token flow
    // @ts-ignore
    //fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, body: JSON.parse(request.body.toString())})});
    fetchMocker.mockResponseOnce(async (request) => {
        // call token with refresj tolken flow 
        const body = JSON.parse(request.body?.toString() ?? "{}");
        const resp2 = await authServer.tokenEndpoint({
            grantType: body.grant_type, 
            client_id : body.client_id, 
            scope : body.scope, 
            client_secret : body.client_secret,
            refreshToken : refresh_token,
        });
        return new Response(JSON.stringify(resp2), {headers: {"content-type": "application/json"}});
    });
   // if (server.oAuthClient) server.oAuthClient["receiveTokenFn"] = receiveFn_post;

    // refresh token if expired post endpoint
    let postRequest = new Request(`http://server.com/refreshTokenIfExpired`, {
        method: "POST",
        body: JSON.stringify({
            refresh_token: refresh_token,
         }),
         headers: {"content-type": "application/json", "cookie": "SESSIONID="+sessionCookieValue},
        });
    let event = new MockRequestEvent("1", postRequest, {});
    event.locals.sessionId = sessionId;
    
    if (!server.oAuthClient) throw new CrossauthError(ErrorCode.Configuration, "No auth client");
    const resp = await server.oAuthClient?.refreshTokensIfExpiredEndpoint.post(event);
    expect(resp).toBeDefined();
    if (!resp || !(resp instanceof Response)) throw Error("Response unefined");
    const body = await resp.json();
    expect(body.access_token).toBeUndefined();
    expect(body.error).toBeUndefined();
});

test('SvelteKitClient.autoRefreshTokens_post', async () => {

    // login using password flow
    const {authServer, refresh_token, server, sessionId, sessionCookieValue} = await oauthLogin();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // Refresh token flow
    // @ts-ignore
    //fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, body: JSON.parse(request.body.toString())})});
    fetchMocker.mockResponseOnce(async (request) => {
        // call token with refresj tolken flow 
        const body = JSON.parse(request.body?.toString() ?? "{}");
        const resp2 = await authServer.tokenEndpoint({
            grantType: body.grant_type, 
            client_id : body.client_id, 
            scope : body.scope, 
            client_secret : body.client_secret,
            refreshToken : refresh_token,
        });
        return new Response(JSON.stringify(resp2), {headers: {"content-type": "application/json"}});
    });
   // if (server.oAuthClient) server.oAuthClient["receiveTokenFn"] = receiveFn_post;

    // refresh token if expired post endpoint
    let postRequest = new Request(`http://server.com/refreshTokenIfExpired`, {
        method: "POST",
        body: JSON.stringify({
            refresh_token: refresh_token,
         }),
         headers: {"content-type": "application/json", "cookie": "SESSIONID="+sessionCookieValue},
        });
    let event = new MockRequestEvent("1", postRequest, {});
    event.locals.sessionId = sessionId;
    
    if (!server.oAuthClient) throw new CrossauthError(ErrorCode.Configuration, "No auth client");
    const resp = await server.oAuthClient?.autoRefreshTokensEndpoint.post(event);
    //expect(typeof resp).not.toBe("object");
    //if (!resp || !(resp instanceof Response)) throw Error("Response is not an Response object");
    const body = await resp.json();
    expect(body?.expires_at).toBeDefined();

});

test('SvelteKitClient.bff_post', async () => {
    // login using password flow
    const {server, sessionId, sessionCookieValue} = await oauthLogin();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, method: request.method, body: JSON.parse(request.body.toString())})});

    // password flow post endpoint
    let postRequest = new Request(`http://server.com/bff/method`, {
        method: "POST",
        body: JSON.stringify({
            param1: 1,
            param2: "a&b"
         }),
         headers: {"content-type": "application/json", "cookie": "SESSIONID="+sessionCookieValue},
    });
    let event = new MockRequestEvent("1", postRequest, {});
    event.locals.sessionId = sessionId;
    if (server.oAuthClient == undefined) throw new Error("server.oAuthClient is undefined");
    const resp = await server.oAuthClient?.bff(event);
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.url).toBe("http://server.com/method");
    expect(body.method).toBe("POST");
    expect(body.body.param1).toBe(1);
    expect(body.body.param2).toBe("a&b");
});

test('SvelteKitClient.bff_get', async () => {
    // login using password flow
    const {server, sessionId, sessionCookieValue} = await oauthLogin();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, method: request.method, body: request.body? JSON.parse(request.body.toString()) : "{}"})});

    // password flow post endpoint
    let getRequest = new Request(`http://server.com/bff/method?param1=a&param2=a+b`, {
        method: "GET",
         headers: {"cookie": "SESSIONID="+sessionCookieValue},
    });
    let event = new MockRequestEvent("1", getRequest, {});
    event.locals.sessionId = sessionId;
    if (server.oAuthClient == undefined) throw new Error("server.oAuthClient is undefined");
    const resp = await server.oAuthClient?.bff(event);
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.url).toContain("http://server.com/method");
    expect(body.method).toBe("GET");
});

test('SvelteKitClient.bffEndpoint_post', async () => {
    // login using password flow
    const {server, sessionId, sessionCookieValue} = await oauthLogin();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, method: request.method, body: JSON.parse(request.body.toString())})});

    // password flow post endpoint
    let postRequest = new Request(`http://server.com/bff/method`, {
        method: "POST",
        body: JSON.stringify({
            param1: 1,
            param2: "a&b"
         }),
         headers: {"content-type": "application/json", "cookie": "SESSIONID="+sessionCookieValue},
    });
    let event = new MockRequestEvent("1", postRequest, {});
    event.locals.sessionId = sessionId;
    if (server.oAuthClient == undefined) throw new Error("server.oAuthClient is undefined");
    const resp = await server.oAuthClient?.bffEndpoint.post(event);
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.url).toBe("http://server.com/method");
    expect(body.method).toBe("POST");
    expect(body.body.param1).toBe(1);
    expect(body.body.param2).toBe("a&b");
});

test('SvelteKitClient.allBffEndpoint_get', async () => {
    // login using password flow
    const {server, sessionId, sessionCookieValue} = await oauthLogin();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, method: request.method, body: request.body? JSON.parse(request.body.toString()) : "{}"})});

    // password flow post endpoint
    let getRequest = new Request(`http://server.com/bff/method1?param1=a&param2=a+b`, {
        method: "GET",
         headers: {"cookie": "SESSIONID="+sessionCookieValue},
    });
    let event = new MockRequestEvent("1", getRequest, {});
    event.locals.sessionId = sessionId;
    if (server.oAuthClient == undefined) throw new Error("server.oAuthClient is undefined");
    const resp = await server.oAuthClient?.allBffEndpoint.get(event);
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.url).toContain("http://server.com/method1");
    expect(body.method).toBe("GET");
});

test('SvelteKitClient.allBffEndpoint_subget', async () => {
    // login using password flow
    const {server, sessionId, sessionCookieValue} = await oauthLogin();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, method: request.method, body: request.body? JSON.parse(request.body.toString()) : "{}"})});

    // password flow post endpoint
    let getRequest = new Request(`http://server.com/bff/method2/a?param1=a&param2=a+b`, {
        method: "GET",
         headers: {"cookie": "SESSIONID="+sessionCookieValue},
    });
    let event = new MockRequestEvent("1", getRequest, {});
    event.locals.sessionId = sessionId;
    if (server.oAuthClient == undefined) throw new Error("server.oAuthClient is undefined");
    const resp = await server.oAuthClient?.allBffEndpoint.get(event);
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.url).toContain("http://server.com/method2");
    expect(body.method).toBe("GET");
});

test('SvelteKitClient.allBffEndpoint_invalidget', async () => {
    // login using password flow
    const {server, sessionId, sessionCookieValue} = await oauthLogin();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, method: request.method, body: request.body? JSON.parse(request.body.toString()) : "{}"})});

    // password flow post endpoint
    let getRequest = new Request(`http://server.com/bff/method3?param1=a&param2=a+b`, {
        method: "GET",
         headers: {"cookie": "SESSIONID="+sessionCookieValue},
    });
    let event = new MockRequestEvent("1", getRequest, {});
    event.locals.sessionId = sessionId;
    if (server.oAuthClient == undefined) throw new Error("server.oAuthClient is undefined");
    const resp = await server.oAuthClient?.allBffEndpoint.get(event);
    expect(resp.status).toBe(401);
});

test('SvelteKitClient.accessToken', async () => {
    // login using password flow
    const {server, sessionId, sessionCookieValue} = await oauthLogin();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, method: request.method, body: request.body? JSON.parse(request.body.toString()) : "{}"})});

    // password flow post endpoint
    let getRequest = new Request(`http://server.com/accessToken`, {
        method: "GET",
         headers: {"cookie": "SESSIONID="+sessionCookieValue},
    });
    let event = new MockRequestEvent("1", getRequest, {});
    event.locals.sessionId = sessionId;
    if (server.oAuthClient == undefined) throw new Error("server.oAuthClient is undefined");
    const resp = await server.oAuthClient?.accessTokenEndpoint.post(event);
    expect(resp.status).toBe(200);
    const body = resp.body;
    expect(typeof(body) == "object" && body?.jti).toBeDefined();
});

test('SvelteKitClient.haveAccessToken', async () => {
    // login using password flow
    const {server, sessionId, sessionCookieValue} = await oauthLogin();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, method: request.method, body: request.body? JSON.parse(request.body.toString()) : "{}"})});

    // password flow post endpoint
    let getRequest = new Request(`http://server.com/haveAccessToken`, {
        method: "GET",
         headers: {"cookie": "SESSIONID="+sessionCookieValue},
    });
    let event = new MockRequestEvent("1", getRequest, {});
    event.locals.sessionId = sessionId;
    if (server.oAuthClient == undefined) throw new Error("server.oAuthClient is undefined");
    const resp = await server.oAuthClient?.haveAccessTokenEndpoint.post(event);
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
});

test('SvelteKitClient.refreshTokenNotAllowed', async () => {
    // login using password flow
    const {server, sessionId, sessionCookieValue} = await oauthLogin();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, method: request.method, body: request.body? JSON.parse(request.body.toString()) : "{}"})});

    // password flow post endpoint
    let getRequest = new Request(`http://server.com/accessToken`, {
        method: "GET",
         headers: {"cookie": "SESSIONID="+sessionCookieValue},
    });
    let event = new MockRequestEvent("1", getRequest, {});
    event.locals.sessionId = sessionId;
    if (server.oAuthClient == undefined) throw new Error("server.oAuthClient is undefined");
    const resp = await server.oAuthClient?.refreshTokenEndpoint.post(event);
    expect(resp.status).toBe(401);
    const body = await resp.json();
    expect(body.jti).toBeUndefined();
});

test('SvelteKitClient.dontHaveRefreshToken', async () => {
    // login using password flow
    const {server, sessionId, sessionCookieValue} = await oauthLogin();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, method: request.method, body: request.body? JSON.parse(request.body.toString()) : "{}"})});

    // password flow post endpoint
    let getRequest = new Request(`http://server.com/haveAccessToken`, {
        method: "GET",
         headers: {"cookie": "SESSIONID="+sessionCookieValue},
    });
    let event = new MockRequestEvent("1", getRequest, {});
    event.locals.sessionId = sessionId;
    if (server.oAuthClient == undefined) throw new Error("server.oAuthClient is undefined");
    const resp = await server.oAuthClient?.haveRefreshTokenEndpoint.post(event);
    expect(resp.status).toBe(401);
    const body = await resp.json();
    expect(body.ok).toBeUndefined();
});

test('SvelteKitClient.dontHaveIdToken', async () => {
    // login using password flow
    const {server, sessionId, sessionCookieValue} = await oauthLogin();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, method: request.method, body: request.body? JSON.parse(request.body.toString()) : "{}"})});

    // password flow post endpoint
    let getRequest = new Request(`http://server.com/haveAccessToken`, {
        method: "GET",
         headers: {"cookie": "SESSIONID="+sessionCookieValue},
    });
    let event = new MockRequestEvent("1", getRequest, {});
    event.locals.sessionId = sessionId;
    if (server.oAuthClient == undefined) throw new Error("server.oAuthClient is undefined");
    const resp = await server.oAuthClient?.haveIdTokenEndpoint.post(event);
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(false);
});

test('SvelteKitClient.idToken', async () => {
    // login using password flow
    const {server, sessionId, sessionCookieValue} = await oauthLogin();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, method: request.method, body: request.body? JSON.parse(request.body.toString()) : "{}"})});

    // password flow post endpoint
    let getRequest = new Request(`http://server.com/idToken`, {
        method: "GET",
         headers: {"cookie": "SESSIONID="+sessionCookieValue},
    });
    let event = new MockRequestEvent("1", getRequest, {});
    event.locals.sessionId = sessionId;
    if (server.oAuthClient == undefined) throw new Error("server.oAuthClient is undefined");
    const resp = await server.oAuthClient?.idTokenEndpoint.post(event);
    expect(resp.status).toBe(204);
});

test('SvelteKitClient.tokens', async () => {
    // login using password flow
    const {server, sessionId, sessionCookieValue} = await oauthLogin();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, method: request.method, body: request.body? JSON.parse(request.body.toString()) : "{}"})});

    // password flow post endpoint
    let getRequest = new Request(`http://server.com/tokens`, {
        method: "GET",
         headers: {"cookie": "SESSIONID="+sessionCookieValue},
    });
    let event = new MockRequestEvent("1", getRequest, {});
    event.locals.sessionId = sessionId;
    if (server.oAuthClient == undefined) throw new Error("server.oAuthClient is undefined");
    const resp = await server.oAuthClient?.tokensEndpoint.post(event);
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.access_token?.jti).toBeDefined();
    expect(body.have_access_token).toBe(true);
    expect(body.have_id_token).toBe(false);
    expect(body.id_token).toBeUndefined();
    expect(body.refresh_token).toBeUndefined();
    expect(body.have_refresh_token).toBeUndefined();
});

test('SvelteKitClient.deviceCodeFlow', async () => {
    // login using password flow
    const {server, sessionId, sessionCookieValue, clientStorage, userStorage} = await oauthLogin();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, method: request.method, body: request.body? JSON.parse(request.body.toString()) : "{}"})});

    // start device flow - device_authorization call
    let postRequest = new Request(`http://server.com/dummy`, {
        method: "POST",
        body: JSON.stringify({scope: "read write"}),
        headers: {"cookie": "SESSIONID="+sessionCookieValue,
            "content-type": "application/json",
        },
    });
    let event = new MockRequestEvent("1", postRequest, {});
    event.locals.sessionId = sessionId;
    if (server.oAuthClient == undefined) throw new Error("server.oAuthClient is undefined");
    let resp : {[key:string]:any} = await server.oAuthClient?.startDeviceCodeFlowEndpoint.actions.default(event);
    expect(resp.url).toBe("http://server.com/device_authorization");
    expect(resp.body.grant_type).toBe("urn:ietf:params:oauth:grant-type:device_code");
    expect(resp.body.client_id).toBe("ABC");
    expect(resp.body.client_secret).toBe("DEF");
    expect(resp.body.scope).toBe("read write");

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({error: "authorization_pending", error_description: "authorization pending"})});

    // poll receiving pending
    postRequest = new Request(`http://server.com/dummy`, {
        method: "POST",
        body: JSON.stringify({device_code: "ABC"}),
        headers: {"cookie": "SESSIONID="+sessionCookieValue,
            "content-type": "application/json",
        },
    });
    event = new MockRequestEvent("1", postRequest, {});
    event.locals.sessionId = sessionId;
    if (server.oAuthClient == undefined) throw new Error("server.oAuthClient is undefined");
    resp = await server.oAuthClient?.pollDeviceCodeFlowEndpoint.actions.default(event);
    expect(resp.error).toBe('authorization_pending');

    // poll receive access token

    const client = await clientStorage.getClientById("ABC");
    const user = await userStorage.getUserByUsername("bob");
    try {
        const tokens = await server.oAuthAuthServer?.authServer.makeAccessToken({
            client,
            client_secret: "DEF",
            scopes: ["read", "write"],
            user: user?.user,
        });
        // @ts-ignore
        fetchMocker.mockResponseOnce((request) => {return JSON.stringify(tokens)});    
    } catch (e) {
        console.log(e);
        process.exit();
    }

    // poll receiving pending
    postRequest = new Request(`http://server.com/dummy`, {
        method: "POST",
        body: JSON.stringify({device_code: "ABC"}),
        headers: {"cookie": "SESSIONID="+sessionCookieValue,
            "content-type": "application/json",
        },
    });
    event = new MockRequestEvent("1", postRequest, {});
    event.locals.sessionId = sessionId;
    if (server.oAuthClient == undefined) throw new Error("server.oAuthClient is undefined");
    resp = await server.oAuthClient?.pollDeviceCodeFlowEndpoint.actions.default(event);
    //expect(resp.error).toBe('authorization_pending');
    
});

test('SvelteKitClient.middleware', async () => {
    const {server, sessionId, sessionCookieValue} = await oauthLogin();

    if (server.oAuthClient && server.oAuthClient.hook) {
        server.oAuthClient["testMiddleware"] = true;

        // insert payload
        if (!server.sessionServer) throw new Error("No session server");
        const sessionManager = server.sessionServer["sessionManager"];
        let sessionData = await sessionManager.dataForSessionId(sessionId??"");
        sessionData.oauth.id_payload = {"sub": "bob"}
        await sessionManager.updateSessionData(sessionId??"", "oauth", sessionData["oauth"]);

        let getRequest = new Request(`http://server.com/passwordflow`, {
            method: "GET",
            headers: {"cookie": "SESSIONID="+sessionCookieValue,
                "content-type": "application/json",
            },
        });
        let event = new MockRequestEvent("1", getRequest, {});
        event.locals.sessionId = sessionId;
    
        await server.oAuthClient.hook({event})
        let locals = server.oAuthClient["testEvent"]?.locals;
        expect(locals?.user?.username).toBe("bob");
        expect(locals?.idTokenPayload?.sub).toBe("bob");
        expect(locals?.authType).toBe("oidc")
    }
});

test('SvelteKitClient.middlewareWithUserMerge', async () => {
    const {server, sessionId, sessionCookieValue} = await oauthLogin({userCreationType: "merge"});

    if (server.oAuthClient && server.oAuthClient.hook) {
        server.oAuthClient["testMiddleware"] = true;

        // insert payload
        if (!server.sessionServer) throw new Error("No session server");
        const sessionManager = server.sessionServer["sessionManager"];
        let sessionData = await sessionManager.dataForSessionId(sessionId??"");
        sessionData.oauth.id_payload = {"sub": "bob"}
        await sessionManager.updateSessionData(sessionId??"", "oauth", sessionData["oauth"]);

        let getRequest = new Request(`http://server.com/passwordflow`, {
            method: "GET",
            headers: {"cookie": "SESSIONID="+sessionCookieValue,
                "content-type": "application/json",
            },
        });
        let event = new MockRequestEvent("1", getRequest, {});
        event.locals.sessionId = sessionId;
    
        await server.oAuthClient.hook({event})
        let locals = server.oAuthClient["testEvent"]?.locals;
        expect(locals?.user?.username).toBe("bob");
        expect(locals?.user?.factor1).toBe("localpassword");
        expect(locals?.user?.sub).toBe("bob");
        expect(locals?.idTokenPayload?.sub).toBe("bob");
        expect(locals?.authType).toBe("oidc")
    }
});

test('SvelteKitClient.middlewareWithUserEmbed', async () => {
    const {server, sessionId, sessionCookieValue} = await oauthLogin({userCreationType: "embed"});

    if (server.oAuthClient && server.oAuthClient.hook) {
        server.oAuthClient["testMiddleware"] = true;

        // insert payload
        if (!server.sessionServer) throw new Error("No session server");
        const sessionManager = server.sessionServer["sessionManager"];
        let sessionData = await sessionManager.dataForSessionId(sessionId??"");
        sessionData.oauth.id_payload = {"sub": "bob"}
        await sessionManager.updateSessionData(sessionId??"", "oauth", sessionData["oauth"]);

        let getRequest = new Request(`http://server.com/passwordflow`, {
            method: "GET",
            headers: {"cookie": "SESSIONID="+sessionCookieValue,
                "content-type": "application/json",
            },
        });
        let event = new MockRequestEvent("1", getRequest, {});
        event.locals.sessionId = sessionId;
    
        await server.oAuthClient.hook({event})
        let locals = server.oAuthClient["testEvent"]?.locals;
        expect(locals?.user?.username).toBe("bob");
        expect(locals?.user?.factor1).toBe("localpassword");
        expect(locals?.user?.idToken?.sub).toBe("bob");
        expect(locals?.idTokenPayload?.sub).toBe("bob");
        expect(locals?.authType).toBe("oidc")
    }
});

test('SvelteKitClient.middlewareWithUserMergeNoUser', async () => {
    const {server, sessionId, sessionCookieValue} = await oauthLogin({userCreationType: "merge"});

    if (server.oAuthClient && server.oAuthClient.hook) {
        server.oAuthClient["testMiddleware"] = true;

        // insert payload
        if (!server.sessionServer) throw new Error("No session server");
        const sessionManager = server.sessionServer["sessionManager"];
        let sessionData = await sessionManager.dataForSessionId(sessionId??"");
        sessionData.oauth.id_payload = {"sub": "bob1"}
        await sessionManager.updateSessionData(sessionId??"", "oauth", sessionData["oauth"]);

        let getRequest = new Request(`http://server.com/passwordflow`, {
            method: "GET",
            headers: {"cookie": "SESSIONID="+sessionCookieValue,
                "content-type": "application/json",
            },
        });
        let event = new MockRequestEvent("1", getRequest, {});
        event.locals.sessionId = sessionId;
    
        await server.oAuthClient.hook({event})
        let locals = server.oAuthClient["testEvent"]?.locals;
        expect(locals?.user).toBeUndefined();
        expect(locals?.authType).toBeUndefined();
    }
});
