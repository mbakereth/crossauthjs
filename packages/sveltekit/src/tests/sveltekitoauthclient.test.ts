import { MockRequestEvent } from './sveltemocks';
import createFetchMock from 'vitest-fetch-mock';
import { type OpenIdConfiguration, type OAuthTokenResponse, CrossauthError, ErrorCode } from '@crossauth/common';
import {  makeServer, getCsrfToken, login, getAuthServer, getAccessToken } from './testshared';

const fetchMocker = createFetchMock(vi);
fetchMocker.enableMocks();

const oidcConfiguration : OpenIdConfiguration = {
    issuer: "http://server.com",
    authorization_endpoint: "http://server.com/authorize",
    token_endpoint: "http://server.com/token",
    token_endpoint_auth_methods_supported: ["client_secret_post"],
    jwks_uri: "http://server.com/jwks",
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "client_credentials", "password", "refresh_token", "http://auth0.com/oauth/grant-type/mfa-otp", "http://auth0.com/oauth/grant-type/mfa-oob"],
    token_endpoint_auth_signing_alg_values_supported: ["RS256"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    claims_supported: ["iss", "sub", "aud", "jti", "iat", "type"],
    request_uri_parameter_supported: true,
    require_request_uri_registration: true,
}

function get(name : string, url : string){
    let names : RegExpExecArray|null;
    if(names=(new RegExp('[?&]'+encodeURIComponent(name)+'=([^&]*)')).exec(url))
       return decodeURIComponent(names[1]);
}

function getSession(res: any) : string {
    const sessionCookies = res.cookies.filter((cookie: any) => {return cookie.name == "SESSIONID"});
    expect(sessionCookies.length).toBe(1);
    return sessionCookies[0].value;
}

beforeAll(async () => {
    fetchMocker.doMock();
});

function getCsrf(res: any) : {csrfCookie: string, csrfToken: string} {
    const body = JSON.parse(res.body)
    const csrfCookies = res.cookies.filter((cookie: any) => {return cookie.name == "CSRFTOKEN"});
    expect(csrfCookies.length).toBe(1);
    const csrfCookie = csrfCookies[0].value;
    const csrfToken = body.args.csrfToken;
    expect(csrfToken).toBeDefined();
    return {csrfCookie, csrfToken};
}

/*
async function getAccessTokenThroughClient(clientParams : {[key:string]:any}) {
    const {authServer} = await getAuthServer();

    const {server, keyStorage} = await makeServer(true, false, false, true, clientParams);

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    let res;
    let body;

    // get csrf token and check password flow get 
    res = await server.app.inject({ method: "GET", url: "/passwordflow" })
    body = JSON.parse(res.body);
    expect(body.template).toBe("passwordflow.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);
    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    const resp = await authServer.tokenEndpoint({
        grantType: "password", 
        clientId : "ABC", 
        scope : "read write", 
        clientSecret : "DEF",
        username: "bob",
        password: "bobPass123",
    });
    const access_token = resp.access_token;
    const refresh_token = resp.refresh_token;

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({access_token: access_token, refresh_token: refresh_token, expires_in: 60_000})});
    res = await server.app.inject({ method: "POST", url: "/passwordflow", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        csrfToken: csrfToken,
        scope: "read write",
        username: "bob",
        password: "bobPass123",
     }});
    const sessionCookie = getSession(res);


    return {server, keyStorage: keyStorage, access_token, sessionCookie, authServer, refresh_token}
}
*/

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
        clientId: "ABC", 
        redirectUri: redirect_uri??"",
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
        const resp = await server.oAuthClient?.authorizationCodeFlowEndpoint.load(event);
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
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.success).toBe(true);
    expect(body.body.grant_type).toBe("client_credentials");
    expect(body.body.client_secret).toBe("DEF");

    const resp2 = await authServer.tokenEndpoint({
        grantType: body.body.grant_type, 
        clientId : body.body.client_id, 
        scope : body.body.scope, 
        clientSecret : body.body.client_secret,
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

    const {server} = await makeServer(true, false, false, true);

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, body: JSON.parse(request.body.toString())})});

    // clientCredentialsFlow post endpoint
    let postRequest = new Request(`http://server.com/refreshTokenFlow`, {
        method: "POST",
        body: JSON.stringify({
            refresh_token: refresh_token,
         }),
         headers: {"content-type": "application/json"},
        });
    let event = new MockRequestEvent("1", postRequest, {});
    if (!server.oAuthClient) throw new CrossauthError(ErrorCode.Configuration, "No auth client");
    const resp = await server.oAuthClient?.refreshTokenFlowEndpoint.post(event);
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.success).toBe(true);
    expect(body.body.grant_type).toBe("refresh_token");
    expect(body.body.client_secret).toBe("DEF");

    const resp2 = await authServer.tokenEndpoint({
        grantType: body.body.grant_type, 
        clientId : body.body.client_id, 
        scope : body.body.scope, 
        clientSecret : body.body.client_secret,
        refreshToken : refresh_token,
    });
    expect(resp2.error).toBeUndefined();
    expect(resp2.access_token).toBeDefined();

});

test('SvelteKitClient.refreshTokenFlow_action', async () => {
    const {authServer, refresh_token} = await getAccessToken();

    const {server} = await makeServer(true, false, false, true, {tokenResponseType: "sendInPage"});

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, body: JSON.parse(request.body.toString())})});

    // clientCredentialsFlow post endpoint
    let postRequest = new Request(`http://server.com/refreshTokenFlow`, {
        method: "POST",
        body: JSON.stringify({
            refresh_token: refresh_token,
         }),
         headers: {"content-type": "application/json"},
        });
    let event = new MockRequestEvent("1", postRequest, {});
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

    const {server} = await makeServer(true, false, false, true);

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
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.success).toBe(true);
    expect(body.body.grant_type).toBe("password");
    expect(body.body.client_secret).toBe("DEF");

    const resp2 = await authServer.tokenEndpoint({
        grantType: body.body.grant_type, 
        clientId : body.body.client_id, 
        scope : body.body.scope, 
        clientSecret : body.body.client_secret,
        username: body.body.username,
        password: body.body.password,
    });
    expect(resp2.error).toBeUndefined();
    expect(resp2.access_token).toBeDefined();

});

test('SvelteKitClient.passwordFlow_action', async () => {

    const {server} = await makeServer(true, false, false, true, {tokenResponseType: "sendInPage"});

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
    const resp = await server.oAuthClient?.passwordFlowEndpoint.actions.default(event);
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

    const {server} = await makeServer(true, false, false, true);

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
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.success).toBe(true);
    expect(body.body.grant_type).toBe("password");
    expect(body.body.client_secret).toBe("DEF");

    // call token with password flow
    const firstTokenResponse = await authServer.tokenEndpoint({
        grantType: body.body.grant_type, 
        clientId : body.body.client_id, 
        scope : body.body.scope, 
        clientSecret : body.body.client_secret,
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
    expect(password2Resp.status).toBe(200);
    const password2Body = await password2Resp.json();
    expect(password2Body.success).toBe(true);
    expect(password2Body.challenge_type).toBe("oob");
    const oobCode = password2Body.oob_code;

    // Call passwordoob to completre MFA
    const {access_token, scope, error: error4, expires_in} =
    await authServer.tokenEndpoint({
        grantType: "http://auth0.com/oauth/grant-type/mfa-oob",
        clientId : "ABC",
        scope: "read write",
        clientSecret: "DEF",
        mfaToken: firstTokenResponse.mfa_token,
        oobCode: oobCode,
        bindingCode: "0000",
    });
    expect(access_token).toBeDefined();
    expect(expires_in).toBeDefined();

    /*
    expect(resp2.error).toBeUndefined();
    expect(resp2.access_token).toBeDefined();*/

});
