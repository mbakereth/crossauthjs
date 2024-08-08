import { MockRequestEvent } from './sveltemocks';
import createFetchMock from 'vitest-fetch-mock';
import { type OpenIdConfiguration, type OAuthTokenResponse } from '@crossauth/common';
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
    grant_types_supported: ["authorization_code", "client_credentials", "password", "refresh_token"],
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

test('FastifyOAuthClient.authzcodeflowLoginNotNeeded_get', async () => {
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

test('FastifyOAuthClient.authzcodeflowLoginNotNeeded_load', async () => {
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
