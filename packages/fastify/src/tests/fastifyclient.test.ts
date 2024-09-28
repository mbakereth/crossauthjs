// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import createFetchMock from 'vitest-fetch-mock';
import { test, expect, beforeAll, afterAll, vi } from 'vitest';
import { FastifyServer, type FastifyServerOptions } from '../fastifyserver';
import fastify, { type FastifyRequest, type FastifyReply } from 'fastify';
import { type OpenIdConfiguration, type OAuthTokenResponse } from '@crossauth/common';
import { getAccessToken, getAuthServer } from './oauthcommon';
import { getTestUserStorage } from './inmemorytestdata';
import { InMemoryKeyStorage, LocalPasswordAuthenticator, KeyStorage } from '@crossauth/backend';
import { FastifyOAuthClient, } from '..';

import path from 'path';

export const CSRFHEADER = "X-CROSSAUTH-CSRF";

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
    grant_types_supported: ["authorization_code", "client_credentials", "password", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"],
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

async function makeClient(options : FastifyServerOptions = {}) : Promise<{server: FastifyServer, keyStorage: KeyStorage}> {
    //const app = fastify({logger: {level: 'debug'}});
    const app = fastify({logger: false});

    // @ts-ignore
    app.decorateReply("view",  function(template, args) {
        return {template: template, args: args};
    });
    
    const userStorage = await getTestUserStorage();
    const keyStorage = new InMemoryKeyStorage();
    let lpAuthenticator = new LocalPasswordAuthenticator(userStorage);
    return {server: new FastifyServer({
        session: {
            keyStorage: keyStorage,
        },
        oAuthClient: {
            authServerBaseUrl: "http://server.com",
        }}, {
        userStorage,
        authenticators: {
            localpassword: lpAuthenticator,
        },
        app: app,
        views: path.join(__dirname, '../views'),
        allowedFactor2: ["none"],
        enableEmailVerification: false,
        siteUrl: `http://localhost:3000`,
        client_id: "ABC",
        client_secret: "DEF",
        validFlows: ["all"], // activate all OAuth flows
        tokenResponseType: "sendJson",
        errorResponseType: "sendJson",
        secret: "ABC",
        ...options,
    }), keyStorage: keyStorage};
}

async function getAccessTokenThroughClient(clientParams : {[key:string]:any}) {
    const {authServer} = await getAuthServer();

    const {server, keyStorage} = await makeClient(clientParams);

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
        client_id : "ABC", 
        scope : "read write", 
        client_secret : "DEF",
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

////////////////////////////////////////////////////////////////////////
// Tests

test('FastifyOAuthClient.authzcodeflowLoginNotNeeded', async () => {
    const {authServer} = await getAccessToken();

    const {server} = await makeClient();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    let res;

    res = await server.app.inject({ method: "GET", url: "/authzcodeflow?scope=read+write" });
    const authUrl = res.headers?.location;
    expect(authUrl).toBeDefined();
    const state = get("state", authUrl??"");
    const response_type = get("response_type", authUrl??"");
    const client_id = get("client_id", authUrl??"");
    const redirect_uri = get("redirect_uri", authUrl??"");
    const scope = get("scope", authUrl??"");
    expect(state).toBeDefined();
    expect(state?.length).toBeGreaterThan(0);
    expect(response_type).toBe("code");
    expect(client_id).toBe("ABC");

    const {code, state: returnedState, error} = await authServer.authorizeGetEndpoint({
        responseType: response_type??"", 
        client_id: client_id??"", 
        redirect_uri: redirect_uri??"",
        scope: scope,
        state: state??""
    });
    expect(error).toBeUndefined();
    expect(returnedState).toBe(state);
    expect(code).toBeDefined();
});


test('FastifyOAuthClient.authzcodeflowWithLoginRedirects', async () => {
    await getAccessToken();

    const {server} = await makeClient({
        loginProtectedFlows: ["all"],
        loginUrl: "/login",
    });

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    let res;

    res = await server.app.inject({ method: "GET", url: "/authzcodeflow?scope=read+write" });
    expect(res.headers?.location).toBe("/login?next=%2Fauthzcodeflow%3Fscope%3Dread%2Bwrite")
});

test('FastifyOAuthClient.clientCredentialsFlow', async () => {
    const {authServer} = await getAuthServer();

    const {server} = await makeClient();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    let res;
    let body;

    // get csrf token
    res = await server.app.inject({ method: "GET", url: "/login" })
    body = JSON.parse(res.body)
    expect(body.template).toBe("login.njk");
    const {csrfCookie, csrfToken} = await getCsrf(res);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({url: request.url, body: JSON.parse(request.body.toString())})});
    res = await server.app.inject({ method: "POST", url: "/clientcredflow", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        csrfToken: csrfToken,
        scope: "read write",
     }});
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
    expect(body.body.grant_type).toBe("client_credentials");
    expect(body.body.client_id).toBe("ABC");
    expect(body.body.client_secret).toBe("DEF");
    expect(body.body.scope).toBe("read write");

    const resp = await authServer.tokenEndpoint({
        grantType: body.body.grant_type, 
        client_id : body.body.client_id, 
        scope : body.body.scope, 
        client_secret : body.body.client_secret,
    });
    expect(resp.error).toBeUndefined();
    expect(resp.access_token).toBeDefined();
});

test('FastifyOAuthClient.passwordFlow', async () => {
    const {authServer} = await getAuthServer();

    const {server} = await makeClient();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    let res;
    let body;

    // get csrf token and check password flow get 
    res = await server.app.inject({ method: "GET", url: "/passwordflow" })
    body = JSON.parse(res.body);
    expect(body.template).toBe("passwordflow.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => JSON.stringify({url: request.url, body: JSON.parse(request.body.toString())}));
    res = await server.app.inject({ method: "POST", url: "/passwordflow", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        csrfToken: csrfToken,
        scope: "read write",
        username: "bob",
        password: "bobPass123",
     }});
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
    expect(body.body.grant_type).toBe("password");
    expect(body.body.client_id).toBe("ABC");
    expect(body.body.client_secret).toBe("DEF");
    expect(body.body.scope).toBe("read write");
    expect(body.body.username).toBe("bob");
    expect(body.body.password).toBe("bobPass123");

    const resp = await authServer.tokenEndpoint({
        grantType: body.body.grant_type, 
        client_id : body.body.client_id, 
        scope : body.body.scope, 
        client_secret : body.body.client_secret,
        username: body.body.username,
        password: body.body.password,
    });
    expect(resp.error).toBeUndefined();
    expect(resp.access_token).toBeDefined();
});

afterAll(async () => {
    fetchMocker.dontMock();
});

test('FastifyOAuthClient.refreshToken', async () => {
    const {authServer, access_token, refresh_token} = await getAccessToken();
    expect(access_token).toBeDefined();

    const resp = await authServer.tokenEndpoint({
        grantType: "refresh_token", 
        client_id : "ABC", 
        client_secret : "DEF",
        refreshToken: refresh_token,
    });
    expect(resp.error).toBeUndefined();
    expect(resp.access_token).toBeDefined();
});

async function receiveFn(_oauthResponse : OAuthTokenResponse, _client: FastifyOAuthClient, _request : FastifyRequest, reply? : FastifyReply) : Promise<FastifyReply|undefined> {
    return reply;
}

test('FastifyOAuthClient.refreshIfExpiredIsExpired', async () => {
    const {access_token, refresh_token} = await getAccessToken();
    expect(access_token).toBeDefined();

    const {server} = await makeClient();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    fetchMocker.mockResponseOnce((request) => JSON.stringify({url: request.url, expires_in: 60_000, access_token: JSON.parse(request.body?.toString()??"{}")}));
    if (server.oAuthClient) server.oAuthClient["receiveTokenFn"] = receiveFn;
    // @ts-ignore
    let res = await server.oAuthClient?.refresh(null, null, true, true, refresh_token, Date.now()-10000);
    expect(res?.access_token).toBeDefined();
});

test('FastifyOAuthClient.refreshIfExpiredIsNotExpired', async () => {
    const {access_token, refresh_token, expires_in} = await getAccessToken();
    expect(access_token).toBeDefined();

    const {server} = await makeClient();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    //fetchMocker.mockResponseOnce((request) => JSON.stringify({url: request.url, access_token: JSON.parse(request.body?.toString()??"{}")}));
    if (server.oAuthClient) server.oAuthClient["receiveTokenFn"] = receiveFn;
    // @ts-ignore
    let res = await server.oAuthClient?.refresh(null, null, true, true, refresh_token, Date.now()+expires_in);
    expect(res?.access_token).toBeUndefined();
});


test('FastifyOAuthClient.refreshFlowEndpoint', async () => { 
    const { server, access_token, refresh_token, sessionCookie, authServer } = await getAccessTokenThroughClient({
        tokenResponseType: "saveInSessionAndLoad",
        bffBaseUrl: "http://res.com",
        bffEndpoints: [{ url: "/test", methods: ["GET"],
        tokenResponseType: "saveInSessionAndRedirect" }],

    });
    expect(access_token).toBeDefined();
    //if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    let res;
    let body;

    // get the csrf token
    res = await server.app.inject({ method: "GET", url: "/passwordflow" })
    body = JSON.parse(res.body);
    expect(body.template).toBe("passwordflow.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);

    const resp = await authServer.tokenEndpoint({
        grantType: "refresh_token", 
        client_id : "ABC", 
        scope : "read write", 
        client_secret : "DEF",
        refreshToken: refresh_token,
    });
    const access_token2 = resp.access_token;
    const refresh_token2 = resp.refresh_token;

    
    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => {return JSON.stringify({access_token: access_token2, refresh_token: refresh_token2})});
    res = await server.app.inject({ method: "POST", url: "/refreshtokenflow", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        csrfToken: csrfToken,
     }});
    body = JSON.parse(res.body);
    expect(body.template).toBe("authorized.njk")
    expect(body.args.access_token).toBeDefined();
    expect(body.args.refresh_token).toBeDefined();

});

test('FastifyOAuthClient.refreshIfExpiredEndpoint_Interactive', async () => { 
    const { server, access_token, refresh_token, sessionCookie, authServer } = await getAccessTokenThroughClient({
        tokenResponseType: "saveInSessionAndLoad",
        bffBaseUrl: "http://res.com",
        bffEndpoints: [{ url: "/test", methods: ["GET"],
        tokenResponseType: "saveInSessionAndRedirect" }],

    });

    expect(access_token).toBeDefined();
    //if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    let res;
    let body;

    // get the csrf token
    res = await server.app.inject({ method: "GET", url: "/passwordflow" })
    body = JSON.parse(res.body);
    expect(body.template).toBe("passwordflow.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);

    // @ts-ignore
    //fetchMocker.mockResponseOnce((request) => {return JSON.stringify({access_token: access_token2, refresh_token: refresh_token2})});
    res = await server.app.inject({ method: "POST", url: "/refreshtokensifexpired", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        csrfToken: csrfToken,
     }});
    body = JSON.parse(res.body);
    expect(body.template).toBe("authorized.njk");

    const resp = await authServer.tokenEndpoint({
        grantType: "refresh_token", 
        client_id : "ABC", 
        scope : "read write", 
        client_secret : "DEF",
        refreshToken: refresh_token,
    });
    const access_token2 = resp.access_token;
    const refresh_token2 = resp.refresh_token;
    

    // expire token
    if (!server.sessionServer) throw new Error("No session server");
    const sessionManager = server.sessionServer["sessionManager"];
    const sessionId = sessionManager.getSessionId(sessionCookie);
    let sessionData = await sessionManager.dataForSessionId(sessionId);
    sessionData.oauth.expires_at = Date.now() - 1000;
    await sessionManager.updateSessionData(sessionId, "oauth", sessionData.oauth)
    fetchMocker.mockResponseOnce((_request) => {return JSON.stringify({expires_in: 60_000, access_token: access_token2, refresh_token: refresh_token2})});
    res = await server.app.inject({ method: "POST", url: "/refreshtokensifexpired", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        csrfToken: csrfToken,
     }});
    body = JSON.parse(res.body);
    expect(body.args.access_token).toBe(access_token2);

});

test('FastifyOAuthClient.refreshIfExpiredEndpoint_NonInteractive', async () => { 
    const { server, access_token, refresh_token, sessionCookie, authServer } = await getAccessTokenThroughClient({
        tokenResponseType: "saveInSessionAndLoad",
        bffBaseUrl: "http://res.com",
        bffEndpoints: [{ url: "/test", methods: ["GET"],
        tokenResponseType: "saveInSessionAndRedirect" }],

    });

    expect(access_token).toBeDefined();
    //if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    let res;
    let body;

    // get the csrf token
    res = await server.app.inject({ method: "GET", url: "/passwordflow" })
    body = JSON.parse(res.body);
    expect(body.template).toBe("passwordflow.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);

    // @ts-ignore
    //fetchMocker.mockResponseOnce((request) => {return JSON.stringify({access_token: access_token2, refresh_token: refresh_token2})});
    res = await server.app.inject({ method: "POST", url: "/api/refreshtokensifexpired", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        csrfToken: csrfToken,
     }});
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);

    const resp = await authServer.tokenEndpoint({
        grantType: "refresh_token", 
        client_id : "ABC", 
        scope : "read write", 
        client_secret : "DEF",
        refreshToken: refresh_token,
    });
    const access_token2 = resp.access_token;
    const refresh_token2 = resp.refresh_token;
    

    // expire token
    if (!server.sessionServer) throw new Error("No session server");
    const sessionManager = server.sessionServer["sessionManager"];
    const sessionId = sessionManager.getSessionId(sessionCookie);
    let sessionData = await sessionManager.dataForSessionId(sessionId);
    sessionData.oauth.expires_at = Date.now() - 1000;
    await sessionManager.updateSessionData(sessionId, "oauth", sessionData.oauth)
    fetchMocker.mockResponseOnce((_request) => {return JSON.stringify({access_token: access_token2, refresh_token: refresh_token2})});
    res = await server.app.inject({ method: "POST", url: "/api/refreshtokensifexpired", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        csrfToken: csrfToken,
     }});
    body = JSON.parse(res.body);
    //expect(body.args.access_token).toBe(access_token2);
    expect(body.ok).toBe(true);
    sessionData = await sessionManager.dataForSessionId(sessionId);
    expect(sessionData.oauth.access_token).toBe(access_token2)

});

test('FastifyOAuthClient.bffGet', async () => {

    const {server, access_token, sessionCookie} = await getAccessTokenThroughClient({tokenResponseType: "saveInSessionAndLoad", bffBaseUrl: "http://res.com", bffEndpoints: [{url: "/test", methods: ["GET"]}]});

    let res;
    let body;

    fetchMocker.mockResponseOnce((req) => {return JSON.stringify({ok: true, authHeader: req.headers.get("Authorization") })});
    res = await server.app.inject({ method: "GET", url: "/bff/test", cookies: {SESSIONID: sessionCookie} });
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
    expect(body.authHeader).toBe("Bearer " + access_token);
});

test('FastifyOAuthClient.bffGetWithQueryParams', async () => {

    const {server, access_token, sessionCookie} = await getAccessTokenThroughClient({tokenResponseType: "saveInSessionAndLoad", bffBaseUrl: "http://res.com", bffEndpoints: [{url: "/test", methods: ["GET"]}]});

    let res;
    let body;

    fetchMocker.mockResponseOnce((req) => {return JSON.stringify({ok: true, url: req.url, authHeader: req.headers.get("Authorization") })});
    res = await server.app.inject({ method: "GET", url: "/bff/test?a=1&b=2", cookies: {SESSIONID: sessionCookie} });
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
    expect(body.authHeader).toBe("Bearer " + access_token);
    expect(body.url).toBe("http://res.com/test?a=1&b=2")
});

test('FastifyOAuthClient.bffPost', async () => {

    const {server, access_token, sessionCookie} = await getAccessTokenThroughClient({tokenResponseType: "saveInSessionAndLoad", bffBaseUrl: "http://res.com", bffEndpoints: [{url: "/test", methods: ["POST"]}]});

    let res;
    let body;

    // get the csrf token
    res = await server.app.inject({ method: "GET", url: "/passwordflow" })
    body = JSON.parse(res.body);
    expect(body.template).toBe("passwordflow.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);

    fetchMocker.mockResponseOnce((req) => {return JSON.stringify({ok: true, url: req.url, authHeader: req.headers.get("Authorization"), body: req.body?.toString()??"{}" })});
    let headers : {[key:string]:string}= {};
    headers[CSRFHEADER] = csrfToken;
    res = await server.app.inject({ 
        method: "POST", url: "/bff/test", 
        cookies: {SESSIONID: sessionCookie, CSRFTOKEN: csrfCookie}, 
        headers: headers,
        payload: {param: "value"} });
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
    expect(body.authHeader).toBe("Bearer " + access_token);
    const requestBody = JSON.parse(body.body);
    expect(requestBody.param).toBe("value");
});

test('FastifyOAuthClient.deviceCodeFlow', async () => {
    const {authServer} = await getAuthServer();

    const {server} = await makeClient();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    let res;
    let body;

    // get csrf token 
    res = await server.app.inject({ method: "GET", url: "/passwordflow" })
    body = JSON.parse(res.body);
    const {csrfCookie, csrfToken} = getCsrf(res);
    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);
    
    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => JSON.stringify({url: request.url, body: JSON.parse(request.body.toString())}));

    // start device flow
    res = await server.app.inject({ method: "POST", 
        url: "/devicecodeflow",
        payload: {
            csrfToken,
            scope: "read write",
        },
        cookies: {CSRFTOKEN: csrfCookie}, 
      });
    body = JSON.parse(res.body);
    expect(body.template).toBe("devicecodeflow.njk");
    expect(body.args.body.grant_type).toBe("urn:ietf:params:oauth:grant-type:device_code");
    expect(body.args.body.client_id).toBe("ABC");
    expect(body.args.body.client_secret).toBe("DEF");
    expect(body.args.body.scope).toBe("read write");


    const authResp = await authServer.deviceAuthorizationEndpoint({client_id: "ABC", scope: "read write", client_secret: "DEF"});
    expect(authResp.device_code).toBeDefined();
    expect(authResp.user_code).toBeDefined();

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => JSON.stringify({url: request.url, body: JSON.parse(request.body.toString())}));

    // poll device flow
    res = await server.app.inject({ method: "POST", 
        url: "/devicecodepoll",
        payload: {
            csrfToken,
            device_code: authResp.device_code,
        },
        cookies: {CSRFTOKEN: csrfCookie}, 
      });
    body = JSON.parse(res.body);
    expect(body.url).toBe("http://server.com/token");
    expect(body.body.grant_type).toBe("urn:ietf:params:oauth:grant-type:device_code");
    expect(body.body.client_id).toBe("ABC");
    expect(body.body.client_secret).toBe("DEF");
    expect(body.body.device_code).toBe(authResp.device_code);
});

test('FastifyOAuthClient.middleware', async () => { 
    const { server, access_token, sessionCookie } = await getAccessTokenThroughClient({
        tokenResponseType: "saveInSessionAndLoad",
        bffBaseUrl: "http://res.com",
        bffEndpoints: [{ url: "/test", methods: ["GET"],
        tokenResponseType: "saveInSessionAndRedirect" }],

    });

    expect(access_token).toBeDefined();
    //if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    let res;
    let body;

    // get the csrf token
    res = await server.app.inject({ method: "GET", url: "/passwordflow" })
    body = JSON.parse(res.body);
    expect(body.template).toBe("passwordflow.njk");
    

    // insert payload
    if (!server.sessionServer) throw new Error("No session server");
    const sessionManager = server.sessionServer["sessionManager"];
    const sessionId = sessionManager.getSessionId(sessionCookie);
    let sessionData = await sessionManager.dataForSessionId(sessionId);
    sessionData.oauth.id_payload = {"sub": "bob"}
    await sessionManager.updateSessionData(sessionId, "oauth", sessionData["oauth"]);

    // call an endpoint
    if (server.oAuthClient) {
        server.oAuthClient["testMiddleware"] = true;
        await server.app.inject({ method: "GET", url: "/passwordflow", cookies: {SESSIONID: sessionCookie} })
        const request = server.oAuthClient["requestObj"];
        expect(request?.user?.username).toBe("bob");
        expect(request?.idTokenPayload?.sub).toBe("bob");
    
    }
});
