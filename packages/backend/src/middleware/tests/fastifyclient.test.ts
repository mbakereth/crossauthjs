import createFetchMock from 'vitest-fetch-mock';
import { test, expect, beforeAll, afterAll, vi } from 'vitest';
import { FastifyServer, type FastifyServerOptions } from '../fastifyserver';
import fastify from 'fastify';
import { OpenIdConfiguration } from '@crossauth/common';
import { getAccessToken, getAuthServer } from '../../oauth/tests/common';
import { getTestUserStorage } from '../../storage/tests/inmemorytestdata';
import { InMemoryKeyStorage } from '../..';
import { LocalPasswordAuthenticator } from '../../authenticators/passwordauth';
import path from 'path';

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
    grant_types_supported: ["authorization_code", "client_credentials"],
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

async function makeClient(options : FastifyServerOptions = {}) : Promise<FastifyServer> {
    const app = fastify({logger: false});

    // @ts-ignore
    app.decorateReply("view",  function(template, args) {
        return {template: template, args: args};
    });
    
    const userStorage = await getTestUserStorage();
    const keyStorage = new InMemoryKeyStorage();
    let lpAuthenticator = new LocalPasswordAuthenticator(userStorage);
    return new FastifyServer(userStorage, {
        session: {
            keyStorage: keyStorage,
            authenticators: {
                localpassword: lpAuthenticator,
            }},
        oAuthClient: {
            authServerBaseUri: "http://server.com",
        }}, {
        app: app,
        views: path.join(__dirname, '../views'),
        allowedFactor2: "none",
        enableEmailVerification: false,
        siteUrl: `http://localhost:3000`,
        clientId: "ABC",
        clientSecret: "DEF",
        validFlows: "all", // activate all OAuth flows
        tokenResponseType: "sendJson",
        errorResponseType: "sendJson",
        secret: "ABC",
        ...options,
    });
}

test('FastifyOAuthClient.authzcodeflowLoginNotNeeded', async () => {
    const {authServer} = await getAccessToken();

    const server = await makeClient();

    fetchMocker.mockResponseOnce(JSON.stringify(oidcConfiguration));
    if (server.oAuthClient) await server.oAuthClient.loadConfig();

    let res;

    res = await server.app.inject({ method: "GET", url: "/authzcodeflow?scope=read+write" });
    const authUrl = res.headers?.location;
    expect(authUrl).toBeDefined();
    const state = get("state", authUrl||"");
    const response_type = get("response_type", authUrl||"");
    const client_id = get("client_id", authUrl||"");
    const redirect_uri = get("redirect_uri", authUrl||"");
    const scope = get("scope", authUrl||"");
    expect(state).toBeDefined();
    expect(state?.length).toBeGreaterThan(0);
    expect(response_type).toBe("code");
    expect(client_id).toBe("ABC");

    const {code, state: returnedState, error} = await authServer.authorizeGetEndpoint({
        responseType: response_type||"", 
        clientId: client_id||"", 
        redirectUri: redirect_uri||"",
        scope: scope,
        state: state||""
    });
    expect(error).toBeUndefined();
    expect(returnedState).toBe(state);
    expect(code).toBeDefined();
});

test('FastifyOAuthClient.authzcodeflowWithLoginRedirects', async () => {
    await getAccessToken();

    const server = await makeClient({
        loginProtectedFlows: "all",
        loginUrl: "/login",
    });

    fetchMocker.mockResponseOnce(JSON.stringify(oidcConfiguration));
    if (server.oAuthClient) await server.oAuthClient.loadConfig();

    let res;

    res = await server.app.inject({ method: "GET", url: "/authzcodeflow?scope=read+write" });
    expect(res.headers?.location).toBe("/login?next=%2Fauthzcodeflow%3Fscope%3Dread%2Bwrite")
});

test('FastifyOAuthClient.clientCredentialsFlow', async () => {
    const {authServer} = await getAuthServer();

    const server = await makeClient();

    fetchMocker.mockResponseOnce(JSON.stringify(oidcConfiguration));
    if (server.oAuthClient) await server.oAuthClient.loadConfig();

    let res;
    let body;

    // get csrf token
    res = await server.app.inject({ method: "GET", url: "/login" })
    body = JSON.parse(res.body)
    expect(body.template).toBe("login.njk");
    const {csrfCookie, csrfToken} = await getCsrf(res);

    // @ts-ignore
    fetchMocker.mockResponseOnce((request) => JSON.stringify({url: request.url, body: JSON.parse(request.body.toString())}));
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

    const resp = await authServer.tokenPostEndpoint({
        grantType: body.body.grant_type, 
        clientId : body.body.client_id, 
        scope : body.body.scope, 
        clientSecret : body.body.client_secret,
    });
    expect(resp.error).toBeUndefined();
    expect(resp.access_token).toBeDefined();
});

afterAll(async () => {
    fetchMocker.dontMock();
});