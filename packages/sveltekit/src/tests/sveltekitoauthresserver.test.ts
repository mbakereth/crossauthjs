import { MockRequestEvent } from './sveltemocks';
import { SvelteKitOAuthResourceServer } from '../sveltekitresserver';
import {  oidcConfiguration, makeServer, getAccessToken } from './testshared';
import { OAuthTokenConsumer } from '@crossauth/backend';
import createFetchMock from 'vitest-fetch-mock';

let fetchMocker = createFetchMock(vi);
fetchMocker.enableMocks();

beforeAll(async () => {
    fetchMocker.doMock();
});

afterEach(async () => {
    vi.restoreAllMocks();
});

export async function oauthLogin () {
    const {server, keyStorage, userStorage} = await makeServer(true, false, false, true, {tokenResponseType: "saveInSessionAndReturn", enableCsrfProtection: false});
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
    if (!resp || !(resp instanceof Response)) throw "response is not an object";
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.access_token).toBeDefined();
    expect(body.refresh_token).toBeDefined();
    const access_token = body.access_token;
    const refresh_token = body.refresh_token;

    let sessionCookieValue = event.cookies.get("SESSIONID");
    let sessionId = server.sessionServer?.sessionManager.getSessionId(sessionCookieValue??"");


    return {server, authServer, sessionCookieValue, sessionId, access_token, refresh_token, keyStorage, userStorage};
};

test('SvelteKitOAuthResourceServer.validAndInvalidAccessToken_authorized', async () => {
    // login using password flow
    const {server, authServer, access_token, userStorage} = await oauthLogin();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    const decodedAccessToken
        = await authServer.validAccessToken(access_token??"");
    expect(decodedAccessToken).toBeDefined();

    // create resource server
    const issuer = process.env["CROSSAUTH_AUTH_SERVER_BASE_URL"]??"";
    const resserver = new SvelteKitOAuthResourceServer(
        [new OAuthTokenConsumer({authServerBaseUrl: issuer})],
        {userStorage}
    );
    fetchMocker.mockResponseOnce(JSON.stringify(oidcConfiguration));
    await resserver.tokenConsumers[issuer].loadConfig();
    fetchMocker.mockResponseOnce(JSON.stringify(authServer.jwks()));
    await resserver.tokenConsumers[issuer].loadJwks();

    // simulate a get request on the res server
    // authorizationCodeFlow get endpoint
    let getRequest = new Request(`http://resserver.com/getresource`, {
        method: "GET",
        headers: {"authorization": "Bearer " + access_token}
        });
    let event = new MockRequestEvent("1", getRequest, {});
    const resp1 = await resserver.authorized(event);
    expect(resp1?.authorized).toBe(true);
    expect(resp1?.tokenPayload).toBeDefined();
    expect(resp1?.user?.username).toBe("bob");

    // simulate an invalid get request on the res server
    // authorizationCodeFlow get endpoint
    getRequest = new Request(`http://resserver.com/getresource`, {
        method: "GET",
        headers: {"authorization": "Bearer " + access_token + "x"}
        });
    event = new MockRequestEvent("1", getRequest, {});
    const resp2 = await resserver.authorized(event);
    expect(resp2?.authorized).toBe(false);
    expect(resp2?.tokenPayload).toBeUndefined();
    expect(resp2?.user).toBeUndefined();

});

test('SvelteKitOAuthResourceServer.validAndInvalidAccessToken_hook', async () => {
    // login using password flow
    const {server, authServer, access_token, userStorage} = await oauthLogin();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    const decodedAccessToken
        = await authServer.validAccessToken(access_token??"");
    expect(decodedAccessToken).toBeDefined();

    // create resource server
    const issuer = process.env["CROSSAUTH_AUTH_SERVER_BASE_URL"]??"";
    const resserver = new SvelteKitOAuthResourceServer(
        [new OAuthTokenConsumer({authServerBaseUrl: issuer})],
        {
            userStorage,
            protectedEndpoints: {
                "/getresource": { scope: ["read", "write"]}
            },
        }
    );
    fetchMocker.mockResponseOnce(JSON.stringify(oidcConfiguration));
    await resserver.tokenConsumers[issuer].loadConfig();
    fetchMocker.mockResponseOnce(JSON.stringify(authServer.jwks()));
    await resserver.tokenConsumers[issuer].loadJwks();

    // simulate a get request on the res server
    // authorizationCodeFlow get endpoint
    let getRequest = new Request(`http://resserver.com/getresource`, {
        method: "GET",
        headers: {"authorization": "Bearer " + access_token}
        });
    let event = new MockRequestEvent("1", getRequest, {});
    expect(resserver.hook).toBeDefined();
    if (!resserver.hook) throw new Error("hook undefined");
    await resserver.hook({event});
    expect(event.locals.user?.username).toBe("bob");
    expect(event.locals.scope?.length).toBe(2);
    let scopes = event.locals.scope ?? [];
    expect(["read", "write"]).toContain(scopes[0]);
    expect(["read", "write"]).toContain(scopes[1]);

    // simulate an invalidget request on the res server
    // authorizationCodeFlow get endpoint
    getRequest = new Request(`http://resserver.com/getresource`, {
        method: "GET",
        headers: {"authorization": "Bearer " + access_token + "x"}
        });
    event = new MockRequestEvent("1", getRequest, {});
    expect(resserver.hook).toBeDefined();
    if (!resserver.hook) throw new Error("hook undefined");
    await resserver.hook({event});
    expect(event.locals.user).toBeUndefined();
    expect(event.locals.scope).toBeUndefined();
});
