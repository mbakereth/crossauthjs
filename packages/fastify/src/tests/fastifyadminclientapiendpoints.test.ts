import { beforeAll, afterEach, expect, test, vi } from 'vitest'
import { makeAppWithOptions, login } from './admincommon';
import { OAuthFlows } from '@crossauth/common';

//export var server : FastifyCookieAuthServer;
export var confirmEmailData :  {token : string, email : string, extraData: {[key:string]: any}};
export var passwordResetData :  {token : string, extraData: {[key:string]: any}};

beforeAll(async () => {
});

afterEach(async () => {
    vi.restoreAllMocks();
});

test('FastifyServer.adminapi.createClientNoUser', async () => {

    const {server, clientStorage} = await makeAppWithOptions();
    const {csrfCookie, csrfToken, sessionCookie} = await login(server);

    let res;
    let body;

    res = await server.app.inject({
        method: "POST",
        url: "/admin/api/createclient",
        cookies: { CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie },
        payload: {
            clientName: "Test Client",
            confidential: "true",
            authorizationCode: "true",
            clientCredentials: "true",
            redirectUris: "http://uri1.com, http://uri2.com",
            csrfToken: csrfToken ,
        }
    });
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
    expect(body.client.clientId).toBeDefined();
    expect(body.client.clientSecret).toBeDefined();

    const newClient = await clientStorage.getClientById(body.client.clientId);
    expect(newClient.clientName).toBe("Test Client")
});

test('FastifyServer.adminapi.createClientWithUser', async () => {

    const {server, clientStorage, userStorage} = await makeAppWithOptions();
    const {csrfCookie, csrfToken, sessionCookie} = await login(server);

    let res;
    let body;

    const {user} = await userStorage.getUserByUsername("bob");
    res = await server.app.inject({
        method: "POST",
        url: "/admin/api/createclient",
        cookies: { CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie },
        payload: {
            clientName: "Test Client",
            confidential: "true",
            authorizationCode: "true",
            clientCredentials: "true",
            redirectUris: "http://uri1.com, http://uri2.com",
            csrfToken: csrfToken ,
            userId: user.id,
        }
    });
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
    expect(body.client.clientId).toBeDefined();
    expect(body.client.clientSecret).toBeDefined();

    const newClient = await clientStorage.getClientById(body.client.clientId);
    expect(newClient.clientName).toBe("Test Client")
});

test('FastifyServer.adminapi.deleteClientNoUser', async () => {
    const {server, clientStorage} = await makeAppWithOptions();
    const {sessionCookie, csrfCookie, csrfToken} = await login(server);

    let res;
    let body;

    const client = {
        clientId : "ABC",
        clientSecret: "DEF",
        clientName: "Test",
        confidential: true,
        redirectUri: ["http://example.com/redirect"],
        validFlow: OAuthFlows.allFlows(),
    };
    await clientStorage.createClient(client);

    res = await server.app.inject({
        method: "POST",
        url: "/admin/api/deleteclient/ABC",
        cookies: { CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie,  },
        payload: { csrfToken: csrfToken },
    });
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);

    let clientStillExists = false;
    try {
        await clientStorage.getClientById("ABC");
        clientStillExists = true;
    } catch {}
    expect(clientStillExists).toBe(false);
});

test('FastifyServer.adminapi.deleteClientUser', async () => {
    const {server, clientStorage, userStorage} = await makeAppWithOptions();
    const {sessionCookie, csrfCookie, csrfToken} = await login(server);

    let res;
    let body;

    const {user} = await userStorage.getUserByUsername("bob");
    const client = {
        clientId : "ABC",
        clientSecret: "DEF",
        clientName: "Test",
        confidential: true,
        redirectUri: ["http://example.com/redirect"],
        validFlow: OAuthFlows.allFlows(),
        user_id: user.id,
    };
    await clientStorage.createClient(client);

    res = await server.app.inject({
        method: "POST",
        url: "/admin/api/deleteclient/ABC",
        cookies: { CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie,  },
        payload: { csrfToken: csrfToken },
    });
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);

    let clientStillExists = false;
    try {
        await clientStorage.getClientById("ABC");
        clientStillExists = true;
    } catch {}
    expect(clientStillExists).toBe(false);
});

