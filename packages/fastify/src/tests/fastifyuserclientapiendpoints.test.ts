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

test('FastifyServer.api.createClient', async () => {

    const {server, clientStorage, userStorage} = await makeAppWithOptions();
    const {csrfCookie, csrfToken, sessionCookie} = await login(server, "bob", "bobPass123");

    let res;
    let body;

    const {user} = await userStorage.getUserByUsername("bob");
    res = await server.app.inject({
        method: "POST",
        url: "/api/createclient",
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

test('FastifyServer.api.deleteClient', async () => {
    const {server, clientStorage, userStorage} = await makeAppWithOptions();
    const {sessionCookie, csrfCookie, csrfToken} = await login(server, "bob", "bobPass123");

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
        userId: user.id,
    };
    await clientStorage.createClient(client);

    res = await server.app.inject({
        method: "POST",
        url: "/api/deleteclient/ABC",
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

test('FastifyServer.api.updateClient', async () => {
    const {server, userStorage, clientStorage} = await makeAppWithOptions();
    const {csrfCookie, csrfToken, sessionCookie} = await login(server, "bob", "bobPass123");

    const {user} = await userStorage.getUserById("bob");
    const {user: user2} = await userStorage.getUserById("alice");

    const client = {
        clientId : "ABC",
        clientSecret: "DEF",
        clientName: "Test",
        confidential: true,
        redirectUri: ["http://example.com/redirect"],
        validFlow: OAuthFlows.allFlows(),
        userId: user.id,
    };
    await clientStorage.createClient(client);
    const initialClient = await clientStorage.getClientById("ABC");

    let res;
    let body;

    res = await server.app.inject({
        method: "POST",
        url: "/api/updateclient/ABC",
        cookies: { CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie },
        payload: {
            clientName: "Test1",
            confidential: "true",
            authorizationCode: "true",
            redirectUris: "http://uri3.com",
            csrfToken: csrfToken ,
            userId: user2.id // should be ignored
        }
    });
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
    expect(body.client.clientId).toBeDefined();
    const newClient = await clientStorage.getClientById(body.client.clientId);
    expect(newClient.clientName).toBe("Test1");
    expect(newClient.userId).toBe(user.id);
    expect(newClient.clientSecret).toBe(initialClient.clientSecret);
    expect(newClient.redirectUri.length).toBe(1);
    expect(newClient.validFlow.length).toBe(1);
});

test('FastifyServer.api.updateClientNotConfidential', async () => {
    const {server, userStorage, clientStorage} = await makeAppWithOptions();
    const {csrfCookie, csrfToken, sessionCookie} = await login(server);

    const {user} = await userStorage.getUserById("bob");

    const client = {
        clientId : "ABC",
        clientSecret: "DEF",
        clientName: "Test",
        confidential: true,
        redirectUri: ["http://example.com/redirect"],
        validFlow: OAuthFlows.allFlows(),
        userId: user.id,
    };
    await clientStorage.createClient(client);

    let res;
    let body;

    res = await server.app.inject({
        method: "POST",
        url: "/api/updateclient/ABC",
        cookies: { CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie },
        payload: {
            clientName: "Test1",
            confidential: "false",
            authorizationCode: "true",
            redirectUris: "http://uri3.com",
            csrfToken: csrfToken ,
        }
    });
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
    expect(body.client.clientId).toBeDefined();
    const newClient = await clientStorage.getClientById(body.client.clientId);
    expect(newClient.clientSecret).toBe(null);
});

test('FastifyServer.api.updateClientConfidential', async () => {
    const {server, userStorage, clientStorage} = await makeAppWithOptions();
    const {csrfCookie, csrfToken, sessionCookie} = await login(server);

    const {user} = await userStorage.getUserById("bob");

    const client = {
        clientId : "ABC",
        clientName: "Test",
        confidential: false,
        redirectUri: ["http://example.com/redirect"],
        validFlow: OAuthFlows.allFlows(),
        userId: user.id,
    };
    await clientStorage.createClient(client);

    let res;
    let body;

    res = await server.app.inject({
        method: "POST",
        url: "/api/updateclient/ABC",
        cookies: { CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie },
        payload: {
            clientName: "Test1",
            confidential: "true",
            authorizationCode: "true",
            redirectUris: "http://uri3.com",
            csrfToken: csrfToken ,
        }
    });
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
    expect(body.client.clientId).toBeDefined();
    expect(body.client.clientSecret).toBeDefined();
    expect(body.client.clientSecret).not.toBe(null);
    const newClient = await clientStorage.getClientById(body.client.clientId);
    expect(newClient.clientSecret).toBeDefined();
    expect(newClient.clientSecret).not.toBe(null);
});
