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
        userId: user.id,
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

test('FastifyServer.adminapi.updateClientNoUser', async () => {
    const {server, clientStorage} = await makeAppWithOptions();
    const {csrfCookie, csrfToken, sessionCookie} = await login(server);

    const client = {
        clientId : "ABC",
        clientSecret: "DEF",
        clientName: "Test",
        confidential: true,
        redirectUri: ["http://example.com/redirect"],
        validFlow: OAuthFlows.allFlows(),
    };
    await clientStorage.createClient(client);
    const initialClient = await clientStorage.getClientById("ABC");

    let res;
    let body;

    res = await server.app.inject({
        method: "POST",
        url: "/admin/api/updateclient/ABC",
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
    const newClient = await clientStorage.getClientById(body.client.clientId);
    expect(newClient.clientName).toBe("Test1");
    expect(newClient.clientSecret).toBe(initialClient.clientSecret);
    expect(newClient.redirectUri.length).toBe(1);
    expect(newClient.validFlow.length).toBe(1);
});

test('FastifyServer.adminapi.updateClientNoUserNotConfidential', async () => {
    const {server, clientStorage} = await makeAppWithOptions();
    const {csrfCookie, csrfToken, sessionCookie} = await login(server);

    const client = {
        clientId : "ABC",
        clientSecret: "DEF",
        clientName: "Test",
        confidential: true,
        redirectUri: ["http://example.com/redirect"],
        validFlow: OAuthFlows.allFlows(),
    };
    await clientStorage.createClient(client);

    let res;
    let body;

    res = await server.app.inject({
        method: "POST",
        url: "/admin/api/updateclient/ABC",
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

test('FastifyServer.adminapi.updateClientNoUserConfidential', async () => {
    const {server, clientStorage} = await makeAppWithOptions();
    const {csrfCookie, csrfToken, sessionCookie} = await login(server);

    const client = {
        clientId : "ABC",
        clientName: "Test",
        confidential: false,
        redirectUri: ["http://example.com/redirect"],
        validFlow: OAuthFlows.allFlows(),
    };
    await clientStorage.createClient(client);

    let res;
    let body;

    res = await server.app.inject({
        method: "POST",
        url: "/admin/api/updateclient/ABC",
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

test('FastifyServer.adminapi.updateClientUser', async () => {
    const {server, userStorage, clientStorage} = await makeAppWithOptions();
    const {csrfCookie, csrfToken, sessionCookie} = await login(server);

    const {user} = await userStorage.getUserById("bob");
    const client = {
        clientId : "ABC",
        clientSecret: "DEF",
        clientName: "Test",
        confidential: true,
        userId: user.id,
        redirectUri: ["http://example.com/redirect"],
        validFlow: OAuthFlows.allFlows(),
    };
    await clientStorage.createClient(client);
    const initialClient = await clientStorage.getClientById("ABC");

    let res;
    let body;

    res = await server.app.inject({
        method: "POST",
        url: "/admin/api/updateclient/ABC",
        cookies: { CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie },
        payload: {
            clientName: "Test1",
            confidential: "true",
            authorizationCode: "true",
            redirectUris: "http://uri3.com",
            csrfToken: csrfToken ,
            userId: user.id,
        }
    });
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
    expect(body.client.clientId).toBeDefined();
    const newClient = await clientStorage.getClientById(body.client.clientId);
    expect(newClient.clientName).toBe("Test1");
    expect(newClient.clientSecret).toBe(initialClient.clientSecret);
    expect(newClient.redirectUri.length).toBe(1);
    expect(newClient.validFlow.length).toBe(1);
    expect(newClient.userId).toBe(user.id);
});
