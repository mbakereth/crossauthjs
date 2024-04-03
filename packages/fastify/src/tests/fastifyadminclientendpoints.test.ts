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

test('FastifyServer.admin.createClientNoUser', async () => {
    const {server, clientStorage} = await makeAppWithOptions();
    const {csrfCookie, csrfToken, sessionCookie} = await login(server);

    let res;
    let body;

    res = await server.app.inject({
        method: "POST",
        url: "/admin/createclient",
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
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body);
    expect(body.args.message).toBeDefined();
    expect(body.args.client.clientSecret).toBeDefined();
    expect(body.args.client.clientId).toBeDefined();
    const newClient = await clientStorage.getClientById(body.args.client.clientId);
    expect(newClient.clientName).toBe("Test Client")
});

test('FastifyServer.admin.createClientWithUser', async () => {
    const {server, clientStorage, userStorage} = await makeAppWithOptions();
    const {csrfCookie, csrfToken, sessionCookie} = await login(server);

    let res;
    let body;

    const {user} = await userStorage.getUserByUsername("bob");
    res = await server.app.inject({
        method: "POST",
        url: "/admin/createclient",
        cookies: { CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie },
        payload: {
            clientName: "Test Client",
            confidential: "true",
            authorizationCode: "true",
            userId : user.id,
            clientCredentials: "true",
            redirectUris: "http://uri1.com, http://uri2.com",
            csrfToken: csrfToken ,
        }
    });
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body);
    expect(body.args.message).toBeDefined();
    expect(body.args.client.clientSecret).toBeDefined();
    expect(body.args.client.clientId).toBeDefined();
    const newClient = await clientStorage.getClientById(body.args.client.clientId);
    expect(newClient.clientName).toBe("Test Client")
    expect(newClient.userId).toBe(user.id)
});

test('FastifyServer.admin.selectClientNoUser', async () => {
    const {server, clientStorage} = await makeAppWithOptions();
    const {sessionCookie} = await login(server);

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
        method: "GET",
        url: "/admin/selectclient",
        cookies: { SESSIONID: sessionCookie },
    });
    body = JSON.parse(res.body);
    expect(body.args.clients.length).toBe(1);
});

test('FastifyServer.admin.selectClientUser', async () => {
    const {server, clientStorage, userStorage} = await makeAppWithOptions();
    const {sessionCookie} = await login(server);

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
        method: "GET",
        url: "/admin/selectclient?userId="+user.id,
        cookies: { SESSIONID: sessionCookie },
    });
    body = JSON.parse(res.body);
    expect(body.args.clients.length).toBe(1);
});

test('FastifyServer.admin.deleteClientNoUser', async () => {
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
        method: "GET",
        url: "/admin/deleteclient/ABC",
        cookies: { SESSIONID: sessionCookie },
    });
    body = JSON.parse(res.body);
    expect(body.template).toBe("deleteclient.njk");

    res = await server.app.inject({
        method: "POST",
        url: "/admin/deleteclient/ABC",
        cookies: { CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie,  },
        payload: { csrfToken: csrfToken },
    });
    body = JSON.parse(res.body);
    expect(body.template).toBe("deleteclient.njk");
    expect(body.args.message).toBe("Client deleted");

    let clientStillExists = false;
    try {
        await clientStorage.getClientById("ABC");
        clientStillExists = true;
    } catch {}
    expect(clientStillExists).toBe(false);
});

test('FastifyServer.admin.deleteClientUser', async () => {
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
        method: "GET",
        url: "/admin/deleteclient/ABC",
        cookies: { SESSIONID: sessionCookie },
    });
    body = JSON.parse(res.body);
    expect(body.template).toBe("deleteclient.njk");

    res = await server.app.inject({
        method: "POST",
        url: "/admin/deleteclient/ABC",
        cookies: { CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie,  },
        payload: { csrfToken: csrfToken },
    });
    body = JSON.parse(res.body);
    expect(body.template).toBe("deleteclient.njk");
    expect(body.args.message).toBe("Client deleted");

    let clientStillExists = false;
    try {
        await clientStorage.getClientById("ABC");
        clientStillExists = true;
    } catch {}
    expect(clientStillExists).toBe(false);
});

test('FastifyServer.admin.updateClientNoUser', async () => {
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
        method: "GET",
        url: "/admin/updateclient/ABC",
        cookies: { SESSIONID: sessionCookie },
    });
    body = JSON.parse(res.body);
    expect(body.template).toBe("updateclient.njk");

    res = await server.app.inject({
        method: "POST",
        url: "/admin/updateclient/ABC",
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
    expect(body.args.message).toBeDefined();
    expect(body.args.client.clientId).toBeDefined();
    const newClient = await clientStorage.getClientById(body.args.client.clientId);
    expect(newClient.clientName).toBe("Test1");
    expect(newClient.clientSecret).toBe(initialClient.clientSecret);
    expect(newClient.redirectUri.length).toBe(1);
    expect(newClient.validFlows.length).toBe(1);
});

test('FastifyServer.admin.updateClientNoUserNotConfidential', async () => {
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
        method: "GET",
        url: "/admin/updateclient/ABC",
        cookies: { SESSIONID: sessionCookie },
    });
    body = JSON.parse(res.body);
    expect(body.template).toBe("updateclient.njk");

    res = await server.app.inject({
        method: "POST",
        url: "/admin/updateclient/ABC",
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
    expect(body.args.message).toBeDefined();
    expect(body.args.client.clientId).toBeDefined();
    const newClient = await clientStorage.getClientById(body.args.client.clientId);
    expect(newClient.clientSecret).toBe(null);
});

test('FastifyServer.admin.updateClientNoUserConfidential', async () => {
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
        method: "GET",
        url: "/admin/updateclient/ABC",
        cookies: { SESSIONID: sessionCookie },
    });
    body = JSON.parse(res.body);
    expect(body.template).toBe("updateclient.njk");

    res = await server.app.inject({
        method: "POST",
        url: "/admin/updateclient/ABC",
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
    expect(body.args.message).toBeDefined();
    expect(body.args.client.clientId).toBeDefined();
    expect(body.args.client.clientSecret).toBeDefined();
    expect(body.args.client.clientSecret).not.toBe(null);
    const newClient = await clientStorage.getClientById(body.args.client.clientId);
    expect(newClient.clientSecret).toBeDefined();
    expect(newClient.clientSecret).not.toBe(null);
});

test('FastifyServer.admin.updateClientUser', async () => {
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
        method: "GET",
        url: "/admin/updateclient/ABC",
        cookies: { SESSIONID: sessionCookie },
    });
    body = JSON.parse(res.body);
    expect(body.template).toBe("updateclient.njk");

    res = await server.app.inject({
        method: "POST",
        url: "/admin/updateclient/ABC",
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
    expect(body.args.message).toBeDefined();
    expect(body.args.client.clientId).toBeDefined();
    const newClient = await clientStorage.getClientById(body.args.client.clientId);
    expect(newClient.clientName).toBe("Test1");
    expect(newClient.clientSecret).toBe(initialClient.clientSecret);
    expect(newClient.redirectUri.length).toBe(1);
    expect(newClient.validFlows.length).toBe(1);
    expect(newClient.userId).toBe(user.id);
});
