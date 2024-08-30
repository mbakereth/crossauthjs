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
            client_name: "Test Client",
            confidential: "true",
            authorizationCode: "true",
            clientCredentials: "true",
            redirect_uris: "http://uri1.com, http://uri2.com",
            csrfToken: csrfToken ,
        }
    });
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body);
    expect(body.args.message).toBeDefined();
    expect(body.args.client.client_secret).toBeDefined();
    expect(body.args.client.client_id).toBeDefined();
    const newClient = await clientStorage.getClientById(body.args.client.client_id);
    expect(newClient.client_name).toBe("Test Client")
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
            client_name: "Test Client",
            confidential: "true",
            authorizationCode: "true",
            userid : user.id,
            clientCredentials: "true",
            redirect_uris: "http://uri1.com, http://uri2.com",
            csrfToken: csrfToken ,
        }
    });
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body);
    expect(body.args.message).toBeDefined();
    expect(body.args.client.client_secret).toBeDefined();
    expect(body.args.client.client_id).toBeDefined();
    const newClient = await clientStorage.getClientById(body.args.client.client_id);
    expect(newClient.client_name).toBe("Test Client")
    expect(newClient.userid).toBe(user.id)
});

test('FastifyServer.admin.selectClientNoUser', async () => {
    const {server, clientStorage} = await makeAppWithOptions();
    const {sessionCookie} = await login(server);

    let res;
    let body;

    const client = {
        client_id : "ABC",
        client_secret: "DEF",
        client_name: "Test",
        confidential: true,
        redirect_uri: ["http://example.com/redirect"],
        valid_flow: OAuthFlows.allFlows(),
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
        client_id : "ABC",
        client_secret: "DEF",
        client_name: "Test",
        confidential: true,
        redirect_uri: ["http://example.com/redirect"],
        valid_flow: OAuthFlows.allFlows(),
        userid: user.id,
    };
    await clientStorage.createClient(client);

    res = await server.app.inject({
        method: "GET",
        url: "/admin/selectclient?userid="+user.id,
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
        client_id : "ABC",
        client_secret: "DEF",
        client_name: "Test",
        confidential: true,
        redirect_uri: ["http://example.com/redirect"],
        valid_flow: OAuthFlows.allFlows(),
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
        client_id : "ABC",
        client_secret: "DEF",
        client_name: "Test",
        confidential: true,
        redirect_uri: ["http://example.com/redirect"],
        valid_flow: OAuthFlows.allFlows(),
        userid: user.id,
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
        client_id : "ABC",
        client_secret: "DEF",
        client_name: "Test",
        confidential: true,
        redirect_uri: ["http://example.com/redirect"],
        valid_flow: OAuthFlows.allFlows(),
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
            client_name: "Test1",
            confidential: "true",
            authorizationCode: "true",
            redirect_uris: "http://uri3.com",
            csrfToken: csrfToken ,
        }
    });
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body);
    expect(body.args.message).toBeDefined();
    expect(body.args.client.client_id).toBeDefined();
    const newClient = await clientStorage.getClientById(body.args.client.client_id);
    expect(newClient.client_name).toBe("Test1");
    expect(newClient.client_secret).toBe(initialClient.client_secret);
    expect(newClient.redirect_uri.length).toBe(1);
    expect(newClient.valid_flow.length).toBe(1);
});

test('FastifyServer.admin.updateClientNoUserNotConfidential', async () => {
    const {server, clientStorage} = await makeAppWithOptions();
    const {csrfCookie, csrfToken, sessionCookie} = await login(server);

    const client = {
        client_id : "ABC",
        client_secret: "DEF",
        client_name: "Test",
        confidential: true,
        redirect_uri: ["http://example.com/redirect"],
        valid_flow: OAuthFlows.allFlows(),
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
            client_name: "Test1",
            confidential: "false",
            authorizationCode: "true",
            redirect_uris: "http://uri3.com",
            csrfToken: csrfToken ,
        }
    });
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body);
    expect(body.args.message).toBeDefined();
    expect(body.args.client.client_id).toBeDefined();
    const newClient = await clientStorage.getClientById(body.args.client.client_id);
    expect(newClient.client_secret).toBe(null);
});

test('FastifyServer.admin.updateClientNoUserConfidential', async () => {
    const {server, clientStorage} = await makeAppWithOptions();
    const {csrfCookie, csrfToken, sessionCookie} = await login(server);

    const client = {
        client_id : "ABC",
        client_name: "Test",
        confidential: false,
        redirect_uri: ["http://example.com/redirect"],
        valid_flow: OAuthFlows.allFlows(),
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
            client_name: "Test1",
            confidential: "true",
            authorizationCode: "true",
            redirect_uris: "http://uri3.com",
            csrfToken: csrfToken ,
        }
    });
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body);
    expect(body.args.message).toBeDefined();
    expect(body.args.client.client_id).toBeDefined();
    expect(body.args.client.client_secret).toBeDefined();
    expect(body.args.client.client_secret).not.toBe(null);
    const newClient = await clientStorage.getClientById(body.args.client.client_id);
    expect(newClient.client_secret).toBeDefined();
    expect(newClient.client_secret).not.toBe(null);
});

test('FastifyServer.admin.updateClientUser', async () => {
    const {server, userStorage, clientStorage} = await makeAppWithOptions();
    const {csrfCookie, csrfToken, sessionCookie} = await login(server);

    const {user} = await userStorage.getUserById("bob");
    const client = {
        client_id : "ABC",
        client_secret: "DEF",
        client_name: "Test",
        confidential: true,
        userid: user.id,
        redirect_uri: ["http://example.com/redirect"],
        valid_flow: OAuthFlows.allFlows(),
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
            client_name: "Test1",
            confidential: "true",
            authorizationCode: "true",
            redirect_uris: "http://uri3.com",
            csrfToken: csrfToken ,
            userid: user.id,
        }
    });
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body);
    expect(body.args.message).toBeDefined();
    expect(body.args.client.client_id).toBeDefined();
    const newClient = await clientStorage.getClientById(body.args.client.client_id);
    expect(newClient.client_name).toBe("Test1");
    expect(newClient.client_secret).toBe(initialClient.client_secret);
    expect(newClient.redirect_uri.length).toBe(1);
    expect(newClient.valid_flow.length).toBe(1);
    expect(newClient.userid).toBe(user.id);
});
