// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
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
            client_name: "Test Client",
            confidential: "true",
            authorizationCode: "true",
            clientCredentials: "true",
            redirect_uris: "http://uri1.com, http://uri2.com",
            csrfToken: csrfToken ,
        }
    });
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
    expect(body.client.client_id).toBeDefined();
    expect(body.client.client_secret).toBeDefined();

    const newClient = await clientStorage.getClientById(body.client.client_id);
    expect(newClient.client_name).toBe("Test Client")
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
            client_name: "Test Client",
            confidential: "true",
            authorizationCode: "true",
            clientCredentials: "true",
            redirect_uris: "http://uri1.com, http://uri2.com",
            csrfToken: csrfToken ,
            userid: user.id,
        }
    });
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
    expect(body.client.client_id).toBeDefined();
    expect(body.client.client_secret).toBeDefined();

    const newClient = await clientStorage.getClientById(body.client.client_id);
    expect(newClient.client_name).toBe("Test Client")
});

test('FastifyServer.adminapi.deleteClientNoUser', async () => {
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
        method: "POST",
        url: "/admin/api/updateclient/ABC",
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
    expect(body.ok).toBe(true);
    expect(body.client.client_id).toBeDefined();
    const newClient = await clientStorage.getClientById(body.client.client_id);
    expect(newClient.client_name).toBe("Test1");
    expect(newClient.client_secret).toBe(initialClient.client_secret);
    expect(newClient.redirect_uri.length).toBe(1);
    expect(newClient.valid_flow.length).toBe(1);
});

test('FastifyServer.adminapi.updateClientNoUserNotConfidential', async () => {
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
        method: "POST",
        url: "/admin/api/updateclient/ABC",
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
    expect(body.ok).toBe(true);
    expect(body.client.client_id).toBeDefined();
    const newClient = await clientStorage.getClientById(body.client.client_id);
    expect(newClient.client_secret).toBe(null);
});

test('FastifyServer.adminapi.updateClientNoUserConfidential', async () => {
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
        method: "POST",
        url: "/admin/api/updateclient/ABC",
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
    expect(body.ok).toBe(true);
    expect(body.client.client_id).toBeDefined();
    expect(body.client.client_secret).toBeDefined();
    expect(body.client.client_secret).not.toBe(null);
    const newClient = await clientStorage.getClientById(body.client.client_id);
    expect(newClient.client_secret).toBeDefined();
    expect(newClient.client_secret).not.toBe(null);
});

test('FastifyServer.adminapi.updateClientUser', async () => {
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
        method: "POST",
        url: "/admin/api/updateclient/ABC",
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
    expect(body.ok).toBe(true);
    expect(body.client.client_id).toBeDefined();
    const newClient = await clientStorage.getClientById(body.client.client_id);
    expect(newClient.client_name).toBe("Test1");
    expect(newClient.client_secret).toBe(initialClient.client_secret);
    expect(newClient.redirect_uri.length).toBe(1);
    expect(newClient.valid_flow.length).toBe(1);
    expect(newClient.userid).toBe(user.id);
});
