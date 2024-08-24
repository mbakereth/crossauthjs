import { MockRequestEvent } from './sveltemocks';
import { test, expect } from 'vitest';
import {  makeServer, getCsrfToken, login } from './testshared';

export var passwordResetData :  {token : string, extraData: {[key:string]: any}};

test('SvelteKitAdminClientEndpoints.selectClients_user', async () => {
    const { server, resolver, handle } = await makeServer();

    // log in
    let resp = await login(server, resolver, handle, "admin", "adminPass123");
    let loginEvent = resp.event;
    loginEvent = resp.event;

    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);
    
    let sessionCookieValue = loginEvent.cookies.get("SESSIONID");
    let sessionId = server.sessionServer?.sessionManager.getSessionId(sessionCookieValue??"");

    // select clients
    let getRequest = new Request("http://ex.com/oauth/clients", {
        method: "POST",
        body: "csrfToken="+csrfToken,
        headers: [
            ["cookie", "CSRFTOKEN="+csrfCookieValue],
            ["cookie", "SESSIONID="+sessionCookieValue],
            ["content-type", "application/x-www-form-urlencoded"],
        ] 
        });
    let event = new MockRequestEvent("1", getRequest, {id: "bob"});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    let resp1 = await server.sessionServer?.adminClientEndpoints.searchClients(event, undefined, undefined, undefined, "bob");
    expect(resp1?.ok).toBe(true);
    expect(resp1?.clients?.length).toBe(1);

});

test('SvelteKitAdminClientEndpoints.selectClients_all', async () => {
    const { server, resolver, handle } = await makeServer();

    // log in
    let resp = await login(server, resolver, handle, "admin", "adminPass123");
    let loginEvent = resp.event;
    loginEvent = resp.event;

    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);
    
    let sessionCookieValue = loginEvent.cookies.get("SESSIONID");
    let sessionId = server.sessionServer?.sessionManager.getSessionId(sessionCookieValue??"");

    // select clients
    let getRequest = new Request("http://ex.com/oauth/clients", {
        method: "POST",
        body: "csrfToken="+csrfToken,
        headers: [
            ["cookie", "CSRFTOKEN="+csrfCookieValue],
            ["cookie", "SESSIONID="+sessionCookieValue],
            ["content-type", "application/x-www-form-urlencoded"],
        ] 
        });
    let event = new MockRequestEvent("1", getRequest, {id: "bob"});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    let resp1 = await server.sessionServer?.adminClientEndpoints.searchClients(event, undefined, undefined, undefined);
    expect(resp1?.ok).toBe(true);
    expect(resp1?.clients?.length).toBe(2);

});

test('SvelteKitAdminClientEndpoints.updateClient', async () => {
    const { server, resolver, handle } = await makeServer();

    // log in
    let resp = await login(server, resolver, handle, "admin", "adminPass123");
    let loginEvent = resp.event;
    loginEvent = resp.event;

    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);
    
    let sessionCookieValue = loginEvent.cookies.get("SESSIONID");
    let sessionId = server.sessionServer?.sessionManager.getSessionId(sessionCookieValue??"");

    let getRequest = new Request("http://ex.com/oauth/clients", {
        method: "GET",
        headers: [
            ["cookie", "CSRFTOKEN="+csrfCookieValue],
            ["cookie", "SESSIONID="+sessionCookieValue],
            ["content-type", "application/x-www-form-urlencoded"],
        ] 
        });
    let event = new MockRequestEvent("1", getRequest, {clientId: "ABC"});
    event.locals.csrfToken = csrfToken;
    let status = 200;
    let resp1 : {[key:string]:any}|undefined = {};
    try {
        resp1 = await server.sessionServer?.adminClientEndpoints.updateClientEndpoint.load(event);
    } catch (e) {
        if (e && typeof(e) == "object"  && "status" in e && typeof(e.status) == "number") status = e.status;
    }
    expect(status).toBe(401);

    event = new MockRequestEvent("1", getRequest, {clientId: "ABC"});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    status = 200;
    try {
        resp1 = await server.sessionServer?.adminClientEndpoints.updateClientEndpoint.load(event);
    } catch (e) {
        if (e && typeof(e) == "object"  && "status" in e && typeof(e.status) == "number") status = e.status;
    }
    expect(status).toBe(200);

    event = new MockRequestEvent("1", getRequest, {clientId: "bob_ABC"});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    resp1 = await server.sessionServer?.adminClientEndpoints.updateClientEndpoint.load(event);
    expect(resp1?.ok).toBe(true);

    let postRequest = new Request("http://ex.com/oauth/clients", {
        method: "POST",
        body: "csrfToken="+csrfToken+"&clientName=newName&confidential=on&redirectUri=http://uri1.com/redirect&authorizationCode=on",
        headers: [
            ["cookie", "CSRFTOKEN="+csrfCookieValue],
            ["cookie", "SESSIONID="+sessionCookieValue],
            ["content-type", "application/x-www-form-urlencoded"],
        ] 
        });
    event = new MockRequestEvent("1", postRequest, {clientId: "bob_ABC"});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    resp1 = await server.sessionServer?.adminClientEndpoints.updateClientEndpoint.actions.default(event);
    expect(resp1?.ok).toBe(true);
    expect(resp1?.client?.clientName).toBe("newName");
    expect(resp1?.plaintextSecret).toBeUndefined();
    expect(resp1?.client?.clientSecret).toContain("pbkdf2:sha256");

    postRequest = new Request("http://ex.com/oauth/clients", {
        method: "POST",
        body: "csrfToken="+csrfToken+"&clientName=newName&confidential=on&redirectUri=http://uri1.com/redirect&authorizationCode=on&resetSecret=on",
        headers: [
            ["cookie", "CSRFTOKEN="+csrfCookieValue],
            ["cookie", "SESSIONID="+sessionCookieValue],
            ["content-type", "application/x-www-form-urlencoded"],
        ] 
        });
    event = new MockRequestEvent("1", postRequest, {clientId: "bob_ABC"});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    resp1 = await server.sessionServer?.adminClientEndpoints.updateClientEndpoint.actions.default(event);
    expect(resp1?.ok).toBe(true);
    expect(resp1?.plaintextSecret).toBeDefined();
    expect(resp1?.client?.clientSecret).not.toContain("pbkdf2:sha256");
});

test('SvelteKitAdminClientEndpoints.deleteClient', async () => {
    const { server, resolver, handle } = await makeServer();

    // log in
    let resp = await login(server, resolver, handle, "admin", "adminPass123");
    let loginEvent = resp.event;
    loginEvent = resp.event;

    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);
    
    let sessionCookieValue = loginEvent.cookies.get("SESSIONID");
    let sessionId = server.sessionServer?.sessionManager.getSessionId(sessionCookieValue??"");

    let getRequest = new Request("http://ex.com/oauth/clients", {
        method: "GET",
        headers: [
            ["cookie", "CSRFTOKEN="+csrfCookieValue],
            ["cookie", "SESSIONID="+sessionCookieValue],
            ["content-type", "application/x-www-form-urlencoded"],
        ] 
        });
    let event = new MockRequestEvent("1", getRequest, {clientId: "ABC"});
    event.locals.csrfToken = csrfToken;
    let status = 200;
    let resp1 : {[key:string]:any}|undefined = {};
    try {
        resp1 = await server.sessionServer?.adminClientEndpoints.deleteClientEndpoint.load(event);
    } catch (e) {
        if (e && typeof(e) == "object"  && "status" in e && typeof(e.status) == "number") status = e.status;
    }
    expect(status).toBe(401);

    event = new MockRequestEvent("1", getRequest, {clientId: "ABC"});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    status = 200;
    try {
        resp1 = await server.sessionServer?.adminClientEndpoints.deleteClientEndpoint.load(event);
    } catch (e) {
        if (e && typeof(e) == "object"  && "status" in e && typeof(e.status) == "number") status = e.status;
    }
    expect(status).toBe(200);

    event = new MockRequestEvent("1", getRequest, {clientId: "bob_ABC"});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    resp1 = await server.sessionServer?.adminClientEndpoints.deleteClientEndpoint.load(event);
    expect(resp1?.ok).toBe(true);

    let postRequest = new Request("http://ex.com/oauth/clients", {
        method: "POST",
        body: "csrfToken="+csrfToken,
        headers: [
            ["cookie", "CSRFTOKEN="+csrfCookieValue],
            ["cookie", "SESSIONID="+sessionCookieValue],
            ["content-type", "application/x-www-form-urlencoded"],
        ] 
        });
    event = new MockRequestEvent("1", postRequest, {clientId: "bob_ABC"});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    resp1 = await server.sessionServer?.adminClientEndpoints.deleteClientEndpoint.actions.default(event);
    expect(resp1?.ok).toBe(true);
});

test('SvelteKitAdminClientEndpoints.createClient', async () => {
    const { server, resolver, handle } = await makeServer();

    // log in
    let resp = await login(server, resolver, handle, "admin", "adminPass123");
    let loginEvent = resp.event;
    loginEvent = resp.event;

    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);
    
    let sessionCookieValue = loginEvent.cookies.get("SESSIONID");
    let sessionId = server.sessionServer?.sessionManager.getSessionId(sessionCookieValue??"");

    let getRequest = new Request("http://ex.com/oauth/clients", {
        method: "GET",
        headers: [
            ["cookie", "CSRFTOKEN="+csrfCookieValue],
            ["cookie", "SESSIONID="+sessionCookieValue],
            ["content-type", "application/x-www-form-urlencoded"],
        ] 
        });
    let event = new MockRequestEvent("1", getRequest, {});
    event.locals.csrfToken = csrfToken;
    let status = 200;
    let resp1 : {[key:string]:any}|undefined = {};
    try {
        resp1 = await server.sessionServer?.adminClientEndpoints.createClientEndpoint.load(event);
    } catch (e) {
        if (e && typeof(e) == "object"  && "status" in e && typeof(e.status) == "number") status = e.status;
    }
    expect(status).toBe(401);

    event = new MockRequestEvent("1", getRequest, {});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    resp1 = await server.sessionServer?.adminClientEndpoints.createClientEndpoint.load(event);
    expect(resp1?.ok).toBe(true);

    let postRequest = new Request("http://ex.com/oauth/clients", {
        method: "POST",
        body: "csrfToken="+csrfToken+"&clientName=newName&confidential=on&redirectUri=http://uri1.com/redirect&authorizationCode=on",
        headers: [
            ["cookie", "CSRFTOKEN="+csrfCookieValue],
            ["cookie", "SESSIONID="+sessionCookieValue],
            ["content-type", "application/x-www-form-urlencoded"],
        ] 
        });
    event = new MockRequestEvent("1", postRequest, {clientId: "bob_ABC"});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    resp1 = await server.sessionServer?.adminClientEndpoints.createClientEndpoint.actions.default(event);
    expect(resp1?.ok).toBe(true);
    expect(resp1?.client?.clientName).toBe("newName");
    expect(resp1?.plaintextSecret).toBeUndefined();
    expect(resp1?.client?.clientSecret).not.toContain("pbkdf2:sha256");
    expect(resp1?.client?.userId).toBeUndefined();

});

test('SvelteKitAdminClientEndpoints.createClientForUser', async () => {
    const { server, resolver, handle } = await makeServer();

    // log in
    let resp = await login(server, resolver, handle, "admin", "adminPass123");
    let loginEvent = resp.event;
    loginEvent = resp.event;

    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);
    
    let sessionCookieValue = loginEvent.cookies.get("SESSIONID");
    let sessionId = server.sessionServer?.sessionManager.getSessionId(sessionCookieValue??"");

    let getRequest = new Request("http://ex.com/oauth/clients", {
        method: "GET",
        headers: [
            ["cookie", "CSRFTOKEN="+csrfCookieValue],
            ["cookie", "SESSIONID="+sessionCookieValue],
            ["content-type", "application/x-www-form-urlencoded"],
        ] 
        });
    let event = new MockRequestEvent("1", getRequest, {});
    event.locals.csrfToken = csrfToken;
    let status = 200;
    let resp1 : {[key:string]:any}|undefined = {};
    try {
        resp1 = await server.sessionServer?.adminClientEndpoints.createClientEndpoint.load(event);
    } catch (e) {
        if (e && typeof(e) == "object"  && "status" in e && typeof(e.status) == "number") status = e.status;
    }
    expect(status).toBe(401);

    event = new MockRequestEvent("1", getRequest, {});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    resp1 = await server.sessionServer?.adminClientEndpoints.createClientEndpoint.load(event);
    expect(resp1?.ok).toBe(true);

    let postRequest = new Request("http://ex.com/oauth/clients?userid=bob", {
        method: "POST",
        body: "csrfToken="+csrfToken+"&clientName=newName&confidential=on&redirectUri=http://uri1.com/redirect&authorizationCode=on&userId=bob",
        headers: [
            ["cookie", "CSRFTOKEN="+csrfCookieValue],
            ["cookie", "SESSIONID="+sessionCookieValue],
            ["content-type", "application/x-www-form-urlencoded"],
        ] 
        });
    event = new MockRequestEvent("1", postRequest, {clientId: "bob_ABC"});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    resp1 = await server.sessionServer?.adminClientEndpoints.createClientEndpoint.actions.default(event);
    expect(resp1?.ok).toBe(true);
    expect(resp1?.client?.clientName).toBe("newName");
    expect(resp1?.plaintextSecret).toBeUndefined();
    expect(resp1?.client?.clientSecret).not.toContain("pbkdf2:sha256");
    expect(resp1?.client?.userId).toBe("bob");

});
