// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { MockRequestEvent } from './sveltemocks';
import { test, expect } from 'vitest';
import {  makeServer, getCsrfToken, login } from './testshared';

export var passwordResetData :  {token : string, extraData: {[key:string]: any}};

test('SvelteKitUserClientEndpoints.selectClients', async () => {
    const { server, resolver, handle, } = await makeServer();

    // log in
    let resp = await login(server, resolver, handle);
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
    let resp1 = await server.sessionServer?.userClientEndpoints.searchClients(event as any);
    expect(resp1?.ok).toBe(true);
    expect(resp1?.clients?.length).toBe(1);

});

test('SvelteKitUserClientEndpoints.updateClient', async () => {
    const { server, resolver, handle } = await makeServer();

    // log in
    let resp = await login(server, resolver, handle);
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
    let event = new MockRequestEvent("1", getRequest, {client_id: "ABC"});
    event.locals.csrfToken = csrfToken;
    let status = 200;
    let resp1 : {[key:string]:any}|undefined = {};
    try {
        resp1 = await server.sessionServer?.userClientEndpoints.updateClientEndpoint.load(event as any);
    } catch (e) {
        if (e && typeof(e) == "object"  && "status" in e && typeof(e.status) == "number") status = e.status;
    }
    expect(status).toBe(302);

    event = new MockRequestEvent("1", getRequest, {client_id: "ABC"});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    status = 200;
    try {
        resp1 = await server.sessionServer?.userClientEndpoints.updateClientEndpoint.load(event as any);
    } catch (e) {
        if (e && typeof(e) == "object"  && "status" in e && typeof(e.status) == "number") status = e.status;
    }
    expect(status).toBe(401);

    event = new MockRequestEvent("1", getRequest, {client_id: "bob_ABC"});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    resp1 = await server.sessionServer?.userClientEndpoints.updateClientEndpoint.load(event as any);
    expect(resp1?.ok).toBe(true);

    let postRequest = new Request("http://ex.com/oauth/clients", {
        method: "POST",
        body: "csrfToken="+csrfToken+"&client_name=newName&confidential=on&redirect_uri=http://uri1.com/redirect&authorizationCode=on",
        headers: [
            ["cookie", "CSRFTOKEN="+csrfCookieValue],
            ["cookie", "SESSIONID="+sessionCookieValue],
            ["content-type", "application/x-www-form-urlencoded"],
        ] 
        });
    event = new MockRequestEvent("1", postRequest, {client_id: "bob_ABC"});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    resp1 = await server.sessionServer?.userClientEndpoints.updateClientEndpoint.actions.default(event as any);
    expect(resp1?.ok).toBe(true);
    expect(resp1?.client?.client_name).toBe("newName");
    expect(resp1?.plaintextSecret).toBeUndefined();
    expect(resp1?.client?.client_secret).toContain("pbkdf2:sha256");

    postRequest = new Request("http://ex.com/oauth/clients", {
        method: "POST",
        body: "csrfToken="+csrfToken+"&client_name=newName&confidential=on&redirect_uri=http://uri1.com/redirect&authorizationCode=on&resetSecret=on",
        headers: [
            ["cookie", "CSRFTOKEN="+csrfCookieValue],
            ["cookie", "SESSIONID="+sessionCookieValue],
            ["content-type", "application/x-www-form-urlencoded"],
        ] 
        });
    event = new MockRequestEvent("1", postRequest, {client_id: "bob_ABC"});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    resp1 = await server.sessionServer?.userClientEndpoints.updateClientEndpoint.actions.default(event as any);
    expect(resp1?.ok).toBe(true);
    expect(resp1?.plaintextSecret).toBeDefined();
    expect(resp1?.client?.client_secret).not.toContain("pbkdf2:sha256");
});

test('SvelteKitUserClientEndpoints.deleteClient', async () => {
    const { server, resolver, handle } = await makeServer();

    // log in
    let resp = await login(server, resolver, handle);
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
    let event = new MockRequestEvent("1", getRequest, {client_id: "ABC"});
    event.locals.csrfToken = csrfToken;
    let status = 200;
    let resp1 : {[key:string]:any}|undefined = {};
    try {
        resp1 = await server.sessionServer?.userClientEndpoints.deleteClientEndpoint.load(event as any);
    } catch (e) {
        if (e && typeof(e) == "object"  && "status" in e && typeof(e.status) == "number") status = e.status;
    }
    expect(status).toBe(302);

    event = new MockRequestEvent("1", getRequest, {client_id: "ABC"});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    status = 200;
    try {
        resp1 = await server.sessionServer?.userClientEndpoints.deleteClientEndpoint.load(event as any);
    } catch (e) {
        if (e && typeof(e) == "object"  && "status" in e && typeof(e.status) == "number") status = e.status;
    }
    expect(status).toBe(401);

    event = new MockRequestEvent("1", getRequest, {client_id: "bob_ABC"});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    resp1 = await server.sessionServer?.userClientEndpoints.deleteClientEndpoint.load(event as any);
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
    event = new MockRequestEvent("1", postRequest, {client_id: "bob_ABC"});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    resp1 = await server.sessionServer?.userClientEndpoints.deleteClientEndpoint.actions.default(event as any);
    expect(resp1?.ok).toBe(true);
});

test('SvelteKitUserClientEndpoints.createClient', async () => {
    const { server, resolver, handle } = await makeServer();

    // log in
    let resp = await login(server, resolver, handle);
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
    let status = 302;
    let resp1 : {[key:string]:any}|undefined = {};
    try {
        resp1 = await server.sessionServer?.userClientEndpoints.createClientEndpoint.load(event as any);
    } catch (e) {
        if (e && typeof(e) == "object"  && "status" in e && typeof(e.status) == "number") status = e.status;
    }
    expect(status).toBe(302);

    event = new MockRequestEvent("1", getRequest, {});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    resp1 = await server.sessionServer?.userClientEndpoints.createClientEndpoint.load(event as any);
    expect(resp1?.ok).toBe(true);

    let postRequest = new Request("http://ex.com/oauth/clients", {
        method: "POST",
        body: "csrfToken="+csrfToken+"&client_name=newName&confidential=on&redirect_uri=http://uri1.com/redirect&authorizationCode=on",
        headers: [
            ["cookie", "CSRFTOKEN="+csrfCookieValue],
            ["cookie", "SESSIONID="+sessionCookieValue],
            ["content-type", "application/x-www-form-urlencoded"],
        ] 
        });
    event = new MockRequestEvent("1", postRequest, {client_id: "bob_ABC"});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    resp1 = await server.sessionServer?.userClientEndpoints.createClientEndpoint.actions.default(event as any);
    expect(resp1?.ok).toBe(true);
    expect(resp1?.client?.client_name).toBe("newName");
    expect(resp1?.plaintextSecret).toBeUndefined();
    expect(resp1?.client?.client_secret).not.toContain("pbkdf2:sha256");

});
