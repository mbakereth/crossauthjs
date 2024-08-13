import { MockRequestEvent } from './sveltemocks';
import { test, expect } from 'vitest';
import {  makeServer, getCsrfToken, login } from './testshared';
import { UserState } from '@crossauth/common';
import createFetchMock from 'vitest-fetch-mock';

export var passwordResetData :  {token : string, extraData: {[key:string]: any}};

test('SvelteKitAdminClientEndpoints.selectClients_user', async () => {
    const { server, resolver, handle, clientStorage } = await makeServer();

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
    expect(resp1?.success).toBe(true);
    expect(resp1?.clients?.length).toBe(1);

});

test('SvelteKitAdminClientEndpoints.selectClients_all', async () => {
    const { server, resolver, handle, clientStorage } = await makeServer();

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
    expect(resp1?.success).toBe(true);
    expect(resp1?.clients?.length).toBe(2);

});
