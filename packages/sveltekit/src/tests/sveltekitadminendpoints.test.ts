import { MockRequestEvent } from './sveltemocks';
import { test, expect } from 'vitest';
import {  makeServer, getCsrfToken, login } from './testshared';
import { UserState } from '@crossauth/common';

export var passwordResetData :  {token : string, extraData: {[key:string]: any}};

test('SvelteKitAdminEndpoints.deleteUser', async () => {
    const { server, resolver, handle, userStorage } = await makeServer();

    // log in
    let resp = await login(server, resolver, handle, "admin", "adminPass123");
    let loginEvent = resp.event;
    loginEvent = resp.event;

    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);
    
    let sessionCookieValue = loginEvent.cookies.get("SESSIONID");
    let sessionId = server.sessionServer?.sessionManager.getSessionId(sessionCookieValue??"");

    // delete user
    let postRequest = new Request("http://ex.com/admin/users/delete", {
        method: "POST",
        body: "csrfToken="+csrfToken,
        headers: [
            ["cookie", "CSRFTOKEN="+csrfCookieValue],
            ["cookie", "SESSIONID="+sessionCookieValue],
            ["content-type", "application/x-www-form-urlencoded"],
        ] 
        });
    let event = new MockRequestEvent("1", postRequest, {id: "bob"});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    let resp1 = await server.sessionServer?.adminEndpoints.deleteUser(event);
    expect(resp1?.success).toBe(true);
    let found = false;
    try {
        await userStorage.getUserByUsername("bob");
        found = true;
    } catch (e) {}
    expect(found).toBe(false);

});

test('SvelteKitAdminEndpoints.createUser', async () => {
    const { server, resolver, handle, userStorage } = await makeServer();

    // log in
    let resp = await login(server, resolver, handle, "admin", "adminPass123");
    let loginEvent = resp.event;
    loginEvent = resp.event;

    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);
    
    let sessionCookieValue = loginEvent.cookies.get("SESSIONID");
    let sessionId = server.sessionServer?.sessionManager.getSessionId(sessionCookieValue??"");

    // create user
    let postRequest = new Request("http://ex.com/admin/users/create", {
        method: "POST",
        body: "csrfToken="+csrfToken + "&" +
            "username=mary&" +
            "password=maryPass123" +
            "repeat_password=maryPass123&" +
            "user_email=mary@mary.com&" +
            "user_phone=12345",
        headers: [
            ["cookie", "CSRFTOKEN="+csrfCookieValue],
            ["cookie", "SESSIONID="+sessionCookieValue],
            ["content-type", "application/x-www-form-urlencoded"],
        ] 
        });
    let event = new MockRequestEvent("1", postRequest, {});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    let resp1 = await server.sessionServer?.adminEndpoints.createUser(event)
    expect(resp1?.success).toBe(true);
    let found = false;
    try {
        await userStorage.getUserByUsername("mary");
        found = true;
    } catch (e) {}
    expect(found).toBe(true);

});

test('SvelteKitAdminEndpoints.createUserNoPassword', async () => {
    const { server, resolver, handle, userStorage } = await makeServer();

    // log in
    let resp = await login(server, resolver, handle, "admin", "adminPass123");
    let loginEvent = resp.event;
    loginEvent = resp.event;

    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);
    
    let sessionCookieValue = loginEvent.cookies.get("SESSIONID");
    let sessionId = server.sessionServer?.sessionManager.getSessionId(sessionCookieValue??"");

    // @ts-ignore
    server["sessionServer"]["sessionManager"]["tokenEmailer"]["_sendPasswordResetToken"] = async function (token : string, email: string, extraData : {[key:string]:any}) {
        passwordResetData = {token, extraData}
    };
    
    // create user
    let postRequest = new Request("http://ex.com/admin/users/create", {
        method: "POST",
        body: "csrfToken="+csrfToken + "&" +
            "username=mary&" +
            "user_email=mary@mary.com&" +
            "user_phone=12345",
        headers: [
            ["cookie", "CSRFTOKEN="+csrfCookieValue],
            ["cookie", "SESSIONID="+sessionCookieValue],
            ["content-type", "application/x-www-form-urlencoded"],
        ] 
        });
    let event = new MockRequestEvent("1", postRequest, {});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    let resp1 = await server.sessionServer?.adminEndpoints.createUser(event);
    expect(resp1?.success).toBe(true);
    let newUser = undefined;
    try {
        const resp2 = await userStorage.getUserByUsername("mary", {skipActiveCheck: true});
        newUser = resp2.user;
    } catch (e) {}
    expect(newUser).toBeDefined();
    expect(newUser?.state).toBe(UserState.passwordResetNeeded);

});

test('SvelteKitAdminEndpoints.createUserFactor2', async () => {
    const { server, resolver, handle, userStorage } = await makeServer();

    // log in
    let resp = await login(server, resolver, handle, "admin", "adminPass123");
    let loginEvent = resp.event;
    loginEvent = resp.event;

    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);
    
    let sessionCookieValue = loginEvent.cookies.get("SESSIONID");
    let sessionId = server.sessionServer?.sessionManager.getSessionId(sessionCookieValue??"");

    // create user
    let postRequest = new Request("http://ex.com/admin/users/create", {
        method: "POST",
        body: "csrfToken="+csrfToken + "&" +
            "username=mary&" +
            "user_email=mary@mary.com&" +
            "user_phone=12345&" +
            "password=maryPass123" +
            "repeat_password=maryPass123&" +
            "factor2=dummyFactor2",
        headers: [
            ["cookie", "CSRFTOKEN="+csrfCookieValue],
            ["cookie", "SESSIONID="+sessionCookieValue],
            ["content-type", "application/x-www-form-urlencoded"],
        ] 
        });
    let event = new MockRequestEvent("1", postRequest, {});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    let resp1 = await server.sessionServer?.adminEndpoints.createUser(event);
    expect(resp1?.success).toBe(true);
    let newUser = undefined;
    try {
        const resp2 = await userStorage.getUserByUsername("mary", {skipActiveCheck: true});
        newUser = resp2.user;
    } catch (e) {}
    expect(newUser).toBeDefined();
    expect(newUser?.state).toBe(UserState.factor2ResetNeeded);

});

test('SvelteKitAdminEndpoints.createUserFactor2NoPassword', async () => {
    const { server, resolver, handle, userStorage } = await makeServer();

    // log in
    let resp = await login(server, resolver, handle, "admin", "adminPass123");
    let loginEvent = resp.event;
    loginEvent = resp.event;

    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);
    
    let sessionCookieValue = loginEvent.cookies.get("SESSIONID");
    let sessionId = server.sessionServer?.sessionManager.getSessionId(sessionCookieValue??"");

    // @ts-ignore
    server["sessionServer"]["sessionManager"]["tokenEmailer"]["_sendPasswordResetToken"] = async function (token : string, email: string, extraData : {[key:string]:any}) {
        passwordResetData = {token, extraData}
    };
    
    // create user
    let postRequest = new Request("http://ex.com/admin/users/create", {
        method: "POST",
        body: "csrfToken="+csrfToken + "&" +
            "username=mary&" +
            "user_email=mary@mary.com&" +
            "user_phone=12345&" +
            "factor2=dummyFactor2",
        headers: [
            ["cookie", "CSRFTOKEN="+csrfCookieValue],
            ["cookie", "SESSIONID="+sessionCookieValue],
            ["content-type", "application/x-www-form-urlencoded"],
        ] 
        });
    let event = new MockRequestEvent("1", postRequest, {});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    let resp1 = await server.sessionServer?.adminEndpoints.createUser(event);
    expect(resp1?.success).toBe(true);
    let newUser = undefined;
    try {
        const resp2 = await userStorage.getUserByUsername("mary", {skipActiveCheck: true});
        newUser = resp2.user;
    } catch (e) {}
    expect(newUser).toBeDefined();
    expect(newUser?.state).toBe(UserState.passwordAndFactor2ResetNeeded);

});

test('SvelteKitAdminEndpoints.updateUser', async () => {
    const { server, resolver, handle, userStorage } = await makeServer();

    // log in
    let resp = await login(server, resolver, handle, "admin", "adminPass123");
    let loginEvent = resp.event;
    loginEvent = resp.event;

    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);
    
    let sessionCookieValue = loginEvent.cookies.get("SESSIONID");
    let sessionId = server.sessionServer?.sessionManager.getSessionId(sessionCookieValue??"");

    // create user
    let postRequest = new Request("http://ex.com/admin/users/edit", {
        method: "POST",
        body: "csrfToken="+csrfToken + "&" +
            "user_email=bob1@bob.com",
        headers: [
            ["cookie", "CSRFTOKEN="+csrfCookieValue],
            ["cookie", "SESSIONID="+sessionCookieValue],
            ["content-type", "application/x-www-form-urlencoded"],
        ] 
        });
    let event = new MockRequestEvent("1", postRequest, {id: "bob"});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;
    event.locals.authType = "cookie";
    event.locals.user = loginEvent.locals.user;
    const {user} = await userStorage.getUserByUsername("bob");
    let resp1 = await server.sessionServer?.adminEndpoints.updateUser(user, event)
    expect(resp1?.success).toBe(true);
    let newUser = undefined;
    try {
        const resp2 = await userStorage.getUserByUsername("bob");
        newUser = resp2.user;
    } catch (e) {}
    expect(newUser).toBeDefined();
    expect(newUser?.email).toBe("bob1@bob.com");

});
