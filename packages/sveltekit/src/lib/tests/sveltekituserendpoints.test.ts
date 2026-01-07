// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { MockRequestEvent } from './sveltemocks';
import { test, expect } from 'vitest';
import {  makeServer, getCsrfToken, login } from './testshared';

export var passwordResetData :  {token : string, extraData: {[key:string]: any}};

test('SvelteKitUserEndpoints.login', async () => {
    const { server, resolver, handle } = await makeServer();
    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);

    const postRequest = new Request("http://ex.com/test", {
        method: "POST",
        body: "csrfToken="+csrfToken+"&username=bob&password=bobPass123",
        headers: { 
            "cookie": "CSRFTOKEN="+csrfCookieValue,
            "content-type": "application/x-www-form-urlencoded",
        }});
    let event = new MockRequestEvent("1", postRequest, {"param1": "value1"});
    event.locals.csrfToken = csrfToken;

    const ret = await server.sessionServer?.userEndpoints.login(event as any);
    expect(ret?.user?.username).toBe("bob");
    expect(event.cookies.get("SESSIONID")).toBeDefined();
});

test('SvelteKitUserEndpoints.logout', async () => {
    const { server, resolver, handle } = await makeServer();
    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);

    let postRequest = new Request("http://ex.com/test", {
        method: "POST",
        body: "csrfToken="+csrfToken+"&username=bob&password=bobPass123",
        headers: { 
            "cookie": "CSRFTOKEN="+csrfCookieValue,
            "content-type": "application/x-www-form-urlencoded",
        }});
    let event = new MockRequestEvent("1", postRequest, {"param1": "value1"});
    event.locals.csrfToken = csrfToken;

    let ret = await server.sessionServer?.userEndpoints.login(event as any);
    expect(ret?.user?.username).toBe("bob");
    expect(event.cookies.get("SESSIONID")).toBeDefined();

    postRequest = new Request("http://ex.com/test", {
        method: "POST",
        body: "csrfToken="+csrfToken+"&username=bob&password=bobPass123",
        headers: { 
            "cookie": "CSRFTOKEN="+csrfCookieValue,
            "content-type": "application/x-www-form-urlencoded",
        }});
    event = new MockRequestEvent("1", postRequest, {"param1": "value1"});
    event.locals.csrfToken = csrfToken;

    ret = await server.sessionServer?.userEndpoints.logout(event as any);
    expect(ret?.user).toBeUndefined();
    expect(event.cookies.get("SESSIONID")).toBeUndefined();
});

test('SvelteKitUserEndpoints.resetPassword', async () => {
    const { server, resolver, handle } = await makeServer();

    // log in
    await login(server, resolver, handle, "alice", "alicePass123");

    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);

    // @ts-ignore
    server["sessionServer"]["sessionManager"]["tokenEmailer"]["_sendPasswordResetToken"] = async function (token : string, email: string, extraData : {[key:string]:any}) {
        passwordResetData = {token, extraData}
    };
    
    // request password reset
    let postRequest = new Request("http://ex.com/passwordreset", {
        method: "POST",
        body: "csrfToken="+csrfToken+"&email=bob@bob.com",
        headers: { 
            "cookie": "CSRFTOKEN="+csrfCookieValue,
            "content-type": "application/x-www-form-urlencoded",
        }});
    let event = new MockRequestEvent("1", postRequest, {});
    event.locals.csrfToken = csrfToken;
    event.cookies.set("CSRFTOKEN", csrfCookieValue, {path: "/"});
    let resp1 = await server.sessionServer?.userEndpoints.requestPasswordReset(event as any);
    expect(resp1?.ok).toBe(true);
    const token = passwordResetData.token;

    // submit password reset
    postRequest = new Request("http://ex.com/passwordreset/"+token, {
        method: "POST",
        body: "csrfToken="+csrfToken+"&new_password='ABCabc123'&repeat_password='ABCabc123'",
        headers: { 
            "cookie": "CSRFTOKEN="+csrfCookieValue,
            "content-type": "application/x-www-form-urlencoded",
        }});
    event = new MockRequestEvent("1", postRequest, {token: token});
    event.locals.csrfToken = csrfToken;
    event.cookies.set("CSRFTOKEN", csrfCookieValue, {path: "/"});
    resp1 = await server.sessionServer?.userEndpoints.resetPassword(event as any);
    expect(resp1?.ok).toBe(true);

});

test('SvelteKitUserEndpoints.changePassword', async () => {
    const { server, resolver, handle } = await makeServer();

    // log in
    let resp = await login(server, resolver, handle, "bob", "bobPass123");
    let loginEvent = resp.event;
    loginEvent = resp.event;

    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);
    
    let sessionCookieValue = loginEvent.cookies.get("SESSIONID");
    let sessionId = server.sessionServer?.sessionManager.getSessionId(sessionCookieValue??"");

    // change password
    let postRequest = new Request("http://ex.com/changepassword", {
        method: "POST",
        body: "csrfToken="+csrfToken+"&old_password=bobPass123&new_password=bobPass12&repeat_password=bobPass12",
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
    let resp1 = await server.sessionServer?.userEndpoints.changePassword(event as any);
    expect(resp1?.ok).toBe(true);

});

test('SvelteKitUserEndpoints.deleteUser', async () => {
    const { server, resolver, handle, userStorage } = await makeServer();

    // log in
    let resp = await login(server, resolver, handle, "bob", "bobPass123");
    let loginEvent = resp.event;
    loginEvent = resp.event;

    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);
    
    let sessionCookieValue = loginEvent.cookies.get("SESSIONID");
    let sessionId = server.sessionServer?.sessionManager.getSessionId(sessionCookieValue??"");

    // delete user
    let postRequest = new Request("http://ex.com/deleteuser", {
        method: "POST",
        body: "csrfToken="+csrfToken,
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
    let resp1 = await server.sessionServer?.userEndpoints.deleteUser(event as any);
    expect(resp1?.ok).toBe(true);
    let found = false;
    try {
        await userStorage.getUserByUsername("bob");
        found = true;
    } catch (e) {}
    expect(found).toBe(false);

});
