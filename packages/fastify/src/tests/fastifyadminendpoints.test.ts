// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { beforeAll, afterEach, expect, test, vi } from 'vitest'
import { ErrorCode } from '@crossauth/common';
import { makeAppWithOptions, login } from './admincommon';

//export var server : FastifyCookieAuthServer;
export var confirmEmailData :  {token : string, email : string, extraData: {[key:string]: any}};
export var passwordResetData :  {token : string, extraData: {[key:string]: any}};

beforeAll(async () => {
});

afterEach(async () => {
    vi.restoreAllMocks();
});

test('FastifyServer.admin.createUser', async () => {
    const {server, userStorage} = await makeAppWithOptions();
    const {csrfCookie, csrfToken, sessionCookie} = await login(server);

    let res;

    res = await server.app.inject({
        method: "POST",
        url: "/admin/createuser",
        cookies: { CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie },
        payload: {
            username: "user1",
            password: "userPass123",
            repeatPassword: "userPass123",
            factor2: "none",
            csrfToken: csrfToken 
        }
    });
    expect(res.statusCode).toBe(302);
    expect(userStorage.getUserByUsername("user1")).toBeDefined();
});

test('FastifyServer.admin.createExistingUser', async () => {
    const {server} = await makeAppWithOptions();
    const {csrfCookie, csrfToken, sessionCookie} = await login(server);

    let res;
    let body;

    res = await server.app.inject({
        method: "POST",
        url: "/admin/createuser",
        cookies: { CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie },
        payload: {
            username: "admin",
            password: "adminPass123",
            repeatPassword: "adminPass123",
            factor2: "none",
            csrfToken: csrfToken 
        }
    });
    body = JSON.parse(res.body)
    expect(body.args.errorCode).toBe(ErrorCode.UserExists);
});

test('FastifyServer.admin.adminPermissions', async () => {
    const {server} = await makeAppWithOptions();
    const {csrfCookie, csrfToken, sessionCookie} = 
    await login(server, "bob", "bobPass123");

    let res;
    let body;

    res = await server.app.inject({
        method: "GET",
        url: "/admin/createuser",
        cookies: { CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie },
        payload: {
            username: "user1",
            password: "userPass123",
            repeatPassword: "userPass123",
            factor2: "none",
            csrfToken: csrfToken 
        }
    });
    expect(res.statusCode).toBe(401);
    body = JSON.parse(res.body)
    expect(body.template).toBe("error.njk")

    res = await server.app.inject({
        method: "POST",
        url: "/admin/createuser",
        cookies: { CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie },
        payload: {
            username: "user1",
            password: "userPass123",
            repeatPassword: "userPass123",
            factor2: "none",
            csrfToken: csrfToken 
        }
    });
    expect(res.statusCode).toBe(401);
    body = JSON.parse(res.body)
    expect(body.template).toBe("admin/createuser.njk");
});

test('FastifyServer.admin.updateUser', async () => {
    const {server, userStorage} = await makeAppWithOptions();
    const {csrfCookie, csrfToken, sessionCookie} = await login(server);

    let res;

    const {user} = await userStorage.getUserByUsername("bob");
    res = await server.app.inject({
        method: "POST",
        url: "/admin/updateuser/"+user.id,
        cookies: { CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie },
        payload: {
            username: "bob",
            user_email: "bob1@bob.com",
            csrfToken: csrfToken 
        }
    });
    expect(res.statusCode).toBe(200);
    const {user: editedUser} = await userStorage.getUserByUsername("bob");
    expect(editedUser.email).toBe("bob1@bob.com");
});

test('FastifyServer.admin.changePassword', async () => {
    const {server, userStorage} = await makeAppWithOptions();
    const {csrfCookie, csrfToken, sessionCookie} = await login(server);

    let res;

    const {user} = await userStorage.getUserByUsername("bob");
    res = await server.app.inject({
        method: "POST",
        url: "/admin/changepassword/"+user.id,
        cookies: { CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie },
        payload: {
            new_password: "bobPass12",
            repeat_password: "bobPass12",
            csrfToken: csrfToken 
        }
    });
    expect(res.statusCode).toBe(200);

    let loginSucceeded = false;
    try {
        await login(server, "bob", "bobPass123");
        loginSucceeded = true;
    } catch {}
    expect(loginSucceeded).toBe(false);

    loginSucceeded = false;
    try {
        await login(server, "bob", "bobPass12");
        loginSucceeded = true;
    } catch {}
    expect(loginSucceeded).toBe(true);
});

test('FastifyServer.admin.deleteUser', async () => {
    const {server, userStorage} = await makeAppWithOptions();
    const {sessionCookie, csrfCookie, csrfToken} = await login(server);

    let res;
    let body;

    const {user} = await userStorage.getUserByUsername("bob");

    res = await server.app.inject({
        method: "GET",
        url: "/admin/deleteuser/" + user.id,
        cookies: { SESSIONID: sessionCookie },
    });
    body = JSON.parse(res.body);
    expect(body.template).toBe("deleteuser.njk");

    res = await server.app.inject({
        method: "POST",
        url: "/admin/deleteuser/" + user.id,
        cookies: { CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie,  },
        payload: { csrfToken: csrfToken },
    });
    body = JSON.parse(res.body);
    expect(body.template).toBe("deleteuser.njk");
    expect(body.args.message).toBe("User deleted");

    let userStillExists = false;
    try {
        await userStorage.getUserByUsername(user.username);
        userStillExists = true;
    } catch {}
    expect(userStillExists).toBe(false);
});
