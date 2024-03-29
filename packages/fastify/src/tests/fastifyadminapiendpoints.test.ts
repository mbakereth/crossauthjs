import { beforeAll, afterEach, expect, test, vi } from 'vitest'
import { makeAppWithOptions, login } from './admincommon';

//export var server : FastifyCookieAuthServer;
export var confirmEmailData :  {token : string, email : string, extraData: {[key:string]: any}};
export var passwordResetData :  {token : string, extraData: {[key:string]: any}};

beforeAll(async () => {
});

afterEach(async () => {
    vi.restoreAllMocks();
});

test('FastifyServer.adminapi.createUser', async () => {

    const {server} = await makeAppWithOptions();
    const {csrfCookie, csrfToken, sessionCookie} = await login(server);

    let res;
    let body;

    res = await server.app.inject({
        method: "POST",
        url: "/admin/api/createuser",
        cookies: { CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie },
        payload: {
            username: "user1",
            password: "userPass123",
            repeatPassword: "userPass123",
            factor2: "none",
            csrfToken: csrfToken 
        }
    });
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
    expect(body.user.state).toBe("active");
    expect(body.emailVerificationNeeded).not.toBe(true);
});

test('FastifyServer.adminapi.adminPermissions', async () => {

    const {server} = await makeAppWithOptions();
    const {csrfCookie, csrfToken, sessionCookie} = 
        await login(server, "bob", "bobPass123");

    let res;
    let body;

    res = await server.app.inject({
        method: "POST",
        url: "/admin/api/createuser",
        cookies: { CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie },
        payload: {
            username: "user1",
            password: "userPass123",
            repeatPassword: "userPass123",
            factor2: "none",
            csrfToken: csrfToken 
        }
    });
    body = JSON.parse(res.body);
    expect(res.statusCode).toBe(401);
    expect(body.ok).toBe(false);
});

test('FastifyServer.adminapi.updateUser', async () => {

    const {server, userStorage} = await makeAppWithOptions();
    const {csrfCookie, csrfToken, sessionCookie} = await login(server);

    let res;
    let body;

    const {user} = await userStorage.getUserByUsername("bob");
    res = await server.app.inject({
        method: "POST",
        url: "/admin/api/updateuser/"+user.id,
        cookies: { CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie },
        payload: {
            user_email: "bob1@bob.com",
            csrfToken: csrfToken 
        }
    });
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
    const {user: editedUser} = await userStorage.getUserByUsername("bob");
    expect(editedUser.email).toBe("bob1@bob.com");
});

test('FastifyServer.adminapi.changePassword', async () => {

    const {server, userStorage} = await makeAppWithOptions();
    const {csrfCookie, csrfToken, sessionCookie} = await login(server);

    let res;
    let body;

    const {user} = await userStorage.getUserByUsername("bob");
    res = await server.app.inject({
        method: "POST",
        url: "/admin/api/changepassword/"+user.id,
        cookies: { CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie },
        payload: {
            new_password: "bobPass12",
            csrfToken: csrfToken 
        }
    });
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);

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
