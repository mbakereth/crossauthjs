import { beforeAll, afterEach, expect, test, vi } from 'vitest'
import path from 'path';
import fastify from 'fastify';
import { getTestUserStorage }  from './inmemorytestdata';
import { InMemoryUserStorage, InMemoryKeyStorage, LocalPasswordAuthenticator, TotpAuthenticator, Hasher, SessionCookie } from '@crossauth/backend';
import { FastifyServer, type FastifyServerOptions } from '../fastifyserver';
import { CrossauthError, ErrorCode } from '@crossauth/common';

//export var server : FastifyCookieAuthServer;
export var confirmEmailData :  {token : string, email : string, extraData: {[key:string]: any}};
export var passwordResetData :  {token : string, extraData: {[key:string]: any}};

beforeAll(async () => {
});

async function makeAppWithOptions(options : FastifyServerOptions = {}) : Promise<{userStorage : InMemoryUserStorage, keyStorage : InMemoryKeyStorage, server: FastifyServer}> {
    const userStorage = await getTestUserStorage();
    const keyStorage = new InMemoryKeyStorage();
    let lpAuthenticator = new LocalPasswordAuthenticator(userStorage, {
        pbkdf2Iterations: 1_000,
    });
    let totpAuthenticator = new TotpAuthenticator("FastifyTest");

    // create a fastify server and mock view to return its arguments
    const app = fastify({logger: false});
    const server = new FastifyServer(userStorage, {
        authenticators: {
            localpassword: lpAuthenticator,
            totp: totpAuthenticator,
        },
        session: {
            keyStorage: keyStorage, 
        }}, {
            app: app,
            views: path.join(__dirname, '../views'),
            secret: "ABCDEFG",
            allowedFactor2: "none, totp",
            siteUrl: `http://localhost:3000`,
            ...options,
        });
    // @ts-ignore
    app.decorateReply("view",  function(template, args) {
        return {template: template, args: args};
    });

    app.setErrorHandler(function (error, _request, reply) {
        // Log error
        //console.log(error)
        // Send error response
        const ce = CrossauthError.asCrossauthError(error);
        return reply.status(ce.httpStatus).send({ ok: false })
    })

    return {userStorage, keyStorage, server};
}

afterEach(async () => {
    vi.restoreAllMocks();
});

function getCsrf(res: any) : {csrfCookie: string, csrfToken: string} {
    const body = JSON.parse(res.body)
    const csrfCookies = res.cookies.filter((cookie: any) => {return cookie.name == "CSRFTOKEN"});
    expect(csrfCookies.length).toBe(1);
    const csrfCookie = csrfCookies[0].value;
    const csrfToken = body.args.csrfToken;
    expect(csrfToken).toBeDefined();
    return {csrfCookie, csrfToken};
}

function getSession(res: any) : string {
    const sessionCookies = res.cookies.filter((cookie: any) => {return cookie.name == "SESSIONID"});
    expect(sessionCookies.length).toBe(1);
    return sessionCookies[0].value;
}

async function login(server: FastifyServer,
    username: string = "admin",
    password: string = "adminPass123") {

    let res;
    let body;

    // Right page served 
    res = await server.app.inject({ method: "GET", url: "/login" })
    body = JSON.parse(res.body)
    expect(body.template).toBe("login.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);

    // successful login
    res = await server.app.inject({
        method: "POST",
        url: "/login",
        cookies: { CSRFTOKEN: csrfCookie },
        payload: { username: username, password: password, csrfToken: csrfToken }
    });
    expect(res.statusCode).toBe(302);
    const sessionCookie = getSession(res);
    return {csrfCookie, csrfToken, sessionCookie};

}

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
