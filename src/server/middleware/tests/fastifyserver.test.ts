import { beforeAll, afterEach, expect, test, vi } from 'vitest'
import path from 'path';
import fastify from 'fastify';
import { getTestUserStorage }  from '../../storage/tests/inmemorytestdata';
import { InMemoryUserStorage, InMemoryKeyStorage } from '../../storage/inmemorystorage';
import { FastifyCookieAuthServer, type FastifyCookieAuthServerOptions } from '../fastifyserver';
import { HashedPasswordAuthenticator } from '../../password';

export var userStorage : InMemoryUserStorage;
export var keyStorage = new InMemoryKeyStorage();
//export var server : FastifyCookieAuthServer;
export var data = {};

beforeAll(async () => {
    // for all these tests, the database will have two users: bob and alice
    userStorage = await getTestUserStorage();
    keyStorage = new InMemoryKeyStorage();
});

function makeAppWithOptions(options : FastifyCookieAuthServerOptions = {}) {
    let authenticator = new HashedPasswordAuthenticator(userStorage);

    // create a fastify server and mock view to return its arguments
    let app = fastify({logger: false});
    let server = new FastifyCookieAuthServer(userStorage, keyStorage, authenticator, {
        app: app,
        views: path.join(__dirname, '../views'),
        secret: "ABCDEFG",
        enableSessions: true,
        ...options,
    });
    // @ts-ignore
    app.decorateReply("view",  function(template, args) {
        return {template: template, args: args};
    });

    // @ts-ignore
    server["sessionManager"]["tokenEmailer"]["_sendEmailVerificationToken"] = async function (token : string, email: string, extraData : {[key:string]:any}) {
            data = {token, email, extraData}
        };
    return server;
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

test('FastifyServer.anonymousGets', async () => {

    let server = makeAppWithOptions();
    let res;
    let body;

    // signup 
    res = await server.app.inject({ method: "GET", url: "/signup" })
    body = JSON.parse(res.body)
    expect(body.template).toBe("signup.njk");

    res = await server.app.inject({ method: "GET", url: "/changepassword" })
    expect(res.statusCode = 401);
});

test('FastifyServer.requestProtectedUrlsAsAnonymous', async () => {

    let server = makeAppWithOptions();
    let res;

    // changepassword
    res = await server.app.inject({ method: "GET", url: "/changepassword" })
    expect(res.statusCode = 401);
    res = await server.app.inject({ method: "POST", url: "/changepassword" })
    expect(res.statusCode = 401);

    // updateuser
    res = await server.app.inject({ method: "GET", url: "/updateuser" })
    expect(res.statusCode = 401);
    res = await server.app.inject({ method: "POST", url: "/updateuser" })
    expect(res.statusCode = 401);

    // api/changepassword
    res = await server.app.inject({ method: "GET", url: "/api/changepassword" })
    expect(res.statusCode = 401);
    res = await server.app.inject({ method: "POST", url: "/api/changepassword" })
    expect(res.statusCode = 401);

    // api/updateuser
    res = await server.app.inject({ method: "GET", url: "/api/updateuser" })
    expect(res.statusCode = 401);
    res = await server.app.inject({ method: "POST", url: "/api/updateuser" })
    expect(res.statusCode = 401);

});

test('FastifyServer.login', async () => {

    let server = makeAppWithOptions();
    let res;
    let body;

    // Right page served 
    res = await server.app.inject({ method: "GET", url: "/login" })
    body = JSON.parse(res.body)
    expect(body.template).toBe("login.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);

    // error page on wrong password
    res = await server.app.inject({ method: "POST", url: "/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "bob", password: "abc", csrfToken: csrfToken} })
    body = JSON.parse(res.body)
    expect(body.template).toBe("login.njk");

    // successful login
    res = await server.app.inject({ method: "POST", url: "/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "bob", password: "bobPass123", csrfToken: csrfToken} })
    expect(res.statusCode).toBe(302);

});

test('FastifyServer.signupWithEmailVerification', async () => {

    let server = makeAppWithOptions({enableEmailVerification: true});

    let res;
    let body;

    // Right page served 
    res = await server.app.inject({ method: "GET", url: "/signup" })
    body = JSON.parse(res.body)
    expect(body.template).toBe("signup.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);

    // error page on password mismatch
    res = await server.app.inject({ method: "POST", url: "/signup", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        repeatPassword: "x",
        user_email: "mary@mary.com", 
        csrfToken: csrfToken
    } })
    body = JSON.parse(res.body)
    expect(body.template).toBe("signup.njk");
    expect(body.args.codeName).toBe("PasswordMatch");
    
    // successful signup
    res = await server.app.inject({ method: "POST", url: "/signup", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        repeatPassword: "maryPass123",
        user_email: "mary@mary.com", 
        csrfToken: csrfToken
    } })
    body = JSON.parse(res.body)
    expect(body.template).toBe("signup.njk");
    expect(body.args.message).toBeDefined();
    await userStorage.deleteUserByUsername("mary");
});

test('FastifyServer.signupWithoutEmailVerification', async () => {

    let server = makeAppWithOptions({enableEmailVerification: false});

    let res;
    let body;

    // Right page served 
    res = await server.app.inject({ method: "GET", url: "/signup" })
    body = JSON.parse(res.body)
    expect(body.template).toBe("signup.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);
    
    // successful signup
    res = await server.app.inject({ method: "POST", url: "/signup", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        repeatPassword: "maryPass123",
        user_email: "mary@mary.com", 
        csrfToken: csrfToken
    } });
    expect(res.statusCode).toBe(302);
});
