import { beforeAll, afterEach, expect, test, vi } from 'vitest'
import path from 'path';
import fastify from 'fastify';
import { getTestUserStorage }  from '../../storage/tests/inmemorytestdata';
import { InMemoryUserStorage, InMemoryKeyStorage } from '../../storage/inmemorystorage';
import { FastifyCookieAuthServer, type FastifyCookieAuthServerOptions } from '../fastifyserver';
import { HashedPasswordAuthenticator } from '../../password';
import { Hasher } from '../../hasher';
import { SessionCookie } from '../../cookieauth';

//export var server : FastifyCookieAuthServer;
export var confirmEmailData :  {token : string, email : string, extraData: {[key:string]: any}};

beforeAll(async () => {
});

async function makeAppWithOptions(options : FastifyCookieAuthServerOptions = {}) : Promise<{userStorage : InMemoryUserStorage, keyStorage : InMemoryKeyStorage, server: FastifyCookieAuthServer}> {
    const userStorage = await getTestUserStorage();
    const keyStorage = new InMemoryKeyStorage();
    let authenticator = new HashedPasswordAuthenticator(userStorage);

    // create a fastify server and mock view to return its arguments
    const app = fastify({logger: false});
    const server = new FastifyCookieAuthServer(userStorage, keyStorage, authenticator, {
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

    return {userStorage, keyStorage, server};
}

afterEach(async () => {
    vi.restoreAllMocks();
});

async function getCsrf(server: any) : Promise<{csrfCookie: string, csrfToken: string}> {
    const res = await server.app.inject({ method: "GET", url: "/api/getcsrftoken" })
    const body = JSON.parse(res.body)
    expect(res.statusCode).toBe(200);
    const csrfCookies = res.cookies.filter((cookie: any) => {return cookie.name == "CSRFTOKEN"});
    expect(csrfCookies.length).toBe(1);
    const csrfCookie = csrfCookies[0].value;
    const csrfToken = body.csrfToken;
    expect(csrfToken).toBeDefined();
    return {csrfCookie, csrfToken};
}

function getSession(res: any) : string {
    const sessionCookies = res.cookies.filter((cookie: any) => {return cookie.name == "SESSIONID"});
    expect(sessionCookies.length).toBe(1);
    return sessionCookies[0].value;
}

test('FastifyServer.api.requestProtectedUrlsAsAnonymous', async () => {

    let {server} = await makeAppWithOptions();
    let res;

    // changepassword
    res = await server.app.inject({ method: "GET", url: "/api/changepassword" })
    expect(res.statusCode = 401);
    res = await server.app.inject({ method: "POST", url: "/api/changepassword" })
    expect(res.statusCode = 401);

    // updateuser
    res = await server.app.inject({ method: "GET", url: "/api/updateuser" })
    expect(res.statusCode = 401);
    res = await server.app.inject({ method: "POST", url: "/api/updateuser" })
    expect(res.statusCode = 401);

    // api/changepassword
    res = await server.app.inject({ method: "GET", url: "/api/api/changepassword" })
    expect(res.statusCode = 401);
    res = await server.app.inject({ method: "POST", url: "/api/api/changepassword" })
    expect(res.statusCode = 401);

    // api/updateuser
    res = await server.app.inject({ method: "GET", url: "/api/api/updateuser" })
    expect(res.statusCode = 401);
    res = await server.app.inject({ method: "POST", url: "/api/api/updateuser" })
    expect(res.statusCode = 401);

});

test('FastifyServer.api.login', async () => {

    let {server} = await makeAppWithOptions();
    let res;
    let body;

    // Get Csrf token 
    const {csrfCookie, csrfToken} = await getCsrf(server);

    // unauthorized
    res = await server.app.inject({ method: "POST", url: "/api/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "bob", password: "abc", csrfToken: csrfToken} })
    body = JSON.parse(res.body)
    expect(res.statusCode).toBe(401);

    // successful login
    res = await server.app.inject({ method: "POST", url: "/api/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "bob", password: "bobPass123", csrfToken: csrfToken} })
    expect(res.statusCode).toBe(200);

});

test('FastifyServer.api.signupWithEmailVerification', async () => {

    let {server} = await makeAppWithOptions({enableEmailVerification: true});

    // @ts-ignore
    server["sessionManager"]["tokenEmailer"]["_sendEmailVerificationToken"] = async function (token : string, email: string, extraData : {[key:string]:any}) {
        confirmEmailData = {token, email, extraData}
    };

    let res;
    let body;

    // Right page served 
    const {csrfCookie, csrfToken} = await getCsrf(server);

    // error page on password mismatch
    res = await server.app.inject({ method: "POST", url: "/api/signup", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        repeatPassword: "x",
        user_email: "mary@mary.com", 
        csrfToken: csrfToken
    } })
    body = JSON.parse(res.body)
    expect(body.ok).toBe(false);
    
    // successful signup
    res = await server.app.inject({ method: "POST", url: "/api/signup", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        repeatPassword: "maryPass123",
        user_email: "mary@mary.com", 
        csrfToken: csrfToken
    } })
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);
    expect(body.emailVerificationNeeded).toBe(true);

    // verify token
    const token = confirmEmailData.token;
    res = await server.app.inject({ method: "GET", url: "/api/verifyemail/" + token});
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);
});
