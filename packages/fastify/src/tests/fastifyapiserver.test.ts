import { beforeAll, afterEach, expect, test, vi } from 'vitest'
import path from 'path';
import fastify from 'fastify';
import { getTestUserStorage }  from './inmemorytestdata';
import { InMemoryUserStorage, InMemoryKeyStorage, LocalPasswordAuthenticator, TotpAuthenticator, EmailAuthenticator, Hasher, SessionCookie } from '@crossauth/backend';
import { FastifyServer, type FastifyServerOptions } from '../fastifyserver';
import { CrossauthError, ErrorCode } from '@crossauth/common';

export var confirmEmailData :  {token : string, email : string, extraData: {[key:string]: any}};
export var emailTokenData :  {to: string, token : string};

beforeAll(async () => {
});

async function makeAppWithOptions(options : FastifyServerOptions = {}) : Promise<{userStorage : InMemoryUserStorage, keyStorage : InMemoryKeyStorage, server: FastifyServer}> {
    const userStorage = await getTestUserStorage();
    const keyStorage = new InMemoryKeyStorage();
    let lpAuthenticator = new LocalPasswordAuthenticator(userStorage, {pbkdf2Iterations: 1_000});
    let totpAuthenticator = new TotpAuthenticator("FastifyTest");
    let emailAuthenticator = new EmailAuthenticator();
    emailAuthenticator["sendToken"] = async function (to: string, token : string) {
        emailTokenData = {token, to}
        return "1";
    };

    // create a fastify server and mock view to return its arguments
    const app = fastify({logger: false});
    const server = new FastifyServer(userStorage, {
        authenticators: {
            localpassword: lpAuthenticator,
            totp: totpAuthenticator,
            email: emailAuthenticator,
        },
        session: {
            keyStorage: keyStorage, 
        }}, {
            app: app,
            views: path.join(__dirname, '../views'),
            secret: "ABCDEFG",
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

test('FastifyServer.api.login', async () => {

    let {server} = await makeAppWithOptions();
    let res;

    // Get Csrf token 
    const {csrfCookie, csrfToken} = await getCsrf(server);

    // unauthorized
    res = await server.app.inject({ method: "POST", url: "/api/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "bob", password: "abc", csrfToken: csrfToken} })
    expect(res.statusCode).toBe(401);

    // successful login
    res = await server.app.inject({ method: "POST", url: "/api/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "bob", password: "bobPass123", csrfToken: csrfToken} })
    expect(res.statusCode).toBe(200);

});

test("FastifyServer.api.errorType", async () => {

    try {
        throw new CrossauthError(ErrorCode.PasswordInvalid);
    } catch (e) {
        const ce = CrossauthError.asCrossauthError(e);
        expect(ce instanceof CrossauthError).toBe(true);
    }
});

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

test('FastifyServer.api.signupWithEmailVerification', async () => {

    let {server} = await makeAppWithOptions({enableEmailVerification: true, passwordResetTextBody: "dummy"});

    // @ts-ignore
    if (!server["sessionServer"]) throw new Error("Sessions not enabled");
    if (!server["sessionServer"]["sessionManager"]) throw new Error("Sessions not enabled");
    if (!server["sessionServer"]["sessionManager"]["tokenEmailer"]) throw new Error("Sessions not enabled");
    server["sessionServer"]["sessionManager"]["tokenEmailer"]["_sendEmailVerificationToken"] = async function (token : string, email: string, extraData : {[key:string]:any}) {
        confirmEmailData = {token, email, extraData}
        return "1";
    };

    let res;
    let body;

    // Right page served 
    const {csrfCookie, csrfToken} = await getCsrf(server);

    // error page on password mismatch
    res = await server.app.inject({ method: "POST", url: "/api/signup", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        repeat_password: "x",
        user_email: "mary@mary.com", 
        csrfToken: csrfToken
    } })
    body = JSON.parse(res.body)
    expect(body.ok).toBe(false);
    
    // successful signup
    res = await server.app.inject({ method: "POST", url: "/api/signup", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        repeat_password: "maryPass123",
        user_email: "mary@mary.com", 
        factor1: "localpassword",
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

test('FastifyServer.api.signupWithoutEmailVerification', async () => {

    let {server} = await makeAppWithOptions({enableEmailVerification: false});

    let res;
    let body;

    // Right page served 
    const {csrfCookie, csrfToken} = await getCsrf(server);

    // error page on password mismatch
    res = await server.app.inject({ method: "POST", url: "/api/signup", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        repeat_password: "x",
        user_email: "mary@mary.com", 
        csrfToken: csrfToken
    } })
    body = JSON.parse(res.body)
    expect(body.ok).toBe(false);
    
    // successful signup
    res = await server.app.inject({ method: "POST", url: "/api/signup", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        repeat_password: "maryPass123",
        user_email: "mary@mary.com", 
        csrfToken: csrfToken
    } })
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);
    expect(body.user.state).toBe("active");
    expect(body.emailVerificationNeeded).toBe(false);
});

test('FastifyServer.api.wrongCsrf', async () => {

    let {server} = await makeAppWithOptions();
    if (!server["sessionServer"]) throw Error("Sessions not enabled");
    const csrfTokens = server["sessionServer"]["sessionManager"]["csrfTokens"];
    let res;
    let body;

    const {csrfCookie} = await getCsrf(server);
    const csrfToken = csrfTokens?.makeCsrfFormOrHeaderToken(Hasher.randomValue(16))

    // Error on invalid token
    res = await server.app.inject({ method: "POST", url: "/api/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "bob", password: "abc", csrfToken: csrfToken} })
    body = JSON.parse(res.body);
    expect(body.errorCodeName).toBe("InvalidCsrf");
    expect(body.ok).toBe(false);
    expect(res.statusCode).toBe(401);

    // error on invalid cookie
    const {csrfToken: csrfToken2} = await getCsrf(server);
    const csrfCookie2 = csrfTokens?.makeCsrfCookie(Hasher.randomValue(16));
    res = await server.app.inject({ method: "POST", url: "/api/login", cookies: {CSRFTOKEN: csrfCookie2?.value??""}, payload: {username: "bob", password: "abc", csrfToken: csrfToken2} })
    body = JSON.parse(res.body);
    expect(body.errorCodeName).toBe("InvalidCsrf");
    expect(body.ok).toBe(false);
    expect(res.statusCode).toBe(401);
});

test('FastifyServer.api.wrongSession', async () => {

    let {server, keyStorage} = await makeAppWithOptions();
    let res;
    let body;

    const {csrfCookie, csrfToken} = await getCsrf(server);

    // successful login
    res = await server.app.inject({ method: "POST", url: "/api/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "bob", password: "bobPass123", csrfToken: csrfToken} })
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
    const sessionCookie = getSession(res);

    // Right page served 
    res = await server.app.inject({ method: "POST", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, url: "/api/userforsessionkey" , payload: {
        csrfToken: csrfToken,
    }});
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);

    // expire session
    if (!server["sessionServer"]) throw Error("Sessions not enabled");
    const session = server["sessionServer"]["sessionManager"]["session"];
    if (!session) throw new Error("Sessions not enabled");
    const sessionId = session.unsignCookie(sessionCookie);
    const sessionHash = SessionCookie.hashSessionId(sessionId);
    const key = await keyStorage.getKey(sessionHash);
    keyStorage.updateKey({value: sessionHash, expires: new Date(key.created.getTime()-1000)});
    res = await server.app.inject({ method: "POST", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, url: "/api/userforsessionkey" , payload: {
        csrfToken: csrfToken,
    }});
    body = JSON.parse(res.body);
    expect(body.ok).toBe(false);
    expect(res.statusCode).toBe(401);

    // Invalid session ID
    const sessionCookie2 = Hasher.randomValue(16);
    keyStorage.updateKey({value: sessionHash, expires: new Date(key.created.getTime()-1000)});
    res = await server.app.inject({ method: "POST", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie2}, url: "/api/userforsessionkey" , payload: {
        csrfToken: csrfToken,
    }});
    body = JSON.parse(res.body);
    expect(body.ok).toBe(false);
    expect(res.statusCode).toBe(401);
});

test('FastifyServer.api.changeEmailWithoutVerification', async () => {

    let {server, userStorage} = await makeAppWithOptions({enableEmailVerification: false});

    let res;
    let body;

    const {csrfCookie, csrfToken} = await getCsrf(server);

    // login
    res = await server.app.inject({ method: "POST", url: "/api/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "bob", password: "bobPass123", csrfToken: csrfToken} })
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
    const sessionCookie = getSession(res);
    
    // successful email update
    res = await server.app.inject({ method: "POST", url: "/api/updateuser", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        user_email: "newbob@bob.com", 
        csrfToken: csrfToken
    } });
    body = JSON.parse(res.body);
    expect(res.statusCode).toBe(200);
    const {user: bob} = await userStorage.getUserByUsername("bob");
    expect(bob.email).toBe("newbob@bob.com");
});

test('FastifyServer.api.changeEmailWithVerification', async () => {

    let {server, userStorage} = await makeAppWithOptions({enableEmailVerification: true, emailVerificationTextBody: "dummy"});
    // @ts-ignore
    server["sessionServer"]["sessionManager"]["tokenEmailer"]["_sendEmailVerificationToken"] = async function (token : string, email: string, extraData : {[key:string]:any}) {
        confirmEmailData = {token, email, extraData}
        return "1";
    };

    let res;
    let body;

    const {csrfCookie, csrfToken} = await getCsrf(server);

    // login
    res = await server.app.inject({ method: "POST", url: "/api/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "bob", password: "bobPass123", csrfToken: csrfToken} })
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
    const sessionCookie = getSession(res);
    
    // successful email update
    res = await server.app.inject({ method: "POST", url: "/api/updateuser", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        user_email: "newbob@bob.com", 
        csrfToken: csrfToken
    } });
    body = JSON.parse(res.body);
    expect(res.statusCode).toBe(200);
    const {user: bob} = await userStorage.getUserByUsername("bob");
    expect(bob.email).toBe("bob@bob.com");

    // verify token
    expect(confirmEmailData.email).toBe("newbob@bob.com")
    const token = confirmEmailData.token;
    res = await server.app.inject({ method: "GET", url: "/api/verifyemail/" + token});
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);
    expect(res.statusCode).toBe(200);
    const {user: bob2} = await userStorage.getUserByUsername("bob");
    expect(bob2.email).toBe("newbob@bob.com");
});

test('FastifyServer.api.changePassword', async () => {

    let {server} = await makeAppWithOptions({enableEmailVerification: false});

    let res;
    let body;

    const {csrfCookie, csrfToken} = await getCsrf(server);

    // login
    res = await server.app.inject({ method: "POST", url: "/api/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "bob", password: "bobPass123", csrfToken: csrfToken} })
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);
    const sessionCookie = getSession(res);
    
    // check wrong password is caught
    res = await server.app.inject({ method: "POST", url: "/api/changepassword", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        old_password: "XXX", 
        new_password: "newPass123",
        repeat_password: "newPass123",
        csrfToken: csrfToken,
    } });
    body = JSON.parse(res.body);
    expect(res.statusCode).toBe(401);
    expect(body.errorCodeName).toBe("PasswordInvalid");

    // check empty password caught
    res = await server.app.inject({ method: "POST", url: "/api/changepassword", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        old_password: "bobPass123", 
        new_password: "",
        repeat_password: "",
        csrfToken: csrfToken,
    } });
    body = JSON.parse(res.body);
    expect(res.statusCode).toBe(401);
    expect(body.errorCodeName).toBe("PasswordFormat");

    // check mismatched passwords caught
    res = await server.app.inject({ method: "POST", url: "/api/changepassword", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        old_password: "bobPass123", 
        new_password: "newPass123",
        repeat_password: "YYY",
        csrfToken: csrfToken,
    } });
    body = JSON.parse(res.body);
    expect(res.statusCode).toBe(401);
    expect(body.errorCodeName).toBe("PasswordMatch");

    // check successful change
    res = await server.app.inject({ method: "POST", url: "/api/changepassword", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        old_password: "bobPass123", 
        new_password: "newPass123",
        repeat_password: "newPass123",
        csrfToken: csrfToken,
    } });
    body = JSON.parse(res.body);
    expect(res.statusCode).toBe(200);
    expect(body.ok).toBe(true);

    // check login with new password
    // login
    res = await server.app.inject({ method: "POST", url: "/api/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "bob", password: "newPass123", csrfToken: csrfToken} })
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
});
