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
export var passwordResetData :  {token : string, extraData: {[key:string]: any}};

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

test('FastifyServer.requestProtectedUrlsAsAnonymous', async () => {

    let {server} = await makeAppWithOptions();
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

    let {server} = await makeAppWithOptions();
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

    let {server} = await makeAppWithOptions({enableEmailVerification: true, emailVerificationTextBody: "dummy"});

    // @ts-ignore
    server["sessionManager"]["tokenEmailer"]["_sendEmailVerificationToken"] = async function (token : string, email: string, extraData : {[key:string]:any}) {
        confirmEmailData = {token, email, extraData}
    };

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
    expect(body.args.errorCodeName).toBe("PasswordMatch");
    
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

    // verify token
    const token = confirmEmailData.token;
    res = await server.app.inject({ method: "GET", url: "/verifyemail/" + token});
    body = JSON.parse(res.body)
    expect(body.template).toBe("emailverified.njk");
});

test('FastifyServer.signupWithoutEmailVerification', async () => {

    let {server} = await makeAppWithOptions({enableEmailVerification: false});

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

test('FastifyServer.wrongCsrf', async () => {

    let {server} = await makeAppWithOptions();
    const csrfTokens = server["sessionManager"]["csrfTokens"];
    let res;
    let body;

    // Right page served 
    res = await server.app.inject({ method: "GET", url: "/login" })
    body = JSON.parse(res.body);
    expect(body.template).toBe("login.njk");
    const {csrfCookie} = getCsrf(res);
    const csrfToken = csrfTokens?.makeCsrfFormOrHeaderToken(Hasher.randomValue(16))

    // Error on invalid token
    res = await server.app.inject({ method: "POST", url: "/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "bob", password: "abc", csrfToken: csrfToken} })
    body = JSON.parse(res.body);
    expect(body.args.errorCodeName).toBe("InvalidKey");

    // error on invalid cookie
    res = await server.app.inject({ method: "GET", url: "/login" })
    const {csrfToken: csrfToken2} = getCsrf(res);
    const csrfCookie2 = csrfTokens?.makeCsrfCookie(Hasher.randomValue(16));
    res = await server.app.inject({ method: "POST", url: "/login", cookies: {CSRFTOKEN: csrfCookie2?.value||""}, payload: {username: "bob", password: "abc", csrfToken: csrfToken2} })
    body = JSON.parse(res.body);
    expect(body.args.errorCodeName).toBe("InvalidKey");

});

test('FastifyServer.wrongSession', async () => {

    let {server, keyStorage} = await makeAppWithOptions();
    let res;
    let body;


    // Right page served 
    res = await server.app.inject({ method: "GET", url: "/login" })
    body = JSON.parse(res.body);
    expect(body.template).toBe("login.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);

    // successful login
    res = await server.app.inject({ method: "POST", url: "/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "bob", password: "bobPass123", csrfToken: csrfToken} })
    expect(res.statusCode).toBe(302);
    const sessionCookie = getSession(res);

    // Right page served 
    res = await server.app.inject({ method: "GET", cookies: {SESSIONID: sessionCookie}, url: "/changepassword" });
    body = JSON.parse(res.body);
    expect(body.template).toBe("changepassword.njk");

    // expire session
    const session = server["sessionManager"]["session"];
    if (!session) throw new Error("Sessions not enabled");
    const sessionId = session.unsignCookie(sessionCookie);
    const sessionHash = SessionCookie.hashSessionKey(sessionId);
    const key = await keyStorage.getKey(sessionHash);
    keyStorage.updateKey({value: sessionHash, expires: new Date(key.created.getTime()-1000)});
    res = await server.app.inject({ method: "GET", cookies: {SESSIONID: sessionCookie}, url: "/changepassword" });
    body = JSON.parse(res.body);
    expect(body.template).toBe("error.njk");
    expect(body.args.status).toBe(401);

    // Invalid session ID
    const sessionCookie2 = Hasher.randomValue(16);
    res = await server.app.inject({ method: "GET", cookies: {SESSIONID: sessionCookie2}, url: "/changepassword" });
    body = JSON.parse(res.body);
    expect(body.template).toBe("error.njk");
    expect(body.args.status).toBe(401);

});

test('FastifyServer.changeEmailWithoutVerification', async () => {

    let {server, userStorage} = await makeAppWithOptions({enableEmailVerification: false});

    let res;
    let body;

    // get login page for CRF token
    res = await server.app.inject({ method: "GET", url: "/login" })
    body = JSON.parse(res.body);
    expect(body.template).toBe("login.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);

    // login
    res = await server.app.inject({ method: "POST", url: "/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "bob", password: "bobPass123", csrfToken: csrfToken} })
    expect(res.statusCode).toBe(302);
    const sessionCookie = getSession(res);

    // Right page served 
    res = await server.app.inject({ method: "GET", url: "/updateuser", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie} })
    body = JSON.parse(res.body)
    expect(body.template).toBe("updateuser.njk");
    
    // successful email update
    res = await server.app.inject({ method: "POST", url: "/updateuser", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        user_email: "newbob@bob.com", 
        csrfToken: csrfToken
    } });
    body = JSON.parse(res.body);
    expect(res.statusCode).toBe(200);
    const {user: bob} = await userStorage.getUserByUsername("bob");
    expect(bob.email).toBe("newbob@bob.com");
});

test('FastifyServer.changeEmailWithVerification', async () => {

    let {server, userStorage} = await makeAppWithOptions({enableEmailVerification: true, emailVerificationTextBody: "dummy"});
    // @ts-ignore
    server["sessionManager"]["tokenEmailer"]["_sendEmailVerificationToken"] = async function (token : string, email: string, extraData : {[key:string]:any}) {
        confirmEmailData = {token, email, extraData}
    };

    let res;
    let body;

    // get login page for CSRF token
    res = await server.app.inject({ method: "GET", url: "/login" })
    body = JSON.parse(res.body);
    expect(body.template).toBe("login.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);

    // login
    res = await server.app.inject({ method: "POST", url: "/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "bob", password: "bobPass123", csrfToken: csrfToken} })
    expect(res.statusCode).toBe(302);
    const sessionCookie = getSession(res);

    // Right page served 
    res = await server.app.inject({ method: "GET", url: "/updateuser", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie} })
    body = JSON.parse(res.body)
    expect(body.template).toBe("updateuser.njk");
    
    // successful email update
    res = await server.app.inject({ method: "POST", url: "/updateuser", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
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
    res = await server.app.inject({ method: "GET", url: "/verifyemail/" + token});
    body = JSON.parse(res.body)
    expect(body.template).toBe("emailverified.njk");
    const {user: bob2} = await userStorage.getUserByUsername("bob");
    expect(bob2.email).toBe("newbob@bob.com");
});

test('FastifyServer.changePassword', async () => {

    let {server} = await makeAppWithOptions({enableEmailVerification: false});

    let res;
    let body;

    // get login page for CSRF token
    res = await server.app.inject({ method: "GET", url: "/login" })
    body = JSON.parse(res.body);
    expect(body.template).toBe("login.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);

    // login
    res = await server.app.inject({ method: "POST", url: "/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "bob", password: "bobPass123", csrfToken: csrfToken} })
    expect(res.statusCode).toBe(302);
    const sessionCookie = getSession(res);

    // Right page served 
    res = await server.app.inject({ method: "GET", url: "/changepassword", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie} })
    body = JSON.parse(res.body)
    expect(body.template).toBe("changepassword.njk");
    
    // check wrong password is caught
    res = await server.app.inject({ method: "POST", url: "/changepassword", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        oldPassword: "XXX", 
        newPassword: "newPass123",
        repeatPassword: "newPass123",
        csrfToken: csrfToken,
    } });
    body = JSON.parse(res.body);
    expect(res.statusCode).toBe(200);
    expect(body.args.errorCodeName).toBe("UsernameOrPasswordInvalid");

    // check empty password caught
    res = await server.app.inject({ method: "POST", url: "/changepassword", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        oldPassword: "bobPass123", 
        newPassword: "",
        repeatPassword: "",
        csrfToken: csrfToken,
    } });
    body = JSON.parse(res.body);
    expect(res.statusCode).toBe(200);
    expect(body.args.errorCodeName).toBe("PasswordFormat");

    // check mismatched passwords caught
    res = await server.app.inject({ method: "POST", url: "/changepassword", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        oldPassword: "bobPass123", 
        newPassword: "newPass123",
        repeatPassword: "YYY",
        csrfToken: csrfToken,
    } });
    body = JSON.parse(res.body);
    expect(res.statusCode).toBe(200);
    expect(body.args.errorCodeName).toBe("PasswordMatch");

    // check successful change
    res = await server.app.inject({ method: "POST", url: "/changepassword", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        oldPassword: "bobPass123", 
        newPassword: "newPass123",
        repeatPassword: "newPass123",
        csrfToken: csrfToken,
    } });
    body = JSON.parse(res.body);
    expect(res.statusCode).toBe(200);
    expect(body.args.errorCodeName).toBeUndefined();

    // check login with new password
    // login
    res = await server.app.inject({ method: "POST", url: "/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "bob", password: "newPass123", csrfToken: csrfToken} })
    expect(res.statusCode).toBe(302);
    
});

test('FastifyServer.passwordReset', async () => {

    let {server} = await makeAppWithOptions({enablePasswordReset: true, passwordResetTextBody: "dummy"});

    // @ts-ignore
    server["sessionManager"]["tokenEmailer"]["_sendPasswordResetToken"] = async function (token : string, email: string, extraData : {[key:string]:any}) {
        passwordResetData = {token, extraData}
    };

    let res;
    let body;

    // Right page served 
    res = await server.app.inject({ method: "GET", url: "/requestpasswordreset" })
    body = JSON.parse(res.body)
    expect(body.template).toBe("requestpasswordreset.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);

    
    // no email on wrong email
    passwordResetData = {token: "", extraData: {}};
    res = await server.app.inject({ method: "POST", url: "/requestpasswordreset", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        email: "no@email.com", 
        csrfToken: csrfToken
    } })
    body = JSON.parse(res.body)
    expect(body.template).toBe("requestpasswordreset.njk");
    expect(body.args.message).toBeDefined();
    expect(passwordResetData.token).toBe("");
    
    // send email with valid password
    res = await server.app.inject({ method: "POST", url: "/requestpasswordreset", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        email: "bob@bob.com", 
        csrfToken: csrfToken
    } })
    body = JSON.parse(res.body)
    expect(body.template).toBe("requestpasswordreset.njk");
    expect(body.args.message).toBeDefined();
    expect(passwordResetData.token).not.toBe("");

    // verify token
    const token = passwordResetData.token;
    res = await server.app.inject({ method: "GET", url: "/resetpassword/" + token});
    body = JSON.parse(res.body)
    expect(body.template).toBe("resetpassword.njk");

    // submit password reset with non matching passwords
    res = await server.app.inject({ method: "POST", url: "/resetpassword", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        token: token, 
        newPassword: "newPass123",
        repeatPassword: "XXX",
        csrfToken: csrfToken,
    } });
    body = JSON.parse(res.body);
    expect(body.args.errorCodeName).toBe("PasswordMatch");

    // submit successful password reset
    res = await server.app.inject({ method: "POST", url: "/resetpassword", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        token: token, 
        newPassword: "newPass123",
        repeatPassword: "newPass123",
        csrfToken: csrfToken,
    } });
    body = JSON.parse(res.body);
    expect(body.args.message).toBeDefined();
    expect(body.args.errorCodeName).toBeUndefined();

    // log in with new password
    res = await server.app.inject({ method: "POST", url: "/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "bob", password: "newPass123", csrfToken: csrfToken} })
    expect(res.statusCode).toBe(302);
});

