import { beforeAll, afterEach, expect, test, vi } from 'vitest'
import path from 'path';
import fastify from 'fastify';
import { getTestUserStorage }  from '../../storage/tests/inmemorytestdata';
import { InMemoryUserStorage, InMemoryKeyStorage } from '../../storage/inmemorystorage';
import { FastifyServer, type FastifyServerOptions } from '../fastifyserver';
import { LocalPasswordAuthenticator } from '../../password';
import { Hasher } from '../../hasher';
import { SessionCookie } from '../../cookieauth';
import Jimp from 'jimp';
import jsQR from 'jsqr';
import { authenticator as gAuthenticator } from 'otplib';


//export var server : FastifyCookieAuthServer;
export var confirmEmailData :  {token : string, email : string, extraData: {[key:string]: any}};
export var passwordResetData :  {token : string, extraData: {[key:string]: any}};

beforeAll(async () => {
});

async function makeAppWithOptions(options : FastifyServerOptions = {}) : Promise<{userStorage : InMemoryUserStorage, keyStorage : InMemoryKeyStorage, server: FastifyServer}> {
    const userStorage = await getTestUserStorage();
    const keyStorage = new InMemoryKeyStorage();
    let authenticator = new LocalPasswordAuthenticator(userStorage);

    // create a fastify server and mock view to return its arguments
    const app = fastify({logger: false});
    const server = new FastifyServer(userStorage, keyStorage, {localpassword: authenticator}, {
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

    app.setErrorHandler(function (error, _request, reply) {
        // Log error
        console.log(error)
        // Send error response
        return reply.status(409).send({ ok: false })
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
    server["sessionServer"]["sessionManager"]["tokenEmailer"]["_sendEmailVerificationToken"] = async function (token : string, email: string, extraData : {[key:string]:any}) {
        confirmEmailData = {token, email, extraData}
        return "1";
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
        repeat_password: "x",
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
        repeat_password: "maryPass123",
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
        repeat_password: "maryPass123",
        user_email: "mary@mary.com", 
        csrfToken: csrfToken
    } });
    expect(res.statusCode).toBe(302);
});

test('FastifyServer.wrongCsrf', async () => {

    let {server} = await makeAppWithOptions();
    if (!server["sessionServer"]) throw Error("Sessions not enabled");
    const csrfTokens = server["sessionServer"]["sessionManager"]["csrfTokens"];
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
    if (!server["sessionServer"]) throw Error("Sessions not enabled");
    const session = server["sessionServer"]["sessionManager"]["session"];
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
    server["sessionServer"]["sessionManager"]["tokenEmailer"]["_sendEmailVerificationToken"] = async function (token : string, email: string, extraData : {[key:string]:any}) {
        confirmEmailData = {token, email, extraData}
        return "1";
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
        old_password: "XXX", 
        new_password: "newPass123",
        repeat_password: "newPass123",
        csrfToken: csrfToken,
    } });
    body = JSON.parse(res.body);
    expect(res.statusCode).toBe(200);
    expect(body.args.errorCodeName).toBe("UsernameOrPasswordInvalid");

    // check empty password caught
    res = await server.app.inject({ method: "POST", url: "/changepassword", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        old_password: "bobPass123", 
        new_password: "",
        repeat_password: "",
        csrfToken: csrfToken,
    } });
    body = JSON.parse(res.body);
    expect(res.statusCode).toBe(200);
    expect(body.args.errorCodeName).toBe("PasswordFormat");

    // check mismatched passwords caught
    res = await server.app.inject({ method: "POST", url: "/changepassword", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        old_password: "bobPass123", 
        new_password: "newPass123",
        repeat_password: "YYY",
        csrfToken: csrfToken,
    } });
    body = JSON.parse(res.body);
    expect(res.statusCode).toBe(200);
    expect(body.args.errorCodeName).toBe("PasswordMatch");

    // check successful change
    res = await server.app.inject({ method: "POST", url: "/changepassword", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        old_password: "bobPass123", 
        new_password: "newPass123",
        repeat_password: "newPass123",
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
    server["sessionServer"]["sessionManager"]["tokenEmailer"]["_sendPasswordResetToken"] = async function (token : string, email: string, extraData : {[key:string]:any}) {
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
        new_password: "newPass123",
        repeat_password: "XXX",
        csrfToken: csrfToken,
    } });
    body = JSON.parse(res.body);
    expect(body.args.errorCodeName).toBe("PasswordMatch");

    // submit successful password reset
    res = await server.app.inject({ method: "POST", url: "/resetpassword", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        token: token, 
        new_password: "newPass123",
        repeat_password: "newPass123",
        csrfToken: csrfToken,
    } });
    body = JSON.parse(res.body);
    expect(body.args.message).toBeDefined();
    expect(body.args.errorCodeName).toBeUndefined();

    // log in with new password
    res = await server.app.inject({ method: "POST", url: "/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "bob", password: "newPass123", csrfToken: csrfToken} })
    expect(res.statusCode).toBe(302);
});

test('FastifyServer.signupTotpWithoutEmailVerification', async () => {

    let {server} = await makeAppWithOptions({enableEmailVerification: false});

    let res;
    let body;

    // Right page served 
    res = await server.app.inject({ method: "GET", url: "/signup" })
    body = JSON.parse(res.body)
    expect(body.template).toBe("signup.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);
    
    // get QR code and extract secret
    res = await server.app.inject({ method: "POST", url: "/signup", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        repeat_password: "maryPass123",
        user_email: "mary@mary.com", 
        csrfToken: csrfToken,
        twoFactor: "on",
    } });
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body);
    const secret = await getSecretFromQr(body);
    expect(secret).toBeDefined();

    const sessionCookie = getSession(res);
    // try twice as the code may be near expiry
    for (let tryNum=0; tryNum<2; ++tryNum) {
        const code = gAuthenticator.generate(secret||"");
        res = await server.app.inject({ method: "POST", url: "/signuptwofactor", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
            csrfToken: csrfToken,
            totpCode: code
        } })
        if (res.statusCode == 302) break;
    }
    expect(res.statusCode).toBe(302);


});

test('FastifyServer.signupTotpWithEmailVerification', async () => {

    let {server} = await makeAppWithOptions({enableEmailVerification: true});
    // @ts-ignore
    server["sessionServer"]["sessionManager"]["tokenEmailer"]["_sendEmailVerificationToken"] = async function (token : string, email: string, extraData : {[key:string]:any}) {
        confirmEmailData = {token, email, extraData}
        return "1";
    };

    let res;
    let body;

    // Right page served 
    res = await server.app.inject({ method: "GET", url: "/signup" })
    body = JSON.parse(res.body)
    expect(body.template).toBe("signup.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);
    
    // get QR code and extract secret
    res = await server.app.inject({ method: "POST", url: "/signup", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        repeat_password: "maryPass123",
        user_email: "mary@mary.com", 
        csrfToken: csrfToken,
        twoFactor: "on",
    } });
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body);
    const secret = await getSecretFromQr(body);
    expect(secret).toBeDefined();

    const sessionCookie = getSession(res);
    // try twice as the code may be near expiry
    for (let tryNum=0; tryNum<2; ++tryNum) {
        const code = gAuthenticator.generate(secret||"");
        res = await server.app.inject({ method: "POST", url: "/signuptwofactor", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
            csrfToken: csrfToken,
            totpCode: code
        } })
        if (res.statusCode == 200) break;
    }
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body)
    expect(body.args.message).toBeDefined();    
    // verify token
    const token = confirmEmailData.token;
    res = await server.app.inject({ method: "GET", url: "/verifyemail/" + token});
    body = JSON.parse(res.body)
    expect(body.template).toBe("emailverified.njk");

});

async function getSecretFromQr(body : {[key:string] : any}) {
    const qrParts = body.args.qr.split(",");
    expect (qrParts.length).toBe(2);
    expect(qrParts[0]).toBe("data:image/png;base64");
    let imageBuffer = Buffer.from(qrParts[1], 'base64');
    const image = await Jimp.read(imageBuffer);

    const imageData = {
        data: new Uint8ClampedArray(image.bitmap.data),
        width: image.bitmap.width,
        height: image.bitmap.height,
    };

    const decodedQR = jsQR(imageData.data, imageData.width, imageData.height);
    expect(decodedQR).not.toBeNull();
    if (decodedQR != null) {
        expect(decodedQR.data).toBeDefined();
        const dataParts = decodedQR.data.split("?");
        expect(dataParts.length).toBe(2);
        const args = dataParts[1].split("&");
        let secret : string|undefined = undefined;
        for (let i=0; i<args.length; ++i) {
            if (args[i].startsWith("secret=")) {
                const argParts = args[i].split("=");
                secret = argParts[1];
            }
        }
        return secret;

    }
}

