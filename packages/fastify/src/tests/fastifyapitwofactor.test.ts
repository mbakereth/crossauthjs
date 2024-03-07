import { beforeAll, afterEach, expect, test, vi } from 'vitest'
import path from 'path';
import fastify from 'fastify';
import { getTestUserStorage }  from './inmemorytestdata';
import { InMemoryUserStorage, InMemoryKeyStorage, LocalPasswordAuthenticator , TotpAuthenticator, EmailAuthenticator, SessionCookie } from '@crossauth/backend';
import { FastifyServer, type FastifyServerOptions } from '../fastifyserver';
import { CrossauthError } from '@crossauth/common';
import { authenticator as gAuthenticator } from 'otplib';

export var confirmEmailData :  {token : string, email : string, extraData: {[key:string]: any}};
export var emailTokenData :  {to: string, otp : string};

beforeAll(async () => {
});

async function makeAppWithOptions(options : FastifyServerOptions = {}) : Promise<{userStorage : InMemoryUserStorage, keyStorage : InMemoryKeyStorage, server: FastifyServer}> {
    const userStorage = await getTestUserStorage();
    const keyStorage = new InMemoryKeyStorage();
    let lpAuthenticator = new LocalPasswordAuthenticator(userStorage, {pbkdf2Iterations: 1_000});
    let totpAuthenticator = new TotpAuthenticator("FastifyTest");
    let emailAuthenticator = new EmailAuthenticator();
    emailAuthenticator["sendToken"] = async function (to: string, otp : string) {
        emailTokenData = {otp, to}
        return "1";
    };

    // create a fastify server and mock view to return its arguments
    const app = fastify({logger: false});
    const server = new FastifyServer(userStorage, {
        session: {
            keyStorage: keyStorage, 
            authenticators: {
                localpassword: lpAuthenticator,
                totp: totpAuthenticator,
                email: emailAuthenticator,
            }}}, {
            app: app,
            views: path.join(__dirname, '../views'),
            secret: "ABCDEFG",
            allowedFactor2: "none, totp, email",
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

async function createTotpAccount(server : FastifyServer) {

    let res;
    let body;

    const {csrfCookie, csrfToken} = await getCsrf(server);

    res = await server.app.inject({ method: "POST", url: "/api/signup", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        user_email: "mary@mary.com", 
        factor2: "totp",
        csrfToken: csrfToken
    } })
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);
    expect(body.totpSecret.length).toBeGreaterThan(1);

    const sessionCookie = getSession(res);
    const secret = body.totpSecret;
    // try twice as the code may be near expiry
    for (let tryNum=0; tryNum<2; ++tryNum) {
        const code = gAuthenticator.generate(secret);
        res = await server.app.inject({ method: "POST", url: "/api/configurefactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
            csrfToken: csrfToken,
            otp: code,
        } })
        body = JSON.parse(res.body)
        if (body.ok == true) break;
    }
    expect(body.ok).toBe(true);
    expect(body.user.username).toBe("mary");

};

async function createEmailAccount(server : FastifyServer) {

    let res;
    let body;

    const {csrfCookie, csrfToken} = await getCsrf(server);

    res = await server.app.inject({ method: "POST", url: "/api/signup", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        user_email: "mary@mary.com", 
        factor2: "email",
        csrfToken: csrfToken
    } })
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);

    const sessionCookie = getSession(res);
    const otp = emailTokenData.otp;
    res = await server.app.inject({ method: "POST", url: "/api/configurefactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        csrfToken: csrfToken,
        otp: otp
    } })
    body = JSON.parse(res.body)
    
    expect(body.ok).toBe(true);
    expect(body.user.username).toBe("mary");

};

async function loginEmail(server : FastifyServer) : Promise<{sessionCookie : string, csrfToken : string, csrfCookie: string}> {

    let res;
    let body;

    const {csrfCookie, csrfToken} = await getCsrf(server);

    res = await server.app.inject({ method: "POST", url: "/api/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        csrfToken: csrfToken
    } })
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);

    const sessionCookie = getSession(res);
    const otp = emailTokenData.otp;
    res = await server.app.inject({ method: "POST", url: "/api/configurefactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        csrfToken: csrfToken,
        otp: otp
    } })
    expect(body.ok).toBe(true);

    const sessionCookie1 = getSession(res);
    const {csrfCookie: csrfCookie1, csrfToken: csrfToken1} = await getCsrf(server);
    return {sessionCookie: sessionCookie1, csrfCookie: csrfCookie1, csrfToken: csrfToken1};
};

async function createNonTotpAccount(server : FastifyServer) {

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

};

test('FastifyServer.api.signupTotpWithoutEmailVerification', async () => {
    let {server} = await makeAppWithOptions({enableEmailVerification: false});

    await createTotpAccount(server);
});

test('FastifyServer.api.signupTotpWithEmailVerification', async () => {
    let {server} = await makeAppWithOptions({enableEmailVerification: true});
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

    const {csrfCookie, csrfToken} = await getCsrf(server);

    res = await server.app.inject({ method: "POST", url: "/api/signup", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        user_email: "mary@mary.com", 
        twoFactor: "on",
        csrfToken: csrfToken,
        factor2: "totp",
    } })
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);
    expect(body.totpSecret.length).toBeGreaterThan(1);

    const sessionCookie = getSession(res);
    const secret = body.totpSecret;
    // try twice as the code may be near expiry
    for (let tryNum=0; tryNum<2; ++tryNum) {
        const code = gAuthenticator.generate(secret);
        res = await server.app.inject({ method: "POST", url: "/api/configurefactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
            csrfToken: csrfToken,
            otp: code
        } })
        body = JSON.parse(res.body)
        if (body.ok == true) break;
    }
    expect(body.ok).toBe(true);
    expect(body.user.username).toBe("mary");
    expect(body.emailVerificationNeeded).toBe(true);

    // verify token
    const token = confirmEmailData.token;
    res = await server.app.inject({ method: "GET", url: "/api/verifyemail/" + token});
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);
});

test('FastifyServer.api.loginTotp', async () => {
    let {server, userStorage} = await makeAppWithOptions({enableEmailVerification: false});

    await createTotpAccount(server);

    let res;
    let body;

    const {csrfCookie, csrfToken} = await getCsrf(server);

    res = await server.app.inject({ method: "POST", url: "/api/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        csrfToken: csrfToken
    } })
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);

    const sessionCookie = getSession(res);
    const {secrets} = await userStorage.getUserByUsername("mary");
    // try twice as the code may be near expiry
    for (let tryNum=0; tryNum<2; ++tryNum) {
        const code = gAuthenticator.generate(secrets.totpSecret??"");
        res = await server.app.inject({ method: "POST", url: "/api/loginfactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
            csrfToken: csrfToken,
            otp: code
        } })
        body = JSON.parse(res.body)
        if (body.ok == true) break;
    }
    expect(body.ok).toBe(true);
    expect(body.user.username).toBe("mary");
});

test('FastifyServer.api.turnOnTotp', async () => {
    let {server, userStorage} = await makeAppWithOptions({enableEmailVerification: false});

    await createNonTotpAccount(server);

    let res;
    let body;

    const {csrfCookie, csrfToken} = await getCsrf(server);

    res = await server.app.inject({ method: "POST", url: "/api/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        csrfToken: csrfToken
    } })
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);

    const sessionCookie = getSession(res);
    const {csrfCookie: csrfCookie2, csrfToken: csrfToken2} = await getCsrf(server);

    res = await server.app.inject({ method: "POST", url: "/api/changefactor2", cookies: {SESSIONID: sessionCookie, CSRFTOKEN: csrfCookie2}, payload: {
        csrfToken: csrfToken2,
        factor2: "totp",
    } });
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);

    const secret = body.totpSecret;
    // try twice as the code may be near expiry
    for (let tryNum=0; tryNum<2; ++tryNum) {
        const code = gAuthenticator.generate(secret);
        res = await server.app.inject({ method: "POST", url: "/api/configurefactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
            csrfToken: csrfToken,
            otp: code,
        } })
        body = JSON.parse(res.body)
        if (body.ok == true) break;
    }
    expect(body.ok).toBe(true);
    expect(body.user.username).toBe("mary");
    const {user: changedUser} = await userStorage.getUserByUsername("mary");
    expect(changedUser.factor2).toBe("totp");
});

test('FastifyServer.api.turnOffTotp', async () => {
    let {server, userStorage} = await makeAppWithOptions({enableEmailVerification: false});

    await createTotpAccount(server);

    let res;
    let body;

    const {csrfCookie, csrfToken} = await getCsrf(server);

    res = await server.app.inject({ method: "POST", url: "/api/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        csrfToken: csrfToken
    } })
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);

    const sessionCookie = getSession(res);
    const {secrets} = await userStorage.getUserByUsername("mary");
    // try twice as the code may be near expiry
    for (let tryNum=0; tryNum<2; ++tryNum) {
        const code = gAuthenticator.generate(secrets.totpSecret??"");
        res = await server.app.inject({ method: "POST", url: "/api/loginfactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
            csrfToken: csrfToken,
            otp: code
        } })
        body = JSON.parse(res.body)
        if (body.ok == true) break;
    }
    expect(body.ok).toBe(true);
    expect(body.user.username).toBe("mary");

    const sessionCookie2 = getSession(res);
    const {csrfCookie: csrfCookie2, csrfToken: csrfToken2} = await getCsrf(server);

    res = await server.app.inject({ method: "POST", url: "/api/changefactor2", cookies: {SESSIONID: sessionCookie2, CSRFTOKEN: csrfCookie2}, payload: {
        csrfToken: csrfToken2,
        factor2: "none",
    } });
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);
    const {user: changedUser} = await userStorage.getUserByUsername("mary");
    expect(changedUser.factor2).toBe("");
});

test('FastifyServer.api.reconfigureTotp', async () => {
    let {server, userStorage} = await makeAppWithOptions({enableEmailVerification: false});

    await createTotpAccount(server);

    let res;
    let body;

    const {csrfCookie, csrfToken} = await getCsrf(server);

    res = await server.app.inject({ method: "POST", url: "/api/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        csrfToken: csrfToken
    } })
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);

    // login with original TOTP
    const sessionCookie = getSession(res);
    const {secrets} = await userStorage.getUserByUsername("mary");
    // try twice as the code may be near expiry
    for (let tryNum=0; tryNum<2; ++tryNum) {
        const code = gAuthenticator.generate(secrets.totpSecret??"");
        res = await server.app.inject({ method: "POST", url: "/api/loginfactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
            csrfToken: csrfToken,
            otp: code,
        } })
        body = JSON.parse(res.body)
        if (body.ok == true) break;
    }
    expect(body.ok).toBe(true);
    expect(body.user.username).toBe("mary");

    const sessionCookie2 = getSession(res);
    const {csrfCookie: csrfCookie2, csrfToken: csrfToken2} = await getCsrf(server);

    res = await server.app.inject({ method: "GET", url: "/api/configurefactor2", cookies: {SESSIONID: sessionCookie2, CSRFTOKEN: csrfCookie2}, payload: {
        csrfToken: csrfToken2,
    } });
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);

    const secret = body.totpSecret;
    // try twice as the code may be near expiry
    for (let tryNum=0; tryNum<2; ++tryNum) {
        const code = gAuthenticator.generate(secret);
        res = await server.app.inject({ method: "POST", url: "/api/configurefactor2", cookies: {CSRFTOKEN: csrfCookie2, SESSIONID: sessionCookie2}, payload: {
            csrfToken: csrfToken2,
            otp: code
        } })
        body = JSON.parse(res.body)
        if (body.ok == true) break;
    }
    expect(body.ok).toBe(true);
    const {user: changedUser, secrets: changedSecrets} = await userStorage.getUserByUsername("mary");
    expect(changedUser.factor2).toBe("totp");
    expect(changedSecrets.totpSecret).toBe(secret);
});

test('FastifyServer.api.signupEmailWithoutEmailVerification', async () => {
    let {server, userStorage} = await makeAppWithOptions({enableEmailVerification: false});

    await createEmailAccount(server);
    const {user} = await userStorage.getUserByUsername("mary");
    expect(user.factor2).toBe("email");
});

test('FastifyServer.api.signupEmailWithoutEmailVerificationWrongCode', async () => {
    let {server, userStorage} = await makeAppWithOptions({enableEmailVerification: false});
    let res;
    let body;

    const {csrfCookie, csrfToken} = await getCsrf(server);

    res = await server.app.inject({ method: "POST", url: "/api/signup", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        user_email: "mary@mary.com", 
        factor2: "email",
        csrfToken: csrfToken
    } })
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);

    const sessionCookie = getSession(res);
    const otp = "XXXXXX";
    res = await server.app.inject({ method: "POST", url: "/api/configurefactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        csrfToken: csrfToken,
        otp: otp
    } })
    body = JSON.parse(res.body)
    
    expect(body.ok).toBe(false);
    await expect(async () => {await userStorage.getUserByUsername("mary")}).rejects.toThrowError();
});

// Email verification should be skipped with this authenticator
test('FastifyServer.api.signupEmailWithEmailVerification', async () => {
    let {server, userStorage} = await makeAppWithOptions({enableEmailVerification: true});

    await createEmailAccount(server);
    const {user} = await userStorage.getUserByUsername("mary");
    expect(user.factor2).toBe("email");
    expect(user.state).toBe("active");
});

test('FastifyServer.api.loginEmail', async () => {
    let {server} = await makeAppWithOptions({enableEmailVerification: false});

    await createEmailAccount(server);

    let res;
    let body;

    const {csrfCookie, csrfToken} = await getCsrf(server);

    res = await server.app.inject({ method: "POST", url: "/api/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        csrfToken: csrfToken
    } })
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);

    const sessionCookie = getSession(res);
    const otp = emailTokenData.otp;
    res = await server.app.inject({ method: "POST", url: "/api/configurefactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        csrfToken: csrfToken,
        otp: otp
    } })
    expect(body.ok).toBe(true);
});

test('FastifyServer.api.turnOnEmail', async () => {
    let {server, userStorage} = await makeAppWithOptions({enableEmailVerification: false});

    await createNonTotpAccount(server);

    let res;
    let body;

    const {csrfCookie, csrfToken} = await getCsrf(server);

    res = await server.app.inject({ method: "POST", url: "/api/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        csrfToken: csrfToken
    } })
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);

    const sessionCookie = getSession(res);
    const {csrfCookie: csrfCookie2, csrfToken: csrfToken2} = await getCsrf(server);

    res = await server.app.inject({ method: "POST", url: "/api/changefactor2", cookies: {SESSIONID: sessionCookie, CSRFTOKEN: csrfCookie2}, payload: {
        csrfToken: csrfToken2,
        factor2: "email",
    } });
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);

    const otp = emailTokenData.otp;
    res = await server.app.inject({ method: "POST", url: "/api/configurefactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        csrfToken: csrfToken,
        otp: otp
    } });
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);
    expect(body.user.username).toBe("mary");
    const {user: changedUser} = await userStorage.getUserByUsername("mary");
    expect(changedUser.factor2).toBe("email");
});

test('FastifyServer.api.turnOffEmail', async () => {
    let {server, userStorage} = await makeAppWithOptions({enableEmailVerification: false});

    await createEmailAccount(server);

    let res;
    let body;

    const {csrfCookie, csrfToken} = await getCsrf(server);

    res = await server.app.inject({ method: "POST", url: "/api/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        csrfToken: csrfToken
    } })
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);

    const sessionCookie = getSession(res);
    const otp = emailTokenData.otp;
    res = await server.app.inject({ method: "POST", url: "/api/loginfactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        csrfToken: csrfToken,
        otp: otp
    } })
    expect(body.ok).toBe(true);
    expect(body.user.username).toBe("mary");
    expect(body.user.factor2).toBe("email");

    const sessionCookie2 = getSession(res);
    const {csrfCookie: csrfCookie2, csrfToken: csrfToken2} = await getCsrf(server);

    res = await server.app.inject({ method: "POST", url: "/api/changefactor2", cookies: {SESSIONID: sessionCookie2, CSRFTOKEN: csrfCookie2}, payload: {
        csrfToken: csrfToken2,
        factor2: "none",
    } });
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);
    const {user: changedUser} = await userStorage.getUserByUsername("mary");
    expect(changedUser.factor2).toBe("");
});

test('FastifyServer.api.loginEmailTokenExpired', async () => {
    let {server, keyStorage} = await makeAppWithOptions({enableEmailVerification: false});

    await createEmailAccount(server);

    let res;
    let body;

    const {csrfCookie, csrfToken} = await getCsrf(server);

    res = await server.app.inject({ method: "POST", url: "/api/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        csrfToken: csrfToken
    } })
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);

    const sessionCookie = getSession(res);
    const otp = emailTokenData.otp;
    // @ts-ignore we will ignore the possibilty of being undefined
    const sessionManager = server["sessionServer"]["sessionManager"];
    expect(sessionManager).toBeDefined();
    // @ts-ignore we will ignore the possibilty of being undefined
    const sessionData = (await sessionManager.dataForSessionKey(sessionCookie))["2fa"];
    const {key} = await sessionManager.userForSessionCookieValue(sessionCookie);
    expect(sessionData?.expiry).toBeDefined();
    // @ts-ignore we will ignore the possibilty of being undefined
    const now = Date.now();
    expect(sessionData?.expiry-now).toBeLessThan(1000*60*6);
    const expired = new Date(now-1000);
    sessionData.expiry = expired.getTime();
    await keyStorage.updateData(
        SessionCookie.hashSessionKey(key.value), 
        "2fa",
        sessionData);

    res = await server.app.inject({ method: "POST", url: "/api/loginfactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        csrfToken: csrfToken,
        otp: otp
    } })
    body = JSON.parse(res.body)
    expect(body.ok).toBe(false);
});

test('FastifyServer.api.signupEmailWithoutEmailVerificationExpiredCode', async () => {
    let {server, userStorage, keyStorage} = await makeAppWithOptions({enableEmailVerification: false});
    let res;
    let body;

    const {csrfCookie, csrfToken} = await getCsrf(server);

    res = await server.app.inject({ method: "POST", url: "/api/signup", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        user_email: "mary@mary.com", 
        factor2: "email",
        csrfToken: csrfToken
    } })
    body = JSON.parse(res.body)
    expect(body.ok).toBe(true);

    const sessionCookie = getSession(res);
    const otp = emailTokenData.otp;

    // @ts-ignore
    const sessionManager = server["sessionServer"]["sessionManager"];
    expect(sessionManager).toBeDefined();
    // @ts-ignore we will ignore the possibilty of being undefined
    const sessionData = (await sessionManager.dataForSessionKey(sessionCookie))["2fa"];
    const {key} = await sessionManager.userForSessionCookieValue(sessionCookie);
    expect(sessionData?.expiry).toBeDefined();
    // @ts-ignore we will ignore the possibilty of being undefined
    const now = Date.now();
    expect(sessionData?.expiry-now).toBeLessThan(1000*60*6);
    const expired = new Date(now-1000);
    sessionData.expiry = expired.getTime();
    await keyStorage.updateData(
        SessionCookie.hashSessionKey(key.value), 
        "2fa",
        sessionData);


    res = await server.app.inject({ method: "POST", url: "/api/configurefactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        csrfToken: csrfToken,
        otp: otp
    } })
    body = JSON.parse(res.body)
    
    expect(body.ok).toBe(false);
    await expect(async () => {await userStorage.getUserByUsername("mary")}).rejects.toThrowError();
});

test('FastifyServer.api.factor2ProtectedPage', async () => {

    let {server} = await makeAppWithOptions({enableEmailVerification: false});
    await createEmailAccount(server);
    const {sessionCookie, csrfToken, csrfCookie} = await loginEmail(server);  
    
    let res;
    let body;

    emailTokenData.otp = "";

    // request change password - expect to be asked for 2FA
    res = await server.app.inject({ method: "POST", url: "/api/changepassword", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        old_password: "maryPass123", 
        new_password: "newPass122",
        repeat_password: "newPass122",
        csrfToken: csrfToken,
    } });
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
    expect(body.factor2Required).toBe(true);

    const otp = emailTokenData.otp;
    expect(otp).not.toBe("");

    // enter otp
    res = await server.app.inject({ method: "POST", url: "/api/changepassword", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        otp: otp, 
        csrfToken: csrfToken,
    } });
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
});

test('FastifyServer.api.factor2ProtectedPageInvalidToken', async () => {

    let {server} = await makeAppWithOptions({enableEmailVerification: false});
    await createEmailAccount(server);
    const {sessionCookie, csrfToken, csrfCookie} = await loginEmail(server);  
    
    let res;
    let body;

    emailTokenData.otp = "";

    // request change password - expect to be asked for 2FA
    res = await server.app.inject({ method: "POST", url: "/api/changepassword", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        old_password: "maryPass123", 
        new_password: "newPass122",
        repeat_password: "newPass122",
        csrfToken: csrfToken,
    } });
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
    expect(body.factor2Required).toBe(true);

    const otp = "XXXXX";

    // enter otp
    res = await server.app.inject({ method: "POST", url: "/api/changepassword", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        otp: otp, 
        csrfToken: csrfToken,
    } });
    body = JSON.parse(res.body);
    expect(body.ok).toBe(false);
    expect(res.statusCode).toBe(401);
});
