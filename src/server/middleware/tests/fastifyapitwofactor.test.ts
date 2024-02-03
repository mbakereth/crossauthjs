import { beforeAll, afterEach, expect, test, vi } from 'vitest'
import path from 'path';
import fastify from 'fastify';
import { getTestUserStorage }  from '../../storage/tests/inmemorytestdata';
import { InMemoryUserStorage, InMemoryKeyStorage } from '../../storage/inmemorystorage';
import { FastifyServer, type FastifyServerOptions } from '../fastifyserver';
import { LocalPasswordAuthenticator } from '../../authenticators/passwordauth';
import { TotpAuthenticator } from '../../authenticators/totpauth';
import { EmailAuthenticator } from '../../authenticators/emailauth';
import { CrossauthError } from '../../..';
import { authenticator as gAuthenticator } from 'otplib';

export var confirmEmailData :  {token : string, email : string, extraData: {[key:string]: any}};
export var emailTokenData :  {to: string, token : string};

beforeAll(async () => {
});

async function makeAppWithOptions(options : FastifyServerOptions = {}) : Promise<{userStorage : InMemoryUserStorage, keyStorage : InMemoryKeyStorage, server: FastifyServer}> {
    const userStorage = await getTestUserStorage();
    const keyStorage = new InMemoryKeyStorage();
    let lpAuthenticator = new LocalPasswordAuthenticator(userStorage);
    let totpAuthenticator = new TotpAuthenticator("FastifyTest");
    let emailAuthenticator = new EmailAuthenticator();
    emailAuthenticator["sendToken"] = async function (to: string, token : string) {
        emailTokenData = {token, to}
        return "1";
    };

    // create a fastify server and mock view to return its arguments
    const app = fastify({logger: false});
    const server = new FastifyServer(userStorage, keyStorage, {
        localpassword: lpAuthenticator,
        totp: totpAuthenticator,
        email: emailAuthenticator
    }, {
        app: app,
        views: path.join(__dirname, '../views'),
        secret: "ABCDEFG",
        enableSessions: true,
        allowedFactor2: "none, totp, email",
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
            totpCode: code
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
    const token = emailTokenData.token;
    res = await server.app.inject({ method: "POST", url: "/api/configurefactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        csrfToken: csrfToken,
        token: token
    } })
    body = JSON.parse(res.body)
    
    expect(body.ok).toBe(true);
    expect(body.user.username).toBe("mary");

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
            totpCode: code
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
        const code = gAuthenticator.generate(secrets.totpSecret||"");
        res = await server.app.inject({ method: "POST", url: "/api/loginfactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
            csrfToken: csrfToken,
            totpCode: code
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
            totpCode: code
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
        const code = gAuthenticator.generate(secrets.totpSecret||"");
        res = await server.app.inject({ method: "POST", url: "/api/loginfactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
            csrfToken: csrfToken,
            totpCode: code
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
        const code = gAuthenticator.generate(secrets.totpSecret||"");
        res = await server.app.inject({ method: "POST", url: "/api/loginfactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
            csrfToken: csrfToken,
            totpCode: code
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
            totpCode: code
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
    const token = "XXXXXX";
    res = await server.app.inject({ method: "POST", url: "/api/configurefactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        csrfToken: csrfToken,
        token: token
    } })
    body = JSON.parse(res.body)
    
    expect(body.ok).toBe(false);
    await expect(async () => {await userStorage.getUserByUsername("mary")}).rejects.toThrowError(CrossauthError);
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
    const token = emailTokenData.token;
    res = await server.app.inject({ method: "POST", url: "/api/configurefactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        csrfToken: csrfToken,
        token: token
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

    const token = emailTokenData.token;
    res = await server.app.inject({ method: "POST", url: "/api/configurefactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        csrfToken: csrfToken,
        token: token
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
    const token = emailTokenData.token;
    res = await server.app.inject({ method: "POST", url: "/api/loginfactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        csrfToken: csrfToken,
        token: token
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
