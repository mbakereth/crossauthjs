import { beforeAll, afterEach, expect, test, vi } from 'vitest'
import path from 'path';
import fastify from 'fastify';
import { getTestUserStorage }  from '../storage/tests/inmemorytestdata';
import { InMemoryUserStorage, InMemoryKeyStorage } from '../storage/inmemorystorage';
import { FastifyServer, type FastifyServerOptions } from '../middleware/fastifyserver';
import { LocalPasswordAuthenticator } from '../password';
import { TotpAuthenticator } from '../totp';
import { Hasher } from '../hasher';
import { SessionCookie } from '../cookieauth';
import { authenticator as gAuthenticator } from 'otplib';

export var confirmEmailData :  {token : string, email : string, extraData: {[key:string]: any}};

beforeAll(async () => {
});

async function makeAppWithOptions(options : FastifyServerOptions = {}) : Promise<{userStorage : InMemoryUserStorage, keyStorage : InMemoryKeyStorage, server: FastifyServer}> {
    const userStorage = await getTestUserStorage();
    const keyStorage = new InMemoryKeyStorage();
    let lpAuthenticator = new LocalPasswordAuthenticator(userStorage);
    let totpAuthenticator = new TotpAuthenticator("FastifyTest");

    // create a fastify server and mock view to return its arguments
    const app = fastify({logger: false});
    const server = new FastifyServer(userStorage, keyStorage, {
        localpassword: lpAuthenticator,
        totp: totpAuthenticator,
    }, {
        app: app,
        views: path.join(__dirname, '../views'),
        secret: "ABCDEFG",
        enableSessions: true,
        allowedFactor2: "totp",
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

test('FastifyServer.api.signupTotpWithoutEmailVerification', async () => {
    let {server} = await makeAppWithOptions({enableEmailVerification: false});

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
        res = await server.app.inject({ method: "POST", url: "/api/signupfactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
            csrfToken: csrfToken,
            totpCode: code
        } })
        body = JSON.parse(res.body)
        if (body.ok == true) break;
    }
    expect(body.ok).toBe(true);
    expect(body.user.username).toBe("mary");
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
        res = await server.app.inject({ method: "POST", url: "/api/signupfactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
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

