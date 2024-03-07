import { beforeAll, afterEach, expect, test, vi } from 'vitest'
import path from 'path';
import fastify from 'fastify';
import { getTestUserStorage }  from './inmemorytestdata';
import { InMemoryUserStorage, InMemoryKeyStorage, TotpAuthenticator, EmailAuthenticator, LocalPasswordAuthenticator, Hasher } from '@crossauth/backend';
import { FastifyServer, type FastifyServerOptions } from '../fastifyserver';
import Jimp from 'jimp';
import jsQR from 'jsqr';
import { authenticator as gAuthenticator } from 'otplib';
import { CrossauthError } from '@crossauth/common';

//export var server : FastifyCookieAuthServer;
export var confirmEmailData :  {token : string, email : string, extraData: {[key:string]: any}};
export var passwordResetData :  {token : string, extraData: {[key:string]: any}};
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

async function createTotpAccount(server : FastifyServer) {

    let res;
    let body;

    res = await server.app.inject({ method: "GET", url: "/login" })
    const {csrfCookie, csrfToken} = await getCsrf(res);

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
            otp: code
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

    // Right page served 
    res = await server.app.inject({ method: "GET", url: "/signup" })
    body = JSON.parse(res.body)
    expect(body.template).toBe("signup.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);
    
    // step one of signup
    res = await server.app.inject({ method: "POST", url: "/signup", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        repeat_password: "maryPass123",
        user_email: "mary@mary.com", 
        csrfToken: csrfToken,
        factor2: "email",
    } });
    expect(res.statusCode).toBe(200);

    // step 2 of signup - send otp
    const otp = emailTokenData.otp;
    const sessionCookie = getSession(res);
    res = await server.app.inject({ method: "POST", url: "/configurefactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        csrfToken: csrfToken,
        otp: otp
    } })

    // check was successful
    expect(res.statusCode).toBe(302);

};

async function loginEmail(server : FastifyServer) : Promise<{sessionCookie: string, csrfCookie: string, csrfToken: string}>{

    let res;
    let body;

    // Right page served 
    res = await server.app.inject({ method: "GET", url: "/login" })
    body = JSON.parse(res.body)
    expect(body.template).toBe("login.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);


    // successful login first factor
    res = await server.app.inject({ method: "POST", url: "/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "mary", password: "maryPass123", csrfToken: csrfToken} })
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body)
    expect(body.template).toBe("factor2.njk");

    // successful login second factor
    const sessionCookie = getSession(res);
    const otp = emailTokenData.otp;
    res = await server.app.inject({ method: "POST", url: "/loginfactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        csrfToken: csrfToken,
        otp: otp
    } })

    expect(res.statusCode).toBe(302);

    // Go to a safe page to get the csrf token
    const sessionCookie2 = getSession(res);
    res = await server.app.inject({ method: "GET", url: "/login" })
    body = JSON.parse(res.body)
    expect(body.template).toBe("login.njk");
    
    const {csrfCookie: csrfCookie2, csrfToken: csrfToken2} = getCsrf(res);
    return {sessionCookie: sessionCookie2, csrfCookie: csrfCookie2, csrfToken: csrfToken2 }

};

async function createNonTotpAccount(server : FastifyServer) {

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
        csrfToken: csrfToken,
        factor2: "none",
    } });
    expect(res.statusCode).toBe(302);

};

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
        factor2: "totp",
    } });
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body);
    const secret = await getSecretFromQr(body);
    expect(secret).toBeDefined();

    const sessionCookie = getSession(res);
    // try twice as the code may be near expiry
    for (let tryNum=0; tryNum<2; ++tryNum) {
        const code = gAuthenticator.generate(secret??"");
        res = await server.app.inject({ method: "POST", url: "/configurefactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
            csrfToken: csrfToken,
            otp: code,
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
        factor2: "totp",
    } });
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body);
    const secret = await getSecretFromQr(body);
    expect(secret).toBeDefined();

    const sessionCookie = getSession(res);
    // try twice as the code may be near expiry
    for (let tryNum=0; tryNum<2; ++tryNum) {
        const code = gAuthenticator.generate(secret??"");
        res = await server.app.inject({ method: "POST", url: "/configurefactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
            csrfToken: csrfToken,
            otp: code,
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

test('FastifyServer.loginTotp', async () => {

    let {server, userStorage} = await makeAppWithOptions();

    await createTotpAccount(server);

    let res;
    let body;

    // Right page served 
    res = await server.app.inject({ method: "GET", url: "/login" })
    body = JSON.parse(res.body)
    expect(body.template).toBe("login.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);


    // successful login first factor
    res = await server.app.inject({ method: "POST", url: "/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "mary", password: "maryPass123", csrfToken: csrfToken} })
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body)
    expect(body.template).toBe("factor2.njk");

    const sessionCookie = getSession(res);
    const {secrets} = await userStorage.getUserByUsername("mary");
    // try twice as the code may be near expiry
    for (let tryNum=0; tryNum<2; ++tryNum) {
        const code = gAuthenticator.generate(secrets.totpSecret??"");
        res = await server.app.inject({ method: "POST", url: "/loginfactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
            csrfToken: csrfToken,
            otp: code,
        } })
        if (res.statusCode == 302) break;
    }
    expect(res.statusCode).toBe(302);
    //expect(body.user.username).toBe("mary");
});

test('FastifyServer.turnOnTotp', async () => {

    let {server, userStorage} = await makeAppWithOptions({enableEmailVerification: false});

    await createNonTotpAccount(server);

    let res;
    let body;

    // get login page 
    res = await server.app.inject({ method: "GET", url: "/login" })
    body = JSON.parse(res.body)
    expect(body.template).toBe("login.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);


    // successful login 
    res = await server.app.inject({ method: "POST", url: "/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "mary", password: "maryPass123", csrfToken: csrfToken} })
    expect(res.statusCode).toBe(302);

    const session2 = getSession(res);

    // get changefactor2 page
    res = await server.app.inject({ method: "GET", url: "/changefactor2", cookies: {SESSIONID: session2} })
    body = JSON.parse(res.body)
    expect(body.template).toBe("changefactor2.njk");
    const {csrfCookie: csrfCookie2, csrfToken: csrfToken2} = getCsrf(res);
    
    // submit change request
    res = await server.app.inject({ method: "POST", url: "/changefactor2", cookies: {SESSIONID: session2, CSRFTOKEN: csrfCookie2}, payload: {
        csrfToken: csrfToken2,
        factor2: "totp"
    }})
    body = JSON.parse(res.body)
    expect(body.template).toBe("configurefactor2.njk");

    //configure TOTP
    const secret = body.args.totpSecret;
    // try twice as the code may be near expiry
    for (let tryNum=0; tryNum<2; ++tryNum) {
        const code = gAuthenticator.generate(secret);
        res = await server.app.inject({ method: "POST", url: "configurefactor2", cookies: {CSRFTOKEN: csrfCookie2, SESSIONID: session2}, payload: {
            csrfToken: csrfToken2,
            otp: code,
        } })
        if (res.statusCode == 200) break;
    }
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body)
    expect(body.args.message).toBeDefined();
    const {user} = await userStorage.getUserByUsername("mary");
    expect(user.factor2).toBe("totp");
});

test('FastifyServer.turnOffTotp', async () => {

    let {server, userStorage} = await makeAppWithOptions({
        enableEmailVerification: false,
        factor2ProtectedApiEndpoints: "",
        factor2ProtectedPageEndpoints: "",
    });

    await createTotpAccount(server);

    let res;
    let body;

    // Right page served 
    res = await server.app.inject({ method: "GET", url: "/login" })
    body = JSON.parse(res.body)
    expect(body.template).toBe("login.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);


    // successful login first factor
    res = await server.app.inject({ method: "POST", url: "/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "mary", password: "maryPass123", csrfToken: csrfToken} })
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body)
    expect(body.template).toBe("factor2.njk");

    const sessionCookie = getSession(res);
    const {secrets} = await userStorage.getUserByUsername("mary");
    // try twice as the code may be near expiry
    for (let tryNum=0; tryNum<2; ++tryNum) {
        const code = gAuthenticator.generate(secrets.totpSecret??"");
        res = await server.app.inject({ method: "POST", url: "/loginfactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
            csrfToken: csrfToken,
            otp: code
        } })
        if (res.statusCode == 302) break;
    }
    expect(res.statusCode).toBe(302);
    //expect(body.user.username).toBe("mary");
    const {user} = await userStorage.getUserByUsername("mary");
    expect(user.factor2).toBe("totp");

    const session2 = getSession(res);

    // get changefactor2 page
    res = await server.app.inject({ method: "GET", url: "/changefactor2", cookies: {SESSIONID: session2} })
    body = JSON.parse(res.body)
    expect(body.template).toBe("changefactor2.njk");
    const {csrfCookie: csrfCookie2, csrfToken: csrfToken2} = getCsrf(res);

    // submit change request
    res = await server.app.inject({ method: "POST", url: "/changefactor2", cookies: {SESSIONID: session2, CSRFTOKEN: csrfCookie2}, payload: {
        csrfToken: csrfToken2,
        factor2: "none"
    }})
    body = JSON.parse(res.body)
    expect(body.template).toBe("configurefactor2.njk");
    expect(body.args.message).toBeDefined();
});

test('FastifyServer.reconfigureTotp', async () => {

    let {server, userStorage} = await makeAppWithOptions({enableEmailVerification: false});

    await createTotpAccount(server);

    let res;
    let body;

    // Right page served 
    res = await server.app.inject({ method: "GET", url: "/login" })
    body = JSON.parse(res.body)
    expect(body.template).toBe("login.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);


    // successful login first factor
    res = await server.app.inject({ method: "POST", url: "/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "mary", password: "maryPass123", csrfToken: csrfToken} })
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body)
    expect(body.template).toBe("factor2.njk");

    const sessionCookie = getSession(res);
    const {secrets} = await userStorage.getUserByUsername("mary");
    // try twice as the code may be near expiry
    for (let tryNum=0; tryNum<2; ++tryNum) {
        const code = gAuthenticator.generate(secrets.totpSecret??"");
        res = await server.app.inject({ method: "POST", url: "/loginfactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
            csrfToken: csrfToken,
            otp: code,
        } })
        if (res.statusCode == 302) break;
    }
    expect(res.statusCode).toBe(302);
    //expect(body.user.username).toBe("mary");
    const {user} = await userStorage.getUserByUsername("mary");
    expect(user.factor2).toBe("totp");

    const session2 = getSession(res);

    // get changefactor2 page
    res = await server.app.inject({ method: "GET", url: "/configurefactor2", cookies: {SESSIONID: session2} })
    body = JSON.parse(res.body)
    expect(body.template).toBe("configurefactor2.njk");
    const {csrfCookie: csrfCookie2, csrfToken: csrfToken2} = getCsrf(res);

    //configure TOTP
    const secret = body.args.totpSecret;
    // try twice as the code may be near expiry
    for (let tryNum=0; tryNum<2; ++tryNum) {
        const code = gAuthenticator.generate(secret);
        res = await server.app.inject({ method: "POST", url: "configurefactor2", cookies: {CSRFTOKEN: csrfCookie2, SESSIONID: session2}, payload: {
            csrfToken: csrfToken2,
            otp: code,
        } })
        if (res.statusCode == 200) break;
    }
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body)
    expect(body.args.message).toBeDefined();
    const {user: user2, secrets: secrets2} = await userStorage.getUserByUsername("mary");
    expect(user2.factor2).toBe("totp");
    expect(secrets2.totpSecret).toBe(secret);
});

test('FastifyServer.signupEmailWithoutEmailVerification', async () => {

    let {server, userStorage} = await makeAppWithOptions({enableEmailVerification: false});

    let res;
    let body;

    // Right page served 
    res = await server.app.inject({ method: "GET", url: "/signup" })
    body = JSON.parse(res.body)
    expect(body.template).toBe("signup.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);
    
    // step one of signup
    res = await server.app.inject({ method: "POST", url: "/signup", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        repeat_password: "maryPass123",
        user_email: "mary@mary.com", 
        csrfToken: csrfToken,
        factor2: "email",
    } });
    expect(res.statusCode).toBe(200);

    // step 2 of signup - send otp
    const otp = emailTokenData.otp;
    const sessionCookie = getSession(res);
    res = await server.app.inject({ method: "POST", url: "/configurefactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        csrfToken: csrfToken,
        otp: otp
    } })

    // check was successful
    expect(res.statusCode).toBe(302);
    const {user} = await userStorage.getUserByUsername("mary");
    expect(user.state).toBe("active");
    expect(user.factor2).toBe("email");
});

// email verification should be skipped
test('FastifyServer.signupEmailWithEmailVerification', async () => {

    let {server, userStorage} = await makeAppWithOptions({enableEmailVerification: true});

    let res;
    let body;

    // Right page served 
    res = await server.app.inject({ method: "GET", url: "/signup" })
    body = JSON.parse(res.body)
    expect(body.template).toBe("signup.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);
    
    // step one of signup
    res = await server.app.inject({ method: "POST", url: "/signup", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        username: "mary", 
        password: "maryPass123", 
        repeat_password: "maryPass123",
        user_email: "mary@mary.com", 
        csrfToken: csrfToken,
        factor2: "email",
    } });
    expect(res.statusCode).toBe(200);

    // step 2 of signup - send otp
    const otp = emailTokenData.otp;
    const sessionCookie = getSession(res);
    res = await server.app.inject({ method: "POST", url: "/configurefactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        csrfToken: csrfToken,
        otp: otp
    } })

    // check was successful
    expect(res.statusCode).toBe(302);
    const {user} = await userStorage.getUserByUsername("mary");
    expect(user.state).toBe("active");
    expect(user.factor2).toBe("email");
});

test('FastifyServer.loginEmail', async () => {

    let {server} = await makeAppWithOptions({enableEmailVerification: false});

    await createEmailAccount(server);

    let res;
    let body;

    // Right page served 
    res = await server.app.inject({ method: "GET", url: "/login" })
    body = JSON.parse(res.body)
    expect(body.template).toBe("login.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);


    // successful login first factor
    res = await server.app.inject({ method: "POST", url: "/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "mary", password: "maryPass123", csrfToken: csrfToken} })
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body)
    expect(body.template).toBe("factor2.njk");

    // successful login second factor
    const sessionCookie = getSession(res);
    const otp = emailTokenData.otp;
    res = await server.app.inject({ method: "POST", url: "/loginfactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        csrfToken: csrfToken,
        otp: otp
    } })

    expect(res.statusCode).toBe(302);
    //expect(body.user.username).toBe("mary");
});

test('FastifyServer.turnOnEmail', async () => {

    let {server, userStorage} = await makeAppWithOptions({enableEmailVerification: false});

    await createNonTotpAccount(server);

    let res;
    let body;

    // get login page 
    res = await server.app.inject({ method: "GET", url: "/login" })
    body = JSON.parse(res.body)
    expect(body.template).toBe("login.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);


    // successful login 
    res = await server.app.inject({ method: "POST", url: "/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "mary", password: "maryPass123", csrfToken: csrfToken} })
    expect(res.statusCode).toBe(302);

    const session2 = getSession(res);

    // get changefactor2 page
    res = await server.app.inject({ method: "GET", url: "/changefactor2", cookies: {SESSIONID: session2} })
    body = JSON.parse(res.body)
    expect(body.template).toBe("changefactor2.njk");
    const {csrfCookie: csrfCookie2, csrfToken: csrfToken2} = getCsrf(res);
    
    // submit change request
    res = await server.app.inject({ method: "POST", url: "/changefactor2", cookies: {SESSIONID: session2, CSRFTOKEN: csrfCookie2}, payload: {
        csrfToken: csrfToken2,
        factor2: "email"
    }})
    body = JSON.parse(res.body)
    expect(body.template).toBe("configurefactor2.njk");

    //configure email
    const otp = emailTokenData.otp;
    res = await server.app.inject({ method: "POST", url: "/configurefactor2", cookies: {CSRFTOKEN: csrfCookie2, SESSIONID: session2}, payload: {
        csrfToken: csrfToken2,
        otp: otp
    } })

    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body)
    expect(body.args.message).toBeDefined();
    const {user} = await userStorage.getUserByUsername("mary");
    expect(user.factor2).toBe("email");
});

test('FastifyServer.totpToEmail', async () => {

    let {server, userStorage} = await makeAppWithOptions({
        factor2ProtectedPageEndpoints: "",
        factor2ProtectedApiEndpoints: "",
        enableEmailVerification: false,
    });

    await createTotpAccount(server);

    let res;
    let body;

    // Right page served 
    res = await server.app.inject({ method: "GET", url: "/login" })
    body = JSON.parse(res.body)
    expect(body.template).toBe("login.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);


    // successful login first factor
    res = await server.app.inject({ method: "POST", url: "/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "mary", password: "maryPass123", csrfToken: csrfToken} })
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body)
    expect(body.template).toBe("factor2.njk");

    const sessionCookie = getSession(res);
    const {secrets} = await userStorage.getUserByUsername("mary");
    // try twice as the code may be near expiry
    for (let tryNum=0; tryNum<2; ++tryNum) {
        const code = gAuthenticator.generate(secrets.totpSecret??"");
        res = await server.app.inject({ method: "POST", url: "/loginfactor2", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
            csrfToken: csrfToken,
            otp: code
        } })
        if (res.statusCode == 302) break;
    }
    expect(res.statusCode).toBe(302);
    //expect(body.user.username).toBe("mary");
    const {user} = await userStorage.getUserByUsername("mary");
    expect(user.factor2).toBe("totp");

    const session2 = getSession(res);

    // get changefactor2 page
    res = await server.app.inject({ method: "GET", url: "/changefactor2", cookies: {SESSIONID: session2} })
    body = JSON.parse(res.body)
    expect(body.template).toBe("changefactor2.njk");
    const {csrfCookie: csrfCookie2, csrfToken: csrfToken2} = getCsrf(res);

    // submit change request
    res = await server.app.inject({ method: "POST", url: "/changefactor2", cookies: {SESSIONID: session2, CSRFTOKEN: csrfCookie2}, payload: {
        csrfToken: csrfToken2,
        factor2: "email"
    }})
    body = JSON.parse(res.body)
    expect(body.template).toBe("configurefactor2.njk");

    //configure email
    const otp = emailTokenData.otp;
    res = await server.app.inject({ method: "POST", url: "/configurefactor2", cookies: {CSRFTOKEN: csrfCookie2, SESSIONID: session2}, payload: {
        csrfToken: csrfToken2,
        otp: otp
    } })

    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body)
    expect(body.args.message).toBeDefined();
    const {user: user2} = await userStorage.getUserByUsername("mary");
    expect(user2.factor2).toBe("email");
});

test('FastifyServer.factor2ProtectedPage', async () => {
    let {server, userStorage} = await makeAppWithOptions({enableEmailVerification: false});

    let res;
    let body;

    await createEmailAccount(server);
    const {sessionCookie, csrfCookie, csrfToken} = await loginEmail(server);

    // get change password page
    res = await server.app.inject({ method: "GET", url: "/changepassword", cookies: {SESSIONID: sessionCookie} })
    body = JSON.parse(res.body)
    expect(body.template).toBe("changepassword.njk");

    emailTokenData.otp = "";

    // submit change password
    res = await server.app.inject({ method: "POST", url: "/changepassword", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        old_password: "maryPass123", 
        new_password: "newPass123",
        repeat_password: "newPass123",
        csrfToken: csrfToken,
    } });
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toBe("/factor2");

    // get factor2 page
    res = await server.app.inject({ method: "GET", url: "/factor2", cookies: {SESSIONID: sessionCookie} })
    body = JSON.parse(res.body)
    expect(body.template).toBe("factor2.njk");

    expect(emailTokenData.otp).not.toBe("");

    // submit changepassword page
    res = await server.app.inject({ method: "POST", url: "/changepassword", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        otp: emailTokenData.otp, 
        csrfToken: csrfToken,
    } });
    expect(res.statusCode).toBe(200);
    const {secrets} = await userStorage.getUserByUsername("mary");
    const passwordsEqual = await Hasher.passwordsEqual("newPass123", secrets.password??"");
    expect(passwordsEqual).toBe(true);
});

test('FastifyServer.factor2ProtectedPageWrongPassword', async () => {
    let {server, userStorage} = await makeAppWithOptions({enableEmailVerification: false});

    let res;
    let body;

    await createEmailAccount(server);
    const {sessionCookie, csrfCookie, csrfToken} = await loginEmail(server);

    // get change password page
    res = await server.app.inject({ method: "GET", url: "/changepassword", cookies: {SESSIONID: sessionCookie} })
    body = JSON.parse(res.body)
    expect(body.template).toBe("changepassword.njk");

    emailTokenData.otp = "";

    // submit change password
    res = await server.app.inject({ method: "POST", url: "/changepassword", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        old_password: "wrongPass123", 
        new_password: "newPass123",
        repeat_password: "newPass123",
        csrfToken: csrfToken,
    } });
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toBe("/factor2");

    // get factor2 page
    res = await server.app.inject({ method: "GET", url: "/factor2", cookies: {SESSIONID: sessionCookie} })
    body = JSON.parse(res.body)
    expect(body.template).toBe("factor2.njk");

    expect(emailTokenData.otp).not.toBe("");

    // submit changepassword page
    res = await server.app.inject({ method: "POST", url: "/changepassword", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        otp: emailTokenData.otp, 
        csrfToken: csrfToken,
    } });
    expect(res.statusCode).toBe(200);
    body = JSON.parse(res.body)
    expect(body.args.errorCodeName).toBe("UsernameOrPasswordInvalid")
    const {secrets} = await userStorage.getUserByUsername("mary");
    const passwordsEqual = await Hasher.passwordsEqual("maryPass123", secrets.password??"");
    expect(passwordsEqual).toBe(true);
});

test('FastifyServer.factor2ProtectedPageWrongToken', async () => {
    let {server, userStorage} = await makeAppWithOptions({enableEmailVerification: false});

    let res;
    let body;

    await createEmailAccount(server);
    const {sessionCookie, csrfCookie, csrfToken} = await loginEmail(server);

    // get change password page
    res = await server.app.inject({ method: "GET", url: "/changepassword", cookies: {SESSIONID: sessionCookie} })
    body = JSON.parse(res.body)
    expect(body.template).toBe("changepassword.njk");

    emailTokenData.otp = "";

    // submit change password
    res = await server.app.inject({ method: "POST", url: "/changepassword", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        old_password: "maryPass123", 
        new_password: "newPass123",
        repeat_password: "newPass123",
        csrfToken: csrfToken,
    } });
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toBe("/factor2");

    // get factor2 page
    res = await server.app.inject({ method: "GET", url: "/factor2", cookies: {SESSIONID: sessionCookie} })
    body = JSON.parse(res.body)
    expect(body.template).toBe("factor2.njk");

    expect(emailTokenData.otp).not.toBe("");

    // submit changepassword page
    res = await server.app.inject({ method: "POST", url: "/changepassword", cookies: {CSRFTOKEN: csrfCookie, SESSIONID: sessionCookie}, payload: {
        otp: "XXXXXX", 
        csrfToken: csrfToken,
    } });
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toBe("/factor2?error=InvalidToken");
    const {secrets} = await userStorage.getUserByUsername("mary");
    const passwordsEqual = await Hasher.passwordsEqual("maryPass123", secrets.password??"");
    expect(passwordsEqual).toBe(true);
});
