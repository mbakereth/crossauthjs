import { beforeAll, afterEach, expect, test, vi } from 'vitest'
import path from 'path';
import fastify from 'fastify';
import {
    InMemoryUserStorage,
    InMemoryKeyStorage,
    InMemoryOAuthClientStorage,
    Crypto,
    LocalPasswordAuthenticator,
    TotpAuthenticator,
    EmailAuthenticator,
    UserStorage } from '@crossauth/backend';
import { FastifyServer, type FastifyServerOptions } from '../fastifyserver';
import {
    CrossauthError,
    ErrorCode,
    OAuthFlows,
    type UserInputFields } from '@crossauth/common';
import { getTestUserStorage }  from './inmemorytestdata';
import { authenticator as gAuthenticator } from 'otplib';
import { KeyPrefix } from '@crossauth/common';

//export var server : FastifyCookieAuthServer;
export var confirmEmailData :  {token : string, email : string, extraData: {[key:string]: any}};
export var passwordResetData :  {token : string, extraData: {[key:string]: any}};
export var emailTokenData :  {to: string, otp : string};

async function createTotpAccount(username: string,
    password: string,
    userStorage: UserStorage) {

    const userInputs : UserInputFields = {
        username: username,
        email: username + "@email.com",
        state: "active",
        factor1: "localpassword", 
        factor2: "totp", 
    };
    let lpAuthenticator = 
        new LocalPasswordAuthenticator(userStorage, {pbkdf2Iterations: 1_000});

    const totpAuth = new TotpAuthenticator("Unittest");
    totpAuth.factorName = "totp";
    const resp = await totpAuth.prepareConfiguration(userInputs);
    if (!resp?.sessionData) throw new CrossauthError(ErrorCode.UnknownError, 
        "TOTP created no session data")

    const user = await userStorage.createUser(userInputs, {
        password: await lpAuthenticator.createPasswordHash(password),
        totpSecret: resp.sessionData.totpSecret,
        } );

    return { user, totpSecret: resp.sessionData.totpSecret };
};

async function createEmailAccount(username: string,
    password: string,
    userStorage: UserStorage) {

    const userInputs : UserInputFields = {
        username: username,
        email: username + "@email.com",
        state: "active",
        factor1: "localpassword", 
        factor2: "email", 
    };
    let lpAuthenticator = 
        new LocalPasswordAuthenticator(userStorage, {pbkdf2Iterations: 1_000});

    const emailAuth = new EmailAuthenticator()
    emailAuth.factorName = "email";
    emailAuth["sendToken"] = async function (to: string, otp : string) {
        emailTokenData = {otp, to}
        return "1";
    };

    const user = await userStorage.createUser(userInputs, {
        password: await lpAuthenticator.createPasswordHash(password),
        } );

    return { user };
};


beforeAll(async () => {
});

async function makeAppWithOptions(options : FastifyServerOptions = {}) : Promise<{userStorage : InMemoryUserStorage, keyStorage : InMemoryKeyStorage, server: FastifyServer}> {
    const userStorage = await getTestUserStorage();
    const keyStorage = new InMemoryKeyStorage();
    let lpAuthenticator = new LocalPasswordAuthenticator(userStorage, {
        pbkdf2Iterations: 1_000,
    });
    const totpAuth = new TotpAuthenticator("Unittest");
    totpAuth.factorName = "totp";
    const emailAuth = new EmailAuthenticator();
    emailAuth.factorName = "email";
    emailAuth["sendToken"] = async function (to: string, otp : string) {
        emailTokenData = {otp, to}
        return "1";
    };
    const clientStorage = new InMemoryOAuthClientStorage();
    const clientSecret = await Crypto.passwordHash("DEF", {
        encode: true,
        iterations: 1000,
        keyLen: 32,
    });
    const client = {
        clientId : "ABC",
        clientSecret: clientSecret,
        clientName: "Test",
        confidential: true,
        redirectUri: ["http://example.com/redirect"],
        validFlow: OAuthFlows.allFlows(),
    };
    await clientStorage.createClient(client);

    // create a fastify server and mock view to return its arguments
    const app = fastify({logger: false});
    const server = new FastifyServer(userStorage, {
        authenticators: {
            localpassword: lpAuthenticator,
            totp: totpAuth,
            email: emailAuth,        
        },
        session: {
            keyStorage: keyStorage, 
        },
        oAuthAuthServer: {
            clientStorage,
            keyStorage,
        }}, {
            app: app,
            views: path.join(__dirname, '../views'),
            allowedFactor2: ["none", "totp", "email"],
            validScopes: ["read", "write"],
            jwtKeyType: "RS256",
            jwtPublicKeyFile: "keys/rsa-public-key.pem",
            jwtPrivateKeyFile: "keys/rsa-private-key.pem",
            siteUrl: `http://localhost:3000`,
            userStorage,
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

async function getCsrf(server : FastifyServer) : Promise<{csrfCookie: string, csrfToken: string}> {
    const res = await server.app.inject({ method: "GET", url: "/login" })
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

async function login(server : FastifyServer) : Promise<{sessionCookie : string, csrfCookie : string, csrfToken : string}> {
    let res;

    const {csrfCookie, csrfToken} = await getCsrf(server);

    // login
    res = await server.app.inject({ method: "POST", url: "/login", cookies: {CSRFTOKEN: csrfCookie}, payload: {username: "bob", password: "bobPass123", csrfToken: csrfToken} })
    expect(res.statusCode).toBe(302);
    const sessionCookie = getSession(res);
    const {csrfCookie : csrfCookie2, csrfToken : csrfToken2} = await getCsrf(server);
    return { sessionCookie, csrfCookie: csrfCookie2, csrfToken: csrfToken2 }
}

function getQueryParams(redirectUri : string) : {[key:string]:string} {
    const parts1 = redirectUri.split("?");
    expect(parts1?.length).toBe(2);
    let params : {[key:string]:string} = {}
    if (parts1) {
        const parts2 = parts1[1]?.split("&");
        for (let i=0; i<parts2.length; ++i) {
            const parts3 = parts2[i].split("=");
            if (parts3.length == 2) params[parts3[0]] = parts3[1];
        }
    }
    return params;

}
test('FastifyAuthServer.authorizeRedirectsToLogin', async () => {

    let {server} = await makeAppWithOptions();
    let res;
    const redirect = encodeURIComponent("http://example.com/redirect")
    res = await server.app.inject({ 
        method: "GET", 
        url: `/authorize?response_type=code&client_id=ABC&redirect_uri=${redirect}&scope=read+write&state=ABC123`,  
        });
    expect(res.statusCode).toBe(302);
});

test('FastifyAuthServer.getAccessTokenWhileLoggedIn', async () => {

    let {server, keyStorage} = await makeAppWithOptions();

    let res;
    let body;

    const {sessionCookie, csrfCookie, csrfToken} = await login(server);
    res = await server.app.inject({ 
        method: "GET", 
        url: `/authorize?response_type=code&client_id=ABC&redirect_uri=http://example.com/redirect&scope=read+write&state=ABC123`,  
        cookies: {SESSIONID: sessionCookie, CSRFTOKEN: csrfCookie}});
    body = JSON.parse(res.body)
    expect(body.template).toBe("userauthorize.njk");
    expect(body.args.response_type).toBe("code");
    expect(body.args.client_id).toBe("ABC");
    expect(body.args.redirect_uri).toBe("http://example.com/redirect");
    expect(body.args.scope).toBe("read write");
    expect(body.args.state).toBe("ABC123");

    res = await server.app.inject({ 
        method: "POST", 
        url: `/userauthorize`,  
        cookies: {SESSIONID: sessionCookie, CSRFTOKEN: csrfCookie}, payload: {
            authorized: "true",
            response_type: "code",
            client_id: "ABC",
            redirect_uri: "http://example.com/redirect",
            scope: "read write",
            state: "ABC123",
            csrfToken: csrfToken,
        }});
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toContain("/redirect?");
    const params = getQueryParams(res.headers.location??"");
    const code = params.code;
    const state = params.state;
    expect(state).toBe("ABC123");
    expect(code).toBeDefined();
    await keyStorage.getKey(KeyPrefix.authorizationCode+Crypto.hash(code??""));

    res = await server.app.inject({ 
        method: "POST", 
        url: `/token`,  
        cookies: {SESSIONID: sessionCookie}, payload: {
            grant_type: "authorization_code",
            client_id: "ABC",
            client_secret: "DEF",
            code: code,
        }});
    body = JSON.parse(res.body);
    expect(body.access_token).toBeDefined();
    // @ts-ignore
    await server.oAuthAuthServer.authServer.validateJwt(body.access_token, "access");

});

test('FastifyAuthServer.getAccessTokenWClientCredentials', async () => {

    let {server} = await makeAppWithOptions();

    let res;
    let body;

    res = await server.app.inject({ 
        method: "POST", 
        url: `/token`,  
        payload: {
            grant_type: "client_credentials",
            client_id: "ABC",
            client_secret: "DEF",
            scope: "read write",
            state: "ABCDEF",
        }});
    body = JSON.parse(res.body);
    expect(body.access_token).toBeDefined();
    // @ts-ignore
    await server.oAuthAuthServer.authServer.validateJwt(body.access_token, "access");

});

test('FastifyAuthServer.getAccessTokenWClientCredentialsBasicAuth', async () => {

    let {server} = await makeAppWithOptions();

    let res;
    let body;

    const authorization = Crypto.base64Encode("ABC:DEF");
    res = await server.app.inject({ 
        method: "POST", 
        url: `/token`,  
        headers: {
            authorization: "Basic " + authorization,
        },
        payload: {
            grant_type: "client_credentials",
            scope: "read write",
            state: "ABCDEF",
        }});
    body = JSON.parse(res.body);
    expect(body.access_token).toBeDefined();
    // @ts-ignore
    await server.oAuthAuthServer.authServer.validateJwt(body.access_token, "access");

});

test('FastifyAuthServer.getAccessTokenWClientCredentialsNoAuth', async () => {

    let {server} = await makeAppWithOptions();

    let res;
    let body;

    res = await server.app.inject({ 
        method: "POST", 
        url: `/token`,  
        payload: {
            grant_type: "client_credentials",
            scope: "read write",
            state: "ABCDEF",
        }});
    body = JSON.parse(res.body);
    expect(body.access_token).toBeUndefined();
    expect(body.error).toBe("access_denied");
    // @ts-ignore

});


test('FastifyAuthServer.getAccessTokenWithPasswordFlow', async () => {

    let {server} = await makeAppWithOptions();

    let res;
    let body;

    res = await server.app.inject({ 
        method: "POST", 
        url: `/token`,  
        payload: {
            grant_type: "password",
            scope: "read write",
            state: "ABCDEF",
            client_id: "ABC",
            client_secret: "DEF",
            username: "bob",
            password: "bobPass123",
        }});
    body = JSON.parse(res.body);
    expect(body.access_token).toBeDefined();
    // @ts-ignore
    await server.oAuthAuthServer.authServer.validateJwt(body.access_token, "access");

});

test('FastifyAuthServer.getAccessTokenWithPasswordMfaOtpFlow', async () => {

    let {server, userStorage} = await makeAppWithOptions();
    const { totpSecret} = 
        await createTotpAccount("mary", "maryPass123", userStorage);

    let res;
    let body;

    // first token request
    res = await server.app.inject({ 
        method: "POST", 
        url: `/token`,  
        payload: {
            grant_type: "password",
            scope: "read write",
            state: "ABCDEF",
            client_id: "ABC",
            client_secret: "DEF",
            username: "mary",
            password: "maryPass123",
        }});
    body = JSON.parse(res.body);
    expect(body.access_token).toBeUndefined();
    expect(body.mfa_token).toBeDefined();
    const mfa_token = body.mfa_token;

    res = await server.app.inject({ 
        method: "GET", 
        url: `/mfa/authenticators`,  
        headers: {
            'authorization': "Bearer " + body.mfa_token,
        }});
    body = JSON.parse(res.body);
    expect(Array.isArray(body)).toBe(true);
    expect(body.length).toBe(1);

    // challenge
    res = await server.app.inject({ 
        method: "POST", 
        url: `/mfa/challenge`,  
        payload: {
            mfa_token: mfa_token,
            client_id : "ABC",
            client_secret: "DEF",
            authenticator_id: "totp",
            challenge_type: "otp",
    }});
    body = JSON.parse(res.body);
    expect(body.challenge_type).toBe("otp");

    const maxTries = 2;
    for (let i=0; i<maxTries; ++i) {
        const otp = gAuthenticator.generate(totpSecret);
        res = await server.app.inject({ 
            method: "POST",
            url: '/token',
            payload: {
                grant_type: "http://auth0.com/oauth/grant-type/mfa-otp",
                client_id : "ABC",
                scope: "read write",
                client_secret: "DEF",
                mfa_token: mfa_token,
                otp: otp
        }});
        body = JSON.parse(res.body);
        if (body.error && i < maxTries-1) continue;
        expect(body.error).toBeUndefined();
        expect(body.access_token).toBeDefined();
        expect(body.scope).toBe("read write");
        break;

    }

});

test('FastifyAuthServer.getAccessTokenWithPasswordMfaOOBFlow', async () => {

    let {server, userStorage} = await makeAppWithOptions();
    await createEmailAccount("mary", "maryPass123", userStorage);

    let res;
    let body;

    // first token request
    res = await server.app.inject({ 
        method: "POST", 
        url: `/token`,  
        payload: {
            grant_type: "password",
            scope: "read write",
            state: "ABCDEF",
            client_id: "ABC",
            client_secret: "DEF",
            username: "mary",
            password: "maryPass123",
        }});
    body = JSON.parse(res.body);
    expect(body.access_token).toBeUndefined();
    expect(body.mfa_token).toBeDefined();
    const mfa_token = body.mfa_token;

    res = await server.app.inject({ 
        method: "GET", 
        url: `/mfa/authenticators`,  
        headers: {
            'authorization': "Bearer " + body.mfa_token,
        }});
    body = JSON.parse(res.body);
    expect(Array.isArray(body)).toBe(true);
    expect(body.length).toBe(1);

    // challenge
    res = await server.app.inject({ 
        method: "POST", 
        url: `/mfa/challenge`,  
        payload: {
            mfa_token: mfa_token,
            client_id : "ABC",
            client_secret: "DEF",
            authenticator_id: "email",
            challenge_type: "oob",
    }});
    body = JSON.parse(res.body);
    expect(body.challenge_type).toBe("oob");
    expect(body.oob_code).toBeDefined();
    expect(body.binding_method).toBe("prompt");

    const otp = emailTokenData.otp;

    res = await server.app.inject({ 
        method: "POST",
        url: '/token',
        payload: {
            grant_type: "http://auth0.com/oauth/grant-type/mfa-oob",
            client_id : "ABC",
            scope: "read write",
            client_secret: "DEF",
            mfa_token: mfa_token,
            oob_code: body.oob_code,
            binding_code: otp
    }});
    body = JSON.parse(res.body);
    expect(body.error).toBeUndefined();
    expect(body.access_token).toBeDefined();
    expect(body.scope).toBe("read write");


});

async function authorize(options : {[key:string]:any} = {}) {
    let {server, keyStorage} = await makeAppWithOptions(options);

    let res;
    let body;

    const {sessionCookie, csrfCookie, csrfToken} = await login(server);
    res = await server.app.inject({ 
        method: "GET", 
        url: `/authorize?response_type=code&client_id=ABC&redirect_uri=http://example.com/redirect&scope=read+write&state=ABC123`,  
        cookies: {SESSIONID: sessionCookie, CSRFTOKEN: csrfCookie}});
    body = JSON.parse(res.body)
    expect(body.args.response_type).toBe("code");

    // get authorization code
    res = await server.app.inject({ 
        method: "POST", 
        url: `/userauthorize`,  
        cookies: {SESSIONID: sessionCookie, CSRFTOKEN: csrfCookie}, payload: {
            authorized: "true",
            response_type: "code",
            client_id: "ABC",
            redirect_uri: "http://example.com/redirect",
            scope: "read write",
            state: "ABC123",
            csrfToken: csrfToken,
        }});
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toContain("/redirect?");
    const params = getQueryParams(res.headers.location??"");
    const code = params.code;
    const state = params.state;
    expect(state).toBe("ABC123");
    expect(code).toBeDefined();
    await keyStorage.getKey(KeyPrefix.authorizationCode+Crypto.hash(code??""));

    // get tokens
    res = await server.app.inject({ 
        method: "POST", 
        url: `/token`,  
        cookies: {SESSIONID: sessionCookie}, payload: {
            grant_type: "authorization_code",
            client_id: "ABC",
            client_secret: "DEF",
            code: code,
        }});
    body = JSON.parse(res.body);
    expect(body.access_token).toBeDefined();

    return {
        server, 
        keyStorage,
        sessionCookie,
        ...body,
    }
}
test('FastifyAuthServer.refreshTokenFlow', async () => {

    let {server, sessionCookie, refresh_token} = await authorize({
        issueRefreshToken: true,
    });

    let res;
    let body;

    res = await server.app.inject({ 
        method: "POST", 
        url: `/token`,  
        cookies: {SESSIONID: sessionCookie}, payload: {
            grant_type: "refresh_token",
            client_id: "ABC",
            client_secret: "DEF",
            refresh_token: refresh_token
        }});
    body = JSON.parse(res.body);
    expect(body.access_token).toBeDefined();
    // @ts-ignore
    await server.oAuthAuthServer.authServer.validateJwt(body.access_token, "access");

});

test('FastifyAuthServer.refreshTokenFlowFromCookie', async () => {

    let {server, sessionCookie, refresh_token} = await authorize({
        issueRefreshToken: true,
        refreshTokenType: "cookie",
    });

    let res;
    let body;

    res = await server.app.inject({ 
        method: "GET", 
        url: `/api/getcsrftoken`,  
        cookies: {SESSIONID: sessionCookie}});
    body = JSON.parse(res.body);
    expect(body.csrfToken).toBeDefined();
    const csrfCookies = res.cookies.filter((cookie: any) => {return cookie.name == "CSRFTOKEN"});
    expect(csrfCookies.length).toBe(1);

    res = await server.app.inject({ 
        method: "POST", 
        url: `/token`,  
        cookies: {
            SESSIONID: sessionCookie,
            CROSSAUTH_REFRESH_TOKEN: refresh_token,
            CSRFTOKEN: csrfCookies[0].value,
        }, headers: {
            "X-CROSSAUTH-CSRF": body.csrfToken
        }, payload: {
            grant_type: "refresh_token",
            client_id: "ABC",
            client_secret: "DEF",
        }});
    body = JSON.parse(res.body);
    expect(body.access_token).toBeDefined();
    // @ts-ignore
    await server.oAuthAuthServer.authServer.validateJwt(body.access_token, "access");

});
