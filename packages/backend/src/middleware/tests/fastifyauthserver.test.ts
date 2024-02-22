import { beforeAll, afterEach, expect, test, vi } from 'vitest'
import path from 'path';
import fastify from 'fastify';
import { getTestUserStorage }  from '../../storage/tests/inmemorytestdata';
import { InMemoryUserStorage, InMemoryKeyStorage, InMemoryOAuthClientStorage } from '../../storage/inmemorystorage';
import { FastifyServer, type FastifyServerOptions } from '../fastifyserver';
import { LocalPasswordAuthenticator } from '../../authenticators/passwordauth';
import { Hasher } from '../../hasher';
import { CrossauthError } from '@crossauth/common';

//export var server : FastifyCookieAuthServer;
export var confirmEmailData :  {token : string, email : string, extraData: {[key:string]: any}};
export var passwordResetData :  {token : string, extraData: {[key:string]: any}};

beforeAll(async () => {
});

async function makeAppWithOptions(options : FastifyServerOptions = {}) : Promise<{userStorage : InMemoryUserStorage, keyStorage : InMemoryKeyStorage, server: FastifyServer}> {
    const userStorage = await getTestUserStorage();
    const keyStorage = new InMemoryKeyStorage();
    let lpAuthenticator = new LocalPasswordAuthenticator(userStorage, {
        pbkdf2Iterations: 1_000,
    });
    const clientStorage = new InMemoryOAuthClientStorage();
    const clientSecret = await Hasher.passwordHash("DEF", {
        encode: true,
        iterations: 1000,
        keyLen: 32,
    });
    const client = {
        clientId : "ABC",
        clientSecret: clientSecret,
        clientName: "Test",
        redirectUri: ["http://example.com/redirect"],
    };
    await clientStorage.createClient(client);

    // create a fastify server and mock view to return its arguments
    const app = fastify({logger: false});
    const server = new FastifyServer(userStorage, {
        session: {
            keyStorage: keyStorage, 
            authenticators: {
                localpassword: lpAuthenticator,
            }},
        oAuthAuthServer: {
            clientStorage,
            keyStorage,
        }}, {
            app: app,
            views: path.join(__dirname, '../views'),
            secret: "ABCDEFG",
            allowedFactor2: "none",
            validScopes: "read, write",
            jwtPublicKeyFile: "keys/rsa-public-key.pem",
            jwtPrivateKeyFile: "keys/rsa-private-key.pem",
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
        let status = 500;
        if (error instanceof CrossauthError) status = (error as CrossauthError).httpStatus;
        return reply.status(status).send({ ok: false })
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
test('FastifyAuthServfer.authorizeRedirectsToLogin', async () => {

    let {server} = await makeAppWithOptions();
    let res;
    const redirect = encodeURI("http://example.com/redirect")
    res = await server.app.inject({ 
        method: "GET", 
        url: `/authorize?response_type=code&client_id=ABC&redirect_uri=${redirect}&scope=read+write&state=ABC123`,  
        });
    expect(res.statusCode).toBe(302);
});

test('FastifyAuthServfer.getAccessTokenWhileLoggedIn', async () => {

    let {server, keyStorage} = await makeAppWithOptions();

    let res;
    let body;

    const {sessionCookie, csrfCookie, csrfToken} = await login(server);
    res = await server.app.inject({ 
        method: "GET", 
        url: `/authorize?response_type=code&client_id=ABC&redirect_uri=/redirect&scope=read+write&state=ABC123`,  
        cookies: {SESSIONID: sessionCookie, CSRFTOKEN: csrfCookie}});
    body = JSON.parse(res.body)
    expect(body.template).toBe("authorize.njk");
    expect(body.args.response_type).toBe("code");
    expect(body.args.client_id).toBe("ABC");
    expect(body.args.redirect_uri).toBe("/redirect");
    expect(body.args.scope).toBe("read write");
    expect(body.args.state).toBe("ABC123");

    res = await server.app.inject({ 
        method: "POST", 
        url: `/authorize`,  
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
    const params = getQueryParams(res.headers.location||"");
    const code = params.code;
    const state = params.state;
    expect(state).toBe("ABC123");
    expect(code).toBeDefined();
    await keyStorage.getKey("authz:"+Hasher.hash(code||""));

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
    await server.authServer.authServer.validateJwt(body.access_token, "access");

});
