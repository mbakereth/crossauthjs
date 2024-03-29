import path from 'path';
import fastify from 'fastify';
import { getTestUserStorage }  from './inmemorytestdata';
import {
    InMemoryUserStorage,
    InMemoryKeyStorage,
    InMemoryOAuthClientStorage,
    LocalPasswordAuthenticator,
    TotpAuthenticator } from '@crossauth/backend';
import { FastifyServer, type FastifyServerOptions } from '../fastifyserver';
import { CrossauthError } from '@crossauth/common';

export async function makeAppWithOptions(options : FastifyServerOptions = {}) 
    : Promise<{
        userStorage: InMemoryUserStorage,
        keyStorage: InMemoryKeyStorage,
        clientStorage: InMemoryOAuthClientStorage,
        server: FastifyServer
    }> {
    const userStorage = await getTestUserStorage();
    const keyStorage = new InMemoryKeyStorage();
    const clientStorage = new InMemoryOAuthClientStorage();
    let lpAuthenticator = new LocalPasswordAuthenticator(userStorage, {
        pbkdf2Iterations: 1_000,
    });
    let totpAuthenticator = new TotpAuthenticator("FastifyTest");

    // create a fastify server and mock view to return its arguments
    const app = fastify({logger: false});
    const server = new FastifyServer(userStorage, {
        authenticators: {
            localpassword: lpAuthenticator,
            totp: totpAuthenticator,
        },
        session: {
            keyStorage: keyStorage, 
        }}, {
            app: app,
            views: path.join(__dirname, '../views'),
            secret: "ABCDEFG",
            allowedFactor2: "none, totp",
            siteUrl: `http://localhost:3000`,
            clientStorage: clientStorage,
            endpoints: "all",
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

    return {userStorage, keyStorage, server, clientStorage};
}

export function getCsrf(res: any) : {csrfCookie: string, csrfToken: string} {
    const body = JSON.parse(res.body)
    const csrfCookies = res.cookies.filter((cookie: any) => {return cookie.name == "CSRFTOKEN"});
    expect(csrfCookies.length).toBe(1);
    const csrfCookie = csrfCookies[0].value;
    const csrfToken = body.args.csrfToken;
    expect(csrfToken).toBeDefined();
    return {csrfCookie, csrfToken};
}

export function getSession(res: any) : string {
    const sessionCookies = res.cookies.filter((cookie: any) => {return cookie.name == "SESSIONID"});
    expect(sessionCookies.length).toBe(1);
    return sessionCookies[0].value;
}

export async function login(server: FastifyServer,
    username: string = "admin",
    password: string = "adminPass123") {

    let res;
    let body;

    // Right page served 
    res = await server.app.inject({ method: "GET", url: "/login" })
    body = JSON.parse(res.body)
    expect(body.template).toBe("login.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);

    // successful login
    res = await server.app.inject({
        method: "POST",
        url: "/login",
        cookies: { CSRFTOKEN: csrfCookie },
        payload: { username: username, password: password, csrfToken: csrfToken }
    });
    expect(res.statusCode).toBe(302);
    const sessionCookie = getSession(res);
    return {csrfCookie, csrfToken, sessionCookie, status: res.statusCode};

}

