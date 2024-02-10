import { test } from 'vitest'
/*import {  beforeAll, expect } from 'vitest'
import { getTestUserStorage }  from '../storage/tests/inmemorytestdata';
import { InMemoryUserStorage, InMemoryKeyStorage } from '../storage/inmemorystorage';
import { FastifyServer, type FastifyServerOptions } from '../middleware/fastifyserver';
import { LocalPasswordAuthenticator } from '../authenticators/passwordauth';
import { TotpAuthenticator } from '../authenticators/totpauth';
import { Hasher } from '../hasher';
import fastify from 'fastify';
import path from 'path';

export var confirmEmailData :  {token : string, email : string, extraData: {[key:string]: any}};

function getCsrf(res: any) : {csrfCookie: string, csrfToken: string} {
    const body = JSON.parse(res.body)
    const csrfCookies = res.cookies.filter((cookie: any) => {return cookie.name == "CSRFTOKEN"});
    expect(csrfCookies.length).toBe(1);
    const csrfCookie = csrfCookies[0].value;
    const csrfToken = body.args.csrfToken;
    expect(csrfToken).toBeDefined();
    return {csrfCookie, csrfToken};
}

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
        allowedFactor2: "none, totp",
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

beforeAll(async () => {
});*/

test('dummy.test', async () => {
});


/*test('FastifyServer.wrongCsrf', async () => {

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
    expect(body.args.errorCodeName).toBe("InvalidCsrf");

    // error on invalid cookie
    res = await server.app.inject({ method: "GET", url: "/login" })
    const {csrfToken: csrfToken2} = getCsrf(res);
    const csrfCookie2 = csrfTokens?.makeCsrfCookie(Hasher.randomValue(16));
    res = await server.app.inject({ method: "POST", url: "/login", cookies: {CSRFTOKEN: csrfCookie2?.value||""}, payload: {username: "bob", password: "abc", csrfToken: csrfToken2} })
    body = JSON.parse(res.body);
    expect(body.args.errorCodeName).toBe("InvalidCsrf");

});
*/