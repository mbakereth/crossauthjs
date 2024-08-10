import { beforeAll, afterEach, expect, test, vi } from 'vitest'
import path from 'path';
import fastify, { FastifyRequest, FastifyReply } from 'fastify';
import { getTestUserStorage }  from './inmemorytestdata';
import { InMemoryUserStorage, InMemoryKeyStorage, ApiKeyManager } from '@crossauth/backend';
import { FastifyServer, type FastifyServerOptions } from '../fastifyserver';
import { CrossauthError } from '@crossauth/common';

//export var server : FastifyCookieAuthServer;
export var confirmEmailData :  {token : string, email : string, extraData: {[key:string]: any}};
export var passwordResetData :  {token : string, extraData: {[key:string]: any}};

const JSONHDR : [string,string] = ['Content-Type', 'application/json; charset=utf-8'];

beforeAll(async () => {
});

async function makeAppWithOptions(options : FastifyServerOptions = {}) : Promise<{userStorage : InMemoryUserStorage, keyStorage : InMemoryKeyStorage, server: FastifyServer, apiKeyManager: ApiKeyManager}> {
    const userStorage = await getTestUserStorage();
    const keyStorage = new InMemoryKeyStorage();
    
    // create a fastify server and mock view to return its arguments
    const app = fastify({logger: false});

    app.get('/', async (request : FastifyRequest, reply : FastifyReply) =>  {
        return reply.header(...JSONHDR).send({ok: true, user : request.user, apiKey: request.apiKey});
    });

    app.get('/protected', async (request : FastifyRequest, reply : FastifyReply) =>  {
        if (!request.apiKey) reply.status(403).header(...JSONHDR).send({ok: false});
        return reply.header(...JSONHDR).send({ok: true, user : request.user, apiKey: request.apiKey});
    });

    app.get('/protectedScopeOne', async (request : FastifyRequest, reply : FastifyReply) =>  {
        if (!(request.apiKey?.scope) || !request.apiKey?.scope.includes("one")) reply.status(403).header(...JSONHDR).send({ok: false});
        return reply.header(...JSONHDR).send({ok: true, user : request.user, apiKey: request.apiKey});
    });

    app.get('/protectedScopeThree', async (request : FastifyRequest, reply : FastifyReply) =>  {
        if (!(request.apiKey?.scope) || !request.apiKey?.scope.includes("three")) reply.status(403).header(...JSONHDR).send({ok: false});
        return reply.header(...JSONHDR).send({ok: true, user : request.user, apiKey: request.apiKey});
    });

    const apiKeyManager = new ApiKeyManager(keyStorage, {secret: "ABCDEFG",});
    
    const server = new FastifyServer({
        apiKey: {
            keyStorage: keyStorage, 
        }}, {
            userStorage, 
            app: app,
            views: path.join(__dirname, '../views'),
            secret: "ABCDEFG",
            allowedFactor2: ["none", "totp"],
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

    return {userStorage, keyStorage, server, apiKeyManager};
}

afterEach(async () => {
    vi.restoreAllMocks();
});

test('FastifyApiKeyServer.validKeyAuthenticates', async () => {

    let {server, apiKeyManager, userStorage} = await makeAppWithOptions();
    const { user } = await userStorage.getUserByUsername("bob");
    const {token} = await apiKeyManager.createKey("default", user.id);
    const res = await server.app.inject({ method: "GET", url: "/", headers: {authorization: apiKeyManager.authScheme + " " + token }});
    const body = JSON.parse(res.body);
    expect(body.user.username).toBe("bob");
    expect(body.apiKey).toBeDefined();
});

test('FastifyApiKeyServer.invalidSignature', async () => {

    let {server, apiKeyManager, userStorage} = await makeAppWithOptions();
    const { user } = await userStorage.getUserByUsername("bob");
    let {token} = await apiKeyManager.createKey("default", user.id);
    token = token.split(".")[0] + ".XXXXXXXXXXXXX";
    const res = await server.app.inject({ method: "GET", url: "/", headers: {authorization: "ApiKey " + token }});
    const body = JSON.parse(res.body);
    expect(body.user).toBeUndefined();
    expect(body.apiKey).toBeUndefined();
});

test('FastifyApiKeyServer.invalidKey', async () => {

    let {server} = await makeAppWithOptions();
    const token = "YYYYYYY.XXXXXXXXXXXXX";
    const res = await server.app.inject({ method: "GET", url: "/", headers: {authorization: "ApiKey " + token }});
    const body = JSON.parse(res.body);
    expect(body.user).toBeUndefined();
    expect(body.apiKey).toBeUndefined();
});

test('FastifyApiKeyServer.scopeIsPassed', async () => {

    let {server, apiKeyManager, userStorage} = await makeAppWithOptions();
    const { user } = await userStorage.getUserByUsername("bob");
    const {token} = await apiKeyManager.createKey("default", user.id, {scope: ["one", "two"]});
    const res = await server.app.inject({ method: "GET", url: "/", headers: {authorization: "ApiKey " + token }});
    const body = JSON.parse(res.body);
    expect(body.user.username).toBe("bob");
    expect(body.apiKey.scope.length).toBe(2);
});

test('FastifyApiKeyServer.keyAllowsAccess', async () => {

    let {server, apiKeyManager, userStorage} = await makeAppWithOptions();
    const { user } = await userStorage.getUserByUsername("bob");
    const {token} = await apiKeyManager.createKey("default", user.id, {scope: ["one", "two"]});
    const res = await server.app.inject({ method: "GET", url: "/protected", headers: {authorization: "ApiKey " + token }});
    const body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
});

test('FastifyApiKeyServer.missingKeyForbidsAccess', async () => {

    let {server} = await makeAppWithOptions();
    const res = await server.app.inject({ method: "GET", url: "/protected"});
    const body = JSON.parse(res.body);
    expect(body.ok).toBe(false);
});

test('FastifyApiKeyServer.scopeAllowsAccess', async () => {

    let {server, apiKeyManager, userStorage} = await makeAppWithOptions();
    const { user } = await userStorage.getUserByUsername("bob");
    const {token} = await apiKeyManager.createKey("default", user.id, {scope: ["one", "two"]});
    const res = await server.app.inject({ method: "GET", url: "/protectedScopeOne", headers: {authorization: "ApiKey " + token }});
    const body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
});

test('FastifyApiKeyServer.scopeForbidsAccess', async () => {

    let {server, apiKeyManager, userStorage} = await makeAppWithOptions();
    const { user } = await userStorage.getUserByUsername("bob");
    const {token} = await apiKeyManager.createKey("default", user.id, {scope: ["one", "two"]});
    const res = await server.app.inject({ method: "GET", url: "/protectedScopeThree", headers: {authorization: "ApiKey " + token }});
    const body = JSON.parse(res.body);
    expect(body.ok).toBe(false);
});
