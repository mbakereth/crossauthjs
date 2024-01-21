import { beforeAll, afterEach, expect, test, vi } from 'vitest'
import path from 'path';
import fastify, { FastifyInstance } from 'fastify';
import { getTestUserStorage }  from '../../storage/tests/inmemorytestdata';
import { InMemoryUserStorage, InMemoryKeyStorage } from '../../storage/inmemorystorage';
import { FastifyCookieAuthServer } from '../fastifyserver';
import { HashedPasswordAuthenticator } from '../../password';

export var userStorage : InMemoryUserStorage;
export var keyStorage = new InMemoryKeyStorage();
export var app : FastifyInstance;
export var server : FastifyCookieAuthServer;

beforeAll(async () => {
    // for all these tests, the database will have two users: bob and alice
    userStorage = await getTestUserStorage();
    keyStorage = new InMemoryKeyStorage();
    let authenticator = new HashedPasswordAuthenticator(userStorage);

    // create a fastify server and mock view to return its arguments
    app = fastify({logger: false});
    server = new FastifyCookieAuthServer(userStorage, keyStorage, authenticator, {
        app: app,
        views: path.join(__dirname, '../views'),
        secret: "ABCDEFG",
        enableSessions: true,
    });
    // @ts-ignore
    app.decorateReply("view",  function(template, args) {
        return {template: template, args: args};
    });
});

afterEach(async () => {
    vi.restoreAllMocks();
});

test('FastifyServer.anonymousGets', async () => {

    let res;
    let body;

    // login 
    res = await app.inject({ method: "GET", url: "/login" })
    body = JSON.parse(res.body)
    expect(body.template).toBe("login.njk");

    // signup 
    res = await app.inject({ method: "GET", url: "/signup" })
    body = JSON.parse(res.body)
    expect(body.template).toBe("signup.njk");

    res = await app.inject({ method: "GET", url: "/changepassword" })
    expect(body.statusCode = 401);
});
