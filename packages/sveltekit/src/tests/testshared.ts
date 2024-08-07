
import { MockResolver, MockRequestEvent } from './sveltemocks';
import { SvelteKitServer } from '../sveltekitserver';
import {
    InMemoryKeyStorage,
    InMemoryUserStorage,
    InMemoryOAuthClientStorage,
    InMemoryOAuthAuthorizationStorage,
    LocalPasswordAuthenticator,
    Crypto,
    DummyFactor2Authenticator,
    SessionCookie,
    EmailAuthenticator,
    ApiKeyManager } from '@crossauth/backend';
    import {
        OAuthFlows
    } from '@crossauth/common';
    
import type { Handle } from '@sveltejs/kit';

export async function createUsers(userStorage: InMemoryUserStorage) {
    let authenticator = new LocalPasswordAuthenticator(userStorage, {pbkdf2Iterations: 1_000});
    await Promise.all([
        userStorage.createUser({
                username: "bob", 
                email: "bob@bob.com",
                state: "active",
                factor1: "localpassword"}, {
                password: await authenticator.createPasswordHash("bobPass123")
                } ),
        userStorage.createUser({
            username: "alice", 
            email: "alice@alice.com",
            state: "active",
            factor1: "localpassword",
            factor2: "dummyFactor2"}, {
            password: await authenticator.createPasswordHash("alicePass123")
            } ),
        userStorage.createUser({
            username: "admin", 
            email: "admin@admin.com",
            state: "active",
            factor1: "localpassword",
            admin: true}, {
            password: await authenticator.createPasswordHash("adminPass123")
            } ),
        ]);
}

export async function createSession(userId : string,
    userStorage: InMemoryUserStorage, 
    keyStorage: InMemoryKeyStorage,
    options = {}) {

    let sessionCookie = new SessionCookie(userStorage, keyStorage, options);
    const key = await sessionCookie.createSessionKey(userId);
    const cookie = sessionCookie.makeCookie(key);
    return {key, cookie};
}

export async function createClients(clientStorage : InMemoryOAuthClientStorage) {
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
}

function redirect(status : number, location : string) {
    throw {status, location}
};

export async function makeServer(makeSession=true, makeApiKey=false, makeOAuthServer=false, options={}) {
    const keyStorage = new InMemoryKeyStorage();
    const userStorage = new InMemoryUserStorage();
    const clientStorage = new InMemoryOAuthClientStorage();
    const authStorage = new InMemoryOAuthAuthorizationStorage();
    if (makeOAuthServer) await createClients(clientStorage);

    const authenticator = new LocalPasswordAuthenticator(userStorage);
    let dummyFactor2Authenticator = new DummyFactor2Authenticator("0000");
    let emailAuthenticator = new EmailAuthenticator();

    await createUsers(userStorage);
    let session = makeSession ? {
        keyStorage: keyStorage,
        options:  {
            allowedFactor2: ["none", "dummyFactor2"],
        }
        } : undefined;
    let apiKey = makeApiKey ? {
        keyStorage: keyStorage
    } : undefined;
    let oAuthAuthServer = makeOAuthServer ? {
            clientStorage,
            keyStorage,
            authenticators: {
                localpassword: authenticator,
                dummyFactor2: dummyFactor2Authenticator,
                email: emailAuthenticator,
            }, 
            options: {
                userStorage,
                authStorage,
            }
               
    } : undefined;

    const server = new SvelteKitServer(userStorage, {
        authenticators: {
            localpassword: authenticator,
            dummyFactor2: dummyFactor2Authenticator,
            email: emailAuthenticator,
        },
        session: session,
        apiKey : apiKey,
        oAuthAuthServer: oAuthAuthServer,
        options: {
            secret: "ABCDEFG",
            loginProtectedPageEndpoints: ["/account"],
            factor2ProtectedPageEndpoints: ["/factor2protected"],
            validScopes: ["read", "write"],
            jwtKeyType: "RS256",
            jwtPublicKeyFile: "keys/rsa-public-key.pem",
            jwtPrivateKeyFile: "keys/rsa-private-key.pem",
            redirect,
            ...options,
        }});   
    const handle = server.hooks;
    const resolver = new MockResolver("Response");

    const apiKeyManager = makeApiKey ? new ApiKeyManager(keyStorage, {secret: "ABCDEFG",}) : undefined;


    return {server, resolver, handle, keyStorage, userStorage, authenticator, apiKeyManager};
}

export function getCookies(resp : Response) {
    const cookieHeaders = resp.headers.getSetCookie();
    let cookies : {[key:string]:string} = {};
    for (let cookie of cookieHeaders) {
        const parts = cookie.split("=", 2);
        const semiColon = parts[1].indexOf(";");
        if (semiColon > -1) {
            const value = parts[1].substring(0, semiColon).trim();
            if (value.length > 0) cookies[parts[0]] = value;
        } else {
            cookies[parts[0]] = parts[1];
        }
    }
    return cookies;
}

export async function getCsrfToken(server : SvelteKitServer, resolver : MockResolver, handle : Handle ) {
    const getRequest = new Request("http://ex.com/test", {method: "GET"});
    let event = new MockRequestEvent("1", getRequest, {"param1": "value1"});

    const resp = await handle({event: event, resolve: resolver.mockResolve});
    /*const cookieNames = resp.headers.getSetCookie().map((el) => el.split("=")[0]);
    expect(cookieNames.length).toBe(2);
    expect(["TESTCOOKIE", "CSRFTOKEN"]).toContain(cookieNames[0]);*/
    const cookies = getCookies(resp);
    expect(cookies["CSRFTOKEN"]).toBeDefined();
    let csrfValid = false;
    try {
        server.sessionServer?.sessionManager.validateCsrfCookie(cookies["CSRFTOKEN"]);
        csrfValid = true;
    } catch (e) {
        console.log(e);
    }
    expect(csrfValid).toBe(true);
    expect(event.locals.csrfToken).toBeDefined();
    return {
        csrfToken: event.locals.csrfToken,
        csrfCookieValue: cookies["CSRFTOKEN"]
    };
}

export async function login(server : SvelteKitServer, resolver : MockResolver, handle : Handle, user : string="bob", password : string="bobPass123") {
    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);

    const postRequest = new Request("http://ex.com/test", {
        method: "POST",
        body: "csrfToken="+csrfToken+"&username=" + user + "&password=" + password,
        headers: { 
            "cookie": "CSRFTOKEN="+csrfCookieValue,
            "content-type": "application/x-www-form-urlencoded",
        }});
    let event = new MockRequestEvent("1", postRequest, {"param1": "value1"});
    event.locals.csrfToken = csrfToken;

    const ret = await server.sessionServer?.userEndpoints.login(event);
    expect(ret?.user?.username).toBe(user);
    expect(event.cookies.get("SESSIONID")).toBeDefined();
    return {event, ret};
};

export async function loginFactor2(server : SvelteKitServer, resolver : MockResolver, handle : Handle, sessionCookieValue : string, sessionId : string) {
    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);

    const postRequest = new Request("http://ex.com/test", {
        method: "POST",
        body: "csrfToken="+csrfToken+"&otp=0000",
        headers: [
            ["set-cookie", "CSRFTOKEN="+csrfCookieValue],
            ["set-cookie", "SESSIONID="+sessionCookieValue],
            ["content-type", "application/x-www-form-urlencoded"],
        ]
        });
    let event = new MockRequestEvent("1", postRequest, {"param1": "value1"});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;

    const ret = await server.sessionServer?.userEndpoints.loginFactor2(event);
    return {event, ret};
};

