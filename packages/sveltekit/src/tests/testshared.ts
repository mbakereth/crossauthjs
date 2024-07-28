
import { MockResolver, MockRequestEvent } from './sveltemocks';
import { SvelteKitServer } from '../sveltekitserver';
import { InMemoryKeyStorage, InMemoryUserStorage, LocalPasswordAuthenticator, SessionCookie } from '@crossauth/backend';
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
            factor1: "localpassword"}, {
            password: await authenticator.createPasswordHash("alicePass123")
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

export async function makeServer() {
    const keyStorage = new InMemoryKeyStorage();
    const userStorage = new InMemoryUserStorage();
    const authenticator = new LocalPasswordAuthenticator(userStorage);

    await createUsers(userStorage);
    const server = new SvelteKitServer(userStorage, {
        authenticators: {
            localpassword: authenticator
        },
        session: {
            keyStorage: keyStorage,
            
        }}, {
            secret: "ABCDEFG",
            loginProtectedPageEndpoints: ["/account"],
        });   
    const handle = server.hooks;
    const resolver = new MockResolver("Response");

    return {server, resolver, handle, keyStorage, userStorage, authenticator};
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

export async function login(server : SvelteKitServer, resolver : MockResolver, handle : Handle) {
    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);

    const postRequest = new Request("http://ex.com/test", {
        method: "POST",
        body: "csrfToken="+csrfToken+"&username=bob&password=bobPass123",
        headers: { 
            "cookie": "CSRFTOKEN="+csrfCookieValue,
            "content-type": "application/x-www-form-urlencoded",
        }});
    let event = new MockRequestEvent("1", postRequest, {"param1": "value1"});
    event.locals.csrfToken = csrfToken;

    const ret = await server.sessionServer?.login(event);
    expect(ret?.user?.username).toBe("bob");
    expect(event.cookies.get("SESSIONID")).toBeDefined();
    return event;
};