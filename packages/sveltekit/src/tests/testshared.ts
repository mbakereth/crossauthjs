
import { MockResolver } from './sveltemocks';
import { SvelteKitServer } from '../sveltekitserver';
import { InMemoryKeyStorage, InMemoryUserStorage, LocalPasswordAuthenticator, SessionCookie } from '@crossauth/backend';

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
            
        }}, {secret: "ABCDEFG"});   
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
        }
    }
    return cookies;
}
