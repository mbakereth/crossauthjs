import { test, expect, beforeAll } from 'vitest';
import { DoubleSubmitCsrfToken, SessionCookie } from '../cookieauth';
import { Backend } from '../backend';
import { HashedPasswordAuthenticator } from '../password';
import { InMemoryUserStorage, InMemoryKeyStorage } from '../storage/inmemorystorage';
import { getTestUserStorage }  from '../storage/tests/inmemorytestdata';
import { CrossauthError } from '../../error';

export var userStorage : InMemoryUserStorage;

// for all these tests, the database will have two users: bob and alice
beforeAll(async () => {
    userStorage = getTestUserStorage();
});


test('SessionCookie.createSessionKey', async () => {
    const keyStorage = new InMemoryKeyStorage();
    const auth = new SessionCookie(userStorage, keyStorage,{secret: "ABCDEFGHIJKLMNOPQRSTUVWX", siteUrl: "http://locahost:3000"});
    const bob = await userStorage.getUserByUsername("bob");
    let { value, created: dateCreated, expires } = await auth.createSessionKey(bob.id);
    let key = await keyStorage.getKey(value);
    expect(key.expires).toBeDefined();
    expect(expires).toBeDefined();
    expect(key.userId).toStrictEqual(bob.id);
    expect(key.expires?.getTime()).toBe(expires?.getTime());
    if (key.expires != undefined && expires != undefined) {
        expect(key.expires?.getTime()-dateCreated.getTime()).toBe(expires?.getTime()-dateCreated.getTime());
    }

});

test('DoubleSubmitCsrfToken.createAndValidateCsrfToken', async () => {
    const auth = new DoubleSubmitCsrfToken({secret: "ABCDEFGHIJKLMNOPQRSTUVWX"});
    let sessionId = "0123456789ABCDEFGHIJKL";
    let token = await auth.createCsrfToken(sessionId);
    let valid = false;
    try {
        auth.validateCsrfToken(token, sessionId);
        valid = true;
    } catch {}
    expect(valid).toBe(true);
});

test('SessionCookie.createSessionKey.encrypted', async () => {
    const keyStorage = new InMemoryKeyStorage();
    const auth = new SessionCookie(userStorage, keyStorage, {secret: "ABCDEFGHIJKLMNOPQRSTUVWX", hashSessionId: true });
    const bob = await userStorage.getUserByUsername("bob");
    let { value, created: dateCreated, expires } = await auth.createSessionKey(bob.id);
    let hashedValue = auth.hashSessionKey(value);
    let key = await keyStorage.getKey(hashedValue);
    expect(key.expires).toBeDefined();
    expect(expires).toBeDefined();
    expect(key.userId).toStrictEqual(bob.id);
    expect(key.expires?.getTime()).toBe(expires?.getTime());
    if (key.expires != undefined && expires != undefined) {
        expect(key.expires?.getTime()-dateCreated.getTime()).toBe(expires?.getTime()-dateCreated.getTime());
    }

});

test('CookieSessionManager.loginGetKeyLogout', async () => {
    const keyStorage = new InMemoryKeyStorage();
    let authenticator = new HashedPasswordAuthenticator(userStorage);
    let manager = new Backend(userStorage, keyStorage, authenticator, {secret: "ABCDEFGHIJKLMNOPQRSTUVWX"});
    let {user: bob, sessionCookie: cookie } = await manager.login("bob", "bobPass123");
    const user = await manager.userForSessionKey(cookie.value);
    expect(user).toBeDefined();
    if (user) expect(user.username).toBe(bob.username);
    await manager.logout(cookie.value);
    await expect(async () => {await manager.userForSessionKey(cookie.value)}).rejects.toThrowError(CrossauthError);
});

test('CookieSessionManager.logoutFromAll', async() => {
    const keyStorage = new InMemoryKeyStorage();
    let authenticator = new HashedPasswordAuthenticator(userStorage);
    let manager = new Backend(userStorage, keyStorage, authenticator, {secret: "ABCDEFGHIJKLMNOPQRSTUVWX"});
    let {user: bob, sessionCookie: cookie } = await manager.login("bob", "bobPass123");
    const user = await manager.userForSessionKey(cookie.value);
    expect(user).toBeDefined();
    if (user) {
        expect(user.username).toBe(bob.username);
        await manager.logoutFromAll(user.username);
        await expect(async () => {await manager.userForSessionKey(cookie.value)}).rejects.toThrowError(CrossauthError);
    }
})

test('CookieSessionManager.createAndValidateCsrfToken', async() => {
    const keyStorage = new InMemoryKeyStorage();
    let authenticator = new HashedPasswordAuthenticator(userStorage);
    let manager = new Backend(userStorage, keyStorage, authenticator, {secret: "ABCDEFGHIJKLMNOPQRSTUVWX"});
    let sessionId = "0123456789ABCDEFGHIJKL";
    let cookie = await manager.createCsrfToken(sessionId);
    let valid = false;
    try {
        manager.validateCsrfToken(cookie.value, sessionId);
        valid = true;
    } catch {}
    expect(valid).toBe(true);

});

