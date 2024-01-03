import { test, expect, beforeAll } from 'vitest';
import { CookieAuth, CookieSessionManager } from '../cookieauth';
import { InMemoryUserStorage, InMemoryKeyStorage } from '../storage/inmemorystorage';
import { getTestUserStorage }  from '../storage/tests/inmemorytestdata';
import { CrossauthError } from '../../error';

export var userStorage : InMemoryUserStorage;

// for all these tests, the database will have two users: bob and alice
beforeAll(async () => {
    userStorage = getTestUserStorage();
});


test('CookieAuth.createSessionKey', async () => {
    const sessionStorage = new InMemoryKeyStorage(userStorage);
    const auth = new CookieAuth(userStorage, sessionStorage);
    const bob = await userStorage.getUserByUsername("bob");
    let { value, created: dateCreated, expires } = await auth.createSessionKey(bob.id);
    let key = await sessionStorage.getKey(value);
    expect(key.expires).toBeDefined();
    expect(expires).toBeDefined();
    expect(key.userId).toStrictEqual(bob.id);
    expect(key.expires?.getTime()).toBe(expires?.getTime());
    if (key.expires != undefined && expires != undefined) {
        expect(key.expires?.getTime()-dateCreated.getTime()).toBe(expires?.getTime()-dateCreated.getTime());
    }

});

test('CookieAuth.createSessionKey.encrypted', async () => {
    const sessionStorage = new InMemoryKeyStorage(userStorage);
    const auth = new CookieAuth(userStorage, sessionStorage, { hashSessionIDs: true });
    const bob = await userStorage.getUserByUsername("bob");
    let { value, created: dateCreated, expires } = await auth.createSessionKey(bob.id);
    let key = await sessionStorage.getKey(value);
    expect(key.expires).toBeDefined();
    expect(expires).toBeDefined();
    expect(key.userId).toStrictEqual(bob.id);
    expect(key.expires?.getTime()).toBe(expires?.getTime());
    if (key.expires != undefined && expires != undefined) {
        expect(key.expires?.getTime()-dateCreated.getTime()).toBe(expires?.getTime()-dateCreated.getTime());
    }

});

test('CookieSessionManager.loginGetKeyLogout', async () => {
    const sessionStorage = new InMemoryKeyStorage(userStorage);
    let manager = new CookieSessionManager(userStorage, sessionStorage);
    let {user: bob, cookie: cookie } = await manager.login("bob", "bobPass123");
    const user = await manager.userForSessionKey(cookie.value);
    expect(user).toBeDefined();
    if (user) expect(user.username).toBe(bob.username);
    await manager.logout(cookie.value);
    await expect(async () => {await manager.userForSessionKey(cookie.value)}).rejects.toThrowError(CrossauthError);
});

test('CookieSessionManager.logoutFromAll', async() => {
    const sessionStorage = new InMemoryKeyStorage(userStorage);
    let manager = new CookieSessionManager(userStorage, sessionStorage);
    let {user: bob, cookie: cookie } = await manager.login("bob", "bobPass123");
    const user = await manager.userForSessionKey(cookie.value);
    expect(user).toBeDefined();
    if (user) {
        expect(user.username).toBe(bob.username);
        await manager.logoutFromAll(user.username);
        await expect(async () => {await manager.userForSessionKey(cookie.value)}).rejects.toThrowError(CrossauthError);
    }
})