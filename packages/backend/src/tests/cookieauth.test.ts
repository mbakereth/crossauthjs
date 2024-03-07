import { test, expect, beforeAll } from 'vitest';
import { DoubleSubmitCsrfToken, SessionCookie } from '../cookieauth';
import { Hasher } from '../hasher';
import { SessionManager } from '../session';
import { LocalPasswordAuthenticator } from '../authenticators/passwordauth';
import { InMemoryUserStorage, InMemoryKeyStorage } from '../storage/inmemorystorage';
import { getTestUserStorage }  from '../storage/tests/inmemorytestdata';
import { CrossauthError } from '@crossauth/common';

export var userStorage : InMemoryUserStorage;

// for all these tests, the database will have two users: bob and alice
beforeAll(async () => {
    userStorage = await getTestUserStorage();
});


test('SessionCookie.createSessionKey', async () => {
    const keyStorage = new InMemoryKeyStorage();
    const auth = new SessionCookie(userStorage, keyStorage, {secret: "ABCDEFGHIJKLMNOPQRSTUVWX", siteUrl: "http://locahost:3000"});
    const {user: bob} = await userStorage.getUserByUsername("bob");
    let { value, created: dateCreated, expires } = await auth.createSessionKey(bob.id);
    let key = await keyStorage.getKey(SessionCookie.hashSessionKey(value));
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
    let authenticator = new LocalPasswordAuthenticator(userStorage);
    let manager = new SessionManager(userStorage, keyStorage, {localpassword: authenticator}, {secret: "ABCDEFGHIJKLMNOPQRSTUVWX"});
    let {user: bob, sessionCookie: cookie } = await manager.login("bob", {password: "bobPass123"});
    const user = await manager.userForSessionKey(cookie.value);
    expect(user).toBeDefined();
    if (user) expect(user.username).toBe(bob.username);
    await manager.logout(cookie.value);
    await expect(async () => {await manager.userForSessionKey(cookie.value)}).rejects.toThrowError();
});

test('CookieSessionManager.logoutFromAll', async() => {
    const keyStorage = new InMemoryKeyStorage();
    let authenticator = new LocalPasswordAuthenticator(userStorage);
    let manager = new SessionManager(userStorage, keyStorage, {localpassword: authenticator}, {secret: "ABCDEFGHIJKLMNOPQRSTUVWX"});
    let {user: bob, sessionCookie: cookie } = await manager.login("bob", {password: "bobPass123"});
    const user = await manager.userForSessionKey(cookie.value);
    expect(user).toBeDefined();
    if (user) {
        expect(user.username).toBe(bob.username);
        await manager.logoutFromAll(user.username);
        await expect(async () => {await manager.userForSessionKey(cookie.value)}).rejects.toThrowError();
    }
})

test('DoubleSubmitCsrfToken.signAndUnsignCookie', async () => {
    const secret = "ABCDEFGHIJKLMNOPQRSTUVWX";
    const auth = new DoubleSubmitCsrfToken({secret: secret});
    const token = auth.createCsrfToken();
    const cookie = auth.makeCsrfCookie(token);
    const cookieToken = Hasher.unsign(cookie.value, secret).v;
    expect(cookieToken).toBe(token);
});

test('DoubleSubmitCsrfToken.makeAndRecoverFormOrHeaderToken', async () => {
    const secret = "ABCDEFGHIJKLMNOPQRSTUVWX";
    const auth = new DoubleSubmitCsrfToken({secret: secret});
    const token = auth.createCsrfToken();
    const formOrHeaderValue = auth.makeCsrfFormOrHeaderToken(token);
    const recoveredToken = auth['unmaskCsrfToken'](formOrHeaderValue);
    expect(recoveredToken).toBe(token);
});

test('DoubleSubmitCsrfToken.createAndValidateCsrfToken', async () => {
    const auth = new DoubleSubmitCsrfToken({secret: "ABCDEFGHIJKLMNOPQRSTUVWX"});
    const token = auth.createCsrfToken();
    const cookie = auth.makeCsrfCookie(token);
    const formOrHeaderValue = auth.makeCsrfFormOrHeaderToken(token);
    let valid = false;
    try {
        auth.validateDoubleSubmitCsrfToken(cookie.value, formOrHeaderValue);
        valid = true;
    } catch {}
    expect(valid).toBe(true);
});
