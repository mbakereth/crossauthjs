import { test, expect, beforeAll } from 'vitest';
import { CookieAuth, CookieSessionManager } from '../cookieauth';
import { HashedPasswordAuthenticator } from '../password';
import { InMemoryUserStorage, InMemoryKeyStorage } from '../storage/inmemorystorage';
import { getTestUserStorage }  from '../storage/tests/inmemorytestdata';
import { CrossauthError } from '../../error';

export var userStorage : InMemoryUserStorage;

// for all these tests, the database will have two users: bob and alice
beforeAll(async () => {
    userStorage = getTestUserStorage();
});




test('CookieAuth.createSessionKey.encrypted', async () => {
    const sessionStorage = new InMemoryKeyStorage();
    const auth = new CookieAuth(userStorage, sessionStorage, {secret: "ABCDEFGHIJKLMNOPQRSTUVWX", hashSessionId: true});
    const bob = await userStorage.getUserByUsername("bob");
    let { value } = await auth.createSessionKey(bob.id);
    let hashedValue = auth.hashSessionKey(value);
    await sessionStorage.getKey(hashedValue);

});

