import { test, expect, beforeAll } from 'vitest';
import { CookieAuth } from '../cookieauth';
import { InMemoryUserStorage, InMemorySessionStorage } from '../storage/inmemorystorage';
import { getTestUserStorage }  from '../storage/tests/inmemorytestdata';

export var userStorage : InMemoryUserStorage;

// for all these tests, the database will have two users: bob and alice
beforeAll(async () => {
    userStorage = getTestUserStorage();
});


test('CookieAuth.createSessionKey', async () => {
    const sessionStorage = new InMemorySessionStorage(userStorage);
    const auth = new CookieAuth(sessionStorage);
    const bob = await userStorage.getUserByUsername("bob");
    let { value, dateCreated, expires } = await auth.createSessionKey(bob.uniqueId);
    let { user, expires: expires2 } = await sessionStorage.getUserForSessionKey(value);
    expect(expires2).toBeDefined();
    expect(expires).toBeDefined();
    expect(user.username).toStrictEqual(bob.username);
    expect(expires2?.getTime()).toBe(expires?.getTime());
    if (expires2 != undefined && expires != undefined) {
        expect(expires2?.getTime()-dateCreated.getTime()).toBe(expires?.getTime()-dateCreated.getTime());
    }

});
