import { test, expect, beforeAll } from 'vitest';
import { HashedPasswordAuthenticator } from '../password';
import { getTestUserStorage }  from '../storage/tests/inmemorytestdata';
import { InMemoryUserStorage } from '../storage/inmemorystorage';
export var userStorage : InMemoryUserStorage;
export var pepperUserStorage : InMemoryUserStorage;

// for all these tests, the database will have two users: bob and alice
beforeAll(async () => {
    userStorage = getTestUserStorage();
    pepperUserStorage = getTestUserStorage("ABCDEFGHIJKLMNOPQRSTUV");
});

test('HashedPasswordAuthenticator.authenticateUser', async () => {
    let authenticator = new HashedPasswordAuthenticator(userStorage);
    let user = await authenticator.authenticateUser("bob", "bobPass123");
    expect(user.username).toBe("bob");
});

test('HashedPasswordAuthenticator.authenticateUseWithPepper', async () => {
    let authenticator = new HashedPasswordAuthenticator(pepperUserStorage, 
        {pepper: "ABCDEFGHIJKLMNOPQRSTUV"});
    let user = await authenticator.authenticateUser("bob", "bobPass123");
    expect(user.username).toBe("bob");
});
