// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { test, expect, beforeAll } from 'vitest';
import { LocalPasswordAuthenticator } from '../authenticators/passwordauth';
import { getTestUserStorage }  from '../storage/tests/inmemorytestdata';
import { InMemoryUserStorage } from '../storage/inmemorystorage';
export var userStorage : InMemoryUserStorage;
export var secretUserStorage : InMemoryUserStorage;

// for all these tests, the database will have two users: bob and alice
beforeAll(async () => {
    userStorage = await getTestUserStorage();
    secretUserStorage = await getTestUserStorage("ABCDEFGHIJKLMNOPQRSTUV");
});

test('HashedPasswordAuthenticator.authenticateUser', async () => {
    let {user, secrets} = await userStorage.getUserByUsername("bob");
    let authenticator = new LocalPasswordAuthenticator(userStorage);
    await authenticator.authenticateUser(user, secrets, {password: "bobPass123"});
    expect(user.username).toBe("bob");
});

test('HashedPasswordAuthenticator.authenticateUseWithSecret', async () => {
    let {user, secrets} = await userStorage.getUserByUsername("bob");
    let authenticator = new LocalPasswordAuthenticator(secretUserStorage, 
        {secret: "ABCDEFGHIJKLMNOPQRSTUV", enableSecretForPasswordHash: true});
     await authenticator.authenticateUser(user, secrets, {password: "bobPass123"});
    expect(user.username).toBe("bob");
});
