import { test, expect, beforeAll } from 'vitest';
import { InMemoryUserStorage, InMemoryKeyStorage } from '../inmemorystorage';
import { CrossauthError } from '../../..';
import { getTestUserStorage }  from './inmemorytestdata';

export var userStorage : InMemoryUserStorage;

// for all these tests, the database will have two users: bob and alice
beforeAll(async () => {
    userStorage = getTestUserStorage();
});

// test getting a user by username and by id
test('InMemoryUserStorage.getUser', async () => {
    const bob = await userStorage.getUserByUsername("bob");
    expect(bob.username).toBe("bob");
    const id = bob.id;
    const bob2 = await userStorage.getUserById(bob.username);
    expect(bob2.id).toBe(id);
    await expect(async () => {await userStorage.getUserByUsername("ABC")}).rejects.toThrowError(CrossauthError);
});

test('InMemoryKeyStorage.createGetAndDeleteSession', async () => {
    const key = "ABCDEF123";
    const keyStorage = new InMemoryKeyStorage(userStorage);
    const bob = await userStorage.getUserByUsername("bob");
    const now = new Date();
    const expiry = new Date();
    expiry.setSeconds(now.getSeconds() + 24*60*60); // 1 day
    await keyStorage.saveKey(bob.username, key, now, expiry);
    let { user, key: sessionKey} = await keyStorage.getUserForKey(key);
    expect(user).toBeDefined();
    if (user) expect(user.username).toBe(bob.username);
    expect(sessionKey.expires).toStrictEqual(expiry);
    keyStorage.deleteKey(key);
    await expect(async () => {await keyStorage.getUserForKey(key)}).rejects.toThrowError(CrossauthError);
});

test("InMemoryKeyStorage.deleteAllKeysForUser", async() => {
    const key1 = "ABCDEF123";
    const key2 = "ABCDEF456";
    const keyStorage = new InMemoryKeyStorage(userStorage);
    const bob = await userStorage.getUserByUsername("bob");
    const now = new Date();
    const expiry = new Date();
    expiry.setSeconds(now.getSeconds() + 24*60*60); // 1 day
    await keyStorage.saveKey(bob.username, key1, now, expiry);
    await keyStorage.saveKey(bob.username, key2, now, expiry);
    await keyStorage.deleteAllForUser(bob.id);
    await expect(async () => {await keyStorage.getUserForKey(key1)}).rejects.toThrowError(CrossauthError);
    await expect(async () => {await keyStorage.getUserForKey(key2)}).rejects.toThrowError(CrossauthError);

});

test("InMemoryKeyStorage.deleteAllKeysForUserExcept", async() => {
    const key1 = "ABCDEF789";
    const key2 = "ABCDEF012";
    const keyStorage = new InMemoryKeyStorage(userStorage);
    const bob = await userStorage.getUserByUsername("bob");
    const now = new Date();
    const expiry = new Date();
    expiry.setSeconds(now.getSeconds() + 24*60*60); // 1 day
    await keyStorage.saveKey(bob.id, key1, now, expiry);
    await keyStorage.saveKey(bob.id, key2, now, expiry);
    await keyStorage.deleteAllForUser(bob.id, key1 );
    let bob2 = await keyStorage.getUserForKey(key1);
    expect(bob2).toBeDefined();
    await expect(async () => {await keyStorage.getUserForKey(key2)}).rejects.toThrowError(CrossauthError);

});

