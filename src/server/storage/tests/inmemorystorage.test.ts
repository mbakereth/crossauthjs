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

test('InMemorySessionStorage.createGetAndDeleteSession', async () => {
    const sessionId = "ABCDEF123";
    const sessionStorage = new InMemoryKeyStorage(userStorage);
    const bob = await userStorage.getUserByUsername("bob");
    const now = new Date();
    const expiry = new Date();
    expiry.setSeconds(now.getSeconds() + 24*60*60); // 1 day
    await sessionStorage.saveKey(bob.username, sessionId, now, expiry);
    let { user, key: sessionKey} = await sessionStorage.getUserForKey(sessionId);
    expect(user.username).toBe(bob.username);
    expect(sessionKey.expires).toStrictEqual(expiry);
    sessionStorage.deleteKey(sessionId);
    await expect(async () => {await sessionStorage.getUserForKey(sessionId)}).rejects.toThrowError(CrossauthError);
});


