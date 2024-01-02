import { test, expect, beforeAll, afterAll } from 'vitest';
import { PrismaUserStorage, PrismaKeyStorage } from '../prismastorage';
import { CrossauthError } from '../../..';
import { PrismaClient } from '@prisma/client';
import { HashedPasswordAuthenticator } from '../../password';

export var prismaClient : PrismaClient;
export var userStorage : PrismaUserStorage;

// for all these tests, the database will have two users: bob and alice
beforeAll(async () => {
    prismaClient = new PrismaClient();
    await prismaClient.user.deleteMany({});
    await prismaClient.key.deleteMany({});
    userStorage = new PrismaUserStorage();
    let authenticator = new HashedPasswordAuthenticator(userStorage);
    await prismaClient.user.create({
        data: {
          username: 'bob',
          passwordHash: authenticator.createPasswordHash("bobPass123", true),
        },
    });
    
    await prismaClient.user.create({
        data: {
            username: 'alice',
            passwordHash:  authenticator.createPasswordHash("alicePass123", true),
        },
      });
});

// test getting a user by username and by id
test('PrismaUserStorage.getUser', async () => {
    const bob = await userStorage.getUserByUsername("bob");
    expect(bob.username).toBe("bob");
    const id = bob.id;
    const bob2 = await userStorage.getUserById(id);
    expect(bob2.id).toBe(id);
    await expect(async () => {await userStorage.getUserByUsername("ABC")}).rejects.toThrowError(CrossauthError);
});

test('PrismaKeyStorage.createGetAndDeleteKey', async () => {
    const key = "ABCDEF123";
    const keyStorage = new PrismaKeyStorage(userStorage);
    const bob = await userStorage.getUserByUsername("bob");
    const now = new Date();
    const expiry = new Date();
    expiry.setSeconds(now.getSeconds() + 24*60*60); // 1 day
    await keyStorage.saveKey(bob.id, key, now, expiry);
    let { user, key: sessionKey} = await keyStorage.getUserForKey(key);
    expect(user).toBeDefined();
    if (user) expect(user.username).toBe(bob.username);
    expect(sessionKey.expires).toStrictEqual(expiry);
    await keyStorage.deleteKey(key);
    await expect(async () => {await keyStorage.getUserForKey(key)}).rejects.toThrowError(CrossauthError);
});

test("PrismaKeyStorage.deleteAllKeysForUser", async() => {
    const key1 = "ABCDEF123";
    const key2 = "ABCDEF456";
    const keyStorage = new PrismaKeyStorage(userStorage);
    const bob = await userStorage.getUserByUsername("bob");
    const now = new Date();
    const expiry = new Date();
    expiry.setSeconds(now.getSeconds() + 24*60*60); // 1 day
    await keyStorage.saveKey(bob.id, key1, now, expiry);
    await keyStorage.saveKey(bob.id, key2, now, expiry);
    await keyStorage.deleteAllForUser(bob.id);
    await expect(async () => {await keyStorage.getUserForKey(key1)}).rejects.toThrowError(CrossauthError);
    await expect(async () => {await keyStorage.getUserForKey(key2)}).rejects.toThrowError(CrossauthError);

});

test("PrismaKeyStorage.deleteAllKeysForUserExcept", async() => {
    const key1 = "ABCDEF789";
    const key2 = "ABCDEF012";
    const keyStorage = new PrismaKeyStorage(userStorage);
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


afterAll(async () => {
    //await prismaClient.user.deleteMany({});
});
