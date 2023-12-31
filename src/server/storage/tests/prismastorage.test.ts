import { test, expect, beforeAll, afterAll } from 'vitest';
import { PrismaUserStorage, PrismaSessionStorage } from '../prismastorage';
import { CrossauthError } from '../../..';
import { PrismaClient } from '@prisma/client';

import { HashedPasswordAuthenticator } from '../../password';

export var prismaClient : PrismaClient;
export var userStorage : PrismaUserStorage;

// for all these tests, the database will have two users: bob and alice
beforeAll(async () => {
    prismaClient = new PrismaClient();
    await prismaClient.user.deleteMany({});
    await prismaClient.session.deleteMany({});
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

test('PrismaSessionStorage.createGetAndDeleteSession', async () => {
    const sessionId = "ABCDEF123";
    const sessionStorage = new PrismaSessionStorage(userStorage);
    const bob = await userStorage.getUserByUsername("bob");
    const now = new Date();
    const expiry = new Date();
    expiry.setSeconds(now.getSeconds() + 24*60*60); // 1 day
    await sessionStorage.saveSession(bob.id, sessionId, now, expiry);
    let { user, expires} = await sessionStorage.getUserForSessionKey(sessionId);
    expect(user.username).toBe(bob.username);
    expect(expires).toStrictEqual(expiry);
    sessionStorage.deleteSession(sessionId);
    await expect(async () => {await sessionStorage.getUserForSessionKey(sessionId)}).rejects.toThrowError(CrossauthError);
});


afterAll(async () => {
    //await prismaClient.user.deleteMany({});
});
