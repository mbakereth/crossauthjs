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
    await userStorage.createUser({
        username: "bob", 
        state: "active",
        dummyField: "abc", 
        email: "bob@bob.com",
    }, {
        password: await authenticator.createPasswordHash("bobPass123"), 
    });
    await userStorage.createUser({
        username: "alice", 
        state: "active",
        dummyField: "abc", 
        email: "alice@alice.com",
    }, {
        password: await authenticator.createPasswordHash("alicePass123"), 
    });
});

/*// test getting a user by username and by id
test('PrismaUserStorage.getUser', async () => {
    const {user: bob} = await userStorage.getUserByUsername("bob");
    expect(bob.username).toBe("bob");
    const id = bob.id;
    const {user: bob2} = await userStorage.getUserById(id);
    expect(bob2.id).toBe(id);
    await expect(async () => {await userStorage.getUserByUsername("ABC")}).rejects.toThrowError(CrossauthError);
});*/

// test updating a field in the user table
test("PrismaUserStorage.updateUser", async() => {
    const {user: bob, secrets: bobsecrets} = await userStorage.getUserByUsername("bob");
    expect(bob.username).toBe("bob");
    bob.dummyField = "def";
    await userStorage.updateUser(bob);
    const {user: bob2} = await userStorage.getUserByUsername("bob");
    expect(bob2.dummyField).toBe("def");
    bob.dummyField = "ghi";
    bobsecrets.password = "ABC";
    await userStorage.updateUser(bob, bobsecrets);
    const {user: bob3, secrets: bob3secrets} = await userStorage.getUserByUsername("bob");
    expect(bob3.dummyField).toBe("ghi");
    expect(bob3secrets.password).toBe("ABC");

})


test('PrismaKeyStorage.createGetAndDeleteKey', async () => {
    const key = "ABCDEF123";
    const keyStorage = new PrismaKeyStorage();
    const {user: bob} = await userStorage.getUserByUsername("bob");
    const now = new Date();
    const expiry = new Date();
    expiry.setSeconds(now.getSeconds() + 24*60*60); // 1 day
    await keyStorage.saveKey(bob.id, key, now, expiry);
    let sessionKey = await keyStorage.getKey(key);
    expect(sessionKey.userId).toBe(bob.id);
    expect(sessionKey.expires).toStrictEqual(expiry);
    await keyStorage.deleteKey(key);
    await expect(async () => {await keyStorage.getKey(key)}).rejects.toThrowError(CrossauthError);
});

test("PrismaKeyStorage.deleteAllKeysForUser", async() => {
    const key1 = "ABCDEF123";
    const key2 = "ABCDEF456";
    const keyStorage = new PrismaKeyStorage();
    const {user: bob} = await userStorage.getUserByUsername("bob");
    const now = new Date();
    const expiry = new Date();
    expiry.setSeconds(now.getSeconds() + 24*60*60); // 1 day
    await keyStorage.saveKey(bob.id, key1, now, expiry);
    await keyStorage.saveKey(bob.id, key2, now, expiry);
    await keyStorage.deleteAllForUser(bob.id, "");
    await expect(async () => {await keyStorage.getKey(key1)}).rejects.toThrowError(CrossauthError);
    await expect(async () => {await keyStorage.getKey(key2)}).rejects.toThrowError(CrossauthError);

});

test("PrismaKeyStorage.deleteAllKeysForUserExcept", async() => {
    const key1 = "ABCDEF789";
    const key2 = "ABCDEF012";
    const keyStorage = new PrismaKeyStorage();
    const {user: bob} = await userStorage.getUserByUsername("bob");
    const now = new Date();
    const expiry = new Date();
    expiry.setSeconds(now.getSeconds() + 24*60*60); // 1 day
    await keyStorage.saveKey(bob.id, key1, now, expiry);
    await keyStorage.saveKey(bob.id, key2, now, expiry);
    await keyStorage.deleteAllForUser(bob.id, "", key1 );
    let bobkey2 = await keyStorage.getKey(key1);
    expect(bobkey2.userId).toBe(bob.id);
    await expect(async () => {await keyStorage.getKey(key2)}).rejects.toThrowError(CrossauthError);

});

afterAll(async () => {
    //await prismaClient.user.deleteMany({});
});
