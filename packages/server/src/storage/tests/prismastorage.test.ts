import { test, expect, beforeAll, afterAll } from 'vitest';
import { PrismaUserStorage, PrismaKeyStorage } from '../prismastorage';
import { CrossauthError } from '@crossauth/common';
import { PrismaClient } from '@prisma/client';
import { LocalPasswordAuthenticator } from '../../authenticators/passwordauth';

export var prismaClient : PrismaClient;
export var userStorage : PrismaUserStorage;

// for all these tests, the database will have two users: bob and alice
beforeAll(async () => {
    prismaClient = new PrismaClient();
    await prismaClient.user.deleteMany({});
    await prismaClient.key.deleteMany({});
    userStorage = new PrismaUserStorage({userEditableFields: "email, dummyField"});
    let authenticator = new LocalPasswordAuthenticator(userStorage);
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

// test getting a user by username and by id
test('PrismaUserStorage.getUser', async () => {
    const {user: bob} = await userStorage.getUserByUsername("bob");
    expect(bob.username).toBe("bob");
    const id = bob.id;
    const {user: bob2} = await userStorage.getUserById(id);
    expect(bob2.id).toBe(id);
    await expect(async () => {await userStorage.getUserByUsername("ABC")}).rejects.toThrowError(CrossauthError);
});

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

test("PeismaStorage.addData", async() => {
    const keyName = "XYZABC12345";
    const now = new Date();
    const expiry = new Date();
    const keyStorage = new PrismaKeyStorage();
    const {user: bob} = await userStorage.getUserByUsername("bob");
    await keyStorage.saveKey(bob.id, keyName, now, expiry);
    await keyStorage.updateData(keyName, "name1", "abc");
    const key1 = await keyStorage.getKey(keyName);
    const jsonData1 = JSON.parse(key1.data||"{}");
    expect(jsonData1.name1).toBe("abc");

    await keyStorage.updateData(keyName, "name2", {"name3": "xyz"});
    const key2 = await keyStorage.getKey(keyName);
    const jsonData2 = JSON.parse(key2.data||"{}");
    expect(jsonData2.name2.name3).toBe("xyz");

    await keyStorage.updateData(keyName, "name1", undefined);
    const key3 = await keyStorage.getKey(keyName);
    const jsonData3 = JSON.parse(key3.data||"{}");
    expect(jsonData3.name1).toBeUndefined();

});

test("PrismaStorage.getAllForUser", async() => {
    const key1 = "ABCDEF123";
    const key2 = "ABCDEF456";
    const key3 = "XYZ123456";
    const keyStorage = new PrismaKeyStorage();
    const {user: bob} = await userStorage.getUserByUsername("bob");
    await keyStorage.deleteAllForUser(bob.id, "");
    await keyStorage.deleteAllForUser(undefined, "");
    const now = new Date();
    const expiry = new Date();
    expiry.setSeconds(now.getSeconds() + 24*60*60); // 1 day
    await keyStorage.saveKey(bob.id, key1, now, expiry);
    await keyStorage.saveKey(bob.id, key2, now, expiry);
    await keyStorage.saveKey(undefined, key3, now, expiry);
    const keys = await keyStorage.getAllForUser(bob.id);
    expect(keys.length).toBe(2);
    expect([key1, key2]).toContain(keys[0].value);
    expect(keys[1].value).not.toBe(key3);
});

test("PrismaStorage.getAllForUserWhenEmpty", async() => {
    const keyStorage = new PrismaKeyStorage();
    const {user: bob} = await userStorage.getUserByUsername("bob");
    await keyStorage.deleteAllForUser(bob.id, "");
    const keys = await keyStorage.getAllForUser(bob.id);
    expect(keys.length).toBe(0);
});

test("PrismaStorage.getAllForNullUser", async() => {
    const key1 = "ABCDEF123";
    const key2 = "ABCDEF456";
    const key3 = "XYZ123456";
    const keyStorage = new PrismaKeyStorage();
    const {user: bob} = await userStorage.getUserByUsername("bob");
    await keyStorage.deleteAllForUser(undefined, "");
    await keyStorage.deleteAllForUser(bob.id, "");
    const now = new Date();
    const expiry = new Date();
    expiry.setSeconds(now.getSeconds() + 24*60*60); // 1 day
    await keyStorage.saveKey(bob.id, key3, now, expiry);
    await keyStorage.saveKey(undefined, key1, now, expiry);
    await keyStorage.saveKey(undefined, key2, now, expiry);
    const keys = await keyStorage.getAllForUser(undefined);
    expect(keys.length).toBe(2);
    expect([key1, key2]).toContain(keys[0].value);
    expect(keys[0].value).not.toBe(key3);
    expect(keys[1].value).not.toBe(key3);
});

test("PrismaStorage.deleteMatchingForUser", async() => {
    const key1 = "ABCDEF123";
    const key2 = "ABCDEF456";
    const keyStorage = new PrismaKeyStorage();
    const {user: bob} = await userStorage.getUserByUsername("bob");
    await keyStorage.deleteAllForUser(undefined, "");
    await keyStorage.deleteAllForUser(bob.id, "");
    const now = new Date();
    const expiry = new Date();
    expiry.setSeconds(now.getSeconds() + 24*60*60); // 1 day
    await keyStorage.saveKey(bob.id, key1, now, expiry);
    await keyStorage.saveKey(bob.id, key2, now, expiry);
    await keyStorage.deleteMatching({userId: bob.id, value: key1});
    const keys = await keyStorage.getAllForUser(bob.id);
    expect(keys.length).toBe(1);
});


afterAll(async () => {
    //await prismaClient.user.deleteMany({});
});
