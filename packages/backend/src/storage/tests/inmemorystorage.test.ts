// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { test, expect, beforeAll } from 'vitest';
import { InMemoryUserStorage, InMemoryKeyStorage, InMemoryOAuthClientStorage, InMemoryOAuthAuthorizationStorage } from '../inmemorystorage';
import { getTestUserStorage }  from './inmemorytestdata';
import { OAuthClient } from '@crossauth/common';

export var userStorage : InMemoryUserStorage;
export var secretUserStorage : InMemoryUserStorage;

// for all these tests, the database will have two users: bob and alice
beforeAll(async () => {
    userStorage = await getTestUserStorage();
    secretUserStorage = await getTestUserStorage("ABCDEFGHIJKLMNOPQRSTUV");
});

// test getting a user by username and by id
test('InMemoryUserStorage.getUser', async () => {
    const {user: bob} = await userStorage.getUserByUsername("bob");
    expect(bob.username).toBe("bob");
    const id = bob.id;
    const {user: bob2} = await userStorage.getUserById(bob.username);
    expect(bob2.id).toBe(id);
    await expect(async () => {await userStorage.getUserByUsername("ABC")}).rejects.toThrowError();
});

// test updating a field
test('InMemoryUserStorage.updateUser', async () => {
    const {user: bob} = await userStorage.getUserByUsername("bob");
    expect(bob.username).toBe("bob");
    userStorage.updateUser({id: "bob", dummyField: "def"});
    const {user: bob2} = await userStorage.getUserByUsername("bob");
    expect(bob2.dummyField).toBe("def");
});


test('InMemoryKeyStorage.createGetAndDeleteSession', async () => {
    const key = "ABCDEF123";
    const keyStorage = new InMemoryKeyStorage();
    const {user: bob} = await userStorage.getUserByUsername("bob");
    const now = new Date();
    const expiry = new Date();
    expiry.setSeconds(now.getSeconds() + 24*60*60); // 1 day
    await keyStorage.saveKey(bob.username, key, now, expiry);
    let sessionKey = await keyStorage.getKey(key);
    expect(sessionKey.userid).toBe(bob.id);
    expect(sessionKey.expires).toStrictEqual(expiry);
    await keyStorage.deleteKey(key);
    await expect(async () => {await keyStorage.getKey(key)}).rejects.toThrowError();
});

test("InMemoryKeyStorage.deleteAllKeysForUser", async() => {
    const key1 = "ABCDEF123";
    const key2 = "ABCDEF456";
    const keyStorage = new InMemoryKeyStorage();
    const {user: bob} = await userStorage.getUserByUsername("bob");
    const now = new Date();
    const expiry = new Date();
    expiry.setSeconds(now.getSeconds() + 24*60*60); // 1 day
    await keyStorage.saveKey(bob.username, key1, now, expiry);
    await keyStorage.saveKey(bob.username, key2, now, expiry);
    await keyStorage.deleteAllForUser(bob.id, "");
    await expect(async () => {await keyStorage.getKey(key1)}).rejects.toThrowError();
    await expect(async () => {await keyStorage.getKey(key2)}).rejects.toThrowError();

});

test("InMemoryKeyStorage.deleteAllKeysForUserExcept", async() => {
    const key1 = "ABCDEF789";
    const key2 = "ABCDEF012";
    const keyStorage = new InMemoryKeyStorage();
    const {user: bob} = await userStorage.getUserByUsername("bob");
    const now = new Date();
    const expiry = new Date();
    expiry.setSeconds(now.getSeconds() + 24*60*60); // 1 day
    await keyStorage.saveKey(bob.username, key1, now, expiry);
    await keyStorage.saveKey(bob.username, key2, now, expiry);
    await keyStorage.deleteAllForUser(bob.id, "", key1 );
    let bobkey2 = await keyStorage.getKey(key1);
    expect(bobkey2.userid).toBe(bob.id);
    await expect(async () => {await keyStorage.getKey(key2)}).rejects.toThrowError();

});

test("InMemoryKeyStorage.secretedHashDifferentFromUnsecreted", async() => {
    const {secrets: bobSecrets} = await userStorage.getUserByUsername("bob");
    const {secrets: secretedBobSecrets} = await secretUserStorage.getUserByUsername("bob");
    expect(bobSecrets.password).not.toBe(secretedBobSecrets.password);
});

test("InMemoryKeyStorage.addData", async() => {
    const keyName = "ABCDEF789";
    const now = new Date();
    const expiry = new Date();
    const keyStorage = new InMemoryKeyStorage();
    await keyStorage.saveKey("bob", keyName, now, expiry);
    await keyStorage.updateData(keyName, "name1", "abc");
    const key1 = await keyStorage.getKey(keyName);
    const jsonData1 = JSON.parse(key1.data??"{}");
    expect(jsonData1.name1).toBe("abc");

    await keyStorage.updateData(keyName, "name2", {"name3": "xyz"});
    const key2 = await keyStorage.getKey(keyName);
    const jsonData2 = JSON.parse(key2.data??"{}");
    expect(jsonData2.name2.name3).toBe("xyz");

    await keyStorage.updateData(keyName, "name1", undefined);
    const key3 = await keyStorage.getKey(keyName);
    const jsonData3 = JSON.parse(key3.data??"{}");
    expect(jsonData3.name1).toBeUndefined();

});

test("InMemoryKeyStorage.updateWithDots", async() => {
    const keyName = "ABCDEF789";
    const now = new Date();
    const expiry = new Date();
    const keyStorage = new InMemoryKeyStorage();
    await keyStorage.saveKey("bob", keyName, now, expiry, JSON.stringify({part1: {part2: "2"}}));
    await keyStorage.updateData(keyName, "part1.part2", {part3: "3", part4: "4"});
    await keyStorage.updateData(keyName, "part1.part5", "5");

    const key = await keyStorage.getKey(keyName);
    let data = JSON.parse(key.data ?? "{}");
    expect(data?.part1?.part2?.part3).toBe("3");
    expect(data?.part1?.part2?.part4).toBe("4");
    expect(data?.part1?.part5).toBe("5");
});

test("InMemoryKeyStorage.updateMAnyWithDots", async() => {
    const keyName = "ABCDEF789";
    const now = new Date();
    const expiry = new Date();
    const keyStorage = new InMemoryKeyStorage();
    await keyStorage.saveKey("bob", keyName, now, expiry, JSON.stringify({part1: {part2: "2"}}));
    await keyStorage.updateManyData(keyName, 
        [{dataName: "part1.part2", value: {part3: "3", part4: "4"}}, 
            {dataName: "part1.part5", value: "5"}]);

    const key = await keyStorage.getKey(keyName);
    let data = JSON.parse(key.data ?? "{}");
    expect(data?.part1?.part2?.part3).toBe("3");
    expect(data?.part1?.part2?.part4).toBe("4");
    expect(data?.part1?.part5).toBe("5");
});

test("InMemoryKeyStorage.deleteWithDots", async() => {
    const keyName = "ABCDEF789";
    const now = new Date();
    const expiry = new Date();
    const keyStorage = new InMemoryKeyStorage();
    await keyStorage.saveKey("bob", keyName, now, expiry, JSON.stringify({part1: {part2:{part3: "3", part4: "4"}, part5: "5"}}));
    await keyStorage.deleteData(keyName, "part1.part2.part3");
    await keyStorage.deleteData(keyName, "part1.part5");

    const key = await keyStorage.getKey(keyName);
    let data = JSON.parse(key.data ?? "{}");
    expect(data?.part1?.part2?.part4).toBeDefined();
    expect(data?.part1?.part2?.part3).toBeUndefined();
    expect(data?.part1?.part5).toBeUndefined();
});

test("InMemoryKeyStorage.getAllForUser", async() => {
    const key1 = "ABCDEF123";
    const key2 = "ABCDEF456";
    const key3 = "XYZ123456";
    const keyStorage = new InMemoryKeyStorage();
    const {user: bob} = await userStorage.getUserByUsername("bob");
    await keyStorage.deleteAllForUser(bob.id, ""); // TODO: this and the next lien do nothing
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

test("InMemoryKeyStorage.getAllForUserWhenEmpty", async() => {
    const keyStorage = new InMemoryKeyStorage();
    const {user: bob} = await userStorage.getUserByUsername("bob");
    await keyStorage.deleteAllForUser(bob.id, "");
    const keys = await keyStorage.getAllForUser(bob.id);
    expect(keys.length).toBe(0);
});

test("InMemoryKeyStorage.getAllForNullUser", async() => {
    const key1 = "ABCDEF123";
    const key2 = "ABCDEF456";
    const key3 = "XYZ123456";
    const keyStorage = new InMemoryKeyStorage();
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

test("InMemoryKeyStorage.deleteKeyForUser", async() => {
    const key1 = "ABCDEF123";
    const key2 = "ABCDEF456";
    const keyStorage = new InMemoryKeyStorage();
    const {user: bob} = await userStorage.getUserByUsername("bob");
    await keyStorage.deleteAllForUser(bob.id, "");
    const now = new Date();
    const expiry = new Date();
    expiry.setSeconds(now.getSeconds() + 24*60*60); // 1 day
    await keyStorage.saveKey(bob.id, key1, now, expiry);
    await keyStorage.saveKey(bob.id, key2, now, expiry);
    await keyStorage.deleteMatching({userid: bob.id, value: key1});
    const keys = await keyStorage.getAllForUser(bob.id);
    expect(keys.length).toBe(1);
});

test("InMemoryKeyStorage.deleteKeyForNoUser", async() => {
    const key1 = "ABCDEF123";
    const key2 = "ABCDEF456";
    const keyStorage = new InMemoryKeyStorage();
    await keyStorage.deleteAllForUser(undefined, "");
    const now = new Date();
    const expiry = new Date();
    expiry.setSeconds(now.getSeconds() + 24*60*60); // 1 day
    await keyStorage.saveKey(undefined, key1, now, expiry);
    await keyStorage.saveKey(undefined, key2, now, expiry);
    await keyStorage.deleteMatching({userid: null, value: key1});
    const keys = await keyStorage.getAllForUser(undefined);
    expect(keys.length).toBe(1);
});

test('InMemoryClientStorage.createGetAndDeleteClient', async () => {
    const clientStorage = new InMemoryOAuthClientStorage();
    const client = {
        client_id : "ABC",
        client_secret: "DEF",
        client_name: "Test",
        redirect_uri: [],
        valid_flow: [],
        confidential: true,
    };
    await clientStorage.createClient(client);
    const getClient = await clientStorage.getClientById(client.client_id);
    expect(getClient.client_secret).toBe(client.client_secret);
    await clientStorage.deleteClient(client.client_id);
    await expect(async () => {await clientStorage.getClientById(client.client_id)}).rejects.toThrowError();
});

test('InMemoryClientStorage.createAndUpdateValidFlows', async () => {
    const clientStorage = new InMemoryOAuthClientStorage();
    const client = {
        client_id : "ABC3b",
        client_secret: "DEF",
        client_name: "Test",
        redirect_uri: ["http://client.com/uri1", "http://client.com/uri2"],
        valid_flow: ["authorizationCode", "authorizationCodeWithPKCE"],
        confidential: true,
    }
    await clientStorage.createClient(client);
    const getClient1 = await clientStorage.getClientById(client.client_id);
    expect(getClient1.valid_flow.length).toBe(2);
    await clientStorage.updateClient({client_id: client.client_id, valid_flow: ["clientCredentials"]});
    const getClient2 = await clientStorage.getClientById(client.client_id);
    expect(getClient2.valid_flow.length).toBe(1);
    expect(getClient2.valid_flow[0]).toBe("clientCredentials");
});

test("InMemoryAuthorization.createAndGetForUser", async () => {
    const authStorage = new InMemoryOAuthAuthorizationStorage();
    await authStorage.updateAuthorizations("ABC", 1, ["read", "write"]);
    const scopes = await authStorage.getAuthorizations("ABC", 1);
    expect(scopes.length).toBe(2);
    expect(["read", "write"]).toContain(scopes[0]);
    expect(["read", "write"]).toContain(scopes[1]);
});

test("InMemoryAuthorization.createAndGetWrongClient", async () => {
    const authStorage = new InMemoryOAuthAuthorizationStorage();
    authStorage.updateAuthorizations("ABCD", 1, ["read", "write"]);
    const scopes = await authStorage.getAuthorizations("ABC", 1);
    expect(scopes.length).toBe(0);
});

test("InMemoryAuthorization.createAndGetWrongUser", async () => {
    const authStorage = new InMemoryOAuthAuthorizationStorage();
    await authStorage.updateAuthorizations("ABC", 2, ["read", "write"]);
    const scopes = await authStorage.getAuthorizations("ABC", 1);
    expect(scopes.length).toBe(0);
});

test("InMemoryAuthorization.createAndGetForClient", async () => {
    const authStorage = new InMemoryOAuthAuthorizationStorage();
    await authStorage.updateAuthorizations("ABC", null, ["read", "write"]);
    const scopes = await authStorage.getAuthorizations("ABC", undefined);
    expect(scopes.length).toBe(2);
    expect(["read", "write"]).toContain(scopes[0]);
    expect(["read", "write"]).toContain(scopes[1]);
});

test("InMemoryAuthorization.createAndGetForUserAndClientDontOverlap", async () => {
    const authStorage = new InMemoryOAuthAuthorizationStorage();
    await authStorage.updateAuthorizations("ABC", 1, ["user1", "user2"]);
    await authStorage.updateAuthorizations("ABC", null, ["client1", "client1"]);

    const userScopes = await authStorage.getAuthorizations("ABC", 1);
    expect(userScopes.length).toBe(2);
    expect(["user1", "user2"]).toContain(userScopes[0]);
    expect(["user1", "user2"]).toContain(userScopes[1]);

    const clientScopes = await authStorage.getAuthorizations("ABC", undefined);
    expect(clientScopes.length).toBe(2);
    expect(["client1", "client1"]).toContain(clientScopes[0]);
    expect(["client1", "client1"]).toContain(clientScopes[1]);
});

test("InMemoryAuthorization.createAndUpdateForUser", async () => {
    const authStorage = new InMemoryOAuthAuthorizationStorage();
    await authStorage.updateAuthorizations("ABC", 1, ["read", "write"]);
    await authStorage.updateAuthorizations("ABC", 1, ["read", "delete"]);
    const scopes = await authStorage.getAuthorizations("ABC", 1);
    expect(scopes.length).toBe(2);
    expect(["read", "delete"]).toContain(scopes[0]);
    expect(["read", "delete"]).toContain(scopes[1]);
});

test('InMemoryClientStorage.getClientByName', async () => {
    const clientStorage = new InMemoryOAuthClientStorage();
    const client = {
        client_id : "ABC",
        client_secret: "DEF",
        client_name: "Test",
        redirect_uri: [],
        valid_flow: [],
        confidential: true,
    };
    await clientStorage.createClient(client);
    const getClients = await clientStorage.getClientByName(client.client_name);
    expect(getClients[0].client_name).toBe(client.client_name);
});

test('InMemoryAuthorization.getClients', async () => {
    const clientStorage = new InMemoryOAuthClientStorage();
    let client : OAuthClient = {
        client_id : "ABC1",
        client_secret: "DEF",
        client_name: "Test1",
        redirect_uri: [],
        valid_flow: [],
        confidential: true,
    }
    await clientStorage.createClient(client);

    client = {
        client_id : "ABC2",
        client_secret: "DEF",
        client_name: "Test2",
        redirect_uri: [],
        valid_flow: [],
        confidential: true,
    }
    await clientStorage.createClient(client);

    client = {
        client_id : "ABC3",
        client_secret: "DEF",
        client_name: "Test3",
        redirect_uri: [],
        valid_flow: [],
        confidential: true,
        userid : 1,
    }
    await clientStorage.createClient(client);

    let getClients = await clientStorage.getClients(undefined, undefined, undefined);
    expect(getClients.length).toBe(3);
    getClients = await clientStorage.getClients(undefined, undefined, null)
    expect(getClients.length).toBe(2);
    getClients = await clientStorage.getClients(undefined, undefined, 1)
    expect(getClients.length).toBe(1);
});
