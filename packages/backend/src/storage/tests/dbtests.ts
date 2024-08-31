import { test, expect } from 'vitest';
import { UserStorage, KeyStorage, OAuthClientStorage, OAuthAuthorizationStorage } from '../../storage';
import { OAuthClient, CrossauthError, ErrorCode } from '@crossauth/common';
import { LocalPasswordAuthenticator } from '../../authenticators/passwordauth';

export function makeDBTests(prefix : string, userStorage : UserStorage, keyStorage : KeyStorage, clientStorage : OAuthClientStorage, authStorage : OAuthAuthorizationStorage, authenticator : LocalPasswordAuthenticator) {


    // test updating a field in the user table
    test(prefix+ ".createUserExisting", async() => {

        let ce : CrossauthError | undefined = undefined;
        try {
            await userStorage.createUser({
                username: "bob", 
                state: "active",
                dummyfield: "abc", 
                email: "bob@bob.com",
            }, {
                password: await authenticator.createPasswordHash("bobPass123"), 
            });    
        } catch (e) {
            ce = CrossauthError.asCrossauthError(e)
        }
        expect(ce?.code).toBe(ErrorCode.UserExists);
    })

    // test getting a user by username and by id
    test(prefix + '.getUser', async () => {
        const {user: bob} = await userStorage.getUserByUsername("bob");
        expect(bob.username).toBe("bob");
        const id = bob.id;
        const {user: bob2} = await userStorage.getUserById(id);
        expect(bob2.id).toBe(id);
        await expect(async () => {await userStorage.getUserByUsername("ABC")}).rejects.toThrowError();
    });

    // test updating a field in the user table
    test(prefix + ".updateUser", async() => {
        const {user: bob, secrets: bobsecrets} = await userStorage.getUserByUsername("bob");
        expect(bob.username).toBe("bob");
        bob.dummyfield = "def";
        await userStorage.updateUser(bob);
        const {user: bob2} = await userStorage.getUserByUsername("bob");
        expect(bob2.dummyfield).toBe("def");
        bob.dummyfield = "ghi";
        bobsecrets.password = "ABC";
        await userStorage.updateUser(bob, bobsecrets);
        const {user: bob3, secrets: bob3secrets} = await userStorage.getUserByUsername("bob");
        expect(bob3.dummyfield).toBe("ghi");
        expect(bob3secrets.password).toBe("ABC");

    })

    // test delete user by username and id
    test(prefix + ".delete", async() => {
        const { user: bob } = await userStorage.getUserByUsername("bob");
        expect(bob.username).toBe("bob");
        await userStorage.deleteUserById(bob.id);
        let haveBob = false;
        try {
            await userStorage.getUserByUsername("bob");
            haveBob = true;
        } catch (e) {}
        expect(haveBob).toBe(false);

        await userStorage.deleteUserByUsername("alice");
        let haveAlice = false;
        try {
            await userStorage.getUserByUsername("alice");
            haveAlice = true;
        } catch (e) {}
        expect(haveAlice).toBe(false);

    });

    test(prefix + '.createKey', async () => {
        const key = "ABCDEF123";
        const {user: bob} = await userStorage.getUserByUsername("bob");
        const now = new Date();
        const expiry = new Date();
        expiry.setSeconds(now.getSeconds() + 24*60*60); // 1 day
        await keyStorage.saveKey(bob.id, key, now, expiry);
        let sessionKey = await keyStorage.getKey(key);
        expect(sessionKey.userid).toBe(bob.id);
        expect(sessionKey.expires).toStrictEqual(expiry);
        await keyStorage.deleteKey(key);
        await expect(async () => {await keyStorage.getKey(key)}).rejects.toThrowError();
    });

    test(prefix + ".deleteAllKeysForUser", async() => {
        const key1 = "ABCDEF123";
        const key2 = "ABCDEF456";
        const {user: bob} = await userStorage.getUserByUsername("bob");
        const now = new Date();
        const expiry = new Date();
        expiry.setSeconds(now.getSeconds() + 24*60*60); // 1 day
        await keyStorage.saveKey(bob.id, key1, now, expiry);
        await keyStorage.saveKey(bob.id, key2, now, expiry);
        await keyStorage.deleteAllForUser(bob.id, "");
        await expect(async () => {await keyStorage.getKey(key1)}).rejects.toThrowError();
        await expect(async () => {await keyStorage.getKey(key2)}).rejects.toThrowError();

    });

    test(prefix + ".deleteAllKeysForUserExcept", async() => {
        const key1 = "ABCDEF789";
        const key2 = "ABCDEF012";
        const {user: bob} = await userStorage.getUserByUsername("bob");
        const now = new Date();
        const expiry = new Date();
        expiry.setSeconds(now.getSeconds() + 24*60*60); // 1 day
        await keyStorage.saveKey(bob.id, key1, now, expiry);
        await keyStorage.saveKey(bob.id, key2, now, expiry);
        await keyStorage.deleteAllForUser(bob.id, "", key1 );
        let bobkey2 = await keyStorage.getKey(key1);
        expect(bobkey2.userid).toBe(bob.id);
        await expect(async () => {await keyStorage.getKey(key2)}).rejects.toThrowError();

    });

    test(prefix + ".addData", async() => {
        const keyName = "XYZABC12345";
        const now = new Date();
        const expiry = new Date();
        const {user: bob} = await userStorage.getUserByUsername("bob");
        await keyStorage.saveKey(bob.id, keyName, now, expiry);
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

    test(prefix + ".getAllForUser", async() => {
        const key1 = "ABCDEF123";
        const key2 = "ABCDEF456";
        const key3 = "XYZ123456";
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

    test(prefix + ".getAllForUserWhenEmpty", async() => {
        const {user: bob} = await userStorage.getUserByUsername("bob");
        await keyStorage.deleteAllForUser(bob.id, "");
        const keys = await keyStorage.getAllForUser(bob.id);
        expect(keys.length).toBe(0);
    });

    test(prefix + ".getAllForNullUser", async() => {
        const key1 = "ABCDEF123";
        const key2 = "ABCDEF456";
        const key3 = "XYZ123456";
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

    test(prefix + ".deleteMatchingForUser", async() => {
        const key1 = "ABCDEF123";
        const key2 = "ABCDEF456";
        const {user: bob} = await userStorage.getUserByUsername("bob");
        await keyStorage.deleteAllForUser(undefined, "");
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

    test(prefix + '.createGetAndDeleteClient', async () => {    
        const client = {
            client_id : "ABC1",
            client_secret: "DEF",
            client_name: "Test",
            redirect_uri: [],
            valid_flow: [],
            confidential: true,
        }
        await clientStorage.createClient(client);
        const getClient = await clientStorage.getClientById(client.client_id);
        expect(getClient.client_secret).toBe(client.client_secret);
        await clientStorage.deleteClient(client.client_id);
        await expect(async () => {await clientStorage.getClientById(client.client_id)}).rejects.toThrowError();
        
    });

    test(prefix + '.createGetAndDeleteClientWithRedirectUri', async () => {    
        const client = {
            client_id : "ABC1",
            client_secret: "DEF",
            client_name: "Test",
            redirect_uri: ["http://server.com/redirect"],
            valid_flow: [],
            confidential: true,
        }
        await clientStorage.createClient(client);
        const getClient = await clientStorage.getClientById(client.client_id);
        expect(getClient.client_secret).toBe(client.client_secret);
        await clientStorage.deleteClient(client.client_id);
        await expect(async () => {await clientStorage.getClientById(client.client_id)}).rejects.toThrowError();
        
    });

    test(prefix + '.createGetAndDeleteClientWithValidFlow', async () => {    
        const client = {
            client_id : "ABC1",
            client_secret: "DEF",
            client_name: "Test",
            redirect_uri: [],
            valid_flow: ["authorizationCode"],
            confidential: true,
        }
        await clientStorage.createClient(client);
        const getClient = await clientStorage.getClientById(client.client_id);
        expect(getClient.client_secret).toBe(client.client_secret);
        await clientStorage.deleteClient(client.client_id);
        await expect(async () => {await clientStorage.getClientById(client.client_id)}).rejects.toThrowError();
        
    });

    test(prefix + '.getClientByName', async () => {
        const client = {
            client_id : "ABC1",
            client_secret: "DEF",
            client_name: "Test",
            redirect_uri: [],
            valid_flow: [],
            confidential: true,
        }
        await clientStorage.createClient(client);
        const getClients = await clientStorage.getClientByName(client.client_name);
        expect(getClients[0].client_name).toBe(client.client_name);
    });
    
    test(prefix + '.getClients', async () => {
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
    
        const {user} = await userStorage.getUserByUsername("bob");
        client = {
            client_id : "ABC3",
            client_secret: "DEF",
            client_name: "Test3",
            redirect_uri: [],
            valid_flow: [],
            confidential: true,
            userid : user.id,
        }
        await clientStorage.createClient(client);
    
        let getClients = await clientStorage.getClients();
        expect(getClients.length).toBe(3);
        getClients = await clientStorage.getClients(undefined, undefined, null)
        expect(getClients.length).toBe(2);
        getClients = await clientStorage.getClients(undefined, undefined, user.id)
        expect(getClients.length).toBe(1);
    });
    
    test(prefix + '.createClientWithRedirectUris', async () => {
        const client = {
            client_id : "ABC2",
            client_secret: "DEF",
            client_name: "Test",
            redirect_uri: ["http://client.com/uri1", "http://client.com/uri2"],
            valid_flow: [],
            confidential: true,
        }
        await clientStorage.createClient(client);
        const getClient = await clientStorage.getClientById(client.client_id);
        expect(getClient.client_secret).toBe(client.client_secret);
        expect(getClient.redirect_uri.length).toBe(2);
        expect(["http://client.com/uri1", "http://client.com/uri2"]).toContain(getClient.redirect_uri[0]);
        expect(["http://client.com/uri1", "http://client.com/uri2"]).toContain(getClient.redirect_uri[1]);
        await clientStorage.deleteClient(client.client_id);
        await expect(async () => {await clientStorage.getClientById(client.client_id)}).rejects.toThrowError();
    });

    test('PrismaStorage.createAndUpdateClient', async () => {
        const client = {
            client_id : "ABC3",
            client_secret: "DEF",
            client_name: "Test",
            redirect_uri: ["http://client.com/uri1", "http://client.com/uri2"],
            valid_flow: [],
            confidential: true,
        }
        await clientStorage.createClient(client);
        await clientStorage.updateClient({client_id: client.client_id, redirect_uri: ["http://client.com/uri3"]});
        const getClient = await clientStorage.getClientById(client.client_id);
        expect(getClient.redirect_uri.length).toBe(1);
        expect(getClient.redirect_uri[0]).toBe("http://client.com/uri3");
    });

    test('PrismaStorage.createAndUpdateValidFlows', async () => {
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
   
    test('PrismaStorage.createInvalid_flow', async () => {
        const client = {
            client_id : "ABC3b",
            client_secret: "DEF",
            client_name: "Test",
            redirect_uri: ["http://client.com/uri1", "http://client.com/uri2"],
            valid_flow: ["authorizationCodeX"],
            confidential: true,
        }
        await expect(async () => {await clientStorage.createClient(client)}).rejects.toThrowError();
    });    

    test(prefix + ".createAndUpdateForUser", async () => {
        const client = {
            client_id : "ABC4",
            client_secret: "DEF",
            client_name: "Test",
            redirect_uri: ["http://client.com/uri1", "http://client.com/uri2"],
            valid_flow: [],
            confidential: true,
        }
        await clientStorage.createClient(client);
        const {user: bob} = await userStorage.getUserByUsername("bob");
        await authStorage.updateAuthorizations("ABC4", bob.id, ["read", "write"]);
        await authStorage.updateAuthorizations("ABC4", bob.id, ["read", "delete"]);
        const scopes = await authStorage.getAuthorizations("ABC4", bob.id);
        expect(scopes.length).toBe(2);
        expect(["read", "delete"]).toContain(scopes[0]);
        expect(["read", "delete"]).toContain(scopes[1]);
    });

}
