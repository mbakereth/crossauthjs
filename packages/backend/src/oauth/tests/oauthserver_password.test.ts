import { test, expect } from 'vitest';
import { OAuthAuthorizationServer } from '../authserver';
import { createClient } from './common';
import { InMemoryKeyStorage } from '../../storage/inmemorystorage';
import { LocalPasswordAuthenticator } from '../..';
import { getTestUserStorage }  from '../../storage/tests/inmemorytestdata';

test('AuthorizationServer.passwordFlow.correctPassword', async () => {
    const {clientStorage, client} = await createClient();
    const keyStorage = new InMemoryKeyStorage();
    const userStorage = await getTestUserStorage();
    const authenticator = new LocalPasswordAuthenticator(userStorage);
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
        userStorage: userStorage,
        authenticator: authenticator,
    });
    const {access_token, error}
        = await authServer.tokenPostEndpoint({
            grantType: "password", 
            clientId: client.clientId, 
            username: "bob",
            password: "bobPass123" ,
            clientSecret: "DEF"});
    expect(error).toBeUndefined();
    expect(access_token).toBeDefined();

});

test('AuthorizationServer.passwordFlow.incorrectPassword', async () => {
    const {clientStorage, client} = await createClient();
    const keyStorage = new InMemoryKeyStorage();
    const userStorage = await getTestUserStorage();
    const authenticator = new LocalPasswordAuthenticator(userStorage);
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
        userStorage: userStorage,
        authenticator: authenticator,
    });
    const {access_token, error}
        = await authServer.tokenPostEndpoint({
            grantType: "password", 
            clientId: client.clientId, 
            username: "bob",
            password: "wrong" ,
            clientSecret: "DEF"});
    expect(error).toBe("access_denied");
    expect(access_token).toBeUndefined();

});

