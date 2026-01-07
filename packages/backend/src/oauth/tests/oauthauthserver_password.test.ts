// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { test, expect } from 'vitest';
import { OAuthAuthorizationServer } from '../authserver';
import { createClient } from './common';
import { InMemoryKeyStorage } from '../../storage/inmemorystorage';
import { LocalPasswordAuthenticator } from '../..';
import { getTestUserStorage }  from '../../storage/tests/inmemorytestdata';
import { jwtDecode } from "jwt-decode";

test('AuthorizationServer.passwordFlow.correctPassword', async () => {
    const {clientStorage, client} = await createClient();
    const keyStorage = new InMemoryKeyStorage();
    const userStorage = await getTestUserStorage();

    const authenticator = new LocalPasswordAuthenticator(userStorage);
    const auth = {
        "localpassword" : authenticator
    };
    const authServer = new OAuthAuthorizationServer(clientStorage, 
        keyStorage, 
        auth, {
        jwtKeyType: "RS256",
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: ["read", "write"],
        userStorage: userStorage,
    });
    const {access_token, error}
        = await authServer.tokenEndpoint({
            grantType: "password", 
            client_id: client.client_id, 
            username: "bob",
            password: "bobPass123" ,
            client_secret: "DEF"});
    expect(error).toBeUndefined();
    expect(access_token).toBeDefined();
    const sub = jwtDecode(access_token??"")?.sub;
    expect(sub).toBe("bob");
});

test('AuthorizationServer.passwordFlow.incorrectPassword', async () => {
    const {clientStorage, client} = await createClient();
    const keyStorage = new InMemoryKeyStorage();
    const userStorage = await getTestUserStorage();
    const authenticator = new LocalPasswordAuthenticator(userStorage);
    const auth = {
        "password" : authenticator
    };
    const authServer = new OAuthAuthorizationServer(clientStorage, 
        keyStorage, 
        auth, {
        jwtKeyType: "RS256",
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: ["read", "write"],
        userStorage: userStorage,
    });
    const {access_token, error}
        = await authServer.tokenEndpoint({
            grantType: "password", 
            client_id: client.client_id, 
            username: "bob",
            password: "wrong" ,
            client_secret: "DEF"});
    expect(error).toBe("access_denied");
    expect(access_token).toBeUndefined();

});
