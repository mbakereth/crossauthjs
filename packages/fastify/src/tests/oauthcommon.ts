// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { expect } from 'vitest';
import {
    OAuthAuthorizationServer,
    InMemoryOAuthClientStorage,
    InMemoryKeyStorage,
    InMemoryOAuthAuthorizationStorage,
    OAuthClientStorage,
    Crypto,
    LocalPasswordAuthenticator,
    TotpAuthenticator,
    EmailAuthenticator } from '@crossauth/backend';
import type { OAuthAuthorizationServerOptions } from '@crossauth/backend';
import { OAuthClient, OAuthFlows } from '@crossauth/common';
import fs from 'node:fs';
import { getTestUserStorage }  from './inmemorytestdata';

export async function createClient(secretRequired = true) : Promise<{clientStorage : OAuthClientStorage, client : OAuthClient}> {
    const clientStorage = new InMemoryOAuthClientStorage();
    const client_secret = await Crypto.passwordHash("DEF", {
        encode: true,
        iterations: 1000,
        keyLen: 32,
    });
    const inputClient = {
        client_id : "ABC",
        client_secret: secretRequired ? client_secret : undefined,
        client_name: "Test",
        redirect_uri: ["http://localhost:3000/authzcode"],
        confidential: secretRequired,
        valid_flow: OAuthFlows.allFlows(),
    };
    const client = await clientStorage.createClient(inputClient);
    return {clientStorage, client};

}

export async function getAuthServer({
    aud, 
    persistAccessToken, 
    emptyScopeIsValid, 
    secretRequired,
    rollingRefreshToken,
    } : {
    challenge?: boolean, 
    aud?: string, 
    persistAccessToken? : boolean, 
    emptyScopeIsValid? : boolean, 
    secretRequired? : boolean,
    rollingRefreshToken? : boolean,
} = {}) {
    const {clientStorage, client} = await createClient(secretRequired == undefined || secretRequired == true);
    const privateKey = fs.readFileSync("keys/rsa-private-key.pem", 'utf8');
    const userStorage = await getTestUserStorage();
    const authStorage = new InMemoryOAuthAuthorizationStorage();
    const lpAuthenticator = new LocalPasswordAuthenticator(userStorage);
    const totpAuth = new TotpAuthenticator("Unittest");
    const emailAuth = new EmailAuthenticator();
    const authenticators = {
        "localpassword": lpAuthenticator,
        totp: totpAuth,
        email: emailAuth,
    };
    let options : OAuthAuthorizationServerOptions = {
        jwtKeyType: "RS256",
        jwtPrivateKey : privateKey,
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: ["read", "write"],
        issueRefreshToken: true,
        emptyScopeIsValid: emptyScopeIsValid,
        validFlows: ["all"],
        userStorage,
        authStorage,
        deviceCodeVerificationUri: "http://localhost:3000/device",
    };
    if (aud) options.audience = aud;
    if (persistAccessToken) {
        options.persistAccessToken = true;
    }
    if (rollingRefreshToken != undefined) options.rollingRefreshToken = rollingRefreshToken;
    const keyStorage = new InMemoryKeyStorage();
    const authServer = new OAuthAuthorizationServer(clientStorage, 
        keyStorage, 
        authenticators,
        options);
    return {client, clientStorage, authServer, keyStorage, userStorage, emailAuth};
}

export async function getAuthorizationCode({
    challenge, 
    aud, 
    persistAccessToken,
    rollingRefreshToken,
} : {challenge?: boolean,
     aud?: string, 
     persistAccessToken? : boolean,
     rollingRefreshToken? : boolean,
    } = {}) {
    const secretRequired = challenge == undefined;
    const {client, clientStorage, authServer, keyStorage, userStorage} = await getAuthServer({challenge, aud, persistAccessToken, secretRequired, rollingRefreshToken});
    const {user} = await userStorage.getUserByUsername("bob");
    const inputState = "ABCXYZ";
    let codeChallenge : string|undefined;
    const codeVerifier = "ABC123";
    if (challenge) codeChallenge = Crypto.hash(codeVerifier);
    const {code, error, error_description} 
        = await authServer.authorizeGetEndpoint({
            responseType: "code", 
            client_id: client.client_id, 
            redirect_uri: client.redirect_uri[0], 
            scope: "read write", 
            state: inputState,
            codeChallenge: codeChallenge,
            user});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();
    return {code, client, clientStorage, authServer, keyStorage};
}

export async function getAccessToken() {

    const {authServer, client, code, clientStorage} = await getAuthorizationCode();
    const {access_token, error, error_description, refresh_token, expires_in}
        = await authServer.tokenEndpoint({
            grantType: "authorization_code", 
            client_id: client.client_id, 
            code: code, 
            client_secret: "DEF"});
    return {authServer, client, code, clientStorage, access_token, error, error_description, refresh_token, expires_in};
};
