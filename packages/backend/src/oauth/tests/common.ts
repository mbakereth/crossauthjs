import { expect } from 'vitest';
import { OAuthAuthorizationServer, type OAuthAuthorizationServerOptions } from '../authserver';
import { InMemoryOAuthClientStorage, InMemoryKeyStorage } from '../../storage/inmemorystorage';
import { OAuthClientStorage } from '../../storage';
import { Hasher } from '../../hasher';
import { OAuthClient, OAuthFlows } from '@crossauth/common';
import fs from 'node:fs';
import { LocalPasswordAuthenticator } from '../..';
import { getTestUserStorage }  from '../../storage/tests/inmemorytestdata';

export async function createClient(secretRequired = true) : Promise<{clientStorage : OAuthClientStorage, client : OAuthClient}> {
    const clientStorage = new InMemoryOAuthClientStorage();
    const clientSecret = await Hasher.passwordHash("DEF", {
        encode: true,
        iterations: 1000,
        keyLen: 32,
    });
    const inputClient = {
        clientId : "ABC",
        clientSecret: secretRequired ? clientSecret : undefined,
        clientName: "Test",
        redirectUri: ["http://localhost:3000/authzcode"],
        confidential: secretRequired,
        validFlow: OAuthFlows.allFlows(),
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
    const authenticator = new LocalPasswordAuthenticator(userStorage);
    let options : OAuthAuthorizationServerOptions = {
        jwtPrivateKey : privateKey,
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write, openid",
        issueRefreshToken: true,
        emptyScopeIsValid: emptyScopeIsValid,
        validFlows: "all",
        userStorage,
        authenticators: {
            "localpassword": authenticator,
        },
    };
    if (aud) options.resourceServers = aud;
    if (persistAccessToken) {
        options.persistAccessToken = true;
    }
    if (rollingRefreshToken != undefined) options.rollingRefreshToken = rollingRefreshToken;
    const keyStorage = new InMemoryKeyStorage();
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, options);
    return {client, clientStorage, authServer, keyStorage, userStorage};
}

export async function getAuthorizationCode({
    challenge, 
    aud, 
    persistAccessToken,
    rollingRefreshToken,
    oidc = false,
} : {challenge?: boolean,
     aud?: string, 
     persistAccessToken? : boolean,
     rollingRefreshToken? : boolean,
     oidc? : boolean,
    } = {}) {
    const secretRequired = challenge == undefined;
    const {client, clientStorage, authServer, keyStorage, userStorage} = await getAuthServer({challenge, aud, persistAccessToken, secretRequired, rollingRefreshToken});
    const {user} = await userStorage.getUserByUsername("bob");
    const inputState = "ABCXYZ";
    let codeChallenge : string|undefined;
    const codeVerifier = "ABC123";
    if (challenge) codeChallenge = Hasher.hash(codeVerifier);
    const {code, error, error_description} 
        = await authServer.authorizeGetEndpoint({
            responseType: "code", 
            clientId: client.clientId, 
            redirectUri: client.redirectUri[0], 
            scope: "read write" + (oidc == true ? " openid" : ""), 
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
            clientId: client.clientId, 
            code: code, 
            clientSecret: "DEF"});
    return {authServer, client, code, clientStorage, access_token, error, error_description, refresh_token, expires_in};
};
