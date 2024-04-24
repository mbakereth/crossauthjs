import { test, expect } from 'vitest';
import { OAuthAuthorizationServer, type OAuthAuthorizationServerOptions } from '../authserver';
import fs from 'node:fs';
import { createClient, getAuthorizationCode } from './common';
import { InMemoryKeyStorage, InMemoryOAuthAuthorizationStorage } from '../../storage/inmemorystorage';
import { Crypto } from '../../crypto';
import { KeyStorage } from '../../storage';
import { getTestUserStorage }  from '../../storage/tests/inmemorytestdata';
import { LocalPasswordAuthenticator } from '../..';
import { KeyPrefix } from '@crossauth/common'

test('AuthorizationServer.AuthzCodeFlow.validAuthorizationCodeRequestPublicKeyFilePrivateKeyFile', async () => {

    const {clientStorage, client} = await createClient();
    const privateKey = fs.readFileSync("keys/rsa-private-key.pem", 'utf8');
    const keyStorage = new InMemoryKeyStorage();
    const userStorage = await getTestUserStorage();
    const authenticator = new LocalPasswordAuthenticator(userStorage);
    const authenticators = {
        "localpassword" : authenticator
    };
    const authServer = new OAuthAuthorizationServer(clientStorage, 
        keyStorage, 
        authenticators, {
        jwtKeyType: "RS256",
        jwtPrivateKey : privateKey,
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: ["read", "write"],
        userStorage, 
    });

    const inputState = "ABCXYZ";
    const {code, state, error, error_description} 
        = await authServer.authorizeGetEndpoint({
            responseType: "code", 
            clientId: client.clientId, 
            redirectUri: client.redirectUri[0], 
            scope: "read write", 
            state: inputState});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();
    expect(state).toBe(inputState);
    const key = await keyStorage.getKey(KeyPrefix.authorizationCode+Crypto.hash(code??""));
    const data = KeyStorage.decodeData(key.data);
    expect(data.scope.length).toBe(2);
    expect(["read", "write"]).toContain(data.scope[0]);
    expect(["read", "write"]).toContain(data.scope[1]);
});

test('AuthorizationServer.AuthzCodeFlow.scopePersistence', async () => {

    const {clientStorage, client} = await createClient();
    const keyStorage = new InMemoryKeyStorage();
    const authStorage = new InMemoryOAuthAuthorizationStorage();
    const userStorage = await getTestUserStorage();
    const authenticator = new LocalPasswordAuthenticator(userStorage);
    const authenticators =  {
        "localpassword" : authenticator
    };
    const authServer = new OAuthAuthorizationServer(clientStorage, 
        keyStorage, 
        authenticators, {
        jwtKeyType: "RS256",
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: ["read", "write"],
        authStorage : authStorage,
        userStorage,
    });
    const inputState = "ABCXYZ";
    const {code, state, error, error_description} 
        = await authServer.authorizeGetEndpoint({
            responseType: "code", 
            clientId: client.clientId, 
            redirectUri: client.redirectUri[0], 
            scope: "read write", 
            state: inputState,
            user: {id: "bob", username: "bob", state: "active"}});
    const scopes = await authStorage.getAuthorizations("ABC", "bob")
    expect(scopes.length).toBe(2);
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();
    expect(state).toBe(inputState);
    const key = await keyStorage.getKey(KeyPrefix.authorizationCode+Crypto.hash(code??""));
    const data = KeyStorage.decodeData(key.data);
    expect(data.scope.length).toBe(2);
    expect(["read", "write"]).toContain(data.scope[0]);
    expect(["read", "write"]).toContain(data.scope[1]);
});

test('AuthorizationServer.AuthzCodeFlow.emptyScopeDisallowed', async () => {

    const {clientStorage, client} = await createClient();
    const keyStorage = new InMemoryKeyStorage();
    const authStorage = new InMemoryOAuthAuthorizationStorage();
    const userStorage = await getTestUserStorage();
    const authenticator = new LocalPasswordAuthenticator(userStorage);
    const authenticators = {
        "localpassword" : authenticator
    };
    const authServer = new OAuthAuthorizationServer(clientStorage, 
        keyStorage, 
        authenticators, {
        jwtKeyType: "RS256",
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: ["read", "write"],
        emptyScopeIsValid: false,
        authStorage : authStorage,
        userStorage,
    });
    const inputState = "ABCXYZ";
    const {error, error_description} 
        = await authServer.authorizeGetEndpoint({
            responseType: "code", 
            clientId: client.clientId, 
            redirectUri: client.redirectUri[0], 
            state: inputState,
            user: {id: "bob", username: "bob", state: "active"}});
    const scopes = await authStorage.getAuthorizations("ABC", "bob")
    expect(scopes.length).toBe(0);
    expect(error).toBeDefined();
    expect(error_description).toBeDefined();
});

test('AuthorizationServer.AuthzCodeFlow.emptyScopeAllowed', async () => {

    const {clientStorage, client} = await createClient();
    const keyStorage = new InMemoryKeyStorage();
    const authStorage = new InMemoryOAuthAuthorizationStorage();
    const userStorage = await getTestUserStorage();
    const authenticator = new LocalPasswordAuthenticator(userStorage);
    const authenticators = {
        "localpassword" : authenticator
    };
    const authServer = new OAuthAuthorizationServer(clientStorage, 
        keyStorage, 
        authenticators, {
        jwtKeyType: "RS256",
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: ["read", "write"],
        authStorage : authStorage,
        emptyScopeIsValid: true,
        userStorage,
   });
    const inputState = "ABCXYZ";
    const {error, error_description} 
        = await authServer.authorizeGetEndpoint({
            responseType: "code", 
            clientId: client.clientId, 
            redirectUri: client.redirectUri[0], 
            state: inputState,
            user: {id: "bob", username: "bob", state: "active"}});
    const scopes = await authStorage.getAuthorizations("ABC", "bob")
    expect(scopes.length).toBe(1);
    expect(scopes[0]).toBeNull();
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();
});

test('AuthorizationServer.AuthzCodeFlow.validAuthorizationCodeRequestPublicKeyFilePrivateKey', async () => {

    const {clientStorage, client} = await createClient();
    const privateKey = fs.readFileSync("keys/rsa-private-key.pem", 'utf8');
    const keyStorage = new InMemoryKeyStorage();
    const userStorage = await getTestUserStorage();
    const authenticator = new LocalPasswordAuthenticator(userStorage);
    const authenticators = {
        "localpassword" : authenticator
    };
    const authServer = new OAuthAuthorizationServer(clientStorage, 
        keyStorage, 
        authenticators, {
        jwtKeyType: "RS256",
        jwtPrivateKey : privateKey,
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: ["read", "write"],
        userStorage,
    });
    const inputState = "ABCXYZ";
    const {code, state, error, error_description} 
        = await authServer.authorizeGetEndpoint({
            responseType: "code", 
            clientId: client.clientId, 
            redirectUri: client.redirectUri[0], 
            scope: "read write", 
            state: inputState});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();
    expect(state).toBe(inputState);
    const key = await keyStorage.getKey(KeyPrefix.authorizationCode+Crypto.hash(code??""));
    const data = KeyStorage.decodeData(key.data);
    expect(data.scope.length).toBe(2);
    expect(["read", "write"]).toContain(data.scope[0]);
    expect(["read", "write"]).toContain(data.scope[1]);
});

test('AuthorizationServer.AuthzCodeFlow.validAuthorizationCodeRequestPublicKeyPrivateKeyFile', async () => {

    const {clientStorage, client} = await createClient();
    const publicKey = fs.readFileSync("keys/rsa-public-key.pem", 'utf8');
    const keyStorage = new InMemoryKeyStorage();
    const userStorage = await getTestUserStorage();
    const authenticator = new LocalPasswordAuthenticator(userStorage);
    const authenticators = {
        "localpassword" : authenticator
    };
    const authServer = new OAuthAuthorizationServer(clientStorage, 
        keyStorage, 
        authenticators, {
        jwtKeyType: "RS256",
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKey : publicKey,
        validateScopes : true,
        validScopes: ["read", "write"],
        userStorage,
    });
    const inputState = "ABCXYZ";
    const {code, state, error, error_description} 
        = await authServer.authorizeGetEndpoint({
            responseType: "code", 
            clientId: client.clientId, 
            redirectUri: client.redirectUri[0], 
            scope: "read write", 
            state: inputState});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();
    expect(state).toBe(inputState);
    const key = await keyStorage.getKey(KeyPrefix.authorizationCode+Crypto.hash(code??""));
    const data = KeyStorage.decodeData(key.data);
    expect(data.scope.length).toBe(2);
    expect(["read", "write"]).toContain(data.scope[0]);
    expect(["read", "write"]).toContain(data.scope[1]);
});

test('AuthorizationServer.AuthzCodeFlow.validAuthorizationCodeRequestSecretKeyFile', async () => {

    const {clientStorage, client} = await createClient();
    //const publicKey = fs.readFileSync("keys/secretkey.txt", 'utf8');
    const keyStorage = new InMemoryKeyStorage();
    const userStorage = await getTestUserStorage();
    const authenticator = new LocalPasswordAuthenticator(userStorage);
    const authenticators = {
        "localpassword" : authenticator
    };
    const authServer = new OAuthAuthorizationServer(clientStorage, 
        keyStorage, 
        authenticators, {
        jwtKeyType: "RS256",
        jwtSecretKeyFile : "keys/secretkey.txt",
        jwtAlgorithm: "HS256",
        validateScopes : true,
        validScopes: ["read", "write"],
        userStorage,
    });
    const inputState = "ABCXYZ";
    const {code, state, error, error_description} 
        = await authServer.authorizeGetEndpoint({
            responseType: "code", 
            clientId: client.clientId, 
            redirectUri: client.redirectUri[0], 
            scope: "read write", 
            state: inputState});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();
    expect(state).toBe(inputState);
    const key = await keyStorage.getKey(KeyPrefix.authorizationCode+Crypto.hash(code??""));
    const data = KeyStorage.decodeData(key.data);
    expect(data.scope.length).toBe(2);
    expect(["read", "write"]).toContain(data.scope[0]);
    expect(["read", "write"]).toContain(data.scope[1]);
});

test('AuthorizationServer.AuthzCodeFlow.validAuthorizationCodeRequestSecretKey', async () => {

    const {clientStorage, client} = await createClient();
    const secretKey = fs.readFileSync("keys/secretkey.txt", 'utf8');
    const keyStorage = new InMemoryKeyStorage();
    const userStorage = await getTestUserStorage();
    const authenticator = new LocalPasswordAuthenticator(userStorage);
    const authenticators = {
        "localpassword" : authenticator
    };
    const authServer = new OAuthAuthorizationServer(clientStorage, 
        keyStorage, 
        authenticators, {
        jwtSecretKey : secretKey,
        jwtAlgorithm: "HS256",
        validateScopes : true,
        validScopes: ["read", "write"],
        userStorage,
    });
    const inputState = "ABCXYZ";
    const {code, state, error, error_description} 
        = await authServer.authorizeGetEndpoint({
            responseType: "code", 
            clientId: client.clientId, 
            redirectUri: client.redirectUri[0], 
            scope: "read write", 
            state: inputState});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();
    expect(state).toBe(inputState);
    const key = await keyStorage.getKey(KeyPrefix.authorizationCode+Crypto.hash(code??""));
    const data = KeyStorage.decodeData(key.data);
    expect(data.scope.length).toBe(2);
    expect(["read", "write"]).toContain(data.scope[0]);
    expect(["read", "write"]).toContain(data.scope[1]);
});

test('AuthorizationServer.AuthzCodeFlow.invalidScope', async () => {

    const {clientStorage, client} = await createClient();
    const userStorage = await getTestUserStorage();
    const authenticator = new LocalPasswordAuthenticator(userStorage);
    const authenticators = {
        "localpassword" : authenticator
    };
    const authServer = new OAuthAuthorizationServer(clientStorage, 
        new InMemoryKeyStorage(), 
        authenticators, {
        jwtKeyType: "RS256",
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: ["read", "write"],
        userStorage,
    });
    const inputState = "ABCXYZ";
    const {error} 
        = await authServer.authorizeGetEndpoint({
            responseType: "code", 
            clientId: client.clientId, 
            redirectUri: client.redirectUri[0], 
            scope: "unregisteredScope", 
            state: inputState});
    expect(error).toBe("invalid_scope");
});

test('AuthorizationServer.AuthzCodeFlow.invalidRedirectUri', async () => {

    const {clientStorage, client} = await createClient();
    const userStorage = await getTestUserStorage();
    const authenticator = new LocalPasswordAuthenticator(userStorage);
    const authenticators = {
        "localpassword" : authenticator
    };
    const authServer = new OAuthAuthorizationServer(clientStorage, 
        new InMemoryKeyStorage(), 
        authenticators, {
        jwtKeyType: "RS256",
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: ["read", "write"],
        userStorage,
    });
    const inputState = "ABCXYZ";
    const {error} 
        = await authServer.authorizeGetEndpoint({
            responseType: "code", 
            clientId: client.clientId, 
            redirectUri: "http://example.com/invalidRedirect", 
            scope: "read write", 
            state: inputState});
    expect(error).toBe("invalid_request");
});

test('AuthorizationServer.AuthzCodeFlow.invalidKeyInConstructor', async () => {

    const {clientStorage} = await createClient();
    const options : OAuthAuthorizationServerOptions = {
        jwtKeyType: "RS256",
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        jwtSecretKeyFile : "keys/secretkey.txt",
        validateScopes : true,
        validScopes: ["read", "write"],

    } 
    await expect(async () => {new OAuthAuthorizationServer(clientStorage,
        new InMemoryKeyStorage(), 
        undefined, 
        options)}).rejects.toThrowError();
});

test('AuthorizationServer.AuthzCodeFlow.invalidResponseType', async () => {
    const {clientStorage, client} = await createClient();
    const userStorage = await getTestUserStorage();
    const authenticator = new LocalPasswordAuthenticator(userStorage);
    const authenticators = {
        "localpassword" : authenticator
    };
    const authServer = new OAuthAuthorizationServer(clientStorage, 
        new InMemoryKeyStorage(), 
        authenticators, {
        jwtKeyType: "RS256",
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: ["read", "write"],
        userStorage,
    });
    const inputState = "ABCXYZ";
    const {error} 
        = await authServer.authorizeGetEndpoint({
            responseType: "x", 
            clientId: client.clientId, 
            redirectUri: client.redirectUri[0], 
            scope: "read write", 
            state: inputState});
    expect(error).toBe("unsupported_response_type");

});

test('AuthorizationServer.AuthzCodeFlow.invalidKey', async () => {

    const {clientStorage, client} = await createClient();
    const userStorage = await getTestUserStorage();
    const authenticator = new LocalPasswordAuthenticator(userStorage);
    const authenticators = {
        "localpassword" : authenticator
    };
    const authServer = new OAuthAuthorizationServer(clientStorage, 
        new InMemoryKeyStorage(), 
        authenticators, {
        jwtKeyType: "RS256",
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key-wrong.pem",
        validateScopes : true,
        validScopes: ["read", "write"],
        userStorage,
    });
    const inputState = "ABCXYZ";
    const {code, state, error} 
        = await authServer.authorizeGetEndpoint({
            responseType: "code", 
            clientId: client.clientId, 
            redirectUri: client.redirectUri[0], 
            scope: "read write", 
            state: inputState});
    expect(error).toBeUndefined();
    expect(state).toBe(inputState);

    const {access_token,  error: error2}
        = await authServer.tokenEndpoint({
            grantType: "authorization_code", 
            clientId: client.clientId, 
            code: code, 
            clientSecret: "DEF"});
    expect(error2).toBeUndefined();

    const decodedAccessToken
        = await authServer.validAccessToken(access_token??"");
    expect(decodedAccessToken).toBeUndefined();
});

test('AuthorizationServer.AuthzCodeFlow.accessToken', async () => {

    const {authServer, client, code} = await getAuthorizationCode();
    const {access_token, refresh_token, expires_in, error, error_description}
        = await authServer.tokenEndpoint({
            grantType: "authorization_code", 
            clientId: client.clientId, 
            code: code, 
            clientSecret: "DEF"});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();

    const decodedAccessToken
        = await authServer.validAccessToken(access_token??"");
    expect(decodedAccessToken).toBeDefined();
    expect(decodedAccessToken?.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[1]);
    expect(decodedAccessToken?.payload.sub).toBe("bob");

    const valid
        = await authServer.validRefreshToken(refresh_token??"");
    expect(valid).toBe(true);
    const refreshData = await authServer.getRefreshTokenData(refresh_token??"");
    expect(["read", "write"]).toContain(refreshData?.scope[0]);
    expect(["read", "write"]).toContain(refreshData?.scope[1]);
    expect(refreshData?.username).toBe("bob");


    expect(expires_in).toBe(60*60);
});

test('AuthorizationServer.AuthzCodeFlow.invalidfAccessToken', async () => {
    const {authServer} = await getAuthorizationCode();
    const decodedAccessToken
        = await authServer.validAccessToken("ABC");
    expect(decodedAccessToken).toBeUndefined();
});

test('AuthorizationServer.AuthzCodeFlow.invalidfRefreshToken', async () => {
    const {authServer} = await getAuthorizationCode();
    const valid
        = await authServer.validRefreshToken("ABC");
    expect(valid).toBe(false);
});

test('AuthorizationServer.AuthzCodeFlow.oidcConfiguration', async () => {
    const {authServer} = await getAuthorizationCode();
 
    const wellKnown = authServer.oidcConfiguration({
        authorizeEndpoint: "/authorize",
        tokenEndpoint: "/token",
        jwksUri: "/jwks",
    });
    expect(wellKnown.authorization_endpoint).toBe(process.env.CROSSAUTH_OAUTH_ISSUER+"/authorize");
    expect(wellKnown.token_endpoint).toBe(process.env.CROSSAUTH_OAUTH_ISSUER+"/token");
    expect(wellKnown.jwks_uri).toBe(process.env.CROSSAUTH_OAUTH_ISSUER+"/jwks");
});

test('AuthorizationServer.AuthzCodeFlow.jwks', async () => {
    const {authServer} = await getAuthorizationCode();
    const jwks = authServer.jwks();
    expect(jwks.keys.length).toBe(1);
    expect(jwks.keys[0].kty).toBe("RSA");
});

test('AuthorizationServer.AuthzCodeFlow.refreshTokenFlowNoRolling', async () => {

    const {authServer, client, code} = await getAuthorizationCode({rollingRefreshToken: false});
    const {refresh_token, error, access_token}
        = await authServer.tokenEndpoint({
            grantType: "authorization_code", 
            clientId: client.clientId, 
            code: code, 
            scope: "read write",
            clientSecret: "DEF"});
    expect(error).toBeUndefined();
    expect(refresh_token).toBeDefined();

    let decodedAccessToken
        = await authServer.validAccessToken(access_token??"");
    expect(decodedAccessToken).toBeDefined();
    expect(decodedAccessToken?.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[1]);
    expect(decodedAccessToken?.payload.sub).toBe("bob");

    const valid
        = await authServer.validRefreshToken(refresh_token??"");
    expect(valid).toBe(true);
    const refreshData = await authServer.getRefreshTokenData(refresh_token??"");
    expect(["read", "write"]).toContain(refreshData?.scope[0]);
    expect(["read", "write"]).toContain(refreshData?.scope[1]);
    expect(refreshData?.username).toBe("bob");

    const {refresh_token: refresh_token2, access_token: access_token2, error: error2}
        = await authServer.tokenEndpoint({
            grantType: "refresh_token", 
            clientId: client.clientId, 
            refreshToken: refresh_token, 
            clientSecret: "DEF"});
    expect(error2).toBeUndefined();
    expect(refresh_token2).toBeUndefined();

    decodedAccessToken
        = await authServer.validAccessToken(access_token2??"");
    expect(decodedAccessToken).toBeDefined();
    expect(decodedAccessToken?.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[1]);
    expect(decodedAccessToken?.payload.sub).toBe("bob");

});

test('AuthorizationServer.AuthzCodeFlow.refreshTokenFlowRolling', async () => {

    const {authServer, client, code} = await getAuthorizationCode({rollingRefreshToken: true});
    const {refresh_token, error, access_token}
        = await authServer.tokenEndpoint({
            grantType: "authorization_code", 
            clientId: client.clientId, 
            code: code, 
            scope: "read write",
            clientSecret: "DEF"});
    expect(error).toBeUndefined();
    expect(refresh_token).toBeDefined();

    let valid
        = await authServer.validRefreshToken(refresh_token??"");
    expect(valid).toBe(true);
    let refreshData = await authServer.getRefreshTokenData(refresh_token??"");
    expect(["read", "write"]).toContain(refreshData?.scope[0]);
    expect(["read", "write"]).toContain(refreshData?.scope[1]);
    expect(refreshData?.username).toBe("bob");

    let decodedAccessToken
        = await authServer.validAccessToken(access_token??"");
    expect(decodedAccessToken).toBeDefined();
    expect(decodedAccessToken?.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[1]);
    expect(decodedAccessToken?.payload.sub).toBe("bob");


    const {refresh_token: refresh_token2, access_token: access_token2, error: error2}
        = await authServer.tokenEndpoint({
            grantType: "refresh_token", 
            clientId: client.clientId, 
            refreshToken: refresh_token, 
            clientSecret: "DEF"});
    expect(error2).toBeUndefined();
    expect(refresh_token2).toBeDefined();
    expect(refresh_token2).not.toBe(refresh_token);

    decodedAccessToken
        = await authServer.validAccessToken(access_token2??"");
    expect(decodedAccessToken).toBeDefined();
    expect(decodedAccessToken?.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[1]);
    expect(decodedAccessToken?.payload.sub).toBe("bob");

    valid
        = await authServer.validRefreshToken(refresh_token??"");
    expect(valid).toBe(true);
    refreshData = await authServer.getRefreshTokenData(refresh_token??"");
    expect(["read", "write"]).toContain(refreshData?.scope[0]);
    expect(["read", "write"]).toContain(refreshData?.scope[1]);
    expect(refreshData?.username).toBe("bob");

});

test('AuthorizationServer.OidcAuthzCodeFlow.accessTokenIdToken', async () => {

    const {authServer, client, code} = await getAuthorizationCode({scopes: "read write openid"});
    const {access_token, refresh_token, expires_in, error, error_description, id_token}
        = await authServer.tokenEndpoint({
            grantType: "authorization_code", 
            clientId: client.clientId, 
            code: code, 
            clientSecret: "DEF"});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();

    const decodedAccessToken
        = await authServer.validAccessToken(access_token??"");
    expect(decodedAccessToken).toBeDefined();
    expect(decodedAccessToken?.payload.scope.length).toBe(3);
    expect(["read", "write", "openid"]).toContain(decodedAccessToken?.payload.scope[0]);
    expect(["read", "write", "openid"]).toContain(decodedAccessToken?.payload.scope[1]);
    expect(["read", "write", "openid"]).toContain(decodedAccessToken?.payload.scope[2]);
    expect(decodedAccessToken?.payload.sub).toBe("bob");

    const valid
        = await authServer.validRefreshToken(refresh_token??"");
    expect(valid).toBe(true);
    const refreshData = await authServer.getRefreshTokenData(refresh_token??"");
    expect(["read", "write", "openid"]).toContain(refreshData?.scope[0]);
    expect(["read", "write", "openid"]).toContain(refreshData?.scope[1]);
    expect(["read", "write", "openid"]).toContain(refreshData?.scope[2]);
    expect(refreshData?.username).toBe("bob");

    const decodedIdToken
        = await authServer.validIdToken(id_token??"");
    expect(decodedIdToken).toBeDefined();
    expect(decodedIdToken?.payload.scope.length).toBe(3);
    expect(["read", "write", "openid"]).toContain(decodedIdToken?.payload.scope[0]);
    expect(["read", "write", "openid"]).toContain(decodedIdToken?.payload.scope[1]);
    expect(["read", "write", "openid"]).toContain(decodedIdToken?.payload.scope[2]);
    expect(decodedIdToken?.payload.sub).toBe("bob");

    expect(expires_in).toBe(60*60);
});

test('AuthorizationServer.OidcAuthzCodeFlow.accessTokenIdTokenAllClaims', async () => {

    const {authServer, client, code} = await getAuthorizationCode({scopes: "read write openid",
        idTokenClaims: {"all": {"email1": "email"}}});
    const {access_token, refresh_token, expires_in, error, error_description, id_token}
        = await authServer.tokenEndpoint({
            grantType: "authorization_code", 
            clientId: client.clientId, 
            code: code, 
            clientSecret: "DEF"});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();

    const decodedAccessToken
        = await authServer.validAccessToken(access_token??"");
    expect(decodedAccessToken).toBeDefined();
    expect(decodedAccessToken?.payload.scope.length).toBe(3);
    expect(["read", "write", "openid"]).toContain(decodedAccessToken?.payload.scope[0]);
    expect(["read", "write", "openid"]).toContain(decodedAccessToken?.payload.scope[1]);
    expect(["read", "write", "openid"]).toContain(decodedAccessToken?.payload.scope[2]);
    expect(decodedAccessToken?.payload.sub).toBe("bob");

    const valid
        = await authServer.validRefreshToken(refresh_token??"");
    expect(valid).toBe(true);
    const refreshData = await authServer.getRefreshTokenData(refresh_token??"");
    expect(["read", "write", "openid"]).toContain(refreshData?.scope[0]);
    expect(["read", "write", "openid"]).toContain(refreshData?.scope[1]);
    expect(["read", "write", "openid"]).toContain(refreshData?.scope[2]);
    expect(refreshData?.username).toBe("bob");

    const decodedIdToken
        = await authServer.validIdToken(id_token??"");
    expect(decodedIdToken).toBeDefined();
    expect(decodedIdToken?.payload.scope.length).toBe(3);
    expect(["read", "write", "openid"]).toContain(decodedIdToken?.payload.scope[0]);
    expect(["read", "write", "openid"]).toContain(decodedIdToken?.payload.scope[1]);
    expect(["read", "write", "openid"]).toContain(decodedIdToken?.payload.scope[2]);
    expect(decodedIdToken?.payload.sub).toBe("bob");
    expect(decodedIdToken?.payload.email1).toBe("bob@bob.com");

    expect(expires_in).toBe(60*60);
});

test('AuthorizationServer.OidcAuthzCodeFlow.accessTokenIdTokenSCopedClaims', async () => {

    const {authServer, client, code} = await getAuthorizationCode({scopes: "read write openid email1",
        idTokenClaims: {"email1": {"email1": "email"}}});
    const {access_token, refresh_token, expires_in, error, error_description, id_token}
        = await authServer.tokenEndpoint({
            grantType: "authorization_code", 
            clientId: client.clientId, 
            code: code, 
            clientSecret: "DEF"});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();

    const decodedAccessToken
        = await authServer.validAccessToken(access_token??"");
    expect(decodedAccessToken).toBeDefined();

    const valid
        = await authServer.validRefreshToken(refresh_token??"");
    expect(valid).toBe(true);

    const decodedIdToken
        = await authServer.validIdToken(id_token??"");
    expect(decodedIdToken).toBeDefined();
    expect(decodedIdToken?.payload.sub).toBe("bob");
    expect(decodedIdToken?.payload.email1).toBe("bob@bob.com");

    expect(expires_in).toBe(60*60);
});
