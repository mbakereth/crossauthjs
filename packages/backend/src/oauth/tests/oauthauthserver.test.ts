import { test, expect } from 'vitest';
import { OAuthAuthorizationServer, type OAuthAuthorizationServerOptions } from '../authserver';
import { CrossauthError } from '@crossauth/common';
import fs from 'node:fs';
import { createClient, getAuthorizationCode } from './common';
import { InMemoryKeyStorage, InMemoryOAuthAuthorizationStorage } from '../../storage/inmemorystorage';
import { Hasher } from '../../hasher';
import { KeyStorage } from '../../storage';

test('AuthorizationServer.validAuthorizationCodeRequestPublicKeyFilePrivateKeyFile', async () => {

    const {clientStorage, client} = await createClient();
    const privateKey = fs.readFileSync("keys/rsa-private-key.pem", 'utf8');
    const keyStorage = new InMemoryKeyStorage();
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtPrivateKey : privateKey,
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
    });
    const inputState = "ABCXYZ";
    const {code, state, error, errorDescription} 
        = await authServer.authorizeGetEndpoint({
            responseType: "code", 
            clientId: client.clientId, 
            redirectUri: client.redirectUri[0], 
            scope: "read write", 
            state: inputState});
    expect(error).toBeUndefined();
    expect(errorDescription).toBeUndefined();
    expect(state).toBe(inputState);
    const key = await keyStorage.getKey("authz:"+Hasher.hash(code||""));
    const data = KeyStorage.decodeData(key.data);
    expect(data.scope.length).toBe(2);
    expect(["read", "write"]).toContain(data.scope[0]);
    expect(["read", "write"]).toContain(data.scope[1]);
});

test('AuthorizationServer.scopePersistence', async () => {

    const {clientStorage, client} = await createClient();
    const keyStorage = new InMemoryKeyStorage();
    const authStorage = new InMemoryOAuthAuthorizationStorage();
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
        authStorage : authStorage,
    });
    const inputState = "ABCXYZ";
    const {code, state, error, errorDescription} 
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
    expect(errorDescription).toBeUndefined();
    expect(state).toBe(inputState);
    const key = await keyStorage.getKey("authz:"+Hasher.hash(code||""));
    const data = KeyStorage.decodeData(key.data);
    expect(data.scope.length).toBe(2);
    expect(["read", "write"]).toContain(data.scope[0]);
    expect(["read", "write"]).toContain(data.scope[1]);
});

test('AuthorizationServer.emptyScopeDisallowed', async () => {

    const {clientStorage, client} = await createClient();
    const keyStorage = new InMemoryKeyStorage();
    const authStorage = new InMemoryOAuthAuthorizationStorage();
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
        emptyScopeIsValid: false,
        authStorage : authStorage,
    });
    const inputState = "ABCXYZ";
    const {error, errorDescription} 
        = await authServer.authorizeGetEndpoint({
            responseType: "code", 
            clientId: client.clientId, 
            redirectUri: client.redirectUri[0], 
            state: inputState,
            user: {id: "bob", username: "bob", state: "active"}});
    const scopes = await authStorage.getAuthorizations("ABC", "bob")
    expect(scopes.length).toBe(0);
    expect(error).toBeDefined();
    expect(errorDescription).toBeDefined();
});

test('AuthorizationServer.emptyScopeAllowed', async () => {

    const {clientStorage, client} = await createClient();
    const keyStorage = new InMemoryKeyStorage();
    const authStorage = new InMemoryOAuthAuthorizationStorage();
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
        authStorage : authStorage,
        emptyScopeIsValid: true,
   });
    const inputState = "ABCXYZ";
    const {error, errorDescription} 
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
    expect(errorDescription).toBeUndefined();
});

test('AuthorizationServer.validAuthorizationCodeRequestPublicKeyFilePrivateKey', async () => {

    const {clientStorage, client} = await createClient();
    const privateKey = fs.readFileSync("keys/rsa-private-key.pem", 'utf8');
    const keyStorage = new InMemoryKeyStorage();
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtPrivateKey : privateKey,
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
    });
    const inputState = "ABCXYZ";
    const {code, state, error, errorDescription} 
        = await authServer.authorizeGetEndpoint({
            responseType: "code", 
            clientId: client.clientId, 
            redirectUri: client.redirectUri[0], 
            scope: "read write", 
            state: inputState});
    expect(error).toBeUndefined();
    expect(errorDescription).toBeUndefined();
    expect(state).toBe(inputState);
    const key = await keyStorage.getKey("authz:"+Hasher.hash(code||""));
    const data = KeyStorage.decodeData(key.data);
    expect(data.scope.length).toBe(2);
    expect(["read", "write"]).toContain(data.scope[0]);
    expect(["read", "write"]).toContain(data.scope[1]);
});

test('AuthorizationServer.validAuthorizationCodeRequestPublicKeyPrivateKeyFile', async () => {

    const {clientStorage, client} = await createClient();
    const publicKey = fs.readFileSync("keys/rsa-public-key.pem", 'utf8');
    const keyStorage = new InMemoryKeyStorage();
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKey : publicKey,
        validateScopes : true,
        validScopes: "read, write",
    });
    const inputState = "ABCXYZ";
    const {code, state, error, errorDescription} 
        = await authServer.authorizeGetEndpoint({
            responseType: "code", 
            clientId: client.clientId, 
            redirectUri: client.redirectUri[0], 
            scope: "read write", 
            state: inputState});
    expect(error).toBeUndefined();
    expect(errorDescription).toBeUndefined();
    expect(state).toBe(inputState);
    const key = await keyStorage.getKey("authz:"+Hasher.hash(code||""));
    const data = KeyStorage.decodeData(key.data);
    expect(data.scope.length).toBe(2);
    expect(["read", "write"]).toContain(data.scope[0]);
    expect(["read", "write"]).toContain(data.scope[1]);
});

test('AuthorizationServer.validAuthorizationCodeRequestSecretKeyFile', async () => {

    const {clientStorage, client} = await createClient();
    //const publicKey = fs.readFileSync("keys/secretkey.txt", 'utf8');
    const keyStorage = new InMemoryKeyStorage();
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtSecretKeyFile : "keys/secretkey.txt",
        jwtAlgorithm: "HS256",
        validateScopes : true,
        validScopes: "read, write",
    });
    const inputState = "ABCXYZ";
    const {code, state, error, errorDescription} 
        = await authServer.authorizeGetEndpoint({
            responseType: "code", 
            clientId: client.clientId, 
            redirectUri: client.redirectUri[0], 
            scope: "read write", 
            state: inputState});
    expect(error).toBeUndefined();
    expect(errorDescription).toBeUndefined();
    expect(state).toBe(inputState);
    const key = await keyStorage.getKey("authz:"+Hasher.hash(code||""));
    const data = KeyStorage.decodeData(key.data);
    expect(data.scope.length).toBe(2);
    expect(["read", "write"]).toContain(data.scope[0]);
    expect(["read", "write"]).toContain(data.scope[1]);
});

test('AuthorizationServer.validAuthorizationCodeRequestSecretKey', async () => {

    const {clientStorage, client} = await createClient();
    const secretKey = fs.readFileSync("keys/secretkey.txt", 'utf8');
    const keyStorage = new InMemoryKeyStorage();
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtSecretKey : secretKey,
        jwtAlgorithm: "HS256",
        validateScopes : true,
        validScopes: "read, write",
    });
    const inputState = "ABCXYZ";
    const {code, state, error, errorDescription} 
        = await authServer.authorizeGetEndpoint({
            responseType: "code", 
            clientId: client.clientId, 
            redirectUri: client.redirectUri[0], 
            scope: "read write", 
            state: inputState});
    expect(error).toBeUndefined();
    expect(errorDescription).toBeUndefined();
    expect(state).toBe(inputState);
    const key = await keyStorage.getKey("authz:"+Hasher.hash(code||""));
    const data = KeyStorage.decodeData(key.data);
    expect(data.scope.length).toBe(2);
    expect(["read", "write"]).toContain(data.scope[0]);
    expect(["read", "write"]).toContain(data.scope[1]);
});

test('AuthorizationServer.invalidScope', async () => {

    const {clientStorage, client} = await createClient();
    const authServer = new OAuthAuthorizationServer(clientStorage, new InMemoryKeyStorage(), {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
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

test('AuthorizationServer.invalidRedirectUri', async () => {

    const {clientStorage, client} = await createClient();
    const authServer = new OAuthAuthorizationServer(clientStorage, new InMemoryKeyStorage(), {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
    });
    const inputState = "ABCXYZ";
    const {error} 
        = await authServer.authorizeGetEndpoint({
            responseType: "code", 
            clientId: client.clientId, 
            redirectUri: "/invalidRedirect", 
            scope: "read write", 
            state: inputState});
    expect(error).toBe("invalid_request");
});

test('AuthorizationServer.invalidKeyInConstructor', async () => {

    const {clientStorage} = await createClient();
    const options : OAuthAuthorizationServerOptions = {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        jwtSecretKeyFile : "keys/secretkey.txt",
        validateScopes : true,
        validScopes: "read, write",

    } 
    await expect(async () => {new OAuthAuthorizationServer(clientStorage, new InMemoryKeyStorage(), options)}).rejects.toThrowError(CrossauthError);
});

test('AuthorizationServer.invalidResponseType', async () => {
    const {clientStorage, client} = await createClient();
    const authServer = new OAuthAuthorizationServer(clientStorage, new InMemoryKeyStorage(), {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
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

test('AuthorizationServer.invalidKey', async () => {

    const {clientStorage, client} = await createClient();
    const authServer = new OAuthAuthorizationServer(clientStorage, new InMemoryKeyStorage(), {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key-wrong.pem",
        validateScopes : true,
        validScopes: "read, write",
    });
    const inputState = "ABCXYZ";
    const {code, state, error, errorDescription} 
        = await authServer.authorizeGetEndpoint({
            responseType: "code", 
            clientId: client.clientId, 
            redirectUri: client.redirectUri[0], 
            scope: "read write", 
            state: inputState});
    expect(error).toBeUndefined();
    expect(errorDescription).toBeUndefined();
    expect(state).toBe(inputState);
    await expect(async () => {await authServer.validateJwt(code||"")}).rejects.toThrowError(CrossauthError);
    });

test('AuthorizationServer.accessToken', async () => {

    const {authServer, client, code} = await getAuthorizationCode();
    const {access_token, refresh_token, expires_in, error, error_description}
        = await authServer.tokenPostEndpoint({
            grantType: "authorization_code", 
            clientId: client.clientId, 
            code: code, 
            clientSecret: client.clientSecret});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();

    const decodedAccessToken
        = await authServer.validateJwt(access_token||"");
    expect(decodedAccessToken.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedAccessToken.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedAccessToken.payload.scope[1]);

    const decodedRefreshToken
        = await authServer.validateJwt(refresh_token||"");
    expect(decodedRefreshToken.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedRefreshToken.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedRefreshToken.payload.scope[1]);

    expect(expires_in).toBe(60*60);
});

test('AuthorizationServer.oidcConfiguration', async () => {
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

test('AuthorizationServer.jwks', async () => {
    const {authServer} = await getAuthorizationCode();
    const jwks = authServer.jwks();
    expect(jwks.keys.length).toBe(1);
    expect(jwks.keys[0].kty).toBe("RSA");
});
