import { test, expect } from 'vitest';
import { OAuthAuthorizationServer, type OAuthAuthorizationServerOptions } from '../authserver';
import { CrossauthError } from '@crossauth/common';
import fs from 'node:fs';
import { createClient, getAuthorizationCode } from './common';

test('AuthorizationServer.validAuthorizationCodeRequestPublicKeyFilePrivateKeyFile', async () => {

    const {clientStorage, client} = await createClient();
    const privateKey = fs.readFileSync("keys/rsa-private-key.pem", 'utf8');
    const authServer = new OAuthAuthorizationServer(clientStorage, {
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
    const decodedToken
        = await authServer.validateJwt(code||"");
    expect(decodedToken.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedToken.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedToken.payload.scope[1]);
});

test('AuthorizationServer.validAuthorizationCodeRequestPublicKeyFilePrivateKey', async () => {

    const {clientStorage, client} = await createClient();
    const privateKey = fs.readFileSync("keys/rsa-private-key.pem", 'utf8');
    const authServer = new OAuthAuthorizationServer(clientStorage, {
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
    const decodedToken
        = await authServer.validateJwt(code||"");
    expect(decodedToken.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedToken.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedToken.payload.scope[1]);
});

test('AuthorizationServer.validAuthorizationCodeRequestPublicKeyPrivateKeyFile', async () => {

    const {clientStorage, client} = await createClient();
    const publicKey = fs.readFileSync("keys/rsa-public-key.pem", 'utf8');
    const authServer = new OAuthAuthorizationServer(clientStorage, {
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
    const decodedToken
        = await authServer.validateJwt(code||"");
    expect(decodedToken.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedToken.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedToken.payload.scope[1]);
});

test('AuthorizationServer.validAuthorizationCodeRequestSecretKeyFile', async () => {

    const {clientStorage, client} = await createClient();
    //const publicKey = fs.readFileSync("keys/secretkey.txt", 'utf8');
    const authServer = new OAuthAuthorizationServer(clientStorage, {
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
    const decodedToken
        = await authServer.validateJwt(code||"");
    expect(decodedToken.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedToken.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedToken.payload.scope[1]);
});

test('AuthorizationServer.validAuthorizationCodeRequestSecretKey', async () => {

    const {clientStorage, client} = await createClient();
    const secretKey = fs.readFileSync("keys/secretkey.txt", 'utf8');
    const authServer = new OAuthAuthorizationServer(clientStorage, {
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
    const decodedToken
        = await authServer.validateJwt(code||"");
    expect(decodedToken.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedToken.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedToken.payload.scope[1]);
});

test('AuthorizationServer.invalidScope', async () => {

    const {clientStorage, client} = await createClient();
    const authServer = new OAuthAuthorizationServer(clientStorage, {
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
    const authServer = new OAuthAuthorizationServer(clientStorage, {
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
    await expect(async () => {new OAuthAuthorizationServer(clientStorage, options)}).rejects.toThrowError(CrossauthError);
});

test('AuthorizationServer.invalidResponseType', async () => {
    const {clientStorage, client} = await createClient();
    const authServer = new OAuthAuthorizationServer(clientStorage, {
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
    const authServer = new OAuthAuthorizationServer(clientStorage, {
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
    const {accessToken, refreshToken, expiresIn, error, errorDescription}
        = await authServer.tokenPostEndpoint({
            grantType: "authorization_code", 
            clientId: client.clientId, 
            code: code, 
            clientSecret: client.clientSecret});
    expect(error).toBeUndefined();
    expect(errorDescription).toBeUndefined();

    const decodedAccessToken
        = await authServer.validateJwt(accessToken||"");
    expect(decodedAccessToken.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedAccessToken.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedAccessToken.payload.scope[1]);

    const decodedRefreshToken
        = await authServer.validateJwt(refreshToken||"");
    expect(decodedRefreshToken.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedRefreshToken.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedRefreshToken.payload.scope[1]);

    expect(expiresIn).toBe(60*60);
});
