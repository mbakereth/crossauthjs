import { test, expect } from 'vitest';
import { OAuthAuthorizationServer, type OAuthAuthorizationServerOptions } from '../authserver';
import { InMemoryOAuthClientStorage } from '../../storage/inmemorystorage';
import { OAuthClientStorage } from '../../storage';
import { OAuthClient, CrossauthError } from '@crossauth/common';
import fs from 'node:fs';

async function createClient() : Promise<{clientStorage : OAuthClientStorage, client : OAuthClient}> {
    const clientStorage = new InMemoryOAuthClientStorage();
    const inputClient = {
        clientId : "ABC",
        clientSecret: "DEF",
        clientName: "Test",
        redirectUri: ["/redirectUri"],
    };
    const client = await clientStorage.createClient(inputClient);
    return {clientStorage, client};

}

test('AuthorizationServer.validAuthorizationCodeRequestPublicKeyFilePrivateKeyFile', async () => {

    const {clientStorage, client} = await createClient();
    const privateKey = fs.readFileSync("keys/rsa-private-key.pem", 'utf8');
    const authServer = new OAuthAuthorizationServer(clientStorage, {
        privateKey : privateKey,
        publicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
    });
    const inputState = "ABCXYZ";
    const {code, state, error, errorDescription} 
        = await authServer.authorizeEndpoint("code", client.clientId, client.redirectUri[0], "read+write", inputState);
    expect(error).toBeUndefined();
    expect(errorDescription).toBeUndefined();
    expect(state).toBe(inputState);
    const decodedToken
        = await authServer.validateAuthorizationCode(code||"");
    expect(decodedToken.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedToken.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedToken.payload.scope[1]);
});

test('AuthorizationServer.validAuthorizationCodeRequestPublicKeyFilePrivateKey', async () => {

    const {clientStorage, client} = await createClient();
    const privateKey = fs.readFileSync("keys/rsa-private-key.pem", 'utf8');
    const authServer = new OAuthAuthorizationServer(clientStorage, {
        privateKey : privateKey,
        publicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
    });
    const inputState = "ABCXYZ";
    const {code, state, error, errorDescription} 
        = await authServer.authorizeEndpoint("code", client.clientId, client.redirectUri[0], "read+write", inputState);
    expect(error).toBeUndefined();
    expect(errorDescription).toBeUndefined();
    expect(state).toBe(inputState);
    const decodedToken
        = await authServer.validateAuthorizationCode(code||"");
    expect(decodedToken.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedToken.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedToken.payload.scope[1]);
});

test('AuthorizationServer.validAuthorizationCodeRequestPublicKeyPrivateKeyFile', async () => {

    const {clientStorage, client} = await createClient();
    const publicKey = fs.readFileSync("keys/rsa-public-key.pem", 'utf8');
    const authServer = new OAuthAuthorizationServer(clientStorage, {
        privateKeyFile : "keys/rsa-private-key.pem",
        publicKey : publicKey,
        validateScopes : true,
        validScopes: "read, write",
    });
    const inputState = "ABCXYZ";
    const {code, state, error, errorDescription} 
        = await authServer.authorizeEndpoint("code", client.clientId, client.redirectUri[0], "read+write", inputState);
    expect(error).toBeUndefined();
    expect(errorDescription).toBeUndefined();
    expect(state).toBe(inputState);
    const decodedToken
        = await authServer.validateAuthorizationCode(code||"");
    expect(decodedToken.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedToken.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedToken.payload.scope[1]);
});

test('AuthorizationServer.validAuthorizationCodeRequestSecretKeyFile', async () => {

    const {clientStorage, client} = await createClient();
    //const publicKey = fs.readFileSync("keys/secretkey.txt", 'utf8');
    const authServer = new OAuthAuthorizationServer(clientStorage, {
        secretKeyFile : "keys/secretkey.txt",
        jwtAlgorithm: "HS256",
        validateScopes : true,
        validScopes: "read, write",
    });
    const inputState = "ABCXYZ";
    const {code, state, error, errorDescription} 
        = await authServer.authorizeEndpoint("code", client.clientId, client.redirectUri[0], "read+write", inputState);
    expect(error).toBeUndefined();
    expect(errorDescription).toBeUndefined();
    expect(state).toBe(inputState);
    const decodedToken
        = await authServer.validateAuthorizationCode(code||"");
    expect(decodedToken.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedToken.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedToken.payload.scope[1]);
});

test('AuthorizationServer.validAuthorizationCodeRequestSecretKey', async () => {

    const {clientStorage, client} = await createClient();
    const secretKey = fs.readFileSync("keys/secretkey.txt", 'utf8');
    const authServer = new OAuthAuthorizationServer(clientStorage, {
        secretKey : secretKey,
        jwtAlgorithm: "HS256",
        validateScopes : true,
        validScopes: "read, write",
    });
    const inputState = "ABCXYZ";
    const {code, state, error, errorDescription} 
        = await authServer.authorizeEndpoint("code", client.clientId, client.redirectUri[0], "read+write", inputState);
    expect(error).toBeUndefined();
    expect(errorDescription).toBeUndefined();
    expect(state).toBe(inputState);
    const decodedToken
        = await authServer.validateAuthorizationCode(code||"");
    expect(decodedToken.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedToken.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedToken.payload.scope[1]);
});

test('AuthorizationServer.invalidScope', async () => {

    const {clientStorage, client} = await createClient();
    const authServer = new OAuthAuthorizationServer(clientStorage, {
        privateKeyFile : "keys/rsa-private-key.pem",
        publicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
    });
    const inputState = "ABCXYZ";
    const {error} 
        = await authServer.authorizeEndpoint("code", client.clientId, client.redirectUri[0], "unregisteredScope", inputState);
    expect(error).toBe("invalid_scope");
});

test('AuthorizationServer.invalidRedirectUri', async () => {

    const {clientStorage, client} = await createClient();
    const authServer = new OAuthAuthorizationServer(clientStorage, {
        privateKeyFile : "keys/rsa-private-key.pem",
        publicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
    });
    const inputState = "ABCXYZ";
    const {error} 
        = await authServer.authorizeEndpoint("code", client.clientId, "/invalidRedirect", "read+write", inputState);
    expect(error).toBe("invalid_request");
});

test('AuthorizationServer.invalidKeyInConstructor', async () => {

    const {clientStorage} = await createClient();
    const options : OAuthAuthorizationServerOptions = {
        privateKeyFile : "keys/rsa-private-key.pem",
        publicKeyFile : "keys/rsa-public-key.pem",
        secretKeyFile : "keys/secretkey.txt",
        validateScopes : true,
        validScopes: "read, write",

    } 
    await expect(async () => {new OAuthAuthorizationServer(clientStorage, options)}).rejects.toThrowError(CrossauthError);
});

test('AuthorizationServer.invalidResponseType', async () => {
    const {clientStorage, client} = await createClient();
    const authServer = new OAuthAuthorizationServer(clientStorage, {
        privateKeyFile : "keys/rsa-private-key.pem",
        publicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
    });
    const inputState = "ABCXYZ";
    const {error} 
        = await authServer.authorizeEndpoint("x", client.clientId, client.redirectUri[0], "read+write", inputState);
    expect(error).toBe("unsupported_response_type");

});

test('AuthorizationServer.invalidKey', async () => {

    const {clientStorage, client} = await createClient();
    const authServer = new OAuthAuthorizationServer(clientStorage, {
        privateKeyFile : "keys/rsa-private-key.pem",
        publicKeyFile : "keys/rsa-public-key-wrong.pem",
        validateScopes : true,
        validScopes: "read, write",
    });
    const inputState = "ABCXYZ";
    const {code, state, error, errorDescription} 
        = await authServer.authorizeEndpoint("code", client.clientId, client.redirectUri[0], "read+write", inputState);
    expect(error).toBeUndefined();
    expect(errorDescription).toBeUndefined();
    expect(state).toBe(inputState);
    await expect(async () => {await authServer.validateAuthorizationCode(code||"")}).rejects.toThrowError(CrossauthError);
});