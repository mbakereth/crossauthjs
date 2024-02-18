import { test, expect } from 'vitest';
import { OAuthAuthorizationServer, type OAuthAuthorizationServerOptions } from '../authserver';
import { OAuthResourceServer } from '../resserver';
import { InMemoryOAuthClientStorage } from '../../storage/inmemorystorage';
import { OAuthClientStorage } from '../../storage';
import { Hasher } from '../../hasher';
import { OAuthClient, CrossauthError } from '@crossauth/common';
import fs from 'node:fs';

async function createClient() : Promise<{clientStorage : OAuthClientStorage, client : OAuthClient}> {
    const clientStorage = new InMemoryOAuthClientStorage();
    const clientSecret = await Hasher.passwordHash("DEF", {
        encode: true,
        iterations: 1000,
        keyLen: 32,
    });
    const inputClient = {
        clientId : "ABC",
        clientSecret: clientSecret,
        clientName: "Test",
        redirectUri: ["/redirectUri"],
    };
    const client = await clientStorage.createClient(inputClient);
    return {clientStorage, client};

}

async function getAuthorizationCode(challenge = false) {
    const {clientStorage, client} = await createClient();
    const privateKey = fs.readFileSync("keys/rsa-private-key.pem", 'utf8');
    const authServer = new OAuthAuthorizationServer(clientStorage, {
        jwtPrivateKey : privateKey,
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
        secret: "ABCDEFG123890",
    });
    const inputState = "ABCXYZ";
    let codeChallenge : string|undefined;
    const codeVerifier = "ABC123";
    if (challenge) codeChallenge = Hasher.hash(codeVerifier);
    const {code, error, errorDescription} 
        = await authServer.authorizeEndpoint("code", client.clientId, client.redirectUri[0], "read write", inputState, undefined, undefined, codeChallenge);
    expect(error).toBeUndefined();
    expect(errorDescription).toBeUndefined();
    return {code, client, clientStorage, authServer};
}

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
        = await authServer.authorizeEndpoint("code", client.clientId, client.redirectUri[0], "read write", inputState);
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
        = await authServer.authorizeEndpoint("code", client.clientId, client.redirectUri[0], "read write", inputState);
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
        = await authServer.authorizeEndpoint("code", client.clientId, client.redirectUri[0], "read write", inputState);
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
        = await authServer.authorizeEndpoint("code", client.clientId, client.redirectUri[0], "read write", inputState);
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
        = await authServer.authorizeEndpoint("code", client.clientId, client.redirectUri[0], "read write", inputState);
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
        = await authServer.authorizeEndpoint("code", client.clientId, client.redirectUri[0], "unregisteredScope", inputState);
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
        = await authServer.authorizeEndpoint("code", client.clientId, "/invalidRedirect", "read write", inputState);
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
        = await authServer.authorizeEndpoint("x", client.clientId, client.redirectUri[0], "read write", inputState);
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
        = await authServer.authorizeEndpoint("code", client.clientId, client.redirectUri[0], "read write", inputState);
    expect(error).toBeUndefined();
    expect(errorDescription).toBeUndefined();
    expect(state).toBe(inputState);
    await expect(async () => {await authServer.validateJwt(code||"")}).rejects.toThrowError(CrossauthError);
    });

test('AuthorizationServer.accessToken', async () => {

    const {authServer, client, code} = await getAuthorizationCode();
    const {accessToken, refreshToken, expiresIn, error, errorDescription}
        = await authServer.authorizeEndpoint("token", client.clientId, client.redirectUri[0], "read write", "ABC", code, client.clientSecret);
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

test('ResourceServer.validAccessToken', async () => {

    const {authServer, client, code} = await getAuthorizationCode();
    const {accessToken, error, errorDescription}
        = await authServer.authorizeEndpoint("token", client.clientId, client.redirectUri[0], "read write", "ABC", code, client.clientSecret);
    expect(error).toBeUndefined();
    expect(errorDescription).toBeUndefined();

    const decodedAccessToken
        = await authServer.validateJwt(accessToken||"");
    expect(decodedAccessToken.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedAccessToken.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedAccessToken.payload.scope[1]);
    const publicKey = fs.readFileSync("keys/rsa-public-key.pem", 'utf8');
    const authorized = await OAuthResourceServer.authorized(accessToken||"", publicKey);
    expect(authorized).toBeDefined();
});

test('ResourceServer.invalidAccessToken', async () => {

    const {authServer, client, code} = await getAuthorizationCode();
    const {accessToken, error, errorDescription}
        = await authServer.authorizeEndpoint("token", client.clientId, client.redirectUri[0], "read write", "ABC", code, client.clientSecret);
    expect(error).toBeUndefined();
    expect(errorDescription).toBeUndefined();

    const decodedAccessToken
        = await authServer.validateJwt(accessToken||"");
    expect(decodedAccessToken.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedAccessToken.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedAccessToken.payload.scope[1]);
    const publicKey = fs.readFileSync("keys/rsa-public-key-wrong.pem", 'utf8');
    const authorized = await OAuthResourceServer.authorized(accessToken||"", publicKey);
    expect(authorized).toBeUndefined();
});

test('ResourceServer.validCodeChallenge', async () => {

    const {authServer, client, code} = await getAuthorizationCode(true);
    const {accessToken, error, errorDescription}
        = await authServer.authorizeEndpoint("token", client.clientId, client.redirectUri[0], "read write", "ABC", code, undefined, undefined, undefined, "ABC123");
    expect(error).toBeUndefined();
    expect(errorDescription).toBeUndefined();

    const decodedAccessToken = await authServer.validateJwt(accessToken||"");
    expect(decodedAccessToken.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedAccessToken.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedAccessToken.payload.scope[1]);
    const publicKey = fs.readFileSync("keys/rsa-public-key.pem", 'utf8');
    const authorized = await OAuthResourceServer.authorized(accessToken||"", publicKey);
    expect(authorized).toBeDefined();
});

test('ResourceServer.invalidCodeChallenge', async () => {

    const {authServer, client, code} = await getAuthorizationCode(true);
    const {error, errorDescription}
        = await authServer.authorizeEndpoint("token", client.clientId, client.redirectUri[0], "read write", "ABC", code, undefined, undefined, undefined, "ABC124");
    expect(error).toBe("access_denied");
});
