import { test, expect } from 'vitest';
import { OAuthAuthorizationServer, type OAuthAuthorizationServerOptions } from '../authserver';
import fs from 'node:fs';
import { createClient, getAuthorizationCode } from './common';
import { InMemoryKeyStorage, InMemoryOAuthAuthorizationStorage } from '../../storage/inmemorystorage';
import { Hasher } from '../../hasher';
import { KeyStorage } from '../../storage';
import { getTestUserStorage }  from '../../storage/tests/inmemorytestdata';
import { LocalPasswordAuthenticator } from '../..';

test('AuthorizationServer.AuthzCodeFlow.validAuthorizationCodeRequestPublicKeyFilePrivateKeyFile', async () => {

    const {clientStorage, client} = await createClient();
    const privateKey = fs.readFileSync("keys/rsa-private-key.pem", 'utf8');
    const keyStorage = new InMemoryKeyStorage();
    const userStorage = await getTestUserStorage();
    const authenticator = new LocalPasswordAuthenticator(userStorage);
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtPrivateKey : privateKey,
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
        userStorage, 
        authenticators: {
            "localpassword" : authenticator
        },
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
    const key = await keyStorage.getKey("authz:"+Hasher.hash(code??""));
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
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
        authStorage : authStorage,
        userStorage,
        authenticators: {
            "localpassword" : authenticator
        },
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
    const key = await keyStorage.getKey("authz:"+Hasher.hash(code??""));
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
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
        emptyScopeIsValid: false,
        authStorage : authStorage,
        userStorage,
        authenticators: {
            "localpassword" : authenticator
        },
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
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
        authStorage : authStorage,
        emptyScopeIsValid: true,
        userStorage,
        authenticators: {
            "localpassword" : authenticator
        },
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
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtPrivateKey : privateKey,
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
        userStorage,
        authenticators: {
            "localpassword" : authenticator
        },
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
    const key = await keyStorage.getKey("authz:"+Hasher.hash(code??""));
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
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKey : publicKey,
        validateScopes : true,
        validScopes: "read, write",
        userStorage,
        authenticators: {
            "localpassword" : authenticator
        },
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
    const key = await keyStorage.getKey("authz:"+Hasher.hash(code??""));
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
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtSecretKeyFile : "keys/secretkey.txt",
        jwtAlgorithm: "HS256",
        validateScopes : true,
        validScopes: "read, write",
        userStorage,
        authenticators: {
            "localpassword" : authenticator
        },
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
    const key = await keyStorage.getKey("authz:"+Hasher.hash(code??""));
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
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtSecretKey : secretKey,
        jwtAlgorithm: "HS256",
        validateScopes : true,
        validScopes: "read, write",
        userStorage,
        authenticators: {
            "localpassword" : authenticator
        },
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
    const key = await keyStorage.getKey("authz:"+Hasher.hash(code??""));
    const data = KeyStorage.decodeData(key.data);
    expect(data.scope.length).toBe(2);
    expect(["read", "write"]).toContain(data.scope[0]);
    expect(["read", "write"]).toContain(data.scope[1]);
});

test('AuthorizationServer.AuthzCodeFlow.invalidScope', async () => {

    const {clientStorage, client} = await createClient();
    const userStorage = await getTestUserStorage();
    const authenticator = new LocalPasswordAuthenticator(userStorage);
    const authServer = new OAuthAuthorizationServer(clientStorage, new InMemoryKeyStorage(), {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
        userStorage,
        authenticators: {
            "localpassword" : authenticator
        },
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
    const authServer = new OAuthAuthorizationServer(clientStorage, new InMemoryKeyStorage(), {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
        userStorage,
        authenticators: {
            "localpassword" : authenticator
        },
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
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        jwtSecretKeyFile : "keys/secretkey.txt",
        validateScopes : true,
        validScopes: "read, write",

    } 
    await expect(async () => {new OAuthAuthorizationServer(clientStorage, new InMemoryKeyStorage(), options)}).rejects.toThrowError();
});

test('AuthorizationServer.AuthzCodeFlow.invalidResponseType', async () => {
    const {clientStorage, client} = await createClient();
    const userStorage = await getTestUserStorage();
    const authenticator = new LocalPasswordAuthenticator(userStorage);
    const authServer = new OAuthAuthorizationServer(clientStorage, new InMemoryKeyStorage(), {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
        userStorage,
        authenticators: {
            "localpassword" : authenticator
        },
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
    const authServer = new OAuthAuthorizationServer(clientStorage, new InMemoryKeyStorage(), {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key-wrong.pem",
        validateScopes : true,
        validScopes: "read, write",
        userStorage,
        authenticators: {
            "localpassword" : authenticator
        },
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
        = await authServer.tokenPostEndpoint({
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
        = await authServer.tokenPostEndpoint({
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

    const decodedRefreshToken
        = await authServer.validRefreshToken(refresh_token??"");
    expect(decodedRefreshToken).toBeDefined();
    expect(decodedRefreshToken?.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedRefreshToken?.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedRefreshToken?.payload.scope[1]);

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
    const decodedRefreshToken
        = await authServer.validRefreshToken("ABC");
    expect(decodedRefreshToken).toBeUndefined();
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
    const {refresh_token, error}
        = await authServer.tokenPostEndpoint({
            grantType: "authorization_code", 
            clientId: client.clientId, 
            code: code, 
            clientSecret: "DEF"});
    expect(error).toBeUndefined();
    expect(refresh_token).toBeDefined();

    const {refresh_token: refresh_token2, error: error2}
        = await authServer.tokenPostEndpoint({
            grantType: "refresh_token", 
            clientId: client.clientId, 
            refreshToken: refresh_token, 
            clientSecret: "DEF"});
    expect(error2).toBeUndefined();
    expect(refresh_token2).toBeUndefined();

});

test('AuthorizationServer.AuthzCodeFlow.refreshTokenFlowRolling', async () => {

    const {authServer, client, code} = await getAuthorizationCode({rollingRefreshToken: true});
    const {refresh_token, error}
        = await authServer.tokenPostEndpoint({
            grantType: "authorization_code", 
            clientId: client.clientId, 
            code: code, 
            clientSecret: "DEF"});
    expect(error).toBeUndefined();
    expect(refresh_token).toBeDefined();

    const {refresh_token: refresh_token2, error: error2}
        = await authServer.tokenPostEndpoint({
            grantType: "refresh_token", 
            clientId: client.clientId, 
            refreshToken: refresh_token, 
            clientSecret: "DEF"});
    expect(error2).toBeUndefined();
    expect(refresh_token2).toBeDefined();
    expect(refresh_token2).not.toBe(refresh_token);

});

test('AuthorizationServer.OidcAuthzCodeFlow.accessTokenIdToken', async () => {

    const {authServer, client, code} = await getAuthorizationCode({oidc: true});
    const {access_token, refresh_token, expires_in, error, error_description, id_token}
        = await authServer.tokenPostEndpoint({
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

    const decodedRefreshToken
        = await authServer.validRefreshToken(refresh_token??"");
    expect(decodedRefreshToken).toBeDefined();
    expect(decodedRefreshToken?.payload.scope.length).toBe(3);
    expect(["read", "write", "openid"]).toContain(decodedRefreshToken?.payload.scope[0]);
    expect(["read", "write", "openid"]).toContain(decodedRefreshToken?.payload.scope[1]);
    expect(["read", "write", "openid"]).toContain(decodedRefreshToken?.payload.scope[2]);

    const decodedIdToken
        = await authServer.validIdToken(id_token??"");
    expect(decodedIdToken).toBeDefined();
    expect(decodedIdToken?.payload.scope.length).toBe(3);
    expect(["read", "write", "openid"]).toContain(decodedRefreshToken?.payload.scope[0]);
    expect(["read", "write", "openid"]).toContain(decodedRefreshToken?.payload.scope[1]);
    expect(["read", "write", "openid"]).toContain(decodedRefreshToken?.payload.scope[2]);
    expect(decodedIdToken?.payload.sub).toBe("bob");

    expect(expires_in).toBe(60*60);
});
