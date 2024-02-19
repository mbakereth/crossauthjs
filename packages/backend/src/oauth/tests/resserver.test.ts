import { test, expect } from 'vitest';
import { OAuthResourceServer } from '../resserver';
import fs from 'node:fs';
import { getAuthorizationCode } from './common';
import { Hasher } from '../../hasher';

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
    const resserver = new OAuthResourceServer({jwtPublicKey: publicKey, clockTolerance: 10});
    const authorized = await resserver.authorized(accessToken||"");
    expect(authorized).toBeDefined();
});

test('ResourceServer.invalidPublicKey', async () => {

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
    const resserver = new OAuthResourceServer({jwtPublicKey: publicKey, clockTolerance: 10});
    const authorized = await resserver.authorized(accessToken||"");
    expect(authorized).toBeUndefined();
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
    const publicKey = fs.readFileSync("keys/rsa-public-key.pem", 'utf8');
    const resserver = new OAuthResourceServer({jwtPublicKey: publicKey, clockTolerance: 10});
    const authorized = await resserver.authorized("x"+accessToken||"");
    expect(authorized).toBeUndefined();
});

test('ResourceServer.validCodeChallenge', async () => {

    const {authServer, client, code} = await getAuthorizationCode({challenge: true});
    const {accessToken, error, errorDescription}
        = await authServer.authorizeEndpoint("token", client.clientId, client.redirectUri[0], "read write", "ABC", code, undefined, undefined, undefined, "ABC123");
    expect(error).toBeUndefined();
    expect(errorDescription).toBeUndefined();

    const decodedAccessToken = await authServer.validateJwt(accessToken||"");
    expect(decodedAccessToken.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedAccessToken.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedAccessToken.payload.scope[1]);
    const publicKey = fs.readFileSync("keys/rsa-public-key.pem", 'utf8');
    const resserver = new OAuthResourceServer({jwtPublicKey: publicKey, clockTolerance: 10});
    const authorized = await resserver.authorized(accessToken||"");
    expect(authorized).toBeDefined();
});

test('ResourceServer.invalidCodeChallenge', async () => {

    const {authServer, client, code} = await getAuthorizationCode({challenge: true});
    const {error}
        = await authServer.authorizeEndpoint("token", client.clientId, client.redirectUri[0], "read write", "ABC", code, undefined, undefined, undefined, "ABC124");
    expect(error).toBe("access_denied");
});

test('ResourceServer.validAud', async () => {

    const {authServer, client, code} = await getAuthorizationCode({aud: "resourceserver"});
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
    const resserver = new OAuthResourceServer({jwtPublicKey: publicKey, clockTolerance: 10, });
    const authorized = await resserver.authorized(accessToken||"");
    expect(authorized).toBeDefined();
});

test('ResourceServer.invalidAud', async () => {

    const {authServer, client, code} = await getAuthorizationCode({aud: "resourceserver"});
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
    const resserver = new OAuthResourceServer({resourceServerName: "wrongresourceserver", jwtPublicKey: publicKey, clockTolerance: 10, });
    const authorized = await resserver.authorized(accessToken||"");
    expect(authorized).toBeUndefined();
});

test('ResourceServer.invalidIsser', async () => {

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
    const resserver = new OAuthResourceServer({jwtPublicKey: publicKey, clockTolerance: 10, oauthIssuers: "http://differentissuer:3000"});
    const authorized = await resserver.authorized(accessToken||"");
    expect(authorized).toBeUndefined();
});

test('ResourceServer.persistAccessToken', async () => {

    const {authServer, client, code, keyStorage} = await getAuthorizationCode({persistAccessToken: true});
    const {accessToken, error, errorDescription}
        = await authServer.authorizeEndpoint("token", client.clientId, client.redirectUri[0], "read write", "ABC", code, client.clientSecret);
    expect(error).toBeUndefined();
    expect(errorDescription).toBeUndefined();

    const decodedAccessToken
        = await authServer.validateJwt(accessToken||"");
    const key = "access:"+Hasher.hash(decodedAccessToken.payload.jti);
    const storedAccessToken = await keyStorage?.getKey(key);
    expect(storedAccessToken?.value).toBe(key);
    const publicKey = fs.readFileSync("keys/rsa-public-key.pem", 'utf8');
    const resserver = new OAuthResourceServer({jwtPublicKey: publicKey, clockTolerance: 10, oauthIssuers: "http://localhost:3000", persistAccessToken: true, keyStorage: keyStorage});
    const authorized = await resserver.authorized(accessToken||"");
    expect(authorized).toBeDefined();

    await keyStorage?.deleteKey(key);
    const unauthorized = await resserver.authorized(accessToken||"");
    expect(unauthorized).toBeUndefined();
});
