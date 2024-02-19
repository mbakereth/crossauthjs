import { test, expect } from 'vitest';
import { OAuthResourceServer } from '../resserver';
import fs from 'node:fs';
import { getAuthorizationCode } from './common';

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
    const resserver = new OAuthResourceServer("resourceserver", {jwtPublicKey: publicKey, clockTolerance: 10});
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
    const resserver = new OAuthResourceServer("resourceserver", {jwtPublicKey: publicKey, clockTolerance: 10});
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
    const resserver = new OAuthResourceServer("resourceserver", {jwtPublicKey: publicKey, clockTolerance: 10});
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
    const resserver = new OAuthResourceServer("resourceserver", {jwtPublicKey: publicKey, clockTolerance: 10});
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
    const resserver = new OAuthResourceServer("resourceserver", {jwtPublicKey: publicKey, clockTolerance: 10, });
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
    const resserver = new OAuthResourceServer("wrongresourceserver", {jwtPublicKey: publicKey, clockTolerance: 10, });
    const authorized = await resserver.authorized(accessToken||"");
    expect(authorized).toBeUndefined();
});

test('ResourceServer.validIsser', async () => {

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
    const resserver = new OAuthResourceServer("resourceserver", {jwtPublicKey: publicKey, clockTolerance: 10, jwtIssuers: "http://localhost:3000"});
    const authorized = await resserver.authorized(accessToken||"");
    expect(authorized).toBeDefined();
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
    const resserver = new OAuthResourceServer("resourceserver", {jwtPublicKey: publicKey, clockTolerance: 10, jwtIssuers: "http://differentissuer:3000"});
    const authorized = await resserver.authorized(accessToken||"");
    expect(authorized).toBeUndefined();
});
