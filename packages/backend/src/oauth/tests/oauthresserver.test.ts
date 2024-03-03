import { test, expect } from 'vitest';
import { OAuthResourceServer } from '../resserver';
import fs from 'node:fs';
import { getAuthorizationCode } from './common';
import { Hasher } from '../../hasher';

test('ResourceServer.validAccessToken', async () => {

    const {authServer, client, code} = await getAuthorizationCode();
    const {access_token, error, error_description}
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
    const publicKey = fs.readFileSync("keys/rsa-public-key.pem", 'utf8');
    const resserver = new OAuthResourceServer({jwtPublicKey: publicKey, clockTolerance: 10});
    const authorized = await resserver.tokenAuthorized(access_token??"");
    expect(authorized).toBeDefined();
});

test('ResourceServer.invalidPublicKey', async () => {

    const {authServer, client, code} = await getAuthorizationCode();
    const {access_token, error, error_description}
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
    const publicKey = fs.readFileSync("keys/rsa-public-key-wrong.pem", 'utf8');
    const resserver = new OAuthResourceServer({jwtPublicKey: publicKey, clockTolerance: 10});
    const authorized = await resserver.tokenAuthorized(access_token??"");
    expect(authorized).toBeUndefined();
});

test('ResourceServer.invalidSecret', async () => {

    const {authServer, client, code} = await getAuthorizationCode();
    const { error }
        = await authServer.tokenPostEndpoint({
            grantType: "authorization_code", 
            clientId: client.clientId, 
            code: code, 
            clientSecret: "DEFG"});
    expect(error).toBe("access_denied");
});

test('ResourceServer.invalidAccessToken', async () => {

    const {authServer, client, code} = await getAuthorizationCode();
    const {access_token, error, error_description}
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
    const publicKey = fs.readFileSync("keys/rsa-public-key.pem", 'utf8');
    const resserver = new OAuthResourceServer({jwtPublicKey: publicKey, clockTolerance: 10});
    const authorized = await resserver.tokenAuthorized("x"+access_token??"");
    expect(authorized).toBeUndefined();
});

test('ResourceServer.validCodeChallenge', async () => {

    const {authServer, client, code} = await getAuthorizationCode({challenge: true});
    const {access_token, error, error_description}
        = await authServer.tokenPostEndpoint({
            grantType: "authorization_code", 
            clientId: client.clientId, 
            code: code, 
            codeVerifier: "ABC123"});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();

    const decodedAccessToken = await authServer.validAccessToken(access_token??"");
    expect(decodedAccessToken).toBeDefined();
    expect(decodedAccessToken?.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[1]);
    const publicKey = fs.readFileSync("keys/rsa-public-key.pem", 'utf8');
    const resserver = new OAuthResourceServer({jwtPublicKey: publicKey, clockTolerance: 10});
    const authorized = await resserver.tokenAuthorized(access_token??"");
    expect(authorized).toBeDefined();
});

test('ResourceServer.invalidCodeChallenge', async () => {

    const {authServer, client, code} = await getAuthorizationCode({challenge: true});
    const {error}
        = await authServer.tokenPostEndpoint({
            grantType: "authorization_code", 
            clientId: client.clientId, 
            code: code, 
            codeVerifier: "ABC124"});
    expect(error).toBe("access_denied");
});

test('ResourceServer.validAud', async () => {

    const {authServer, client, code} = await getAuthorizationCode({aud: "resourceserver"});
    const {access_token, error, error_description}
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
    const publicKey = fs.readFileSync("keys/rsa-public-key.pem", 'utf8');
    const resserver = new OAuthResourceServer({jwtPublicKey: publicKey, clockTolerance: 10, });
    const authorized = await resserver.tokenAuthorized(access_token??"");
    expect(authorized).toBeDefined();
});

test('ResourceServer.invalidAud', async () => {

    const {authServer, client, code} = await getAuthorizationCode({aud: "resourceserver"});
    const {access_token, error, error_description}
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
    const publicKey = fs.readFileSync("keys/rsa-public-key.pem", 'utf8');
    const resserver = new OAuthResourceServer({resourceServerName: "wrongresourceserver", jwtPublicKey: publicKey, clockTolerance: 10, });
    const authorized = await resserver.tokenAuthorized(access_token??"");
    expect(authorized).toBeUndefined();
});

test('ResourceServer.invalidIsser', async () => {

    const {authServer, client, code} = await getAuthorizationCode();
    const {access_token, error, error_description}
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
    const publicKey = fs.readFileSync("keys/rsa-public-key.pem", 'utf8');
    const resserver = new OAuthResourceServer({jwtPublicKey: publicKey, clockTolerance: 10, oauthIssuers: "http://differentissuer:3000"});
    const authorized = await resserver.tokenAuthorized(access_token??"");
    expect(authorized).toBeUndefined();
});

test('ResourceServer.persistAccessToken', async () => {

    const {authServer, client, code, keyStorage} = await getAuthorizationCode({persistAccessToken: true});
    const {access_token, error, error_description}
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
    const key = "access:"+Hasher.hash(decodedAccessToken?.payload.jti);
    const storedAccessToken = await keyStorage?.getKey(key);
    expect(storedAccessToken?.value).toBe(key);
    const publicKey = fs.readFileSync("keys/rsa-public-key.pem", 'utf8');
    const resserver = new OAuthResourceServer({jwtPublicKey: publicKey, clockTolerance: 10, oauthIssuers: "http://localhost:3000", persistAccessToken: true, keyStorage: keyStorage});
    const authorized = await resserver.tokenAuthorized(access_token??"");
    expect(authorized).toBeDefined();

    await keyStorage?.deleteKey(key);
    const unauthorized = await resserver.tokenAuthorized(access_token??"");
    expect(unauthorized).toBeUndefined();
});

test('ResourceServer.validateWithJwks', async () => {

    const {authServer, client, code} = await getAuthorizationCode();
    const {access_token, error, error_description}
        = await authServer.tokenPostEndpoint({
            grantType: "authorization_code", 
            clientId: client.clientId, 
            code: code, 
            clientSecret: "DEF"});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();

    const resserver = new OAuthResourceServer({clockTolerance: 10});

    const jwks = authServer.jwks();
    expect(jwks.keys.length).toBe(1);
    expect(jwks.keys[0].kty).toBe("RSA");
    await resserver.loadJwks(jwks);
    const authorized = await resserver.tokenAuthorized(access_token??"");
    expect(authorized).toBeDefined();
});
