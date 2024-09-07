// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { test, expect } from 'vitest';
import { OAuthResourceServer } from '../resserver';
import fs from 'node:fs';
import { getAuthorizationCode } from './common';
import { Crypto } from '../../crypto';
import { KeyPrefix } from '@crossauth/common';
import { OAuthTokenConsumer } from '../tokenconsumer';

test('ResourceServer.validAccessToken', async () => {

    const {authServer, client, code} = await getAuthorizationCode();
    const {access_token, error, error_description}
        = await authServer.tokenEndpoint({
            grantType: "authorization_code", 
            client_id: client.client_id, 
            code: code, 
            client_secret: "DEF"});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();

    const decodedAccessToken
        = await authServer.validAccessToken(access_token??"");
    expect(decodedAccessToken).toBeDefined();
    expect(decodedAccessToken?.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[1]);
    const publicKey = fs.readFileSync("keys/rsa-public-key.pem", 'utf8');
    const resserver = new OAuthResourceServer(
        [new OAuthTokenConsumer({
            jwtKeyType: "RS256",
            jwtPublicKey: publicKey,
            clockTolerance: 10
    })]);
    const authorized = await resserver.accessTokenAuthorized(access_token??"");
    expect(authorized).toBeDefined();
});

test('ResourceServer.invalidPublicKey', async () => {

    const {authServer, client, code} = await getAuthorizationCode();
    const {access_token, error, error_description}
        = await authServer.tokenEndpoint({
            grantType: "authorization_code", 
            client_id: client.client_id, 
            code: code, 
            client_secret: "DEF"});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();

    const decodedAccessToken
        = await authServer.validAccessToken(access_token??"");
    expect(decodedAccessToken).toBeDefined();
    expect(decodedAccessToken?.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[1]);
    const publicKey = fs.readFileSync("keys/rsa-public-key-wrong.pem", 'utf8');
    const resserver = new OAuthResourceServer(
        [new OAuthTokenConsumer({
            jwtKeyType: "RS256",
            jwtPublicKey: publicKey,
            clockTolerance: 10
    })]);
    const authorized = await resserver.accessTokenAuthorized(access_token??"");
    expect(authorized).toBeUndefined();
});

test('ResourceServer.invalidSecret', async () => {

    const {authServer, client, code} = await getAuthorizationCode();
    const { error }
        = await authServer.tokenEndpoint({
            grantType: "authorization_code", 
            client_id: client.client_id, 
            code: code, 
            client_secret: "DEFG"});
    expect(error).toBe("access_denied");
});

test('ResourceServer.invalidAccessToken', async () => {

    const {authServer, client, code} = await getAuthorizationCode();
    const {access_token, error, error_description}
        = await authServer.tokenEndpoint({
            grantType: "authorization_code", 
            client_id: client.client_id, 
            code: code, 
            client_secret: "DEF"});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();

    const decodedAccessToken
        = await authServer.validAccessToken(access_token??"");
    expect(decodedAccessToken).toBeDefined();
    expect(decodedAccessToken?.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[1]);
    const publicKey = fs.readFileSync("keys/rsa-public-key.pem", 'utf8');
    const resserver = new OAuthResourceServer(
        [new OAuthTokenConsumer({
            jwtKeyType: "RS256",
            jwtPublicKey: publicKey,
            clockTolerance: 10
    })]);
    const authorized = await resserver.accessTokenAuthorized("x"+access_token??"");
    expect(authorized).toBeUndefined();
});

test('ResourceServer.validCodeChallenge', async () => {

    const {authServer, client, code} = await getAuthorizationCode({challenge: true});
    const {access_token, error, error_description}
        = await authServer.tokenEndpoint({
            grantType: "authorization_code", 
            client_id: client.client_id, 
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
    const resserver = new OAuthResourceServer(
        [new OAuthTokenConsumer({
            jwtKeyType: "RS256",
            jwtPublicKey: publicKey,
            clockTolerance: 10
    })]);
    const authorized = await resserver.accessTokenAuthorized(access_token??"");
    expect(authorized).toBeDefined();
});

test('ResourceServer.invalidCodeChallenge', async () => {

    const {authServer, client, code} = await getAuthorizationCode({challenge: true});
    const {error}
        = await authServer.tokenEndpoint({
            grantType: "authorization_code", 
            client_id: client.client_id, 
            code: code, 
            codeVerifier: "ABC124"});
    expect(error).toBe("access_denied");
});

test('ResourceServer.validAud', async () => {

    const {authServer, client, code} = await getAuthorizationCode({aud: "resourceserver"});
    const {access_token, error, error_description}
        = await authServer.tokenEndpoint({
            grantType: "authorization_code", 
            client_id: client.client_id, 
            code: code, 
            client_secret: "DEF"});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();

    const decodedAccessToken
        = await authServer.validAccessToken(access_token??"");
        expect(decodedAccessToken).toBeDefined();
        expect(decodedAccessToken?.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[1]);
    const publicKey = fs.readFileSync("keys/rsa-public-key.pem", 'utf8');
    const resserver = new OAuthResourceServer(
        [new OAuthTokenConsumer({
            jwtKeyType: "RS256",
            jwtPublicKey: publicKey,
            clockTolerance: 10
    })]);
    const authorized = await resserver.accessTokenAuthorized(access_token??"");
    expect(authorized).toBeDefined();
});

test('ResourceServer.invalidAud', async () => {

    const {authServer, client, code} = await getAuthorizationCode({aud: "resourceserver"});
    const {access_token, error, error_description}
        = await authServer.tokenEndpoint({
            grantType: "authorization_code", 
            client_id: client.client_id, 
            code: code, 
            client_secret: "DEF"});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();

    const decodedAccessToken
        = await authServer.validAccessToken(access_token??"");
        expect(decodedAccessToken).toBeDefined();
        expect(decodedAccessToken?.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[1]);
    const publicKey = fs.readFileSync("keys/rsa-public-key.pem", 'utf8');
    const resserver = new OAuthResourceServer(
        [new OAuthTokenConsumer({
            audience: "wrongresourceserver",
            jwtKeyType: "RS256",
            jwtPublicKey: publicKey,
            clockTolerance: 10
    })]);
    const authorized = await resserver.accessTokenAuthorized(access_token??"");
    expect(authorized).toBeUndefined();
});

test('ResourceServer.invalidIsser', async () => {

    const {authServer, client, code} = await getAuthorizationCode();
    const {access_token, error, error_description}
        = await authServer.tokenEndpoint({
            grantType: "authorization_code", 
            client_id: client.client_id, 
            code: code, 
            client_secret: "DEF"});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();

    const decodedAccessToken
        = await authServer.validAccessToken(access_token??"");
    expect(decodedAccessToken).toBeDefined();
    expect(decodedAccessToken?.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[1]);
    const publicKey = fs.readFileSync("keys/rsa-public-key.pem", 'utf8');
    const resserver = 
        new OAuthResourceServer(
            [new OAuthTokenConsumer({
                jwtKeyType: "RS256",
                jwtPublicKey: publicKey,
                clockTolerance: 10,
                authServerBaseUrl: "http://expectedissuer.com",
        })]);
    const authorized = await resserver.accessTokenAuthorized(access_token??"");
    expect(authorized).toBeUndefined();
});

test('ResourceServer.persistAccessToken', async () => {

    const {authServer, client, code, keyStorage} = await getAuthorizationCode({persistAccessToken: true});
    const {access_token, error, error_description}
        = await authServer.tokenEndpoint({
            grantType: "authorization_code", 
            client_id: client.client_id, 
            code: code, 
            client_secret: "DEF"});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();

    const decodedAccessToken
        = await authServer.validAccessToken(access_token??"");
    expect(decodedAccessToken).toBeDefined();
    const key = KeyPrefix.accessToken+Crypto.hash(decodedAccessToken?.payload.jti);
    const storedAccessToken = await keyStorage?.getKey(key);
    expect(storedAccessToken?.value).toBe(key);
    const publicKey = fs.readFileSync("keys/rsa-public-key.pem", 'utf8');
    const resserver = 
        new OAuthResourceServer(
            [new OAuthTokenConsumer({
                jwtKeyType: "RS256",
                jwtPublicKey: publicKey,
                clockTolerance: 10,
                persistAccessToken: true, keyStorage: keyStorage
        })]);
    const authorized = await resserver.accessTokenAuthorized(access_token??"");
    expect(authorized).toBeDefined();

    await keyStorage?.deleteKey(key);
    const unauthorized = await resserver.accessTokenAuthorized(access_token??"");
    expect(unauthorized).toBeUndefined();
});

test('ResourceServer.validateWithJwks', async () => {

    const {authServer, client, code} = await getAuthorizationCode();
    const {access_token, error, error_description}
        = await authServer.tokenEndpoint({
            grantType: "authorization_code", 
            client_id: client.client_id, 
            code: code, 
            client_secret: "DEF"});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();

    const resserver = 
        new OAuthResourceServer(
            [new OAuthTokenConsumer({
                clockTolerance: 10,
        })]);

    const jwks = authServer.jwks();
    expect(jwks.keys.length).toBe(1);
    expect(jwks.keys[0].kty).toBe("RSA");
    await resserver.tokenConsumers[process.env["CROSSAUTH_AUTH_SERVER_BASE_URL"]??""].loadJwks(jwks);
    const authorized = await resserver.accessTokenAuthorized(access_token??"");
    expect(authorized).toBeDefined();
});
