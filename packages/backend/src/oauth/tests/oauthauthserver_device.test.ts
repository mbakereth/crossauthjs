import { test, expect } from 'vitest';
import { OAuthAuthorizationServer } from '../authserver';
import { createClient } from './common';
import { InMemoryKeyStorage } from '../../storage/inmemorystorage';
import { LocalPasswordAuthenticator } from '../..';
import { getTestUserStorage }  from '../../storage/tests/inmemorytestdata';

test('AuthorizationServer.deviceCodeFlow', async () => {
    const {clientStorage, client} = await createClient();
    const keyStorage = new InMemoryKeyStorage();
    const userStorage = await getTestUserStorage();

    let user = await userStorage.getUserByUsername("bob");

    const authenticator = new LocalPasswordAuthenticator(userStorage);
    const auth = {
        "localpassword" : authenticator
    };
    const authServer = new OAuthAuthorizationServer(clientStorage, 
        keyStorage, 
        auth, {
        jwtKeyType: "RS256",
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: ["read", "write"],
        userStorage: userStorage,
        deviceCodeVerificationUri: "http://localhost:5173/device",
    });

    // call device authorization endpoint to start flow
    const deviceAuthRet = await authServer.deviceAuthorizationEndpoint({
        clientId: client.clientId,
        scope: "read write",
        clientSecret: "DEF"
    });
    expect(deviceAuthRet.device_code).toBeDefined();
    expect(deviceAuthRet.user_code?.length).toBe(9);
    expect(deviceAuthRet.expires_in).toBe(300);
    expect(deviceAuthRet.interval).toBe(5);
    expect(deviceAuthRet.verification_uri).toBe('http://localhost:5173/device');
    expect(deviceAuthRet.verification_uri_complete).toContain('http://localhost:5173/device?user_code=');
    expect(deviceAuthRet.error).toBeUndefined();


    // poll token - should get authorization pending
    let tokenRet = await authServer.tokenEndpoint({
        grantType: "urn:ietf:params:oauth:grant-type:device_code", 
        clientId: client.clientId, 
        clientSecret: "DEF",
        deviceCode: deviceAuthRet.device_code});
    expect(tokenRet.error).toBe("authorization_pending");
    expect(tokenRet.access_token).toBeUndefined();

    // call deviceCodeVerificationUri to enter wrong user code
    let deviceRet = await authServer.deviceEndpoint({
        userCode: "ABC" ?? "",
        user: user?.user,
    });
    expect(deviceRet.ok).toBe(false);
    expect(deviceRet.error).toBe("access_denied");

    // poll token - should still get authorization pending
    tokenRet = await authServer.tokenEndpoint({
        grantType: "urn:ietf:params:oauth:grant-type:device_code", 
        clientId: client.clientId, 
        clientSecret: "DEF",
        deviceCode: deviceAuthRet.device_code});
    expect(tokenRet.error).toBe("authorization_pending");
    expect(tokenRet.access_token).toBeUndefined();

    // call deviceCodeVerificationUri to enter right user code
    deviceRet = await authServer.deviceEndpoint({
        userCode: deviceAuthRet.user_code ?? "",
        user: user?.user,
    });
    expect(deviceRet.ok).toBe(true);
    expect(deviceRet.error).toBeUndefined();
    expect(deviceRet.client_id).toBe(client.clientId);
    expect(deviceRet.scope).toBe("read write");

    // poll token - should still get authorization pending as scopes are validated
    tokenRet = await authServer.tokenEndpoint({
        grantType: "urn:ietf:params:oauth:grant-type:device_code", 
        clientId: client.clientId, 
        clientSecret: "DEF",
        deviceCode: deviceAuthRet.device_code});
    expect(tokenRet.error).toBe("authorization_pending");
    expect(tokenRet.access_token).toBeUndefined();
    
    await authServer.validateAndPersistScope(client.clientId, "read write");

    // tell auth server that scopes have been authorized
    const authRet = await authServer.authorizeDeviceFlowScopes(deviceAuthRet.user_code ?? "");
    console.log(authRet);

    // now we should get an access token
    tokenRet = await authServer.tokenEndpoint({
        grantType: "urn:ietf:params:oauth:grant-type:device_code", 
        clientId: client.clientId, 
        clientSecret: "DEF",
        deviceCode: deviceAuthRet.device_code});
    expect(tokenRet.error).toBeUndefined();
    expect(tokenRet.access_token).toBeDefined();

});
