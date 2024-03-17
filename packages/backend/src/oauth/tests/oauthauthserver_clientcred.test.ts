import { test, expect } from 'vitest';
import { getAuthServer } from './common';
test('AuthorizationServer.ClientCredFlow.accessToken', async () => {

    const {authServer, client} = await getAuthServer();
    const {access_token, refresh_token, expires_in, error, error_description}
        = await authServer.tokenEndpoint({
            grantType: "client_credentials", 
            clientId: client.clientId, 
            clientSecret: "DEF",
            scope: "read write"});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();

    const decodedAccessToken
        = await authServer.validAccessToken(access_token??"");
    expect(decodedAccessToken).toBeDefined()
    expect(decodedAccessToken?.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedAccessToken?.payload.scope[1]);

    const valid
        = await authServer.validRefreshToken(refresh_token??"");
    expect(valid).toBe(true)
    const refreshData = await authServer.getRefreshTokenData(refresh_token??"");
    expect(["read", "write"]).toContain(refreshData?.scope[0]);
    expect(["read", "write"]).toContain(refreshData?.scope[1]);
    expect(refreshData?.username).toBeUndefined();

    expect(expires_in).toBe(60*60);
});

test('AuthorizationServer.ClientCredFlow.missingScopeValid', async () => {

    const {authServer, client} = await getAuthServer();
    const {access_token, refresh_token, expires_in, error, error_description}
        = await authServer.tokenEndpoint({
            grantType: "client_credentials", 
            clientId: client.clientId, 
            clientSecret: "DEF"});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();

    const decodedAccessToken
        = await authServer.validAccessToken(access_token??"");
        expect(decodedAccessToken).toBeDefined();
        expect(decodedAccessToken?.payload.scope).toBeUndefined();

    const valid
        = await authServer.validRefreshToken(refresh_token??"");
    expect(valid).toBe(true);

    expect(expires_in).toBe(60*60);
});

test('AuthorizationServer.ClientCredFlow.missingScopeInvalid', async () => {

    const {authServer} = await getAuthServer({emptyScopeIsValid: false});
    const {error}
        = await authServer.tokenEndpoint({
            grantType: "client_credentials", 
            clientId: "ABC", 
            clientSecret: "DEF"});
    expect(error).toBe("invalid_scope");
});

test('AuthorizationServer.ClientCredFlow.missingClientSecret', async () => {

    const {authServer, client} = await getAuthServer();
    const {error}
        = await authServer.tokenEndpoint({
            grantType: "client_credentials", 
            scope: "read write",
            clientId: client.clientId});
    expect(error).toBe("access_denied");
});
