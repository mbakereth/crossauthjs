import { test, expect } from 'vitest';
import { getAuthServer } from './common';
test('AuthorizationServer.ClientCredFlow.accessToken', async () => {

    const {authServer, client} = await getAuthServer();
    const {access_token, refresh_token, expires_in, error, error_description}
        = await authServer.tokenPostEndpoint({
            grantType: "client_credentials", 
            clientId: client.clientId, 
            clientSecret: client.clientSecret,
            scope: "read write"});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();

    const decodedAccessToken
        = await authServer.validateJwt(access_token||"");
    expect(decodedAccessToken.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedAccessToken.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedAccessToken.payload.scope[1]);

    const decodedRefreshToken
        = await authServer.validateJwt(refresh_token||"");
    expect(decodedRefreshToken.payload.scope.length).toBe(2);
    expect(["read", "write"]).toContain(decodedRefreshToken.payload.scope[0]);
    expect(["read", "write"]).toContain(decodedRefreshToken.payload.scope[1]);

    expect(expires_in).toBe(60*60);
});

test('AuthorizationServer.ClientCredFlow.missingScopeValid', async () => {

    const {authServer, client} = await getAuthServer();
    const {access_token, refresh_token, expires_in, error, error_description}
        = await authServer.tokenPostEndpoint({
            grantType: "client_credentials", 
            clientId: client.clientId, 
            clientSecret: client.clientSecret});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();

    const decodedAccessToken
        = await authServer.validateJwt(access_token||"");
    expect(decodedAccessToken.payload.scope).toBeUndefined();

    const decodedRefreshToken
        = await authServer.validateJwt(refresh_token||"");
    expect(decodedRefreshToken.payload.scope).toBeUndefined();

    expect(expires_in).toBe(60*60);
});

test('AuthorizationServer.ClientCredFlow.missingScopeVInalid', async () => {

    const {authServer, client} = await getAuthServer({emptyScopeIsValid: false});
    const {error}
        = await authServer.tokenPostEndpoint({
            grantType: "client_credentials", 
            clientId: client.clientId, 
            clientSecret: client.clientSecret});
    expect(error).toBe("invalid_scope");
});

test('AuthorizationServer.ClientCredFlow.missingClientSecret', async () => {

    const {authServer, client} = await getAuthServer();
    const {error}
        = await authServer.tokenPostEndpoint({
            grantType: "client_credentials", 
            scope: "read write",
            clientId: client.clientId});
    expect(error).toBe("access_denied");
});
