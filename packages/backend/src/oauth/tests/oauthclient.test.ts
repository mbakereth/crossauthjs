// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import createFetchMock from 'vitest-fetch-mock';
import { test, expect, vi, beforeAll, afterAll } from 'vitest';
import { getAccessToken } from './common';
import { OAuthClientBackend } from '../client'
import { OpenIdConfiguration } from '@crossauth/common';
import { Crypto } from '../../crypto';
 
const fetchMocker = createFetchMock(vi);
fetchMocker.enableMocks();

const oidcConfiguration : OpenIdConfiguration = {
    issuer: "http://server.com",
    authorization_endpoint: "http://server.com/authorize",
    token_endpoint: "http://server.com/token",
    token_endpoint_auth_methods_supported: ["client_secret_post"],
    jwks_uri: "http://server.com/jwks",
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "client_credentials", "password"],
    token_endpoint_auth_signing_alg_values_supported: ["RS256"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    claims_supported: ["iss", "sub", "aud", "jti", "iat", "type"],
    request_uri_parameter_supported: true,
    require_request_uri_registration: true,
}



beforeAll(async () => {
    fetchMocker.doMock();
});


test('OAuthClient.startAuthorizationCodeFlow', async () => {
    const {code, access_token} = await getAccessToken();
    
    const oauthClient = new OAuthClientBackend("http://authserver.com", { 
        client_id: "ABC",
        client_secret: "DEF",
        redirect_uri: "http://client.com/authzcode"
    });
    

    fetchMocker.mockResponseOnce(JSON.stringify(oidcConfiguration));
    await oauthClient.loadConfig();
    const state = Crypto.randomValue(32);
    const {url} = await oauthClient["startAuthorizationCodeFlow"](state, {scope: "read write"});
    expect(url).toBeDefined();
    expect(state).toBeDefined();
    expect(state?.length).toBeGreaterThan(0);

    //fetchMocker.mockResponseOnce((req) => (req.body??"{}").toString());
    fetchMocker.mockResponseOnce((req) => {
        const params = JSON.parse((req.body??"{}").toString());
        if (params.code != code) return "{}";
        return JSON.stringify({
            access_token: access_token,
            token_type: "Bearer",
            expires_in: new Date(new Date().getTime()+1000*60*5),
    })});
    const resp = await oauthClient["redirectEndpoint"]({ code });
    expect(resp.access_token).toBeDefined();

});

test('OAuthClient.clientCredentialsFlow', async () => {
    
    const oauthClient = new OAuthClientBackend("http://authserver.com", { 
        client_id: "ABC",
        client_secret: "DEF",
        redirect_uri: "http://client.com/authzcode"
    });
    

    fetchMocker.mockResponseOnce(JSON.stringify(oidcConfiguration));
    await oauthClient.loadConfig();
    const state = Crypto.randomValue(32);
    const {url} = await oauthClient["startAuthorizationCodeFlow"](state, { scope: "read write" });
    expect(url).toBeDefined();
    expect(state?.length).toBeGreaterThan(0);

    fetchMocker.mockResponseOnce((_req) => {
        return JSON.stringify({
            access_token: "dummy",
            token_type: "Bearer",
            expires_in: new Date(new Date().getTime()+1000*60*5),
    })});
    const resp = await oauthClient["clientCredentialsFlow"]("read write");
    expect(resp.access_token).toBeDefined();

});

test('OAuthClient.passwordFlow', async () => {
    
    const oauthClient = new OAuthClientBackend("http://authserver.com", { 
        client_id: "ABC",
        client_secret: "DEF",
        redirect_uri: "http://client.com/authzcode"
    });
    

    fetchMocker.mockResponseOnce(JSON.stringify(oidcConfiguration));
    await oauthClient.loadConfig();
    const state = Crypto.randomValue(32);
    const {url} = await oauthClient["startAuthorizationCodeFlow"](state, { scope: "read write" });
    expect(url).toBeDefined();
    expect(state?.length).toBeGreaterThan(0);

    fetchMocker.mockResponseOnce((req) => {
        const params = JSON.parse((req.body??"{}").toString());
        if (params.username != "bob" || params.password != "bobPass123") return {};
        return JSON.stringify({
            access_token: "dummy",
            token_type: "Bearer",
            expires_in: new Date(new Date().getTime()+1000*60*5),
    })});
    const resp = await oauthClient["passwordFlow"]("bob", "bobPass123", "read write");
    expect(resp.access_token).toBeDefined();

});

afterAll(async () => {
    fetchMocker.dontMock();
});
