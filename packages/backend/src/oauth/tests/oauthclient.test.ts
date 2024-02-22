import createFetchMock from 'vitest-fetch-mock';
import { test, expect, vi, beforeAll, afterAll } from 'vitest';
import { getAccessToken } from './common';
import { OAuthClient } from '../client.ts'
import { OpenIdConfiguration } from '@crossauth/common';

function get(name : string, url : string){
    let names : RegExpExecArray|null;
    if(names=(new RegExp('[?&]'+encodeURIComponent(name)+'=([^&]*)')).exec(url))
       return decodeURIComponent(names[1]);
 }
 
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
    grant_types_supported: ["authorization_code"],
    token_endpoint_auth_signing_algorithms_supported: ["RS256"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    claims_supported: ["iss", "sub", "aud", "jti", "iat", "type"],
    request_uri_parameter_supported: true,
    require_request_uri_registration: true,
}



beforeAll(async () => {
    fetchMocker.doMock();
});


test('ResourceServer.validAccessToken', async () => {
    const {code, access_token} = await getAccessToken();

    const oauthClient = new OAuthClient({ 
        authServerBaseUri: "http://authserver.com",
        clientId: "ABC",
        clientSecret: "DEF",
        redirectUri: "http://client.com/authzcode"
    });
    

    fetchMocker.mockResponseOnce(JSON.stringify(oidcConfiguration));
    await oauthClient.fetchConfig();
    const url = await oauthClient["startAuthorizationCodeFlow"]("read write", false);
    const state = get("state",url);
    expect(state).toBeDefined();
    expect(state?.length).toBeGreaterThan(0);

    //fetchMocker.mockResponseOnce((req) => (req.body||"{}").toString());
    fetchMocker.mockResponseOnce((req) => {
        const params = JSON.parse((req.body||"{}").toString());
        if (params.code != code) return "{}";
        return JSON.stringify({
            access_token: access_token,
            token_type: "Bearer",
            expires_in: new Date(new Date().getTime()+1000*60*5),
    })});
    const resp = await oauthClient["redirectEndpoint"](code, state);
    expect(resp.access_token).toBeDefined();

});

afterAll(async () => {
    fetchMocker.dontMock();
});
