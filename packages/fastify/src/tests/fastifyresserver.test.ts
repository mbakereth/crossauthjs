import createFetchMock from 'vitest-fetch-mock';
import { test, expect , vi, beforeAll, afterAll } from 'vitest';
import { FastifyOAuthResourceServer } from '../fastifyresserver';
import { OpenIdConfiguration } from '@crossauth/common';
import { getAuthorizationCode } from './oauthcommon';
import { FastifyRequest, FastifyReply } from 'fastify';
import fastify from 'fastify';

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

test('FastifyOAuthResourceServer.validAndInvalidAccessToken', async () => {

    const {authServer, client, code} = await getAuthorizationCode();
    const {access_token, error, error_description}
        = await authServer.tokenEndpoint({
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
    const app = fastify({logger: false});
    const resserver = new FastifyOAuthResourceServer(
        app, undefined, {}, {authServerBaseUri: "http://server.com"}
    );
    fetchMocker.mockResponseOnce(JSON.stringify(oidcConfiguration));
    await resserver.tokenConsumer.loadConfig();
    fetchMocker.mockResponseOnce(JSON.stringify(authServer.jwks()));
    await resserver.tokenConsumer.loadJwks();
    // @ts-ignore
    const reply : FastifyRequest = {
        headers: {authorization: "Bearer " + access_token}
    }
    const resp1 = await resserver["authorized"](reply);
    expect(resp1?.authorized).toBe(true);

    // @ts-ignore
    const reply2 : FastifyRequest = {
        headers: {authorization: "Bearer " + access_token+"x"}
    }
    const resp2 = await resserver["authorized"](reply2);
    expect(resp2?.authorized).toBe(false);
});

const JSONHDR : [string,string] = ['Content-Type', 'application/json; charset=utf-8'];

test('FastifyOAuthResourceServer.preHandlerHook', async () => {

    const {authServer, client, code} = await getAuthorizationCode();
    const {access_token, error, error_description}
        = await authServer.tokenEndpoint({
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
    const app = fastify({logger: false});
    const resserver = new FastifyOAuthResourceServer(
        app, undefined, {}, {authServerBaseUri: "http://server.com"}
    );
    app.get('/post',  async (request : FastifyRequest, reply : FastifyReply) =>  {
        reply.header(...JSONHDR).send({token: request.accessTokenPayload});
    });

    fetchMocker.mockResponseOnce(JSON.stringify(oidcConfiguration));
    await resserver.tokenConsumer.loadConfig();
    fetchMocker.mockResponseOnce(JSON.stringify(authServer.jwks()));
    await resserver.tokenConsumer.loadJwks();
    // @ts-ignore
    const reply : FastifyRequest = {
        headers: {authorization: "Bearer " + access_token}
    }
    const resp1 = await resserver["authorized"](reply);
    expect(resp1?.authorized).toBe(true);

    // @ts-ignore
    const reply2 : FastifyRequest = {
        headers: {authorization: "Bearer " + access_token+"x"}
    }
    const resp2 = await resserver["authorized"](reply2);
    expect(resp2?.authorized).toBe(false);
});

afterAll(async () => {
    fetchMocker.dontMock();
});
