import createFetchMock from 'vitest-fetch-mock';
import { test, expect, beforeAll, afterAll, vi } from 'vitest';
import { FastifyServer, type FastifyServerOptions } from '../fastifyserver';
import fastify from 'fastify';
import {
    type OpenIdConfiguration,
    type UserInputFields,
    CrossauthError,
    ErrorCode } from '@crossauth/common';
import { getAuthServer } from './oauthcommon';
import { getTestUserStorage } from './inmemorytestdata';
import {
    InMemoryKeyStorage,
    LocalPasswordAuthenticator,
    KeyStorage,
    UserStorage,
    TotpAuthenticator,
    EmailAuthenticator } from '@crossauth/backend';
import { authenticator as gAuthenticator } from 'otplib';

import path from 'path';

const fetchMocker = createFetchMock(vi);
fetchMocker.enableMocks();

export var emailTokenData :  {to: string, otp : string};

async function createTotpAccount(username: string,
    password: string,
    userStorage: UserStorage) {

    const userInputs : UserInputFields = {
        username: username,
        email: username + "@email.com",
        state: "active",
        factor1: "localpassword", 
        factor2: "totp", 
    };
    let lpAuthenticator = 
        new LocalPasswordAuthenticator(userStorage, {pbkdf2Iterations: 1_000});

    const totpAuth = new TotpAuthenticator("Unittest");
    totpAuth.factorName = "totp";
    const resp = await totpAuth.prepareConfiguration(userInputs);
    if (!resp?.sessionData) throw new CrossauthError(ErrorCode.UnknownError, 
        "TOTP created no session data")

    const user = await userStorage.createUser(userInputs, {
        password: await lpAuthenticator.createPasswordHash(password),
        totpSecret: resp.sessionData.totpSecret,
        } );

    return { user, totpSecret: resp.sessionData.totpSecret };
};

async function createEmailAccount(username: string,
    password: string,
    userStorage: UserStorage) {

    const userInputs : UserInputFields = {
        username: username,
        email: username + "@email.com",
        state: "active",
        factor1: "localpassword", 
        factor2: "email", 
    };
    let lpAuthenticator = 
        new LocalPasswordAuthenticator(userStorage, {pbkdf2Iterations: 1_000});

    const emailAuth = new EmailAuthenticator()
    emailAuth.factorName = "email";

    const user = await userStorage.createUser(userInputs, {
        password: await lpAuthenticator.createPasswordHash(password),
        } );

    return { user };
};

const oidcConfiguration : OpenIdConfiguration = {
    issuer: "http://server.com",
    authorization_endpoint: "http://server.com/authorize",
    token_endpoint: "http://server.com/token",
    token_endpoint_auth_methods_supported: ["client_secret_post"],
    jwks_uri: "http://server.com/jwks",
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code",
        "client_credentials",
        "refresh_token",
        "password",
        "http://auth0.com/oauth/grant-type/mfa-otp",
        "http://auth0.com/oauth/grant-type/mfa-oob"],
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

function getCsrf(res: any) : {csrfCookie: string, csrfToken: string} {
    const body = JSON.parse(res.body)
    const csrfCookies = res.cookies.filter((cookie: any) => {return cookie.name == "CSRFTOKEN"});
    expect(csrfCookies.length).toBe(1);
    const csrfCookie = csrfCookies[0].value;
    const csrfToken = body.args.csrfToken;
    expect(csrfToken).toBeDefined();
    return {csrfCookie, csrfToken};
}

async function makeClient(options : FastifyServerOptions = {}) : Promise<{server: FastifyServer, keyStorage: KeyStorage}> {
    //const app = fastify({logger: {level: 'debug'}});
    const app = fastify({logger: false});

    // @ts-ignore
    app.decorateReply("view",  function(template, args) {
        return {template: template, args: args};
    });
    
    const userStorage = await getTestUserStorage();
    const keyStorage = new InMemoryKeyStorage();
    let lpAuthenticator = new LocalPasswordAuthenticator(userStorage);
    const totpAuth = new TotpAuthenticator("Unittest");
    totpAuth.factorName = "totp";
    const emailAuth = new EmailAuthenticator();
    emailAuth.factorName = "email";
    emailAuth["sendToken"] = async function (to: string, otp : string) {
        emailTokenData = {otp, to}
        return "1";
    };
    return {server: new FastifyServer({
        session: {
            keyStorage: keyStorage,
        },
        oAuthClient: {
            authServerBaseUrl: "http://server.com",
        }}, {
        userStorage,
        authenticators: {
            localpassword: lpAuthenticator,
            totp: totpAuth,
            email: emailAuth,
        },
        app: app,
        views: path.join(__dirname, '../views'),
        allowedFactor2: ["none"],
        enableEmailVerification: false,
        siteUrl: `http://localhost:3000`,
        clientId: "ABC",
        clientSecret: "DEF",
        validFlows: ["all"], // activate all OAuth flows
        tokenResponseType: "sendJson",
        errorResponseType: "sendJson",
        secret: "ABC",
        ...options,
    }), keyStorage: keyStorage};
}

////////////////////////////////////////////////////////
// TESTS

test('FastifyOAuthClient.Mfa.otp', async () => {
    const {authServer, userStorage, emailAuth} = await getAuthServer();

    emailAuth["sendToken"] = async function (to: string, otp : string) {
        emailTokenData = {otp, to}
        return "1";
    };

    const { totpSecret} =
        await createTotpAccount("mary", "maryPass123", userStorage)

    const {server} = await makeClient();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    let res;
    let body;

    // get csrf token and check password flow get 
    res = await server.app.inject({ method: "GET", url: "/passwordflow" })
    body = JSON.parse(res.body);
    expect(body.template).toBe("passwordflow.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);

    ////// Call password flow - expect MFA to initiate
    const firstTokenResponse = 
        await authServer.tokenEndpoint({
            grantType: "password", 
            clientId: "ABC", 
            username: "mary",
            password: "maryPass123" ,
            clientSecret: "DEF"});

    fetchMocker.mockResponseOnce((_req) => {
         return JSON.stringify(firstTokenResponse)});
    const authenticatorsResponse = 
        await authServer.mfaAuthenticatorsEndpoint(firstTokenResponse.mfa_token??"");
    fetchMocker.mockResponseOnce((_req) => {
        return JSON.stringify(authenticatorsResponse.authenticators)});
        fetchMocker.mockResponseOnce((_req) => {
            return JSON.stringify({challenge_type: "otp"})});
    
    res = await server.app.inject({ method: "POST", url: "/passwordflow", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        csrfToken: csrfToken,
        scope: "read write",
        username: "mary",
        password: "maryPass123",
     }});
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
    expect(body.template).toBe("mfaotp.njk");
    expect(body.args.mfa_token).toBe(firstTokenResponse.mfa_token);

    // Call passwordotp to completre MFA
    const maxTries = 2;
    for (let i=0; i<maxTries; ++i) {
        const otp = gAuthenticator.generate(totpSecret);

        const {access_token, scope, error: error4, expires_in} =
        await authServer.tokenEndpoint({
            grantType: "http://auth0.com/oauth/grant-type/mfa-otp",
            clientId : "ABC",
            scope: "read write",
            clientSecret: "DEF",
            mfaToken: firstTokenResponse.mfa_token,
            otp: otp
        });
        if (error4 && i < maxTries-1) continue;

        if (error4) {
            expect(error4).toBeUndefined();
        }

        fetchMocker.mockResponseOnce((_req) => {
            return JSON.stringify({

            access_token: access_token,
            expires_in: expires_in,
            scope: scope,
            token_type: "Bearer",
            });});

        res = await server.app.inject({ method: "POST", url: "/passwordotp", payload: {
            scope: "read write",
            mfa_token: firstTokenResponse.mfa_token,
            otp: otp,
         }});
         body = JSON.parse(res.body)
         expect(access_token).toBeDefined();

         break;
    }


});

test('FastifyOAuthClient.Mfa.oob', async () => {
    const {authServer, userStorage, emailAuth} = await getAuthServer();

    emailAuth["sendToken"] = async function (to: string, otp : string) {
        emailTokenData = {otp, to}
        return "1";
    };

     await createEmailAccount("mary", "maryPass123", userStorage)

    const {server} = await makeClient();

    if (server.oAuthClient) await server.oAuthClient.loadConfig(oidcConfiguration);

    let res;
    let body;

    // get csrf token and check password flow get 
    res = await server.app.inject({ method: "GET", url: "/passwordflow" })
    body = JSON.parse(res.body);
    expect(body.template).toBe("passwordflow.njk");
    const {csrfCookie, csrfToken} = getCsrf(res);

    ////// Call password flow - expect MFA to initiate
    const firstTokenResponse = 
        await authServer.tokenEndpoint({
            grantType: "password", 
            clientId: "ABC", 
            username: "mary",
            password: "maryPass123" ,
            clientSecret: "DEF"});

    fetchMocker.mockResponseOnce((_req) => {
         return JSON.stringify(firstTokenResponse)});
    const authenticatorsResponse = 
        await authServer.mfaAuthenticatorsEndpoint(firstTokenResponse.mfa_token??"");
    const challengeResponse = await authServer.mfaChallengeEndpoint(
        firstTokenResponse.mfa_token??"",
        "ABC",
        "DEF",
        "oob",
        "email",
    )
    fetchMocker.mockResponseOnce((_req) => {
        return JSON.stringify(authenticatorsResponse.authenticators)});
        fetchMocker.mockResponseOnce((_req) => {
            return JSON.stringify({
                challenge_type: "oob",
                oob_code: challengeResponse.oob_code,
                binding_method: "prompt"
            })});
    
    res = await server.app.inject({ method: "POST", url: "/passwordflow", cookies: {CSRFTOKEN: csrfCookie}, payload: {
        csrfToken: csrfToken,
        scope: "read write",
        username: "mary",
        password: "maryPass123",
     }});
    body = JSON.parse(res.body);
    expect(body.ok).toBe(true);
    expect(body.template).toBe("mfaoob.njk");
    expect(body.args.mfa_token).toBe(firstTokenResponse.mfa_token);
    const oobCode = body.args.oob_code;

    // Call passwordoob to completre MFA
    const maxTries = 2;
    for (let i=0; i<maxTries; ++i) {
        const otp = emailTokenData.otp;

        const {access_token, scope, error: error4, expires_in} =
        await authServer.tokenEndpoint({
            grantType: "http://auth0.com/oauth/grant-type/mfa-oob",
            clientId : "ABC",
            scope: "read write",
            clientSecret: "DEF",
            mfaToken: firstTokenResponse.mfa_token,
            oobCode: oobCode,
            bindingCode: otp,
        });
        if (error4 && i < maxTries-1) continue;

        if (error4) {
            expect(error4).toBeUndefined();
        }

        fetchMocker.mockResponseOnce((_req) => {
            return JSON.stringify({

            access_token: access_token,
            expires_in: expires_in,
            scope: scope,
            token_type: "Bearer",
            });});

        res = await server.app.inject({ method: "POST", url: "/passwordoob", payload: {
            scope: "read write",
            mfa_token: firstTokenResponse.mfa_token,
            otp: otp,
         }});
         body = JSON.parse(res.body)
         expect(access_token).toBeDefined();

         break;
    }


});

/////////////////////////

afterAll(async () => {
    fetchMocker.dontMock();
});
