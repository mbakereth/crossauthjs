// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file

import { MockResolver, MockRequestEvent } from './sveltemocks';
import { SvelteKitServer } from '../sveltekitserver';
import { OAuthAuthorizationServer } from '@crossauth/backend';
import type { OAuthAuthorizationServerOptions } from '@crossauth/backend';
import { type OpenIdConfiguration, type OAuthClient } from '@crossauth/common';

import {
    InMemoryKeyStorage,
    InMemoryUserStorage,
    InMemoryOAuthClientStorage,
    InMemoryOAuthAuthorizationStorage,
    LocalPasswordAuthenticator,
    Crypto,
    DummyFactor2Authenticator,
    SessionCookie,
    EmailAuthenticator,
    ApiKeyManager } from '@crossauth/backend';
    import {
        OAuthFlows
} from '@crossauth/common';
import fs from 'node:fs';

import type { Handle } from '@sveltejs/kit';

export const oidcConfiguration : OpenIdConfiguration = {
    issuer: "http://server.com",
    authorization_endpoint: "http://server.com/authorize",
    token_endpoint: "http://server.com/token",
    token_endpoint_auth_methods_supported: ["client_secret_post"],
    jwks_uri: "http://server.com/jwks",
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "client_credentials", "password", "refresh_token", "http://auth0.com/oauth/grant-type/mfa-otp", "http://auth0.com/oauth/grant-type/mfa-oob", "urn:ietf:params:oauth:grant-type:device_code"],
    token_endpoint_auth_signing_alg_values_supported: ["RS256"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    claims_supported: ["iss", "sub", "aud", "jti", "iat", "type"],
    request_uri_parameter_supported: true,
    require_request_uri_registration: true,
}


export async function createUsers(userStorage: InMemoryUserStorage) {
    let authenticator = new LocalPasswordAuthenticator(userStorage, {pbkdf2Iterations: 1_000});
    await Promise.all([
        userStorage.createUser({
                username: "bob", 
                email: "bob@bob.com",
                state: "active",
                factor1: "localpassword"}, {
                password: await authenticator.createPasswordHash("bobPass123")
                } ),
        userStorage.createUser({
            username: "alice", 
            email: "alice@alice.com",
            state: "active",
            factor1: "localpassword",
            factor2: "dummyFactor2"}, {
            password: await authenticator.createPasswordHash("alicePass123")
            } ),
        userStorage.createUser({
            username: "admin", 
            email: "admin@admin.com",
            state: "active",
            factor1: "localpassword",
            admin: true}, {
            password: await authenticator.createPasswordHash("adminPass123")
            } ),
        ]);
}

export async function createSession(userid : string,
    userStorage: InMemoryUserStorage, 
    keyStorage: InMemoryKeyStorage,
    options = {}) {

    let sessionCookie = new SessionCookie(keyStorage, {userStorage, ...options});
    const key = await sessionCookie.createSessionKey(userid);
    const cookie = sessionCookie.makeCookie(key);
    return {key, cookie};
}

export async function createClients(clientStorage : InMemoryOAuthClientStorage, secretRequired = true) {
    const client_secret = await Crypto.passwordHash("DEF", {
        encode: true,
        iterations: 1000,
        keyLen: 32,
    });
    let client : OAuthClient = {
        client_id : "ABC",
        client_secret: secretRequired ? client_secret : undefined,
        client_name: "Test",
        confidential: secretRequired,
        redirect_uri: ["http://example.com/redirect"],
        valid_flow: OAuthFlows.allFlows(),
    };
    const retClient = client;
    await clientStorage.createClient(client);

    client = {
        client_id : "bob_ABC",
        client_secret: secretRequired ? client_secret : undefined,
        client_name: "Test",
        confidential: secretRequired,
        redirect_uri: ["http://example.com/redirect"],
        valid_flow: OAuthFlows.allFlows(),
        userid: "bob",
    };
    await clientStorage.createClient(client);

    return retClient;
}

function redirect(status : number, location : string) {
    throw {status, location}
};

function error(status : number, text : string) {
    throw {status, text, message: text};
};

export async function makeServer(makeSession=true, makeApiKey=false, makeOAuthServer=false, makeOAuthClient=false, options={}) {
    const keyStorage = new InMemoryKeyStorage();
    const userStorage = new InMemoryUserStorage();
    const clientStorage = new InMemoryOAuthClientStorage();
    const authStorage = new InMemoryOAuthAuthorizationStorage();
    if (makeOAuthServer) await createClients(clientStorage);

    const authenticator = new LocalPasswordAuthenticator(userStorage);
    let dummyFactor2Authenticator = new DummyFactor2Authenticator("0000");
    let emailAuthenticator = new EmailAuthenticator();

    await createUsers(userStorage);
    await createClients(clientStorage);
    let session = makeSession ? {
        keyStorage: keyStorage,
        options:  {
            allowedFactor2: ["none", "dummyFactor2"],
        }
        } : undefined;
    let apiKey = makeApiKey ? {
        keyStorage: keyStorage
    } : undefined;
    let oAuthAuthServer = makeOAuthServer ? {
            clientStorage,
            keyStorage,
            authenticators: {
                localpassword: authenticator,
                dummyFactor2: dummyFactor2Authenticator,
                email: emailAuthenticator,
            }, 
            options: {
                userStorage,
                authStorage,
                deviceCodeVerificationUri: "http://localhost:5174/device",
                userCodeThrottle: 0,
            }
               
    } : undefined;
    let oAuthClient = makeOAuthClient ? {
        authServerBaseUrl: "http://server.com",
    } : undefined;

    const server = new SvelteKitServer({
        session: session,
        apiKey : apiKey,
        oAuthAuthServer: oAuthAuthServer,
        oAuthClient : oAuthClient,
        options: {
            userStorage, 
            clientStorage,
            authenticators: {
                localpassword: authenticator,
                dummyFactor2: dummyFactor2Authenticator,
                email: emailAuthenticator,
            },
            secret: "ABCDEFG",
            loginProtectedPageEndpoints: ["/account"],
            factor2ProtectedPageEndpoints: ["/factor2protected"],
            validScopes: ["read", "write"],
            jwtKeyType: "RS256",
            jwtPublicKeyFile: "keys/rsa-public-key.pem",
            jwtPrivateKeyFile: "keys/rsa-private-key.pem",
            tokenResponseType: "sendJson",
            errorResponseType: "sendJson",
            client_id: "ABC",
            client_secret: "DEF",
            redirect_uri: "http://example.com/redirect",
            validFlows: ["all"], // activate all OAuth flows
            bffEndpointName: "/bff",
            bffBaseUrl: "http://server.com",
            bffEndpoints: [
                {url: "method1", methods: ["GET"], matchSubUrls: false},
                {url: "method2", methods: ["GET"], matchSubUrls: true},
            ],
            tokenEndpoints: [
                "access_token",
                "have_access_token",
                "id_token",
                "have_id_token",
            ],
            redirect,
            error,
            ...options,
        }});   
    const handle = server.hooks;
    const resolver = new MockResolver("Response");

    const apiKeyManager = makeApiKey ? new ApiKeyManager(keyStorage, {secret: "ABCDEFG",}) : undefined;


    return {server, resolver, handle, keyStorage, userStorage, authenticator, apiKeyManager, clientStorage};
}

export function getCookies(resp : Response) {
    let cookies : {[key:string]:string} = {};
    for (let pair of resp.headers) {
        if (pair[0] == "set-cookie") {
            const parts = pair[1].split("=", 2);
            const semiColon = parts[1].indexOf(";");
            if (semiColon > -1) {
                const value = parts[1].substring(0, semiColon).trim();
                if (value.length > 0) cookies[parts[0]] = value;
            } else {
                cookies[parts[0]] = parts[1];
            }
        }
    }
    /*
    const cookieHeaders = resp.headers.getSetCookie();
    let cookies : {[key:string]:string} = {};
    for (let cookie of cookieHeaders) {
        const parts = cookie.split("=", 2);
        const semiColon = parts[1].indexOf(";");
        if (semiColon > -1) {
            const value = parts[1].substring(0, semiColon).trim();
            if (value.length > 0) cookies[parts[0]] = value;
        } else {
            cookies[parts[0]] = parts[1];
        }
    }*/
    return cookies;
}

export async function getCsrfToken(server : SvelteKitServer, resolver : MockResolver, handle : Handle ) {
    const getRequest = new Request("http://ex.com/test", {method: "GET"});
    let event = new MockRequestEvent("1", getRequest, {"param1": "value1"});

    const resp = await handle({event: event, resolve: resolver.mockResolve});
    /*const cookieNames = resp.headers.getSetCookie().map((el) => el.split("=")[0]);
    expect(cookieNames.length).toBe(2);
    expect(["TESTCOOKIE", "CSRFTOKEN"]).toContain(cookieNames[0]);*/
    const cookies = getCookies(resp);
    expect(cookies["CSRFTOKEN"]).toBeDefined();
    let csrfValid = false;
    try {
        server.sessionServer?.sessionManager.validateCsrfCookie(cookies["CSRFTOKEN"]);
        csrfValid = true;
    } catch (e) {
        console.log(e);
    }
    expect(csrfValid).toBe(true);
    expect(event.locals.csrfToken).toBeDefined();
    return {
        csrfToken: event.locals.csrfToken,
        csrfCookieValue: cookies["CSRFTOKEN"]
    };
}

export async function login(server : SvelteKitServer, resolver : MockResolver, handle : Handle, user : string="bob", password : string="bobPass123") {
    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);
    const postRequest = new Request("http://ex.com/test", {
        method: "POST",
        body: "csrfToken="+csrfToken+"&username=" + user + "&password=" + password,
        headers: { 
            "cookie": "CSRFTOKEN="+csrfCookieValue,
            "content-type": "application/x-www-form-urlencoded",
        }});
    let event = new MockRequestEvent("1", postRequest, {"param1": "value1"});
    event.locals.csrfToken = csrfToken;

    const ret = await server.sessionServer?.userEndpoints.login(event);
    expect(ret?.user?.username).toBe(user);
    expect(event.cookies.get("SESSIONID")).toBeDefined();
    return {event, ret};
};

export async function loginFactor2(server : SvelteKitServer, resolver : MockResolver, handle : Handle, sessionCookieValue : string, sessionId : string) {
    const {csrfToken, csrfCookieValue} = await getCsrfToken(server, resolver, handle);

    const postRequest = new Request("http://ex.com/test", {
        method: "POST",
        body: "csrfToken="+csrfToken+"&otp=0000",
        headers: [
            ["set-cookie", "CSRFTOKEN="+csrfCookieValue],
            ["set-cookie", "SESSIONID="+sessionCookieValue],
            ["content-type", "application/x-www-form-urlencoded"],
        ]
        });
    let event = new MockRequestEvent("1", postRequest, {"param1": "value1"});
    event.locals.csrfToken = csrfToken;
    event.locals.sessionId = sessionId;

    const ret = await server.sessionServer?.userEndpoints.loginFactor2(event);
    return {event, ret};
};

export async function getAuthServer({
    aud, 
    persistAccessToken, 
    emptyScopeIsValid, 
    secretRequired,
    rollingRefreshToken,
    } : {
    challenge?: boolean, 
    aud?: string, 
    persistAccessToken? : boolean, 
    emptyScopeIsValid? : boolean, 
    secretRequired? : boolean,
    rollingRefreshToken? : boolean,
} = {}) {
    const clientStorage = new InMemoryOAuthClientStorage();
    const client = await createClients(clientStorage, secretRequired == undefined || secretRequired == true);
    const privateKey = fs.readFileSync("keys/rsa-private-key.pem", 'utf8');
    const userStorage = new InMemoryUserStorage();
    await createUsers(userStorage);
    const lpAuthenticator = new LocalPasswordAuthenticator(userStorage);
    const dummyFactor2 = new DummyFactor2Authenticator("0000");
    const authenticators = {
        "localpassword": lpAuthenticator,
        "dummyFactor2": dummyFactor2,
    };
    let options : OAuthAuthorizationServerOptions = {
        jwtKeyType: "RS256",
        jwtPrivateKey : privateKey,
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: ["read", "write"],
        issueRefreshToken: true,
        emptyScopeIsValid: emptyScopeIsValid,
        validFlows: ["all"],
        userStorage,
        authStorage: new InMemoryOAuthAuthorizationStorage(),
    };
    if (aud) options.audience = aud;
    if (persistAccessToken) {
        options.persistAccessToken = true;
    }
    if (rollingRefreshToken != undefined) options.rollingRefreshToken = rollingRefreshToken;
    const keyStorage = new InMemoryKeyStorage();
    const authServer = new OAuthAuthorizationServer(clientStorage, 
        keyStorage, 
        authenticators,
        options);
    return {client, clientStorage, authServer, keyStorage, userStorage};
}

export async function getAuthorizationCode({
    challenge, 
    aud, 
    persistAccessToken,
    rollingRefreshToken,
} : {challenge?: boolean,
     aud?: string, 
     persistAccessToken? : boolean,
     rollingRefreshToken? : boolean,
    } = {}) {
    const secretRequired = challenge == undefined;
    const {client, clientStorage, authServer, keyStorage, userStorage} = await getAuthServer({challenge, aud, persistAccessToken, secretRequired, rollingRefreshToken});
    const {user} = await userStorage.getUserByUsername("bob");
    const inputState = "ABCXYZ";
    let codeChallenge : string|undefined;
    const codeVerifier = "ABC123";
    if (challenge) codeChallenge = Crypto.hash(codeVerifier);
    const {code, error, error_description} 
        = await authServer.authorizeGetEndpoint({
            responseType: "code", 
            client_id: client.client_id, 
            redirect_uri: client.redirect_uri[0], 
            scope: "read write", 
            state: inputState,
            codeChallenge: codeChallenge,
            user});
    expect(error).toBeUndefined();
    expect(error_description).toBeUndefined();
    return {code, client, clientStorage, authServer, keyStorage};
}


export async function getAccessToken() {

    const {authServer, client, code, clientStorage} = await getAuthorizationCode();
    const {access_token, error, error_description, refresh_token, expires_in}
        = await authServer.tokenEndpoint({
            grantType: "authorization_code", 
            client_id: client.client_id, 
            code: code, 
            client_secret: "DEF"});
    return {authServer, client, code, clientStorage, access_token, error, error_description, refresh_token, expires_in};
};
