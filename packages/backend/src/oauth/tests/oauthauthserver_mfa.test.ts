import { test, expect } from 'vitest';
import { OAuthAuthorizationServer } from '../authserver';
import { createClient } from './common';
import { UserStorage } from '../../storage';
import { TotpAuthenticator } from '../../authenticators/totpauth';
import { EmailAuthenticator } from '../../authenticators/emailauth';
import { InMemoryKeyStorage, InMemoryUserStorage } from '../../storage/inmemorystorage';
import { LocalPasswordAuthenticator } from '../..';
import { authenticator as gAuthenticator } from 'otplib';
import { CrossauthError, ErrorCode, UserInputFields } from '@crossauth/common';

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

test('AuthorizationServer.Mfa.correctPasswordMfaOTPFlow', async () => {
    const {clientStorage, client} = await createClient();
    const keyStorage = new InMemoryKeyStorage();
    const userStorage = new InMemoryUserStorage();

    const lpAuthenticator = new LocalPasswordAuthenticator(userStorage);
    const totpAuth = new TotpAuthenticator("Unittest");
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
        userStorage: userStorage,
        authenticators: {
            "localpassword" : lpAuthenticator,
            "totp": totpAuth,
        },
    });

    const { totpSecret} = 
        await createTotpAccount("bob", "bobPass123", userStorage);
    const {access_token, error, mfa_token}
        = await authServer.tokenPostEndpoint({
            grantType: "password", 
            clientId: client.clientId, 
            username: "bob",
            password: "bobPass123" ,
            clientSecret: "DEF"});
    expect(error).toBe("mfa_required");
    expect(access_token).toBeUndefined();
    expect(mfa_token).toBeDefined();

    const {authenticators, error: error2} = 
        await authServer.mfaAuthenticatorsEndpoint(mfa_token??"");
    expect(error2).toBeUndefined();
    expect(authenticators).toBeDefined();
    expect(authenticators?.length).toBe(1);
    expect((authenticators??[])[0].id).toBe("totp");
    expect((authenticators??[])[0].authenticator_type).toBe("otp");
    expect((authenticators??[])[0].active).toBe(true);

    const { challenge_type, oob_code, binding_method, error: error3} =
        await authServer.mfaChallengeEndpoint(mfa_token ?? "",
            client.clientId,
            "DEF",
            "otp",
            "totp");
    expect(error3).toBeUndefined();
    expect(oob_code).toBeUndefined();
    expect(binding_method).toBeUndefined();
    expect(challenge_type).toBe("otp");

    const maxTries = 2;
    for (let i=0; i<maxTries; ++i) {
        const otp = gAuthenticator.generate(totpSecret);
        const {access_token, scope, error: error4} =
        await authServer.tokenPostEndpoint({
            grantType: "http://auth0.com/oauth/grant-type/mfa-otp",
            clientId : client.clientId,
            scope: "read write",
            clientSecret: "DEF",
            mfaToken: mfa_token,
            otp: otp
        });
        if (error4 && i < maxTries-1) continue;

        expect(error4).toBeUndefined();
        expect(access_token).toBeDefined();
        expect(scope).toBe("read write");
        break;

    }
});


test('AuthorizationServer.Mfa.invalidMfa1', async () => {
    const {clientStorage, client} = await createClient();
    const keyStorage = new InMemoryKeyStorage();
    const userStorage = new InMemoryUserStorage();

    const lpAuthenticator = new LocalPasswordAuthenticator(userStorage);
    const totpAuth = new TotpAuthenticator("Unittest");
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
        userStorage: userStorage,
        authenticators: {
            "localpassword" : lpAuthenticator,
            "totp": totpAuth,
        },
    });

    const { totpSecret} = 
        await createTotpAccount("bob", "bobPass123", userStorage);
    const {access_token, error, mfa_token}
        = await authServer.tokenPostEndpoint({
            grantType: "password", 
            clientId: client.clientId, 
            username: "bob",
            password: "bobPass123" ,
            clientSecret: "DEF"});
    expect(error).toBe("mfa_required");
    expect(access_token).toBeUndefined();
    expect(mfa_token).toBeDefined();

    const {authenticators, error: error2} = 
        await authServer.mfaAuthenticatorsEndpoint(mfa_token??"");
    expect(error2).toBeUndefined();
    expect(authenticators).toBeDefined();
    expect(authenticators?.length).toBe(1);
    expect((authenticators??[])[0].id).toBe("totp");
    expect((authenticators??[])[0].authenticator_type).toBe("otp");
    expect((authenticators??[])[0].active).toBe(true);

    const { challenge_type, oob_code, binding_method, error: error3} =
        await authServer.mfaChallengeEndpoint(mfa_token ?? "",
            client.clientId,
            "DEF",
            "otp",
            "totp");
    expect(error3).toBeUndefined();
    expect(oob_code).toBeUndefined();
    expect(binding_method).toBeUndefined();
    expect(challenge_type).toBe("otp");

    const maxTries = 2;
    for (let i=0; i<maxTries; ++i) {
        const otp = gAuthenticator.generate(totpSecret);
        const {access_token, error: error4} =
        await authServer.tokenPostEndpoint({
            grantType: "http://auth0.com/oauth/grant-type/mfa-otp",
            clientId : client.clientId,
            scope: "read write",
            clientSecret: "DEF",
            mfaToken: mfa_token+"x",
            otp: otp
        });
        if (error4 && i < maxTries-1) continue;

        expect(error4).toBe("access_denied");
        expect(access_token).toBeUndefined();
        break;

    }
});

test('AuthorizationServer.Mfa.invalidMfa2', async () => {
    const {clientStorage, client} = await createClient();
    const keyStorage = new InMemoryKeyStorage();
    const userStorage = new InMemoryUserStorage();

    const lpAuthenticator = new LocalPasswordAuthenticator(userStorage);
    const totpAuth = new TotpAuthenticator("Unittest");
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
        userStorage: userStorage,
        authenticators: {
            "localpassword" : lpAuthenticator,
            "totp": totpAuth,
        },
    });

    await createTotpAccount("bob", "bobPass123", userStorage);
    const {access_token, error, mfa_token}
        = await authServer.tokenPostEndpoint({
            grantType: "password", 
            clientId: client.clientId, 
            username: "bob",
            password: "bobPass123" ,
            clientSecret: "DEF"});
    expect(error).toBe("mfa_required");
    expect(access_token).toBeUndefined();
    expect(mfa_token).toBeDefined();

    const {authenticators, error: error2} = 
        await authServer.mfaAuthenticatorsEndpoint(mfa_token??"");
    expect(error2).toBeUndefined();
    expect(authenticators).toBeDefined();
    expect(authenticators?.length).toBe(1);
    expect((authenticators??[])[0].id).toBe("totp");
    expect((authenticators??[])[0].authenticator_type).toBe("otp");
    expect((authenticators??[])[0].active).toBe(true);

    const { challenge_type, error: error3} =
        await authServer.mfaChallengeEndpoint(mfa_token ?? "",
            client.clientId,
            "DEF"+"x",
            "otp",
            "totp");
    expect(error3).toBe("access_denied");
    expect(challenge_type).toBeUndefined();

});

test('AuthorizationServer.Mfa.invalidMfa3', async () => {
    const {clientStorage, client} = await createClient();
    const keyStorage = new InMemoryKeyStorage();
    const userStorage = new InMemoryUserStorage();

    const lpAuthenticator = new LocalPasswordAuthenticator(userStorage);
    const totpAuth = new TotpAuthenticator("Unittest");
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
        userStorage: userStorage,
        authenticators: {
            "localpassword" : lpAuthenticator,
            "totp": totpAuth,
        },
    });

    await createTotpAccount("bob", "bobPass123", userStorage);
    const {access_token, error, mfa_token}
        = await authServer.tokenPostEndpoint({
            grantType: "password", 
            clientId: client.clientId, 
            username: "bob",
            password: "bobPass123" ,
            clientSecret: "DEF"});
    expect(error).toBe("mfa_required");
    expect(access_token).toBeUndefined();
    expect(mfa_token).toBeDefined();

    const {authenticators, error: error2} = 
        await authServer.mfaAuthenticatorsEndpoint("XXX");
    expect(error2).toBe("access_denied");
    expect(authenticators).toBeUndefined();

});

test('AuthorizationServer.Mfa.correctPasswordMfaOOBFlow', async () => {
    const {clientStorage, client} = await createClient();
    const keyStorage = new InMemoryKeyStorage();
    const userStorage = new InMemoryUserStorage();

    const lpAuthenticator = new LocalPasswordAuthenticator(userStorage);
    const emailAuth = new EmailAuthenticator();
    emailAuth["sendToken"] = async function (to: string, otp : string) {
        emailTokenData = {otp, to}
        return "1";
    };
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
        userStorage: userStorage,
        authenticators: {
            "localpassword" : lpAuthenticator,
            "email": emailAuth,
        },
    });

    await createEmailAccount("bob", "bobPass123", userStorage);
    const {access_token, error, mfa_token}
        = await authServer.tokenPostEndpoint({
            grantType: "password", 
            clientId: client.clientId, 
            username: "bob",
            password: "bobPass123" ,
            clientSecret: "DEF"});
    expect(error).toBe("mfa_required");
    expect(access_token).toBeUndefined();
    expect(mfa_token).toBeDefined();

    const {authenticators, error: error2} = 
        await authServer.mfaAuthenticatorsEndpoint(mfa_token??"");
    expect(error2).toBeUndefined();
    expect(authenticators).toBeDefined();
    expect(authenticators?.length).toBe(1);
    expect((authenticators??[])[0].id).toBe("email");
    expect((authenticators??[])[0].authenticator_type).toBe("oob");
    expect((authenticators??[])[0].active).toBe(true);

   const { challenge_type, oob_code, binding_method, error: error3} =
        await authServer.mfaChallengeEndpoint(mfa_token ?? "",
            client.clientId,
            "DEF",
            "oob",
            "email");
    expect(error3).toBeUndefined();
    expect(oob_code).toBeDefined();
    expect(binding_method).toBe("prompt");
    expect(challenge_type).toBe("oob");
    const otp = emailTokenData.otp;
    
    const {access_token: access_token2, scope, error: error4} =
    await authServer.tokenPostEndpoint({
        grantType: "http://auth0.com/oauth/grant-type/mfa-oob",
        clientId : client.clientId,
        scope: "read write",
        clientSecret: "DEF",
        mfaToken: mfa_token,
        oobCode: oob_code,
        bindingCode: otp
    });

    expect(error4).toBeUndefined();
    expect(access_token2).toBeDefined();
    expect(scope).toBe("read write");
});

test('AuthorizationServer.Mfa.correctPasswordMfaOOBFlowInvalidMFAToken', async () => {
    const {clientStorage, client} = await createClient();
    const keyStorage = new InMemoryKeyStorage();
    const userStorage = new InMemoryUserStorage();

    const lpAuthenticator = new LocalPasswordAuthenticator(userStorage);
    const emailAuth = new EmailAuthenticator();
    emailAuth["sendToken"] = async function (to: string, otp : string) {
        emailTokenData = {otp, to}
        return "1";
    };
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
        userStorage: userStorage,
        authenticators: {
            "localpassword" : lpAuthenticator,
            "email": emailAuth,
        },
    });

    await createEmailAccount("bob", "bobPass123", userStorage);
    const {access_token, error, mfa_token}
        = await authServer.tokenPostEndpoint({
            grantType: "password", 
            clientId: client.clientId, 
            username: "bob",
            password: "bobPass123" ,
            clientSecret: "DEF"});
    expect(error).toBe("mfa_required");
    expect(access_token).toBeUndefined();
    expect(mfa_token).toBeDefined();

    const {authenticators, error: error2} = 
        await authServer.mfaAuthenticatorsEndpoint(mfa_token??"");
    expect(error2).toBeUndefined();
    expect(authenticators).toBeDefined();
    expect(authenticators?.length).toBe(1);
    expect((authenticators??[])[0].id).toBe("email");
    expect((authenticators??[])[0].authenticator_type).toBe("oob");
    expect((authenticators??[])[0].active).toBe(true);

   const { challenge_type, oob_code, binding_method, error: error3} =
        await authServer.mfaChallengeEndpoint(mfa_token ?? "",
            client.clientId,
            "DEF",
            "oob",
            "email");
    expect(error3).toBeUndefined();
    expect(oob_code).toBeDefined();
    expect(binding_method).toBe("prompt");
    expect(challenge_type).toBe("oob");
    const otp = emailTokenData.otp;
    
    const {access_token: access_token2, error: error4} =
    await authServer.tokenPostEndpoint({
        grantType: "http://auth0.com/oauth/grant-type/mfa-oob",
        clientId : client.clientId,
        scope: "read write",
        clientSecret: "DEF",
        mfaToken: "XXX",
        oobCode: oob_code,
        bindingCode: otp
    });

    expect(error4).toBe("access_denied");
    expect(access_token2).toBeUndefined();
});

test('AuthorizationServer.Mfa.correctPasswordMfaOOBFlowInvalidOTP', async () => {
    const {clientStorage, client} = await createClient();
    const keyStorage = new InMemoryKeyStorage();
    const userStorage = new InMemoryUserStorage();

    const lpAuthenticator = new LocalPasswordAuthenticator(userStorage);
    const emailAuth = new EmailAuthenticator();
    emailAuth["sendToken"] = async function (to: string, otp : string) {
        emailTokenData = {otp, to}
        return "1";
    };
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
        userStorage: userStorage,
        authenticators: {
            "localpassword" : lpAuthenticator,
            "email": emailAuth,
        },
    });

    await createEmailAccount("bob", "bobPass123", userStorage);
    const {access_token, error, mfa_token}
        = await authServer.tokenPostEndpoint({
            grantType: "password", 
            clientId: client.clientId, 
            username: "bob",
            password: "bobPass123" ,
            clientSecret: "DEF"});
    expect(error).toBe("mfa_required");
    expect(access_token).toBeUndefined();
    expect(mfa_token).toBeDefined();

    const {authenticators, error: error2} = 
        await authServer.mfaAuthenticatorsEndpoint(mfa_token??"");
    expect(error2).toBeUndefined();
    expect(authenticators).toBeDefined();
    expect(authenticators?.length).toBe(1);
    expect((authenticators??[])[0].id).toBe("email");
    expect((authenticators??[])[0].authenticator_type).toBe("oob");
    expect((authenticators??[])[0].active).toBe(true);

   const { challenge_type, oob_code, binding_method, error: error3} =
        await authServer.mfaChallengeEndpoint(mfa_token ?? "",
            client.clientId,
            "DEF",
            "oob",
            "email");
    expect(error3).toBeUndefined();
    expect(oob_code).toBeDefined();
    expect(binding_method).toBe("prompt");
    expect(challenge_type).toBe("oob");
    const otp = emailTokenData.otp;
    
    const {access_token: access_token2, error: error4} =
    await authServer.tokenPostEndpoint({
        grantType: "http://auth0.com/oauth/grant-type/mfa-oob",
        clientId : client.clientId,
        scope: "read write",
        clientSecret: "DEF",
        mfaToken: mfa_token,
        oobCode: oob_code,
        bindingCode: otp+"0"
    });

    expect(error4).toBe("access_denied");
    expect(access_token2).toBeUndefined();
});

test('AuthorizationServer.Mfa.correctPasswordMfaOOBFlowInvalidOOBCode', async () => {
    const {clientStorage, client} = await createClient();
    const keyStorage = new InMemoryKeyStorage();
    const userStorage = new InMemoryUserStorage();

    const lpAuthenticator = new LocalPasswordAuthenticator(userStorage);
    const emailAuth = new EmailAuthenticator();
    emailAuth["sendToken"] = async function (to: string, otp : string) {
        emailTokenData = {otp, to}
        return "1";
    };
    const authServer = new OAuthAuthorizationServer(clientStorage, keyStorage, {
        jwtPrivateKeyFile : "keys/rsa-private-key.pem",
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
        userStorage: userStorage,
        authenticators: {
            "localpassword" : lpAuthenticator,
            "email": emailAuth,
        },
    });

    await createEmailAccount("bob", "bobPass123", userStorage);
    const {access_token, error, mfa_token}
        = await authServer.tokenPostEndpoint({
            grantType: "password", 
            clientId: client.clientId, 
            username: "bob",
            password: "bobPass123" ,
            clientSecret: "DEF"});
    expect(error).toBe("mfa_required");
    expect(access_token).toBeUndefined();
    expect(mfa_token).toBeDefined();

    const {authenticators, error: error2} = 
        await authServer.mfaAuthenticatorsEndpoint(mfa_token??"");
    expect(error2).toBeUndefined();
    expect(authenticators).toBeDefined();
    expect(authenticators?.length).toBe(1);
    expect((authenticators??[])[0].id).toBe("email");
    expect((authenticators??[])[0].authenticator_type).toBe("oob");
    expect((authenticators??[])[0].active).toBe(true);

   const { challenge_type, oob_code, binding_method, error: error3} =
        await authServer.mfaChallengeEndpoint(mfa_token ?? "",
            client.clientId,
            "DEF",
            "oob",
            "email");
    expect(error3).toBeUndefined();
    expect(oob_code).toBeDefined();
    expect(binding_method).toBe("prompt");
    expect(challenge_type).toBe("oob");
    const otp = emailTokenData.otp;
    
    const {access_token: access_token2, error: error4} =
    await authServer.tokenPostEndpoint({
        grantType: "http://auth0.com/oauth/grant-type/mfa-oob",
        clientId : client.clientId,
        scope: "read write",
        clientSecret: "DEF",
        mfaToken: mfa_token,
        oobCode: oob_code+"0",
        bindingCode: otp
    });

    expect(error4).toBe("access_denied");
    expect(access_token2).toBeUndefined();
});
