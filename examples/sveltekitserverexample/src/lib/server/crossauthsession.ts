import { SvelteKitSessionServer, SvelteKitServer } from '@crossauth/sveltekit';
import {
    PrismaKeyStorage,
    PrismaUserStorage,
    PrismaOAuthClientStorage,
    PrismaOAuthAuthorizationStorage,
    LocalPasswordAuthenticator,
    EmailAuthenticator,
    TotpAuthenticator,
    DummyFactor2Authenticator } from '@crossauth/backend';
import { CrossauthError } from '@crossauth/common'
import { PrismaClient } from '@prisma/client'
import { redirect, error } from '@sveltejs/kit';

export const prisma = new PrismaClient();
const userStorage = new PrismaUserStorage({prismaClient : prisma, userEditableFields: ["email"]});
const keyStorage = new PrismaKeyStorage({prismaClient : prisma});
const clientStorage = new PrismaOAuthClientStorage({prismaClient : prisma});
const authStorage = new PrismaOAuthAuthorizationStorage({prismaClient : prisma});
const passwordAuthenticator = new LocalPasswordAuthenticator(userStorage);
const dummyAuthenticator = new DummyFactor2Authenticator("0000");
const totpAuthenticator = new TotpAuthenticator("Sveltekit Example")
const emailAuthenticator = new EmailAuthenticator();
export let crossauth : SvelteKitServer;
try {
    crossauth = new SvelteKitServer({
        session: {
            keyStorage: keyStorage,
            options: {
                allowedFactor2: ["none", "totp", "dummy"],
            }
        },
        oAuthAuthServer: {
            clientStorage,
            keyStorage,
            options: {
                authStorage,
                deviceCodeVerificationUri: "https://192.168.0.101:5173/oauth/device",
            }
        },
        oAuthResServer: {
            options: {
                protectedEndpoints: {"/resource": {scope: ["read", "write"]}},
                errorBody: {ok: false},
            },
        },
        options: {
            userStorage,
            clientStorage,
            authenticators: {
                localpassword: passwordAuthenticator,
                totp: totpAuthenticator,
                email: emailAuthenticator,
                dummy: dummyAuthenticator,
            },
            loginProtectedPageEndpoints: ["/account"],
            factor2ProtectedPageEndpoints: ["/resetpassword/*"],
            adminPageEndpoints: ["/admin", "/admin/**"],
            loginUrl: "/login",
            loginRedirectUrl: "/",
            validFlows: ['all'],
            redirect,
            error
        }});
    
} catch (e) {
    const ce = CrossauthError.asCrossauthError(e);
    console.log(ce);
    throw error(500, ce?.message )
    crossauth = new SvelteKitServer({});
}
