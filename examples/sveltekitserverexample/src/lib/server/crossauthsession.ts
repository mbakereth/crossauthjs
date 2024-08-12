import { SvelteKitSessionServer, SvelteKitServer } from '@crossauth/sveltekit';
import {
    PrismaKeyStorage,
    PrismaUserStorage,
    PrismaOAuthClientStorage,
    LocalPasswordAuthenticator,
    EmailAuthenticator,
    TotpAuthenticator } from '@crossauth/backend';
import { CrossauthError } from '@crossauth/common'
import { PrismaClient } from '@prisma/client'
import { redirect, error } from '@sveltejs/kit';

export const prisma = new PrismaClient();
const userStorage = new PrismaUserStorage({prismaClient : prisma, userEditableFields: ["email"]});
const keyStorage = new PrismaKeyStorage({prismaClient : prisma});
// @ts-ignore
const clientStorage = new PrismaOAuthClientStorage({prismaClient : prisma});
const passwordAuthenticator = new LocalPasswordAuthenticator(userStorage);
const totpAuthenticator = new TotpAuthenticator("Sveltekit Example")
const emailAuthenticator = new EmailAuthenticator();
export let crossauth : SvelteKitServer;
try {
    crossauth = new SvelteKitServer({
        session: {
            keyStorage: keyStorage,
            options: {
                allowedFactor2: ["none", "totp"],
            }
        },
        options: {
            userStorage,
            clientStorage,
            authenticators: {
                localpassword: passwordAuthenticator,
                totp: totpAuthenticator,
                email: emailAuthenticator,
            },
            loginProtectedPageEndpoints: ["/account"],
            factor2ProtectedPageEndpoints: ["/resetpassword/*"],
            adminPageEndpoints: ["/admin", "/admin/**"],
            unauthorizedUrl: "/401",
            redirect,
            error
        }});
    
} catch (e) {
    const ce = CrossauthError.asCrossauthError(e);
    console.log(ce);
    throw error(500, ce?.message )
    crossauth = new SvelteKitServer({});
}
