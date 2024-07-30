import { SvelteKitSessionServer, SvelteKitServer } from '@crossauth/sveltekit';
import {
    PrismaKeyStorage,
    PrismaUserStorage,
    LocalPasswordAuthenticator,
    EmailAuthenticator,
    TotpAuthenticator } from '@crossauth/backend';
import { PrismaClient } from '@prisma/client'
import { redirect, error } from '@sveltejs/kit';

//export const crossauthSession = new SvelteKitSessionServer();
export const prisma = new PrismaClient();
const userStorage = new PrismaUserStorage({prismaClient : prisma, userEditableFields: ["email"]});
const keyStorage = new PrismaKeyStorage({prismaClient : prisma});
const passwordAuthenticator = new LocalPasswordAuthenticator(userStorage);
const totpAuthenticator = new TotpAuthenticator("Sveltekit Example")
const emailAuthenticator = new EmailAuthenticator();
export const crossauth = new SvelteKitServer(userStorage, {
    authenticators: {
        localpassword: passwordAuthenticator,
        totp: totpAuthenticator,
        email: emailAuthenticator,
    },
    session: {
        keyStorage: keyStorage,
        options: {
            allowedFactor2: ["none", "totp"],
        }
    }}, {
        loginProtectedPageEndpoints: ["/account", "/changepassword"],
        factor2ProtectedPageEndpoints: ["/passwordreset/*"],
        adminPageEndpoints: ["/admin", "/admin/**"],
        unauthorizedPage: "/401",
        redirect,
        error
    });