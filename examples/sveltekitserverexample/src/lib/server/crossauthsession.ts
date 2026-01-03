// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
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
import { PrismaClient } from '$lib/generated/prisma/client.js'
import { PrismaBetterSqlite3 } from '@prisma/adapter-better-sqlite3';
import { redirect, error } from '@sveltejs/kit';

const connectionString = `${process.env.DATABASE_URL}`;
const adapter = new PrismaBetterSqlite3({ url: connectionString });
const prisma = new PrismaClient({adapter});
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
