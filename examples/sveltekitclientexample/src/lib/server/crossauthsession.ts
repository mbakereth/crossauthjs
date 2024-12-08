// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { SvelteKitSessionServer, SvelteKitServer } from '@crossauth/sveltekit';
import {
    PrismaKeyStorage,
    PrismaUserStorage,
    PrismaOAuthClientStorage,
    PrismaOAuthAuthorizationStorage,
    LocalPasswordAuthenticator,
} from '@crossauth/backend';
import { CrossauthError, OAuthFlows } from '@crossauth/common'
import { PrismaClient } from '@prisma/client'
import { redirect, error } from '@sveltejs/kit';

export const prisma = new PrismaClient();
const userStorage = new PrismaUserStorage({prismaClient : prisma, userEditableFields: ["email"]});
const keyStorage = new PrismaKeyStorage({prismaClient : prisma});
const clientStorage = new PrismaOAuthClientStorage({prismaClient : prisma});
const authStorage = new PrismaOAuthAuthorizationStorage({prismaClient : prisma});
const passwordAuthenticator = new LocalPasswordAuthenticator(userStorage);
export let crossauth : SvelteKitServer;
try {
    crossauth = new SvelteKitServer({
        session: {
            keyStorage: keyStorage,
            options: {
                allowedFactor2: ["none", "totp"],
                enableCsrfProtection: false,
            }
        },
        oAuthClient: {
            authServerBaseUrl: process.env["AUTH_SERVER_BASE_URL"] ?? "",
            options: {
                authorizedUrl: "/authorized",
                tokenResponseType: "saveInSessionAndRedirect",
                errorResponseType: "svelteKitError",
                bffEndpoints: [{url: "/resource", methods: ["GET"]}],
                tokenEndpoints: ["id_token", "access_token", "refresh_token", "have_access_token", "have_id_token", "have_refresh_token"],
                loginProtectedFlows: [OAuthFlows.AuthorizationCode, OAuthFlows.AuthorizationCodeWithPKCE],
            },
        }, 
        options: {
            userStorage,
            clientStorage,
            authenticators: {
                localpassword: passwordAuthenticator,
            },
            loginProtectedPageEndpoints: ["/account", "/flows/authzcodeflow"],
            factor2ProtectedPageEndpoints: ["/resetpassword/*"],
            adminPageEndpoints: ["/admin", "/admin/**"],
            loginUrl: "/login",
            loginRedirectUrl: "/",
            redirect,
            error
        }});
    
} catch (e) {
    const ce = CrossauthError.asCrossauthError(e);
    console.log(ce);
    throw error(500, ce?.message )
    crossauth = new SvelteKitServer({});
}
