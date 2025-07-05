// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { SvelteKitSessionServer, SvelteKitServer } from '@crossauth/sveltekit';
import {
    PrismaKeyStorage,
    PrismaUserStorage,
    LdapUserStorage,
    LocalPasswordAuthenticator,
    LdapAuthenticator,
 } from '@crossauth/backend';
import { CrossauthError } from '@crossauth/common'
import { PrismaClient } from '@prisma/client'
import { redirect, error } from '@sveltejs/kit';

export const prisma = new PrismaClient({
//    log: ['query', 'info', 'warn', 'error'],
});
const userStorage = new PrismaUserStorage({
    prismaClient : prisma, 
    userEditableFields: ["email"],
    adminEditableFields: ["factor1", "admin"]});

const ldapStorage = new LdapUserStorage(userStorage)
const keyStorage = new PrismaKeyStorage({prismaClient : prisma});
const passwordAuthenticator = new LocalPasswordAuthenticator(userStorage);
const ldapAuthenticator = new LdapAuthenticator(ldapStorage);
export let crossauth : SvelteKitServer;
try {
    crossauth = new SvelteKitServer({
        session: {
            keyStorage: keyStorage,
            options: {
                allowedFactor2: ["none"],
            }
        },
        options: {
            userStorage,
            authenticators: {
                localpassword: passwordAuthenticator,
                ldap: ldapAuthenticator,
            },
            loginProtectedPageEndpoints: ["/**"],
            loginProtectedExceptionPageEndpoints: ["/login", "/login/**", "/logout", "/logout/**", "/__data.json"],
            adminPageEndpoints: ["/admin", "/admin/**"],
            loginUrl: "/login",
            logoutUrl: "/logout",
            loginRedirectUrl: "/",
            // these next two are due to a sveltekit limitation
            // always include them
            redirect,
            error
        }});
    
} catch (e) {
    const ce = CrossauthError.asCrossauthError(e);
    console.log(ce);
    throw error(500, ce?.message )
    crossauth = new SvelteKitServer({});
}
