import { SvelteKitSessionServer, SvelteKitServer } from '@crossauth/sveltekit';
import { PrismaKeyStorage, PrismaUserStorage, LocalPasswordAuthenticator } from '@crossauth/backend';
import { PrismaClient } from '@prisma/client'

//export const crossauthSession = new SvelteKitSessionServer();
export const prisma = new PrismaClient();
const userStorage = new PrismaUserStorage({prismaClient : prisma, userEditableFields: ["email"]});
const keyStorage = new PrismaKeyStorage({prismaClient : prisma});
const passwordAuthenticator = new LocalPasswordAuthenticator(userStorage);
export const crossauth = new SvelteKitServer(userStorage, {
    authenticators: {
        localpassword: passwordAuthenticator
    },
    session: {
        keyStorage: keyStorage,
    }}, {});