// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { PrismaClient } from '@prisma/client'
import { LocalPasswordAuthenticator } from '@crossauth/backend';
import { PrismaUserStorage, PrismaOAuthClientStorage, Crypto } from '@crossauth/backend';
import { CrossauthLogger, OAuthFlows } from '@crossauth/common';

const prisma = new PrismaClient();

let userStorage = new PrismaUserStorage({prismaClient : prisma});
let clientStorage = new PrismaOAuthClientStorage({prismaClient : prisma});

async function main() {
    await prisma.user.deleteMany();
    await prisma.key.deleteMany();
    await prisma.oAuthClient.deleteMany();

    let authenticator = new LocalPasswordAuthenticator(userStorage);
    const user1 = await userStorage.createUser({
        username: "bob", 
        state: "active",
        factor1: "localpassword",
        email: "bob@bob.com",
    }, {
        password: await authenticator.createPasswordHash("bobPass123"), 
    });

    const user2 = await userStorage.createUser({
        username: "alice", 
        state: "active",
        factor1: "localpassword",
        factor2: "dummy",
        email: "alice@alice.com",
    }, {
        password: await authenticator.createPasswordHash("alicePass123"), 
    });

    const admin = await userStorage.createUser({
        username: "admin", 
        state: "active",
        factor1: "localpassword",
        email: "admin@admin.com",
        admin: true,
    }, {
        password: await authenticator.createPasswordHash("adminPass123"), 
    });

    console.log({ user1, user2, admin });

    const client_secret = await Crypto.passwordHash("DEF", {
        encode: true,
        iterations: 1000,
        keyLen: 32,
    });

    const nonUserClient = await clientStorage.createClient({
        client_id : "Client1",
        client_secret: client_secret,
        client_name: "Client1",
        confidential: true,
        redirect_uri: ["http://localhost:3001/authzcode"],
        valid_flow: OAuthFlows.allFlows(),
        userid: undefined,
    });

    const userClient = await clientStorage.createClient({
        client_id : "Client2",
        client_secret: client_secret,
        client_name: "Client2",
        confidential: true,
        redirect_uri: ["http://localhost:5174/authcode"],
        valid_flow: OAuthFlows.allFlows(),
        userid: user1.id,
    });

    console.log({ nonUserClient, userClient });

}
main()
    .then(async () => {
        await prisma.$disconnect()
    })
    .catch(async (e) => {
        console.error(e)
        await prisma.$disconnect()
        // @ts-ignore
        process.exit(1)
    })
