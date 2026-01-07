// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { beforeEach, afterAll } from 'vitest';
import { PrismaUserStorage, PrismaKeyStorage, PrismaOAuthClientStorage, PrismaOAuthAuthorizationStorage } from '../prismastorage';
import { PrismaClient } from '../../lib/generated/prisma/client';
import { LocalPasswordAuthenticator } from '../../authenticators/passwordauth';
import { PrismaBetterSqlite3 } from '@prisma/adapter-better-sqlite3';

//export var prismaClient : PrismaClient;
export var userStorage : PrismaUserStorage;
const connectionString = `${process.env.DATABASE_URL}`;
const adapter = new PrismaBetterSqlite3({ url: connectionString });
var prismaClient = new PrismaClient({adapter});

import { makeDBTests } from './dbtests';

userStorage = new PrismaUserStorage({prismaClient: prismaClient, userEditableFields: ["email", "dummyField"], useridForeignKeyColumn:"userid"});
let authenticator = new LocalPasswordAuthenticator(userStorage);
const keyStorage = new PrismaKeyStorage({prismaClient: prismaClient, useridForeignKeyColumn:"userid"});
const clientStorage = new PrismaOAuthClientStorage({prismaClient: prismaClient, useridForeignKeyColumn:"userid"});
const authStorage = new PrismaOAuthAuthorizationStorage({prismaClient: prismaClient, useridForeignKeyColumn:"userid"});

// for all these tests, the database will have two users: bob and alice
beforeEach(async () => {
    await prismaClient.user.deleteMany({});
    await prismaClient.key.deleteMany({});
    await prismaClient.oAuthClient.deleteMany({});
    await prismaClient.oAuthAuthorization.deleteMany({});

    // create users
    await userStorage.createUser({
        username: "bob", 
        state: "active",
        dummyfield: "abc", 
        email: "bob@bob.com",
    }, {
        password: await authenticator.createPasswordHash("bobPass123"), 
    });
    await userStorage.createUser({
        username: "alice", 
        state: "active",
        dummyfield: "abc", 
        email: "alice@alice.com",
    }, {
        password: await authenticator.createPasswordHash("alicePass123"), 
    });

});


makeDBTests("PrismaStorage", userStorage, keyStorage, clientStorage, authStorage, authenticator);

afterAll(async () => {
    //await prismaClient.user.deleteMany({});
});
