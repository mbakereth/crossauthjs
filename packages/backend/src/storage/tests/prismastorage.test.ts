// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { beforeEach, afterAll } from 'vitest';
import { PrismaUserStorage, PrismaKeyStorage, PrismaOAuthClientStorage, PrismaOAuthAuthorizationStorage } from '../prismastorage';
import { PrismaClient } from '@prisma/client';
import { LocalPasswordAuthenticator } from '../../authenticators/passwordauth';

//export var prismaClient : PrismaClient;
export var userStorage : PrismaUserStorage;
var prismaClient = new PrismaClient();

import { makeDBTests } from './dbtests';

userStorage = new PrismaUserStorage({prismaClient: prismaClient, userEditableFields: ["email", "dummyField"], useridForeignKeyColumn:"user_id"});
let authenticator = new LocalPasswordAuthenticator(userStorage);
const keyStorage = new PrismaKeyStorage({prismaClient: prismaClient, useridForeignKeyColumn:"user_id"});
const clientStorage = new PrismaOAuthClientStorage({prismaClient: prismaClient, useridForeignKeyColumn:"user_id"});
const authStorage = new PrismaOAuthAuthorizationStorage({prismaClient: prismaClient, useridForeignKeyColumn:"user_id"});

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
