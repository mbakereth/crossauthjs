import { test,  beforeAll, afterAll } from 'vitest';
import { PrismaUserStorage } from '../storage/prismastorage';
import { PrismaClient } from '@prisma/client';

export var prismaClient : PrismaClient;
export var userStorage : PrismaUserStorage;

// for all these tests, the database will have two users: bob and alice
beforeAll(async () => {
    prismaClient = new PrismaClient();
    await prismaClient.user.deleteMany({});
    await prismaClient.key.deleteMany({});
    userStorage = new PrismaUserStorage({extraFields: "dummyField"});
    });

// test getting a user by username and by id
test('PrismaUserStorage.getUser', async () => {
});

afterAll(async () => {
    //await prismaClient.user.deleteMany({});
});
