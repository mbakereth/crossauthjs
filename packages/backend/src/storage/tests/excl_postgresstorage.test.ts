// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import pg from 'pg';
import { beforeEach } from 'vitest';
import { PostgresUserStorage, PostgresKeyStorage, PostgresOAuthClientStorage, PostgresOAuthAuthorizationStorage } from '../postgresstorage';
import { LocalPasswordAuthenticator } from '../../authenticators/passwordauth';
import { makeDBTests } from './dbtests';

var pool = new pg.Pool()
let userStorage = new PostgresUserStorage(pool);
let authenticator = new LocalPasswordAuthenticator(userStorage);
const keyStorage = new PostgresKeyStorage(pool);
const clientStorage = new PostgresOAuthClientStorage(pool);
const authStorage = new PostgresOAuthAuthorizationStorage(pool);

// for all these tests, the database will have two users: bob and alice
beforeEach(async () => {
    await deleteAll();

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

async function deleteAll() {
    const pgClient = await pool.connect();
    // delete users
    try {
        Promise.all([
            pgClient.query({text: `delete from oauthauthorization`,}),
            pgClient.query({text: `delete from oauthclientredirecturi`,}),
            pgClient.query({text: `delete from oauthclientvalidflow`,}),
            pgClient.query({text: `delete from oauthclient`,}),
            pgClient.query({text: `delete from keys`,}),
            pgClient.query({text: `delete from usersecrets`}),
            pgClient.query({text: `delete from users`})
        ]);
    } catch (e) {
        console.log(e)
        throw e
    } finally {
        pgClient.release();
    }
}

makeDBTests("PostgresStorage", userStorage, keyStorage, clientStorage, authStorage, authenticator);
