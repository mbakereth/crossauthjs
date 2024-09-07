// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import sqlite3 from 'sqlite3';
import { beforeEach, afterEach } from 'vitest';
import { SqliteUserStorage, SqliteKeyStorage, SqliteOAuthClientStorage, SqliteOAuthAuthorizationStorage } from '../sqlitestorage';
import { LocalPasswordAuthenticator } from '../../authenticators/passwordauth';
import { makeDBTests } from './dbtests';

var filename = "sql/sqlite/test.sqlite3";
let userStorage = new SqliteUserStorage(filename);
let authenticator = new LocalPasswordAuthenticator(userStorage);
const keyStorage = new SqliteKeyStorage(filename, { dateFields: ["created", "expires", "lastactive"]});
const clientStorage = new SqliteOAuthClientStorage(filename);
const authStorage = new SqliteOAuthAuthorizationStorage(filename);

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

afterEach(async () => {
    //await deleteAll();
});

async function deleteAllFromTable(table : string, database : sqlite3.Database) {
    await new Promise((resolve,reject)=>{
        database.run("delete from " + table, [],
            (err:any, rows:{[key:string]: any}[]|undefined)=>{
                if(err) reject(err);
                resolve(rows);
        })
    });
    
}

async function deleteAll() {
    let database = new sqlite3.Database(filename);
    // delete users
    try {
        await deleteAllFromTable("oauthauthorization", database);
        await deleteAllFromTable("oauthclientredirecturi", database);
        await deleteAllFromTable("oauthclientvalidflow", database);
        await deleteAllFromTable("oauthclient", database);
        await deleteAllFromTable("keys", database);
        await deleteAllFromTable("usersecrets", database);
        await deleteAllFromTable("users", database);
    } catch (e) {
        throw e
    } finally {
        database.close();
    }
}

makeDBTests("SqliteStorage", userStorage, keyStorage, clientStorage, authStorage, authenticator);
