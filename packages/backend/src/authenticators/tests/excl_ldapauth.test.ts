// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { test, expect } from 'vitest';
import { InMemoryUserStorage } from '../../storage/inmemorystorage';
import { LdapUserStorage } from '../../storage/ldapstorage';
import { LdapAuthenticator } from '../ldapauth';
import { UserInputFields } from '@crossauth/common';

function getAuth() {
    const ldapUrls = process.env["LDAPURLS"] ? process.env["LDAPURLS"].split(",") : ["ldap://localhost:1389"]
    const ldapUserSearchBase = process.env["LDAPSEARCH"] ?? "ou=users,dc=example,dc=org";
    const ldapUsernameAttribute = process.env["LDAPUSERNAMEATTR"] ?? "cn";
    const username = process.env["LDAPUSER"] ?? "dave";
    const password = process.env["LDAPPASSWORD"] ?? "davePass123";
    const email = process.env["LDAPEMAIL"] ?? "dave@dave.com";

    return {ldapUrls, ldapUserSearchBase, ldapUsernameAttribute, username, password, email};
}
test('Ldapauth.authenticateUserInLdapAndLocal', async () => {
    const {ldapUrls, ldapUserSearchBase, ldapUsernameAttribute, username, password, email} = getAuth();

    const localStorage = new InMemoryUserStorage();
    const ldapStorage = new LdapUserStorage(localStorage, {
        ldapUrls,
        ldapUserSearchBase,
        ldapUsernameAttribute,
    });
    const auth = new LdapAuthenticator(ldapStorage, {
        ldapAutoCreateAccount: false,
    })
    await ldapStorage.createUser(
        {username, state: "active", email}, 
        {password});
    const {user} = await ldapStorage.getUserByUsername(username);
    await auth.authenticateUser(user, {}, {password});
});

test('Ldapauth.authenticateUserInLdapNotInLocal', async () => {
    const {ldapUrls, ldapUserSearchBase, ldapUsernameAttribute, username} = getAuth();

    const localStorage = new InMemoryUserStorage();
    const ldapStorage = new LdapUserStorage(localStorage, {
        ldapUrls,
        ldapUserSearchBase,
        ldapUsernameAttribute,
    });
    await expect(async () => {await ldapStorage.getUserByUsername(username)}).rejects.toThrowError();
});

test('Ldapauth.authenticateUserAutoCreate', async () => {
    const {ldapUrls, ldapUserSearchBase, ldapUsernameAttribute, username, password, email} = getAuth();

    const localStorage = new InMemoryUserStorage();
    const ldapStorage = new LdapUserStorage(localStorage, {
        ldapUrls,
        ldapUserSearchBase,
        ldapUsernameAttribute,
    });
    const auth = new LdapAuthenticator(ldapStorage, {
        ldapAutoCreateAccount: true,
    })
    const user : UserInputFields = {
        username,
        state: "active",
        email,
    }
    await auth.authenticateUser(user, {}, {password});
    const {user: newUser} = await ldapStorage.getUserByUsername(username)
    expect(newUser.email).toBe(email);

});
