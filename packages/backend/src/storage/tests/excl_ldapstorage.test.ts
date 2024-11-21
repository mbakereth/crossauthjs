// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { test, expect } from 'vitest';
import { InMemoryUserStorage } from '../inmemorystorage';
import { LdapUserStorage } from '../ldapstorage';

test('LdapStorage.createUser', async () => {
    if (!process.env["LDAPUSER"] || !process.env["LDAPPASSWORD"] || !process.env["LDAPEMAIL"] || !process.env["LDAPURLS"]) {
        console.log("Skipping external LDAP test")
        return;
    }

    const ldapUrls = process.env["LDAPURLS"] ? process.env["LDAPURLS"].split(",") : ["ldap://localhost:1389"]
    const ldapUserSearchBase = process.env["LDAPSEARCH"] ?? "ou=users,dc=example,dc=org";
    const ldapUsernameAttribute = process.env["LDAPUSERNAMEATTR"] ?? "cn";
    const username = process.env["LDAPUSER"] ?? "dave";
    const password = process.env["LDAPPASSWORD"] ?? "davePass123";
    const email = process.env["LDAPEMAIL"] ?? "dave@dave.com";
    try {
        const localStorage = new InMemoryUserStorage();
        const ldapStorage = new LdapUserStorage(localStorage, {
            ldapUrls,
            ldapUserSearchBase,
            ldapUsernameAttribute,
        });
        await ldapStorage.createUser(
            {username, state: "active", email}, 
            {password});
        const {user} = await localStorage.getUserByUsername(process.env["LDAPUSER"]);
        expect(user.email).toBe(process.env["LDAPEMAIL"]);    
    } catch (e) {
        console.log(e);
        expect(e).toBeUndefined();
    }

})