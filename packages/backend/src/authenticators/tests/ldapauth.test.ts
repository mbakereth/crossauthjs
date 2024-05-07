import { test, expect } from 'vitest';
import { InMemoryUserStorage } from '../../storage/inmemorystorage';
import { LdapUserStorage } from '../../storage/ldapstorage';
import { LdapAuthenticator } from '../ldapauth';
import { UserInputFields } from '@crossauth/common';

test('Ldapauth.authenticateUserInLdapAndLocal', async () => {
    const localStorage = new InMemoryUserStorage();
    const ldapStorage = new LdapUserStorage(localStorage, {
        ldapUrls: ["ldap://localhost:1389"],
        ldapUserSearchBase: "ou=users,dc=example,dc=org",
        ldapUsernameAttribute: "cn",
    });
    const auth = new LdapAuthenticator(ldapStorage, {
        ldapAutoCreateAccount: false,
    })
    await ldapStorage.createUser(
        {username: "dave", state: "active", email: "dave@dave.com"}, 
        {password: "davePass123"});
    const {user} = await ldapStorage.getUserByUsername("dave");
    await auth.authenticateUser(user, {}, {password: "davePass123"});
});

test('Ldapauth.authenticateUserInLdapNotInLocal', async () => {
    const localStorage = new InMemoryUserStorage();
    const ldapStorage = new LdapUserStorage(localStorage, {
        ldapUrls: ["ldap://localhost:1389"],
        ldapUserSearchBase: "ou=users,dc=example,dc=org",
        ldapUsernameAttribute: "cn",
    });
    await expect(async () => {await ldapStorage.getUserByUsername("dave")}).rejects.toThrowError();
});

test('Ldapauth.authenticateUserAutoCreate', async () => {
    const localStorage = new InMemoryUserStorage();
    const ldapStorage = new LdapUserStorage(localStorage, {
        ldapUrls: ["ldap://localhost:1389"],
        ldapUserSearchBase: "ou=users,dc=example,dc=org",
        ldapUsernameAttribute: "cn",
    });
    const auth = new LdapAuthenticator(ldapStorage, {
        ldapAutoCreateAccount: true,
    })
    const user : UserInputFields = {
        username: "dave",
        state: "active",
        email: "dave@dave.com",
    }
    await auth.authenticateUser(user, {}, {password: "davePass123"});
    const {user: newUser} = await ldapStorage.getUserByUsername("dave")
    expect(newUser.email).toBe("dave@dave.com");

});
