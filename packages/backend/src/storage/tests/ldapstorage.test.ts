import { test, expect } from 'vitest';
import { InMemoryUserStorage } from '../inmemorystorage';
import { LdapUserStorage } from '../ldapstorage';

test('LdapStorage.createUser', async () => {
    const localStorage = new InMemoryUserStorage();
    const ldapStorage = new LdapUserStorage(localStorage, {
        ldapUrls: ["ldap://localhost:1389"],
        ldapUserSearchBase: "ou=users,dc=example,dc=org",
        ldapUsernameAttribute: "cn",
    });
    await ldapStorage.createUser(
        {username: "dave", state: "active", email: "dave@dave.com"}, 
        {password: "davePass123"});
    const {user} = await localStorage.getUserByUsername("dave");
    expect(user.email).toBe("dave@dave.com");
});
