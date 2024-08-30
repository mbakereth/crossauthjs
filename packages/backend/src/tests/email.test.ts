import { test, expect, beforeAll } from 'vitest';
import { TokenEmailer } from '../emailtokens';
import { InMemoryUserStorage, InMemoryKeyStorage } from '../storage/inmemorystorage';
import { getTestUserStorage }  from '../storage/tests/inmemorytestdata';

export var userStorage : InMemoryUserStorage;

// for all these tests, the database will have two users: bob and alice
beforeAll(async () => {
    userStorage = await getTestUserStorage();
});


test('TokenEmailer.verifyEmailVerificationToken_activation', async () => {
    const sessionStorage = new InMemoryKeyStorage();
    const emailer = new TokenEmailer(userStorage, sessionStorage, {
        emailFrom: "crossauth@crossauth.com",
        smtpHost: "localhost",
        smtpPort: 1025,
        smtpUseTls: false,
        views: "test/views",
        siteUrl: "localhost",
    });
    let {user: bob} = await userStorage.getUserByUsername("bob");
    let token = await emailer["createAndSaveEmailVerificationToken"](bob.id);
    let {userid, newEmail} = await emailer["verifyEmailVerificationToken"](token);
    expect(userid).toBe(bob.id);
    expect(newEmail).toBe('');
});

test('TokenEmailer.verifyEmailVerificationToken_emailchange', async () => {
    const sessionStorage = new InMemoryKeyStorage();
    const emailer = new TokenEmailer(userStorage, sessionStorage, {
        emailFrom: "crossauth@crossauth.com",
        smtpHost: "localhost",
        smtpPort: 1025,
        smtpUseTls: false,
        views: "test/views",
        siteUrl: "localhost",
    });
    let {user: bob} = await userStorage.getUserByUsername("bob");
    let token = await emailer["createAndSaveEmailVerificationToken"](bob.id, "newbob@bob.com");
    let {userid, newEmail} = await emailer["verifyEmailVerificationToken"](token);
    expect(userid).toBe(bob.id);
    expect(newEmail).toBe("newbob@bob.com");
});

test('TokenEmailer.verifyPasswordResetToken', async () => {
    const sessionStorage = new InMemoryKeyStorage();
    const emailer = new TokenEmailer(userStorage, sessionStorage, {
        emailFrom: "crossauth@crossauth.com",
        smtpHost: "localhost",
        smtpPort: 1025,
        smtpUseTls: false,
        views: "test/views",
        siteUrl: "localhost",
    });
    let {user: bob} = await userStorage.getUserByUsername("bob");
    let token = await emailer["createAndSavePasswordResetToken"](bob.id);
    await emailer["verifyPasswordResetToken"](token);
});
