import { test, expect, beforeAll } from 'vitest';
import { TokenEmailer } from '../email';
import { InMemoryUserStorage, InMemoryKeyStorage } from '../storage/inmemorystorage';
import { getTestUserStorage }  from '../storage/tests/inmemorytestdata';
import { CrossauthError } from '../../error';

export var userStorage : InMemoryUserStorage;

// for all these tests, the database will have two users: bob and alice
beforeAll(async () => {
    userStorage = getTestUserStorage();
});


test('TokenEmailer.verifyEmailVerificationToken_activation', async () => {
    const sessionStorage = new InMemoryKeyStorage();
    const secret = "ABCDEFGHIJKLMNOPQRSTUV";
    const emailer = new TokenEmailer(userStorage, sessionStorage, {
        secret: secret,
        emailFrom: "crossauth@crossauth.com",
        smtpHost: "localhost",
        smtpPort: 1025,
        smtpUseTls: false,
        views: "test/views",
        siteUrl: "localhost",
    });
    let bob = await userStorage.getUserByUsername("bob");
    let token = await emailer["createAndSaveEmailVerificationToken"](bob.id, bob.email);
    let {userId, newEmail} = await emailer["verifyEmailVerificationToken"](token);
    expect(userId).toBe(bob.id);
    expect(newEmail).toBe('');
});

test('TokenEmailer.verifyEmailVerificationToken_emailchange', async () => {
    const sessionStorage = new InMemoryKeyStorage();
    const secret = "ABCDEFGHIJKLMNOPQRSTUV";
    const emailer = new TokenEmailer(userStorage, sessionStorage, {
        secret: secret,
        emailFrom: "crossauth@crossauth.com",
        smtpHost: "localhost",
        smtpPort: 1025,
        smtpUseTls: false,
        views: "test/views",
        siteUrl: "localhost",
    });
    let bob = await userStorage.getUserByUsername("bob");
    let token = await emailer["createAndSaveEmailVerificationToken"](bob.id, bob.email, "newbob@bob.com");
    let {userId, newEmail} = await emailer["verifyEmailVerificationToken"](token);
    expect(userId).toBe(bob.id);
    expect(newEmail).toBe("newbob@bob.com");
});

test('TokenEmailer.verifyPasswordResetToken', async () => {
    const sessionStorage = new InMemoryKeyStorage();
    const secret = "ABCDEFGHIJKLMNOPQRSTUV";
    const emailer = new TokenEmailer(userStorage, sessionStorage, {
        secret: secret,
        emailFrom: "crossauth@crossauth.com",
        smtpHost: "localhost",
        smtpPort: 1025,
        smtpUseTls: false,
        views: "test/views",
        siteUrl: "localhost",
    });
    let bob = await userStorage.getUserByUsername("bob");
    let token = await emailer["createAndSavePasswordResetToken"](bob.id, bob.email, bob.passwordHash);
    await emailer["verifyPasswordResetToken"](token);
});
