import { test, expect } from 'vitest';
import { Crypto } from '../crypto';


test('Crypto.signAndUnsign', async () => {
    const payload = {foo: "bar"};
    const secret = "SECRET";
    const sig = Crypto.sign(payload, secret);
    const decoded = Crypto.unsign(sig, secret);
    expect(decoded.foo).toBe(payload.foo);
});

test('Crypto.passwordHashAndCompare', async () => {
    const password = "PASSWORD"
    const hash = await Crypto.passwordHash(password, {encode: true});
    const equal = await Crypto.passwordsEqual(password, hash);
    expect(equal).toBe(true);
});

test('Crypto.hashAndCompare', async () => {
    const plaintext = "PLAINTEXT"
    const hash = Crypto.hash(plaintext);
    expect(hash).toBe('y0Dn2tyGFhuXmN5IUS8zLSHBQfzB4ooIb95KM3WqsbU');
});

test('Crypto.hashAndCompareWithSecret', async () => {
    const password = "PASSWORD"
    const secret = "SECRET";
    const hash = await Crypto.passwordHash(password, {encode: true, secret: secret});
    const equal = await Crypto.passwordsEqual(password, hash, secret);
    expect(equal).toBe(true);
});

test('Crypto.xor', async () => {
    const value = Buffer.from("ABCDEFG").toString("base64url");
    const mask  = Buffer.from("HIJKLMN").toString("base64url");
    const maskedValue = Crypto.xor(value, mask);
    const unmaskedValue = Crypto.xor(maskedValue, mask);
    expect(unmaskedValue).toBe(value);
});

test('Crypto.symmetricEncryption', async () => {
    const key = "xkDDElW4zZTLdIZ3AS0v0gJbh_SZZSAo6YuWDeEtBaU";
    const plaintext = "This is the plaintext";
    const ciphertext = Crypto.symmetricEncrypt(plaintext, key);
    const recoveredText = Crypto.symmetricDecrypt(ciphertext, key);
    expect(recoveredText).toBe(plaintext);
});