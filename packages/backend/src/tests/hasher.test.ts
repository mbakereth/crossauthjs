import { test, expect } from 'vitest';
import { Hasher } from '../hasher';


test('Hasher.signAndUnsign', async () => {
    const payload = {foo: "bar"};
    const secret = "SECRET";
    const sig = Hasher.sign(payload, secret);
    const decoded = Hasher.unsign(sig, secret);
    expect(decoded.foo).toBe(payload.foo);
});

test('Hasher.passwordHashAndCompare', async () => {
    const password = "PASSWORD"
    const hash = await Hasher.passwordHash(password, {encode: true});
    const equal = await Hasher.passwordsEqual(password, hash);
    expect(equal).toBe(true);
});

test('Hasher.hashAndCompare', async () => {
    const plaintext = "PLAINTEXT"
    const hash = Hasher.hash(plaintext);
    expect(hash).toBe('y0Dn2tyGFhuXmN5IUS8zLSHBQfzB4ooIb95KM3WqsbU');
});

test('Hasher.hashAndCompareWithSecret', async () => {
    const password = "PASSWORD"
    const secret = "SECRET";
    const hash = await Hasher.passwordHash(password, {encode: true, secret: secret});
    const equal = await Hasher.passwordsEqual(password, hash, secret);
    expect(equal).toBe(true);
});

test('Hasher.xor', async () => {
    const value = Buffer.from("ABCDEFG").toString("base64url");
    const mask  = Buffer.from("HIJKLMN").toString("base64url");
    const maskedValue = Hasher.xor(value, mask);
    const unmaskedValue = Hasher.xor(maskedValue, mask);
    expect(unmaskedValue).toBe(value);
});

test('Hasher.symmetricEncryption', async () => {
    const key = "xkDDElW4zZTLdIZ3AS0v0gJbh_SZZSAo6YuWDeEtBaU";
    const plaintext = "This is the plaintext";
    const ciphertext = Hasher.symmetricEncrypt(plaintext, key);
    const recoveredText = Hasher.symmetricDecrypt(ciphertext, key);
    expect(recoveredText).toBe(plaintext);
});