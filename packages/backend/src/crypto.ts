// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import {  pbkdf2, createHmac, createHash, timingSafeEqual, randomBytes, randomUUID, createCipheriv, createDecipheriv }  from 'node:crypto';
import { ErrorCode, CrossauthError } from '@crossauth/common';
import { promisify } from 'node:util';

// the following comply with NIST and OWASP recommendations
const PBKDF2_DIGEST = process.env["PBKDF2_DIGEST"] || "sha256";
const PBKDF2_ITERATIONS = Number(process.env["PBKDF2_ITERATIONS"] || 600_000);
const PBKDF2_KEYLENGTH = Number(process.env["PBKDF2_KEYLENGTH"] || 32); // in bytes, before base64
const PBKDF2_SALTLENGTH = Number(process.env["PBKDF2_KEYLENGTH"] || 16); // in bytes, before base64 

const SIGN_DIGEST = "sha256";

/**
 * An object that contains all components of a hashed password.  Hashing is done with PBKDF2
 */
export interface PasswordHash {
    /** The actual hashed password in Base64 format */
    hashedPassword : string,

    /** The random salt used to create the hashed password */
    salt : string,

    /** Number of iterations for PBKDF2*/
    iterations: number,

    /** If true, secret (application secret) is also used to hash the password*/
    useSecret: boolean,

    /** The key length parameter passed to PBKDF2 - hash will be this number of characters long */
    keyLen : number,

    /** The digest algorithm to use, eg `sha512` */
    digest : string
}

/**
 * Option parameters for {@link Crypto.passwordHash}
 */
export interface HashOptions {

    /** A salt to prepend to the message before hashing */
    salt? : string;

    /** Whether to Base64-URL-encode the result */
    encode? : boolean;

    /** A secret to append to the salt when hashing, or undefined for no secret */
    secret? : string;

    /** Number of PBKDF2 iterations */
    iterations? : number,

    /** Length (before Base64-encoding) of the PBKDF2 key being generated */
    keyLen? : number,

    /** PBKDF2 digest method */
    digest? : string,
}

/**
 * Provides cryptographic functions
 */
export class Crypto {

    /**
     * Returns true if the plaintext password, when hashed, equals the one in the hash, using
     * it's hasher settings
     * @param plaintext the plaintext password
     * @param encodedHash the previously-hashed version 
     * @param secret if `useHash`in `encodedHash` is true, uses as a pepper for the hasher
     * @returns true if they are equal, false otherwise
     */
    static async passwordsEqual(plaintext : string, encodedHash : string, secret? : string) : Promise<boolean> {
        let hash = Crypto.decodePasswordHash(encodedHash);
        let newHash = await Crypto.passwordHash(plaintext, {
            salt: hash.salt,
            encode: false,
            secret: hash.useSecret ? secret : undefined,
            iterations : hash.iterations,
            keyLen : hash.keyLen,
            digest : hash.digest
        });
        if (newHash.length != hash.hashedPassword.length) {
            throw new CrossauthError(ErrorCode.PasswordInvalid);
        }
        return timingSafeEqual(Buffer.from(newHash), Buffer.from(hash.hashedPassword));
    }

    /**
     * Decodes a string from base64 to UTF-89
     * @param encoded base64-encoded text
     * @returns URF-8 text
     */
    static base64Decode(encoded : string) : string {
        return Buffer.from(encoded, 'base64url').toString('utf-8');
    }

    /**
     * Base64-encodes UTF-8 text
     * @param text UTF-8 text
     * @returns Base64 text
     */
    static base64Encode(text : string) : string {
        return Buffer.from(text, 'utf-8').toString('base64url');
    }

    /**
     * Splits a hashed password into its component parts.  Return it as a {@link PasswordHash }.
     * 
     * The format of the hash should be
     * ```
     * digest:keyLen:iterations:useSecret:salt:hashedPassword
     * ```
     * The hashed password part is the Base64 encoding of the PBKDF2 password.
     * @param hash the hassed password to decode.  See above for format
     * @returns {@link PasswordHash} object containing the deecoded hash components
     */
    static decodePasswordHash(hash : string) : PasswordHash {
        const parts = hash.split(':');
        if (parts.length != 7) {
            throw new CrossauthError(ErrorCode.InvalidHash);
            if (parts[0] != "pbkdf2") {
                throw new CrossauthError(ErrorCode.UnsupportedAlgorithm);
            }
        }
        try {
            return {
                hashedPassword : parts[6],
                salt : parts[5],
                useSecret : parts[4] != "0",
                iterations : Number(parts[3]),
                keyLen : Number(parts[2]),
                digest : parts[1]
            };
        } catch (e) {
            throw new CrossauthError(ErrorCode.InvalidHash);
        }
    }

    /**
     * Encodes a hashed password into the string format it is stored as.  
     * 
     * See {@link decodePasswordHash } for the format it is stored in.
     * 
     * @param hashedPassword the Base64-encoded PBKDF2 hash of the password
     * @param salt the salt used for the password.
     * @param useSecret whether or not to use the application secret as part
     *        of the hash.
     * @param iterations the number of PBKDF2 iterations
     * @param keyLen the key length PBKDF2 parameter - results in a hashed password this length, before Base64,
     * @param digest The digest algorithm, eg `pbkdf2`
     * @returns a string encode the above parameters.
     */
    static encodePasswordHash(hashedPassword : string, 
                       salt : string, 
                       useSecret : boolean,
                       iterations : number, 
                       keyLen : number, 
                       digest : string) : string {
        return "pbkdf2" + ":" + digest + ":" + String(keyLen) + ":" + String(iterations) + ":" + (useSecret?1:0) + ":" + salt + ":" + hashedPassword;
    }

    /**
     * Creates a random salt
     * @returns random salt as a base64 encoded string
     */
    static randomSalt() : string {
        return Crypto.randomValue(PBKDF2_SALTLENGTH);
    }

    /**
     * Creates a random string encoded as in base64url
     * @param length length of the string to create
     * @returns the random value as a string.  Number of bytes will be greater as it is base64 encoded.
     */
    static randomValue(length : number) : string {
        return randomBytes(length).toString('base64url');
    }

    static Base32 = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".split(""); // not real base32 - omits 1,i,0,o

    /**
     * Creates a random base-23 string
     * @param length length of the string to create
     * @returns the random value as a string.  Number of bytes will be greater as it is base64 encoded.
     */
    static randomBase32(length : number, dashEvery? : number) : string {
        let bytes = [...randomBytes(length)];
        const str = (bytes.map((i) => Crypto.Base32[i%32])).join("");
        if (!dashEvery) return str;
        return str.match(/(.{1,4})/g)?.join("-") ?? str;
    }

    /**
     * Creates a UUID
     */
    static uuid() : string {
        return randomUUID();
    }

    /**
     * Standard hash using SHA256 (not PBKDF2 or HMAC)
     * 
     * @param plaintext text to hash
     * @returns the string containing the hash 
     */
    static hash(plaintext : string) {
        return this.sha256(plaintext);
    }

    /**
     * Standard hash using SHA256 (not PBKDF2 or HMAC)
     * 
     * @param plaintext text to hash
     * @returns the string containing the hash 
     */
    static sha256(plaintext : string) {
        return createHash('sha256').update(plaintext).digest('base64url')
    }

    /**
     * Hashes a password and returns it as a base64 or base64url encoded string
     * @param plaintext password to hash
     * @param options 
     *        - `salt`: salt to use.  Make a random one if not passed
     *        - `secret`: optional application secret password to apply as a pepper
     *        - `encode`: if true, returns the full string as it should be stored in the database.
     * @returns the string containing the hash and the values to decode it
     */
    static async passwordHash(plaintext : string, options : HashOptions = {}) 
        : Promise<string> {
        let { salt, secret, encode} = {...options};
        if (!salt) salt = Crypto.randomSalt();
        let useSecret = secret != undefined;
        let saltAndSecret = useSecret ? salt + "!" + secret : salt;
        
        if (encode == undefined) encode = false;
        const pbkdf2Async = promisify(pbkdf2);
        const hashBytes = await pbkdf2Async(
            plaintext, 
            saltAndSecret, 
            options.iterations??PBKDF2_ITERATIONS, 
            options.keyLen??PBKDF2_KEYLENGTH,
            options.digest??PBKDF2_DIGEST 
        );
        let passwordHash = hashBytes.toString('base64url');
        if (encode) passwordHash = this.encodePasswordHash(
            passwordHash, salt, useSecret, options.iterations??PBKDF2_ITERATIONS, options.keyLen??PBKDF2_KEYLENGTH, options.digest??PBKDF2_DIGEST);
        return passwordHash;
    }

    /**
     * For creating non-JWT tokens (eg password reset tokens.)  The
     * hash is of a JSON containing the payload, timestamp and optionally
     * a salt.
     * @param payload the payload to hash
     * @param salt optional salt (use if the payload is small)
     * @param timestamp time the token will expire
     * @returns a Base64-URL-encoded string that can be hashed.
     */
    static signableToken(payload : {[key:string]: any}, salt? : string, timestamp? : number) : string {
        if (salt == undefined) salt = Crypto.randomSalt();
        if (!timestamp) timestamp = (new Date()).getTime();
        return Buffer.from(JSON.stringify({...payload, t: timestamp, s: salt})).toString('base64url');
    }

    /**
     * Signs a JSON payload by creating a hash, using a secret and 
     * optionally also a salt and timestamp
     * 
     * @param payload object to sign (will be stringified as a JSON)
     * @param secret secret key, which must be a string
     * @param salt optionally, a salt to concatenate with the payload (must be a string)
     * @param timestamp optionally, a timestamp to include in the signed date as a Unix date
     * @returns Base64-url encoded hash
     */
    static sign(payload : {[key:string]: any}, secret: string, salt? : string, timestamp? : number) : string {
        const payloadStr = Crypto.signableToken(payload, salt, timestamp);
        const hmac = createHmac(SIGN_DIGEST, secret);
        return payloadStr + "." + hmac.update(payloadStr).digest('base64url');

    }

    /**
     * This can be called for a string payload that is a cryptographically
     * secure random string.  No salt is added and the token is assumed to
     * be Base64Url already
     * 
     * @param payload string to sign 
     * @param secret the secret to sign with
     * @returns Base64-url encoded hash
     */
    static signSecureToken(payload : string, secret: string) : string {
        const hmac = createHmac(SIGN_DIGEST, secret);
        return payload + "." + hmac.update(payload).digest('base64url');

    }

    /**
     * Validates a signature and, if valid, return the unstringified payload
     * @param signedMessage signed message (base64-url encoded)
     * @param secret secret key, which must be a string
     * @param expiry if set, validation will fail if the timestamp in the payload is after this date
     * @returns if signature is valid, the payload as an object
     * @throws {@link @crossauth/common!CrossauthError} with 
     *         {@link @crossauth/common!ErrorCode} of `InvalidKey` if signature
     *         is invalid or has expired.  
     */
    static unsign(signedMessage : string, secret : string, expiry?: number) : {[key:string] : any} {
        const parts = signedMessage.split(".");
        if (parts.length != 2) throw new CrossauthError(ErrorCode.InvalidKey);
        const msg = parts[0];
        const sig = parts[1];
        const payload = JSON.parse(Buffer.from(msg, "base64url").toString());
        if (expiry) {
            const expireTime = payload.t + expiry*1000;
            if (expireTime > (new Date().getTime())) throw new CrossauthError(ErrorCode.Expired);
        }
        const hmac = createHmac(SIGN_DIGEST, secret);
        const newSig = hmac.update(msg).digest('base64url');
        if (newSig.length != sig.length)
            throw new CrossauthError(ErrorCode.InvalidKey, "Signature does not match payload");
        if  (!timingSafeEqual(Buffer.from(newSig), Buffer.from(sig))) {
            throw new CrossauthError(ErrorCode.InvalidKey, "Signature does not match payload");
        }
        return payload;        
    }

    /**
     * Validates a signature signed with `signSecureToken` and, if valid, 
     * return the unstringified payload
     * @param signedMessage signed message (base64-url encoded)
     * @param secret secret key, which must be a string
     * @returns if signature is valid, the payload as a string
     * @throws {@link @crossauth/common!CrossauthError} with 
     *         {@link @crossauth/common!ErrorCode} of `InvalidKey` if signature
     *         is invalid or has expired.  
     */
    static unsignSecureToken(signedMessage : string, secret : string) : string {
        const parts = signedMessage.split(".");
        if (parts.length != 2) throw new CrossauthError(ErrorCode.InvalidKey);
        const msg = parts[0];
        const sig = parts[1];
        const payload = msg;
        const hmac = createHmac(SIGN_DIGEST, secret);
        const newSig = hmac.update(msg).digest('base64url');
        if (newSig.length != sig.length)
            throw new CrossauthError(ErrorCode.InvalidKey, "Signature does not match payload");
        if  (!timingSafeEqual(Buffer.from(newSig), Buffer.from(sig))) {
            throw new CrossauthError(ErrorCode.InvalidKey, "Signature does not match payload");
        }
        return payload;        
    }
    

    /**
     * XOR's two arrays of base64url-encoded strings
     * @param value to XOR
     * @param mask mask to XOR it with
     * @return an XOR'r string
     */
    static xor(value : string, mask : string) {
        const valueArray = Buffer.from(value, 'base64url');
        const maskArray = Buffer.from(mask, 'base64url');
        const resultArray = valueArray.map((b, i) => b ^ maskArray[i]);
        return Buffer.from(resultArray).toString('base64url');
      
    }

    /**
     * Symmetric encryption using a key that must be a string
     * 
     * @param plaintext Text to encrypt
     * @param keyString the symmetric key
     * @returns Encrypted text Base64-url encoded.
     */
    static symmetricEncrypt(plaintext : string, keyString : string, iv : Buffer|undefined = undefined) {
        if (!iv) iv = randomBytes(16);
        let key = Buffer.from(keyString, 'base64url');
        var encrypt = createCipheriv('aes-256-cbc', key, iv);
        let encrypted = encrypt.update(plaintext);
        encrypted = Buffer.concat([encrypted, encrypt.final()]);
        return iv.toString('base64url') + "." + encrypted.toString('base64url');
    }

    /**
     * Symmetric decryption using a key that must be a string
     * 
     * @param ciphertext Base64-url encoded ciphertext
     * @param keyString the symmetric key
     * @returns Decrypted text
     */
    static symmetricDecrypt(ciphertext : string, keyString : string) {
        let key = Buffer.from(keyString, 'base64url');
        const parts = ciphertext.split(".");
        if (parts.length != 2) throw new CrossauthError(ErrorCode.InvalidHash, "Not AES-256-CBC ciphertext");
        let iv = Buffer.from(parts[0], 'base64url');
        let encryptedText = Buffer.from(parts[1], 'base64url');
    
        var decrypt = createDecipheriv('aes-256-cbc', key, iv);
        let decrypted = decrypt.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decrypt.final()]);
        return decrypted.toString();
    }
}
