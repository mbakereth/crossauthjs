import {  pbkdf2, createHmac, createHash, timingSafeEqual, randomBytes }  from 'node:crypto';
import { ErrorCode, CrossauthError } from '../error';
import { promisify } from 'node:util';
import { CrossauthLogger, j } from '..';

// the following comply with NIST and OWASP recommendations
const PBKDF2_DIGEST = "sha256";
const PBKDF2_ITERATIONS = 600_000;
const PBKDF2_KEYLENGTH = 32; // in bytes, before base64
const PBKDF2_SALTLENGTH = 16; // in bytes, before base64 

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
 * Option parameters for {@link Hasher.passwordHash}
 */
export interface HashOptions {
    salt? : string;
    encode? : boolean;
    secret? : string;
    iterations? : number,
    keyLen? : number,
    digest? : string,
}

export class Hasher {

    /**
     * Returns true if the plaintext password, when hashed, equals the one in the hash, using
     * it's hasher settings
     * @param plaintext the plaintext password
     * @param encodedHash the previously-hashed version 
     * @param secret if `useHash`in `encodedHash` is true, uses as a pepper for the hasher
     * @returns true if they are equal, false otherwise
     */
    static async passwordsEqual(plaintext : string, encodedHash : string, secret? : string) : Promise<boolean> {
        let hash = Hasher.decodePasswordHash(encodedHash);
        let newHash = await Hasher.passwordHash(plaintext, {
            salt: hash.salt,
            encode: false,
            secret: hash.useSecret ? secret : undefined,
            iterations : hash.iterations,
            keyLen : hash.keyLen,
            digest : hash.digest
        });
        if (newHash.length != hash.hashedPassword.length) {
            CrossauthLogger.logger.debug(j({msg: "Passwords different length " + newHash + " " + hash.hashedPassword}));
            throw new CrossauthError(ErrorCode.PasswordInvalid);
        }
        return timingSafeEqual(Buffer.from(newHash), Buffer.from(hash.hashedPassword));
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
     * @returns 
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
     * @param iterations the number of PBKDF2 iterations
     * @param keyLen the key length PBKDF2 parameter - results in a hashed password this length, before Base64,
     * @param digest The digest algorithm, eg `pbkdf2`
     * @param secret If defined, this will be appended to the salt when creating the hash
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
        return Hasher.randomValue(PBKDF2_SALTLENGTH);
    }

    /**
     * Creates a random string encoded as in base64url
     * @param length length of the string to create
     * @returns the random value as a string.  Number of bytes will be greater as it is base64 encoded.
     */
    static randomValue(length : number) : string {
        return randomBytes(length).toString('base64url');
    }

    /**
     * Standard hash using SHA256 (not PBKDF2 or HMAC)
     * 
     * @param plaintext text to hash
     * @returns the string containing the hash 
     */
    static hash(plaintext : string) {
        return createHash('sha256').update(plaintext).digest('base64url')
    }

    /**
     * Hashes a password and returns it as a base64 or base64url encoded string
     * @param plaintext password to hash
     * @param options salt: salt to use.  Make a random one if not passed
     *               secret: optional application secret password to apply as a pepper
     *               encode: if true, returns the full string as it should be stored in the database.
     * @returns the string containing the hash and the values to decode it
     */
    static async passwordHash(plaintext : string, options : HashOptions = {}) {
        let { salt, secret, encode} = {...options};
        if (!salt) salt = Hasher.randomSalt();
        let useSecret = secret != undefined;
        let saltAndSecret = useSecret ? salt + "!" + secret : salt;
        
        if (encode == undefined) encode = false;
        const pbkdf2Async = promisify(pbkdf2);
        const hashBytes = await pbkdf2Async(
            plaintext, 
            saltAndSecret, 
            options.iterations||PBKDF2_ITERATIONS, 
            options.keyLen||PBKDF2_KEYLENGTH,
            options.digest||PBKDF2_DIGEST 
        );
        let passwordHash = hashBytes.toString('base64url');
        if (encode) passwordHash = this.encodePasswordHash(
            passwordHash, salt, useSecret, PBKDF2_ITERATIONS, PBKDF2_KEYLENGTH, PBKDF2_DIGEST);
        return passwordHash;
    }

    static signableToken(payload : {[key:string]: any}, salt? : string, timestamp? : number) : string {
        if (!salt) salt = Hasher.randomSalt();
        if (!timestamp) timestamp = (new Date()).getTime();
        return Buffer.from(JSON.stringify({...payload, t: timestamp, s: salt})).toString('base64url');
    }

    static sign(payload : {[key:string]: any}|string, secret: string, salt? : string, timestamp? : number) : string {
        if (typeof payload != "string") {
            payload = Hasher.signableToken(payload, salt, timestamp);
        }
        const hmac = createHmac(SIGN_DIGEST, secret);
        return payload + "." + hmac.update(payload).digest('base64url');

    }

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
            CrossauthLogger.logger.debug(j({msg: "Signature signature does not match payload"}));
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

}