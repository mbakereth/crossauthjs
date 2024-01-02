import { pbkdf2Sync }  from 'node:crypto';
import { ErrorCode, CrossauthError } from '../error';

/**
 * Optional parameters for {@link HasherOptions}.
 * 
 * See {@link Hasher.constructor} for definitions.
 */
export interface HasherOptions {
    digest? : string,
    iterations? : number,
    keyLength? : number,
    saltLength? : number,
}

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

    /** The key length parameter passed to PBKDF2 - hash will be this number of characters long */
    keyLen : number,

    /** The digest algorithm to use, eg `sha512` */
    digest : string
}

/**
 * Option parameters for {@link Hasher.hash}
 */
export interface HashOptions {
    salt? : string,
    charset? : "base64"|"base64url";
    encode? : boolean,
}

export class Hasher {
    private digest : string = "sha512";
    private iterations : number = 100000
    private keyLength : number = 32;
    private saltLength : number = 32;

    constructor({digest,
        iterations, 
        keyLength,
        saltLength} : HasherOptions = {}) {
        
        if (digest) this.digest = digest;
        if (iterations) this.iterations = iterations;
        if (keyLength) this.keyLength = keyLength
        if (saltLength) this.saltLength = saltLength;

    }

    base64ToBase64Url(base64 : string) : string{
        return base64.replace(/=+/g,"").replace(/\//g,"_").replace(/\+/g,"-");
    }

    base64UrlToBase64(base64Url : string) : string {
        let s = base64Url.replace(/_/g,"/").replace(/-/g,"+");
        let mod = s.length % 4;
        if (mod == 0) {
            return s;
        } else if (mod == 1) {
            throw new CrossauthError(ErrorCode.InvalidHash);
        } else if (mod == 2) {
            return s + "==";
        } else {
            return s + "=";
        }
    }

    /**
     * Splits a hashed password into its component parts.  Return it as a {@link PasswordHash }.
     * 
     * The format of the hash should be
     * ```
     * digest:keyLen:iterations:salt:hashedPassword
     * ```
     * The hashed password part is the Base64 encoding of the PBKDF2 password.
     * @param hash the hassed password to decode.  See above for format
     * @returns 
     */
    static decodePasswordHash(hash : string) : PasswordHash {
        const parts = hash.split(':');
        let error : CrossauthError|undefined = undefined;
        if (parts.length != 6) {
            throw new CrossauthError(ErrorCode.InvalidHash);
            if (parts[0] != "pbkdf2") {
                throw new CrossauthError(ErrorCode.UnsupportedAlgorithm);
            }
        }
        try {
            return {
                hashedPassword : parts[5],
                salt : parts[4],
                iterations : Number(parts[3]),
                keyLen : Number(parts[2]),
                digest : parts[1]
            };
        } catch (e) {
            error = new CrossauthError(ErrorCode.InvalidHash);
        }
        if (error) throw error;
        return {
            hashedPassword : "",
            salt : ",",
            iterations : 0,
            keyLen : 0,
            digest : ""
        }; // never reached but needed to shut typescript up
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
     * @returns a string encode the above parameters.
     */
    encodePasswordHash(hashedPassword : string, 
                       salt : string, 
                       iterations : number, 
                       keyLen : number, 
                       digest : string) : string {
        return "pbkdf2" + ":" + digest + ":" + String(keyLen) + ":" + String(iterations) + ":" + salt + ":" + hashedPassword;
    }

    randomSalt() : string {
        const array = new Uint8Array(this.saltLength);
        crypto.getRandomValues(array);
        return Buffer.from(array).toString('base64');

    }
    hash(plaintext : string, {salt, charset, encode} : HashOptions = {}) {
        if (salt == undefined) salt = this.randomSalt();
        
        if (charset == undefined) charset = "base64";
        if (encode == undefined) encode = false;
        let passwordHash = pbkdf2Sync(
            plaintext, 
            salt, 
            this.iterations, 
            this.keyLength,
            this.digest 
        ).toString('base64');
        if (charset == "base64url") passwordHash = this.base64ToBase64Url(passwordHash);
        if (encode) passwordHash = this.encodePasswordHash(
            passwordHash, salt, this.iterations, this.keyLength, this.digest);
        return passwordHash;
    }
}