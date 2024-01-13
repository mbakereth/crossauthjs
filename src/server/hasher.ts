import { pbkdf2Sync }  from 'node:crypto';
import { ErrorCode, CrossauthError } from '../error';
import { CrossauthLogger } from '..';
import { setParameter, ParamType } from './utils';

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
    secret? : string,
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

    /** If true, secret (application secret) is also used to hash the password*/
    usesecret: boolean,

    /** The key length parameter passed to PBKDF2 - hash will be this number of characters long */
    keyLen : number,

    /** The digest algorithm to use, eg `sha512` */
    digest : string
}

/**
 * Option parameters for {@link Hasher.hash}
 */
export interface HashOptions {
    salt? : string;
    charset? : "base64"|"base64url";
    encode? : boolean;
}

export class Hasher {
    private digest : string = "sha512";
    private iterations : number = 100000
    private keyLength : number = 32;
    private saltLength : number = 32;
    private secret : string|undefined= undefined;

    constructor(options : HasherOptions = {}) {
        
        setParameter("saltLength", ParamType.Number, this, options, "HASHER_SALT_LENGTH");
        setParameter("iterations", ParamType.Number, this, options, "HASHER_ITERATIONS");
        setParameter("keyLength", ParamType.Number, this, options, "HASHER_KEY_LENGTH");
        setParameter("digest", ParamType.Number, this, options, "HASHER_DIGEST");
        setParameter("secret", ParamType.String, this, options, "CROSSAUTH_SECRET");

    }

    static base64ToBase64Url(base64 : string) : string{
        return base64.replace(/=+/g,"").replace(/\//g,"_").replace(/\+/g,"-");
    }

    static base64UrlToBase64(base64Url : string) : string {
        let s = base64Url.replace(/_/g,"/").replace(/-/g,"+");
        let mod = s.length % 4;
        if (mod == 0) {
            return s;
        } else if (mod == 1) {
            CrossauthLogger.logger.error("Invalid hash length.  Stack trace follows");
            let err = new CrossauthError(ErrorCode.InvalidHash);
            CrossauthLogger.logger.error(err.stack);
            throw err;
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
                usesecret : parts[4] != "0",
                iterations : Number(parts[3]),
                keyLen : Number(parts[2]),
                digest : parts[1]
            };
        } catch (e) {
            error = new CrossauthError(ErrorCode.InvalidHash);
            CrossauthLogger.logger.error("Attempt to decode invalid hash.  Stack trace follows");
            CrossauthLogger.logger.error(error.stack);
        }
        if (error) throw error;
        return {
            hashedPassword : "",
            salt : ",",
            iterations : 0,
            usesecret: false,
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
     * @param secret If defined, this will be appended to the salt when creating the hash
     * @returns a string encode the above parameters.
     */
    encodePasswordHash(hashedPassword : string, 
                       salt : string, 
                       iterations : number, 
                       keyLen : number, 
                       digest : string) : string {
        let usesecret : number = this.secret != undefined ? 1 : 0;
        return "pbkdf2" + ":" + digest + ":" + String(keyLen) + ":" + String(iterations) + ":" + usesecret + ":" + salt + ":" + hashedPassword;
    }

    /**
     * Creates a random salt
     * @returns random salt as a base64 encoded string
     */
    randomSalt() : string {
        const array = new Uint8Array(this.saltLength);
        crypto.getRandomValues(array);
        return Hasher.base64ToBase64Url(Buffer.from(array).toString('base64'));

    }

    /**
     * Creates a random string
     * @param length length of the string to create
     * @param charset base64 or base64url
     * @returns the random value as a string.  Number of bytes will be greater as it is base64 encoded.
     */
    static randomValue(length : number, charset: string = "base64url") {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        const res = Buffer.from(array).toString('base64');
        if (charset == "base64") return res;
        else return Hasher.base64ToBase64Url(res);
    }

    /**
     * Hashes the password and returns it as a base64 or base64url encoded string
     * @param plaintext password to hash
     * @param param1 salt: salt to use.  Make a random one if not passed
     *               charset: "base64" or "base64url"
     *               encode: if true, returns the full string as it should be stored in the database.
     * @returns the string containing the hash and the values to decode it
     */
    hash(plaintext : string, {salt, charset, encode} : HashOptions = {}) {
        if (salt == undefined) salt = this.randomSalt();
        let usesecret = this.secret != undefined;
        let saltAndsecret = usesecret ? salt + "!" + this.secret : salt;
        
        if (charset == undefined) charset = "base64";
        if (encode == undefined) encode = false;
        let passwordHash = pbkdf2Sync(
            plaintext, 
            saltAndsecret, 
            this.iterations, 
            this.keyLength,
            this.digest 
        ).toString('base64');
        if (charset == "base64url") passwordHash = Hasher.base64ToBase64Url(passwordHash);
        if (encode) passwordHash = this.encodePasswordHash(
            passwordHash, salt, this.iterations, this.keyLength, this.digest);
        return passwordHash;
    }
}