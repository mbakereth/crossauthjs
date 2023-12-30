import type { 
    User, 
} from '../interfaces.ts';
import { pbkdf2Sync }  from 'node:crypto';
import { ErrorCode, CrossauthError } from '../error';
import { UserStorage } from './storage'

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

/** Optional parameters to pass to {@link UsernamePasswordAuthenticator} constructor. */
export interface UsernamePasswordAuthenticatorOptions {

    /** Number of PBKDF2 iterations to use when generating password hashes */
    iterations? : number,

    /** The key length parameter passed to PBKDF2 - hash will be this number of characters long */
    keyLen? : number,

    /** The digest algorithm to use, eg `sha512` */
    digest? : string,

    /** The number of random characters to generate for the password hash */
    saltLength?: number;
}

/**
 * Base class for username/password authentication.
 * 
 * Subclass this if you want something other than PBKDF2 password hashing.
 */
export abstract class UsernamePasswordAuthenticator {

    // throws Connection, UserNotExist, PasswordNotMatch
    abstract authenticateUser(username : string, password : string) : Promise<User>;
}

/**
 * Does username/password authentication using PBKDF2 hashed passwords.
 */
export class HashedPasswordAuthenticator extends UsernamePasswordAuthenticator {

    private userStorage : UserStorage;
    private iterations = 100000;
    private keyLen = 64;
    private digest = 'sha512';
    private saltLength = 16;

    private saltChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" 
        + "abcdefghijklmnopqrstuvwxyz"
        + "0123456789"

    /**
     * Create a new authenticator.
     * 
     * See crypto.pbkdf2 for more information on the optional parameters.
     * 
     * @param userStorage an object that can getch usernames and hashed passwords from wherever they are stored, eg a database table
     * @param iterations number of PBKDF2 iterations.  Defaults to 10000.
     * @param keyLen length of generated hash.  Defaults to 64.
     * @param digest digest algorithm to use.  Defaults to `sha512`.
     * @param saltLength generate a salt with this number of characters.  Defaults to 16.
     */
    constructor(userStorage : UserStorage,
                {iterations,
                keyLen,
                digest,
                saltLength
        } : UsernamePasswordAuthenticatorOptions = {}) {
        super();
        this.userStorage = userStorage;
        if (iterations) {
            this.iterations = iterations;
        }
        if (keyLen) {
            this.keyLen = keyLen;
        }
        if (digest) {
            this.digest = digest;
        }
        if (saltLength) {
            this.saltLength = saltLength;
        }
    }

    /**
     * Authenticates the user, returning a the user as a {@link User} object.
     * 
     * If you set `extraFields` when constructing the {@link UserStorage} instance passed to the constructor,
     * these will be included in the returned User object.  `hashedPassword`, if present in the User object,
     * will be removed.
     * 
     * @param username the username to authenticate
     * @param password the password to hash and match against the hashed password on the user storage.
     * @returns A {@link User } object with the optional extra fields but without the hashed password.  See explaination above.
     * @throws {@link index!CrossauthError} with {@link ErrorCode} of `Connection`, `UserNotExist`or `PasswordNotMatch`.
     */
    async authenticateUser(username : string, password : string) : Promise<User> {
        let user = await this.userStorage.getUserByUsername(username);
        let storedPasswordHash = await this.decodePasswordHash(await user.passwordHash);

        let inputPasswordHash = pbkdf2Sync(
            password, 
            storedPasswordHash.salt, 
            storedPasswordHash.iterations, 
            storedPasswordHash.keyLen,
             storedPasswordHash.digest 
        ).toString('base64');
        if (storedPasswordHash.hashedPassword != inputPasswordHash)
            throw new CrossauthError(ErrorCode.PasswordNotMatch);
        if ("passwordHash" in user) {
            delete user.passwordHash;
        }
        return user;
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
    decodePasswordHash(hash : string) : PasswordHash {
        const parts = hash.split(':');
        if (parts.length != 5) {
            throw new CrossauthError(ErrorCode.InvalidHash);
        }
        try {
            return {
                hashedPassword : parts[4],
                salt : parts[3],
                iterations : Number(parts[2]),
                keyLen : Number(parts[1]),
                digest : parts[0]
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
     * @returns a string encode the above parameters.
     */
    private encodePasswordHash(hashedPassword : string, 
                       salt : string, 
                       iterations : number, 
                       keyLen : number, 
                       digest : string) : string {
        return digest + ":" + String(keyLen) + ":" + String(iterations) + ":" + salt + ":" + hashedPassword;
    }

    /**
     * Creates and returns a hashed of the passed password
     * 
     * If the optional parameters `iterations`, `keyLen` or `digest` are passed, they override the class defaults,
     * 
     * @param password the password to hash
     * @param encode if true, encode this as a string including the salt, algorith, etc (see {@link decodePasswordHash}).  Otherwise just returns the Base64-encoded hash.
     * @param salt the salt to use.  If undefined, a random one will be generated
     * @param iterations the number of PBKDF2 iterations to use 
     * @param keyLen the length of hash to generate, before Base64
     * @param digest the digest algorithm, eg `sha512`
     * @returns either a string of the Base64-encoded hash, or the fully qualified hash, depending on `encode`.  See above.
     */
    createPasswordHash(password : string, encode = false, 
                       {salt, iterations, keyLen, digest} :
                       {salt? : string, 
                        iterations? : number, 
                        keyLen? : number, 
                        digest? : string} = {}) : string {
        
        if (salt == undefined) {
            const len = this.saltChars.length;
            salt = Array.from({length: this.saltLength}, 
                () => this.saltChars.charAt(Math.floor(Math.random() * len))).join("");
    
        }
        if (iterations == undefined) {
            iterations = this.iterations;
        }
        if (keyLen == undefined) {
            keyLen = this.keyLen;
        }
        if (digest == undefined) {
            digest = this.digest;
        }
        let passwordHash = pbkdf2Sync(
            password, 
            salt, 
            iterations, 
            keyLen,
            digest 
        ).toString('base64');
        if (!encode) {
            return passwordHash;
        } else {
            return this.encodePasswordHash(passwordHash, salt, iterations, keyLen, digest);
        }
    }
}
