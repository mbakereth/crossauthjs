import type { User } from '../interfaces.ts';
import { ErrorCode, CrossauthError } from '../error';
import { UserStorage } from './storage'
import { Hasher } from './hasher';
import { CrossauthLogger } from '../logger.ts';

/** Optional parameters to pass to {@link UsernamePasswordAuthenticator} constructor. */
export interface UsernamePasswordAuthenticatorOptions {

    /** Number of PBKDF2 iterations to use when generating password hashes */
    iterations? : number,

    /** The key length parameter passed to PBKDF2 - hash will be this number of characters long */
    keyLen? : number,

    /** The digest algorithm to use, eg `sha512` */
    digest? : string,

    /** The number of random characters to generate for the password hash, using only Base64 characters */
    saltLength?: number;

    /** If defined, this will be used as an application password when hashing passwords (appended to salt) */
    pepper? : string
}

/**
 * Base class for username/password authentication.
 * 
 * Subclass this if you want something other than PBKDF2 password hashing.
 */
export abstract class UsernamePasswordAuthenticator {

    // throws Connection, UserNotExist, PasswordNotMatch
    /**
     * Should return the user if it exists in storage, otherwise throw {@link index!CrossauthError}:
     * with {@link index!ErrorCode} of `Connection`, `UserNotExist` or `PasswordNotMatch`
     * 
     * @param username the username to authenticate
     * @param password the password to authenticate
     */
    abstract authenticateUser(username : string, password : string) : Promise<User>;

    abstract createPasswordForStorage(password : string) : Promise<string>;
}

/**
 * Does username/password authentication using PBKDF2 hashed passwords.
 */
export class HashedPasswordAuthenticator extends UsernamePasswordAuthenticator {

    private userStorage : UserStorage;
    private iterations = 100000;
    private keyLength = 64;
    private digest = 'sha512';
    private saltLength = 16; 
    private pepper : string|undefined = undefined;

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
                saltLength,
                pepper
        } : UsernamePasswordAuthenticatorOptions = {}) {
        super();
        this.userStorage = userStorage;
        if (iterations) this.iterations = iterations;
        if (keyLen) this.keyLength = keyLen;
        if (digest) this.digest = digest;
        if (saltLength) this.saltLength = saltLength;
        if (pepper) this.pepper = pepper;
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
        let storedPasswordHash = Hasher.decodePasswordHash(await user.passwordHash);

        const hasher = new Hasher({
            digest: storedPasswordHash.digest,
            iterations: storedPasswordHash.iterations, 
            keyLength: storedPasswordHash.keyLen,
            saltLength: this.saltLength,
            pepper: this.pepper,
        });
        let inputPasswordHash = hasher.hash(password, {salt: storedPasswordHash.salt});
        if (storedPasswordHash.hashedPassword != inputPasswordHash) {
            CrossauthLogger.logger.debug("Invalid password " + password + " " + storedPasswordHash + " " + inputPasswordHash);
            throw new CrossauthError(ErrorCode.PasswordNotMatch);
        }
        if ("passwordHash" in user) {
            delete user.passwordHash;
        }
        return user;
    }

    /**
     * Creates and returns a hashed of the passed password
     * 
     * If the optional parameters `iterations`, `keyLen` or `digest` are passed, they override the class defaults,
     * 
     * @param password the password to hash
     * @param encode if true, encode this as a string including the salt, algorith, etc (see {@link decodePasswordHash}).  Otherwise just returns the Base64-encoded hash.
     * @param salt the salt to use.  If undefined, a random one will be generated.
     * @param iterations the number of PBKDF2 iterations to use 
     * @param keyLen the length of hash to generate, before Base64
     * @param digest the digest algorithm, eg `sha512`
     * @returns either a string of the Base64-encoded hash, or the fully qualified hash, depending on `encode`.  See above.
     */
    createPasswordHash(password : string, encode = false, 
                       {salt, iterations, keyLength: keyLen, digest} :
                       {salt? : string, 
                        iterations? : number, 
                        keyLength? : number, 
                        digest? : string} = {}) : string {
        
        const hasher = new Hasher({
            digest: digest||this.digest,
            iterations: iterations||this.iterations,
            keyLength: keyLen||this.keyLength,
            saltLength: this.saltLength||this.saltLength,
            pepper: this.pepper,
        });

        return hasher.hash(password, {salt: salt, encode: encode});
    }

    /**
     * Just calls createPasswordHash with encode set to true
     * @param password the password to hash
     */
    async createPasswordForStorage(password : string) : Promise<string> {
        return this.createPasswordHash(password, true);
    }

}
