import type { User } from '../interfaces.ts';
import { ErrorCode, CrossauthError } from '../error';
import { UserStorage } from './storage'
import { Hasher } from './hasher';
import { CrossauthLogger, j } from '../logger.ts';
import { setParameter, ParamType } from './utils.ts';

/** Optional parameters to pass to {@link UsernamePasswordAuthenticator} constructor. */
export interface UsernamePasswordAuthenticatorOptions {
    secret? : string,
    enableSecretForPasswordHash? : boolean;
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
    private secret : string|undefined = undefined;
    enableSecretForPasswords : boolean = false;

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
                options : UsernamePasswordAuthenticatorOptions = {}) {
        super();
        this.userStorage = userStorage;
        setParameter("secret", ParamType.String, this, options, "HASHER_SECRET");
        setParameter("enableSecretForPasswordHash", ParamType.Boolean, this, options, "ENABLE_SECRET_FOR_PASSWORDS");

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

        if (!await Hasher.passwordsEqual(password, user.passwordHash, this.secret)) {
            CrossauthLogger.logger.debug(j({msg: "Invalid password hash", user: user.username}));
            throw new CrossauthError(ErrorCode.PasswordInvalid);
        }
        delete user.passwordHash;
        return user;
    }

    /**
     * Creates and returns a hashed of the passed password, with the hasing parameters encoded ready
     * for storage.
     * 
     * If salt is not provieed, a random one is greated.  If secret was passed to the constructor 
     * or in the .env, and enableSecretInPasswords was set to true, it is used as the pepper.
     * used as the pepper.
     * 
     * If the optional parameters `iterations`, `keyLen` or `digest` are passed, they override the class defaults,
     * 
     * @param password the password to hash
     * @param salt the salt to use.  If undefined, a random one will be generated.
     * @returns the encoded hash string.
     */
    async createPasswordHash(password : string, salt? : string) : Promise<string> {
        
        return await Hasher.passwordHash(password, {salt: salt, encode: true, 
            secret: this.enableSecretForPasswords ? this.secret : undefined});
    }

    /**
     * Just calls createPasswordHash with encode set to true
     * @param password the password to hash
     */
    async createPasswordForStorage(password : string) : Promise<string> {
        return this.createPasswordHash(password);
    }

}
