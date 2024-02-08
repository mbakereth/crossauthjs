import type { User, UserSecretsInputFields, Key, UserInputFields } from '../../interfaces.ts';
import { ErrorCode, CrossauthError } from '../../error.ts';
import { UserStorage } from '../storage.ts'
import { Hasher } from '../hasher.ts';
import { CrossauthLogger, j } from '../../logger.ts';
import { setParameter, ParamType } from '../utils.ts';
import { Authenticator, type AuthenticationParameters , type AuthenticationOptions} from '../auth.ts';

/**
 * Default password validator.
 * 
 * Passwords must be at leat 8 characters, contain at least one lowercase character, at least one uppercase
 * chracter and at least one digit.
 * @param password The password to validate
 * @returns an array of errors.  If there were no errors, returns an empty array
 */
function defaultPasswordValidator(params : AuthenticationParameters) : string[] {
    let errors : string[] = [];
    if (!params.password) errors.push("Password not provided");
    else {
        const password = params.password;
        if (password.length < 8) errors.push("Password must be at least 8 characters");
        if (password.match(/[a-z]/) == null) errors.push("Password must contain at least one lowercase character");
        if (password.match(/[A-Z]/) == null) errors.push("Password must contain at least one uppercase character");
        if (password.match(/[0-9]/) == null) errors.push("Password must contain at least one digit");
    }
    return errors;
}


/** Optional parameters to pass to {@link export class LocalPasswordAuthenticator extends Authenticator {
} constructor. */
export interface LocalPasswordAuthenticatorOptions extends AuthenticationOptions {
    secret? : string,
    enableSecretForPasswordHash? : boolean;

    /** Function that throws a {@link index!CrossauthError} with {@link index!ErrorCode} `PasswordFormat` if the password doesn't confirm to local rules (eg number of charafters)  */
    validatePasswordFn? : (params : AuthenticationParameters) => string[];
}

/**
 * Does username/password authentication using PBKDF2 hashed passwords.
 */
export class LocalPasswordAuthenticator extends Authenticator {

    private secret : string|undefined = undefined;
    enableSecretForPasswords : boolean = false;
    validatePasswordFn : (params : AuthenticationParameters) => string[] = defaultPasswordValidator;

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
    constructor(_userStorage : UserStorage,
                options : LocalPasswordAuthenticatorOptions = {}) {
        super({friendlyName: "Local password", ...options});
        setParameter("secret", ParamType.String, this, options, "HASHER_SECRET");
        setParameter("enableSecretForPasswordHash", ParamType.Boolean, this, options, "ENABLE_SECRET_FOR_PASSWORDS");
        if (options.validatePasswordFn) this.validatePasswordFn = options.validatePasswordFn;
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
    async authenticateUser(user : User, secrets: UserSecretsInputFields, params: AuthenticationParameters) : Promise<void> {
        if (!params.password) throw new CrossauthError(ErrorCode.PasswordInvalid, "Password not provided");
        if (!secrets.password) throw new CrossauthError(ErrorCode.PasswordInvalid);
        if (!await Hasher.passwordsEqual(params.password, secrets.password, this.secret)) {
            CrossauthLogger.logger.debug(j({msg: "Invalid password hash", user: user.username}));
            throw new CrossauthError(ErrorCode.PasswordInvalid);
        }
        if (user.state == "awaitingtwofactorsetup") throw new CrossauthError(ErrorCode.TwoFactorIncomplete);
        if (user.state == "awaitingemailverification") throw new CrossauthError(ErrorCode.EmailNotVerified);
        if (user.state == "deactivated") throw new CrossauthError(ErrorCode.UserNotActive);
    }

    secretNames() : string[] {
        return ["password"];
    }

    validateSecrets(params : AuthenticationParameters) : string[] {
        return this.validatePasswordFn(params);
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

    /**
     * A static version of the password hasher, provided for convenience
     * @param password : unhashed password
     * @param secret secret, if used when hashing passwords, or undefined if not
     * @returns hashed password in the format used for user storage
     */
    static async hashPassword(password : string, secret? : string) {
        return await Hasher.passwordHash(password, {encode: true, secret: secret});
    }

    /**
     * A static version of the password hasher, provided for convenience
     * @param password : unhashed password
     * @param password : hashed password
     * @param secret secret, if used when hashing passwords, or undefined if not
     * @returns true if match, false otherwise
     */
    async passwordMatchesHash(password : string, passwordHash : string, secret? : string) {
        return await Hasher.passwordsEqual(password, passwordHash, secret);
    }

    async createPersistentSecrets(_username : string, params: AuthenticationParameters, repeatParams: AuthenticationParameters) : Promise<Partial<UserSecretsInputFields>> {
        if (!params.password) throw new CrossauthError(ErrorCode.Unauthorized, "No password provided");
        if (repeatParams && repeatParams.password != params.password) {
            throw new CrossauthError(ErrorCode.PasswordMatch);
        }
        return {password: await LocalPasswordAuthenticator.hashPassword(params.password)};
    }

    async createOneTimeSecrets(_user : User) : Promise<Partial<UserSecretsInputFields>> {
        return { }
    }

    canCreateUser() : boolean { return true; }
    canUpdateUser() : boolean { return true; }

    skipEmailVerificationOnSignup() : boolean {
        return false;
    }
    async prepareConfiguration(_user : UserInputFields) : Promise<{userData: {[key:string]: any}, sessionData: {[key:string]: any}}|undefined> {
        return undefined;
    }

    async reprepareConfiguration(_username : string, _sessionKey : Key) : Promise<{userData: {[key:string]: any}, secrets: Partial<UserSecretsInputFields>, newSessionData: {[key:string]: any}|undefined}|undefined> {
        return undefined;
    }
}
