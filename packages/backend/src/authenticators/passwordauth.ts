import type { User, UserSecretsInputFields, Key, UserInputFields } from '@crossauth/common';
import { ErrorCode, CrossauthError } from '@crossauth/common';
import { UserStorage } from '../storage.ts'
import { Crypto } from '../crypto.ts';
import { CrossauthLogger, j } from '@crossauth/common';
import { setParameter, ParamType } from '../utils.ts';
import { PasswordAuthenticator, type AuthenticationParameters , type AuthenticationOptions} from '../auth.ts';

/**
 * Default password validator.
 * 
 * Passwords must be at leat 8 characters, contain at least one lowercase
 * character, at least one uppercase chracter and at least one digit.
 * @param params contains the password to validate in `password`
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


/** 
 * Optional parameters to pass to {@link LocalPasswordAuthenticator} 
 * constructor. 
 */
export interface LocalPasswordAuthenticatorOptions extends AuthenticationOptions {

    /** Application secret.  If defined, it is used as the secret in PBKDF2 to hash passwords */
    secret? : string,

    /** If true, the `secret` will be concatenated to the salt when generating a hash for storing the password */
    enableSecretForPasswordHash? : boolean;

    /** Digest method for PBKDF2 hasher.. Default `sha256` */
    pbkdf2Digest? : string,

    /** Number of PBKDF2 iterations.  Default 600_000 */
    pbkdf2Iterations? : number,

    /** Number of characters for salt, before base64-enoding.  Default 16 */
    pbkdf2SaltLength? : number,

    /** Length the PBKDF2 key to generate, before bsae64-url encoding.  Default 32 */
    pbkdf2KeyLength? : number,

    /** Function that throws a {@link @crossauth/common!CrossauthError} with 
     *  {@link @crossauth/common!ErrorCode} `PasswordFormat` if the password 
     *  doesn't confirm to local rules (eg number of charafters)  */
    validatePasswordFn? : (params : AuthenticationParameters) => string[];
}

/**
 * Does username/password authentication using PBKDF2 hashed passwords.
 */
export class LocalPasswordAuthenticator extends PasswordAuthenticator {

    static NoPassword = "********";
    private secret : string|undefined = undefined;

    /** If true, the secret key will be added to the salt when hashing.  Default false */
    enableSecretForPasswords : boolean = false;

    /** See {@link LocalPasswordAuthenticatorOptions.pbkdf2Digest}  */
    pbkdf2Digest? : string = "sha256";

    /** See {@link LocalPasswordAuthenticatorOptions.pbkdf2Iterations}  */
    pbkdf2Iterations? : number = 600_000;

    /** See {@link LocalPasswordAuthenticatorOptions.pbkdf2SaltLength}  */
    pbkdf2SaltLength? : number = 16;

    /** See {@link LocalPasswordAuthenticatorOptions.pbkdf2KeyLength}  */
    pbkdf2KeyLength? : number = 32;

    /** See {@link LocalPasswordAuthenticatorOptions.validatePasswordFn}  */
    validatePasswordFn : (params : AuthenticationParameters) => string[] = 
        defaultPasswordValidator;

    /**
     * Create a new authenticator.
     * 
     * See crypto.pbkdf2 for more information on the optional parameters.
     * 
     * @param _userStorage ignored
     * @param options see {@link LocalPasswordAuthenticatorOptions}
     */
    constructor(_userStorage : UserStorage,
                options : LocalPasswordAuthenticatorOptions = {}) {
        super({friendlyName: "Local password", ...options});
        setParameter("secret", ParamType.String, this, options, "HASHER_SECRET");
        setParameter("enableSecretForPasswordHash", ParamType.Boolean, this, options, "ENABLE_SECRET_FOR_PASSWORDS");
        setParameter("pbkdf2Digest", ParamType.String, this, options, "PASSWORD_PBKDF2_DIGEST");
        setParameter("pbkdf2Iterations", ParamType.String, this, options, "PASSWORD_PBKDF2_ITERATIONS");
        setParameter("pbkdf2SaltLength", ParamType.String, this, options, "PASSWORD_PBKDF2_SALTLENGTH");
        setParameter("pbkdf2KeyLength", ParamType.String, this, options, "PASSWORD_PBKDF2_KEYLENGTH");
        if (options.validatePasswordFn) this.validatePasswordFn = options.validatePasswordFn;
    }

    /**
     * Authenticates the user, returning a the user as a {@link User} object.
     * 
     * If you set `extraFields` when constructing the {@link UserStorage} instance passed to the constructor,
     * these will be included in the returned User object.  `hashedPassword`, if present in the User object,
     * will be removed.
     * 
     * @param user the `username` field should contain the username
     * @param secrets from the `UserSecrets` table.  `password` is expected to be present
     * @param params the user input.  `password` is expected to be present
     * @throws {@link @crossauth/common!CrossauthError} with
     *         {@link @crossauth/common!ErrorCode} of `Connection`, 
     *         `UserNotExist`or `PasswordInvalid`, `TwoFactorIncomplete`,
     *         `EmailNotVerified` or `UserNotActive`.
     */
    async authenticateUser(user : UserInputFields, secrets: UserSecretsInputFields, params: AuthenticationParameters) : Promise<void> {
        if (!params.password) throw new CrossauthError(ErrorCode.PasswordInvalid, "Password not provided");
        if (!secrets.password) throw new CrossauthError(ErrorCode.PasswordInvalid);
        if (!await Crypto.passwordsEqual(params.password, secrets.password, this.secret)) {
            CrossauthLogger.logger.debug(j({msg: "Invalid password hash", user: user.username}));
            throw new CrossauthError(ErrorCode.PasswordInvalid);
        }
        if (user.state == "awaitingtwofactorsetup") throw new CrossauthError(ErrorCode.TwoFactorIncomplete);
        if (user.state == "awaitingemailverification") throw new CrossauthError(ErrorCode.EmailNotVerified);
        if (user.state == "deactivated") throw new CrossauthError(ErrorCode.UserNotActive);
    }

    /**
     * Calls the implementor-provided `validatePasswordFn` 
     * 
     * This function is called to apply local password policy (password length,
     * uppercase/lowercase etc)
     * @param params the password should be in `password`
     * @returns an array of errors
     */
    validateSecrets(params : AuthenticationParameters) : string[] {
        return this.validatePasswordFn(params);
    }


    /**
     * Creates and returns a hash of the passed password, with the hashing parameters encoded ready
     * for storage.
     * 
     * If salt is not provieed, a random one is greated.  If secret was passed to the constructor 
     * or in the .env, and enableSecretInPasswords was set to true, it is used as the pepper.
     * used as the pepper.
     * 
     * @param password the password to hash
     * @param salt the salt to use.  If undefined, a random one will be generated.
     * @returns the encoded hash string.
     */
    async createPasswordHash(password : string, salt? : string) : Promise<string> {
        
        return await Crypto.passwordHash(password, {
            salt: salt, 
            encode: true, 
            secret: this.enableSecretForPasswords ? this.secret : undefined,
            iterations: this.pbkdf2Iterations,
            keyLen: this.pbkdf2KeyLength,
            digest: this.pbkdf2Digest,
        });
    }

    /**
     * Just calls createPasswordHash with encode set to true
     * @param password the password to hash
     * @returns a string for storing in storage
     */
    async createPasswordForStorage(password : string) : Promise<string> {
        return this.createPasswordHash(password);
    }

    /**
     * A static version of the password hasher, provided for convenience
     * @param password : unhashed password
     * @param passwordHash : hashed password
     * @param secret secret, if used when hashing passwords, or undefined if not
     * @returns true if match, false otherwise
     */
    async passwordMatchesHash(password : string, passwordHash : string, secret? : string) {
        if (passwordHash == LocalPasswordAuthenticator.NoPassword) return false;
        return await Crypto.passwordsEqual(password, passwordHash, secret);
    }

    /**
     * This will return p hash of the passed password.
     * @param _username ignored
     * @param params expected to contain `password`
     * @param repeatParams if defined, this is expected to also contain 
     *        `password` and is checked to match the one in `params`
     * @returns the newly created password in the `password` field.
     */
    async createPersistentSecrets(_username : string, 
        params: AuthenticationParameters, 
        repeatParams: AuthenticationParameters) : Promise<Partial<UserSecretsInputFields>> {
        if (!params.password) throw new CrossauthError(ErrorCode.Unauthorized, "No password provided");
        if (repeatParams && repeatParams.password != params.password) {
            throw new CrossauthError(ErrorCode.PasswordMatch);
        }
        return {password: await this.createPasswordHash(params.password)};
    }

    /**
     * Does nothing for this class.
     */
    async createOneTimeSecrets(_user : User) : Promise<Partial<UserSecretsInputFields>> {
        return { }
    }

    /**
     * @returns true - this class can create users
     */
    canCreateUser() : boolean { return true; }
    /**
     * @returns true - this class can update users
     */
    canUpdateUser() : boolean { return true; }

    /**
     * @returns true - users can update secrets
     */
    canUpdateSecrets() : boolean {
        return true;
    }

    /**
     * @returns false, if email verification is enabled, it should be for this authenticator too
     */
    skipEmailVerificationOnSignup() : boolean {
        return false;
    }

    /**
     * Does nothing for this class.
     */
    async prepareConfiguration(_user : UserInputFields) : Promise<{userData: {[key:string]: any}, sessionData: {[key:string]: any}}|undefined> {
        return undefined;
    }

    /**
     * Does nothing for this class.
     */
    async reprepareConfiguration(_username : string, _sessionKey : Key) : Promise<{userData: {[key:string]: any}, secrets: Partial<UserSecretsInputFields>, newSessionData: {[key:string]: any}|undefined}|undefined> {
        return undefined;
    }
}
