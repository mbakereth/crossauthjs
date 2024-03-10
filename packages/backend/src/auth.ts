import { CrossauthError, ErrorCode } from '@crossauth/common';
import type { User, UserInputFields, UserSecretsInputFields, Key } from '@crossauth/common';

/** Parameters needed for this this class to authenticator a user (besides username)
 * An example is `password`
*/
export interface AuthenticationParameters extends UserSecretsInputFields {
    otp? : string,
}

/**
 * Options to pass to the constructor.
 */
export interface AuthenticationOptions {
    /** If passed, this is what will be displayed to the user when selecting
     * an authentication method.
     */
    friendlyName? : string,

}

export interface AuthenticatorCapabilities {
    canCreateUser: boolean,
    canUpdateUser: boolean,
    canUpdateSecrets: boolean,
}

/**
 * Base class for username/password authentication.
 * 
 * Subclass this if you want something other than PBKDF2 password hashing.
 */
export abstract class Authenticator {

    abstract skipEmailVerificationOnSignup() : boolean;
    abstract prepareConfiguration(user : UserInputFields) : Promise<{userData: {[key:string]: any}, sessionData: {[key:string]: any} }|undefined>;
    abstract reprepareConfiguration(username : string, sessionKey : Key) : Promise<{userData: {[key:string]: any}, secrets: Partial<UserSecretsInputFields>, newSessionData: {[key:string]: any}|undefined}|undefined>;
    friendlyName : string;
    factorName : string = ""; // overridden when registered to backend

    /** 
     * Constructor.
     * @param options see {@link AuthenticationOptions}
     */
    constructor(options? : AuthenticationOptions) {
        if (!options?.friendlyName) throw new CrossauthError(ErrorCode.Configuration, "Authenticator must have a friendly name");
         this.friendlyName = options?.friendlyName;

    }

    /**
     * Should return the user if it exists in storage, otherwise throw {@link @crossauth/common!CrossauthError}:
     * with {@link @crossauth/common!ErrorCode} of `Connection`, `UserNotExist` or `PasswordNotMatch`
     * 
     * @param username the username to authenticate
     * @param password the password to authenticate
     */
    abstract authenticateUser(user : UserInputFields|undefined, secrets : UserSecretsInputFields, params: AuthenticationParameters) : Promise<void>;

    /**
     * This method should create and return any secrets that are persisted in storage, eg hashes of passwords.
     * 
     * Not all authenticators have persistent secrets.
     * @param username username to create secrets for
     * @param params user-provided secrets (ie unhashed)
     * @param repeatParams if present, secrets will be checked to be identical in this and `params`, throwing an exception if they are not
     */
    abstract createPersistentSecrets(username : string, params: AuthenticationParameters, repeatParams?: AuthenticationParameters) : Promise<Partial<UserSecretsInputFields>>;

    /**
     * Creates one-time secrets, eg one-time codes that are sent in email or SMS.
     * 
     * Not all authenticators create one time secrets
     * @param user user to create secrets for.
     */
    abstract createOneTimeSecrets(user : User) : Promise<Partial<UserSecretsInputFields>>;

    /**
     * If true, it is expected that this authenticator allows users to be created.
     */
    abstract canCreateUser() : boolean;

    /**
     * If true, it is expected that this authenticator allows users to be updated.
     */
    abstract canUpdateSecrets() : boolean;

    /**
     * If true, it is expected that this authenticator allows users to change their secrets.
     */
    abstract canUpdateUser() : boolean;

    /**
     * All peristent secrets created and managed by this authenticator, eg `password`
     * 
     * When user data is passed, it is filtered by this list.
     */
    abstract secretNames() : string[];

    /**
     * All transient secrets created and managed by this authenticator, eg `otp`
     * 
     * When user data is passed, it is filtered by this list.
     */
    abstract transientSecretNames() : string[];

    /**
     * Implementations should use this to validate secrets against local requirements,
     * eg minimum password length.
     * @param params user-provided secrets to validate
     */
    abstract validateSecrets(params : AuthenticationParameters) : string[];

    capabilities() : AuthenticatorCapabilities {
        return {
            canCreateUser: this.canCreateUser(),
            canUpdateUser: this.canUpdateUser(),
            canUpdateSecrets: this.canUpdateSecrets(),
        }
    }
}

export abstract class PasswordAuthenticator extends Authenticator {
    secretNames() {return ["password"];}
    transientSecretNames() {return [];}
}
