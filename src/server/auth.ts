import { CrossauthError, ErrorCode } from '../error.ts';
import type { User, UserInputFields, UserSecretsInputFields, Key } from '../interfaces.ts';

/** Parameters needed for this this class to authenticator a user (besides username)
 * An example is `password`
*/
export interface AuthenticationParameters {
    [key:string] : any,
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

    constructor(options? : AuthenticationOptions) {
        if (!options?.friendlyName) throw new CrossauthError(ErrorCode.Configuration, "Authenticator must have a friendly name");
         this.friendlyName = options?.friendlyName;

    }
    // throws Connection, UserNotExist, PasswordNotMatch
    /**
     * Should return the user if it exists in storage, otherwise throw {@link index!CrossauthError}:
     * with {@link index!ErrorCode} of `Connection`, `UserNotExist` or `PasswordNotMatch`
     * 
     * @param username the username to authenticate
     * @param password the password to authenticate
     */
    abstract authenticateUser(user : User|undefined, secrets : UserSecretsInputFields, params: AuthenticationParameters) : Promise<void>;

    abstract createPersistentSecrets(username : string, params: AuthenticationParameters, repeatParams?: AuthenticationParameters) : Promise<Partial<UserSecretsInputFields>>;
    abstract createOneTimeSecrets(user : User) : Promise<Partial<UserSecretsInputFields>>;

    abstract canCreateUser() : boolean;
    abstract canUpdateUser() : boolean;
    abstract secretNames() : string[];
    abstract validateSecrets(params : AuthenticationParameters) : string[];
}

