import type { User, UserSecrets, UserSecretsInputFields, Key } from '../interfaces.ts';

/** Optional parameters to pass to {@link UsernamePasswordAuthenticator} constructor. */
export interface AuthenticationParameters {
    [key:string] : any,
}

/**
 * Base class for username/password authentication.
 * 
 * Subclass this if you want something other than PBKDF2 password hashing.
 */
export abstract class Authenticator {

    abstract skipEmailVerificationOnSignup() : boolean;
    abstract prepareAuthentication(username : string) : Promise<{userData: {[key:string]: any}, sessionData: {[key:string]: any} }|undefined>;
    abstract reprepareAuthentication(username : string, sessionKey : Key) : Promise<{userData: {[key:string]: any}, secrets: Partial<UserSecretsInputFields>}|undefined>;
        
    // throws Connection, UserNotExist, PasswordNotMatch
    /**
     * Should return the user if it exists in storage, otherwise throw {@link index!CrossauthError}:
     * with {@link index!ErrorCode} of `Connection`, `UserNotExist` or `PasswordNotMatch`
     * 
     * @param username the username to authenticate
     * @param password the password to authenticate
     */
    abstract authenticateUser(user : User|undefined, secrets : UserSecretsInputFields, params: AuthenticationParameters) : Promise<void>;

    abstract createSecrets(username : string, params: AuthenticationParameters, repeatParams?: AuthenticationParameters) : Promise<Partial<UserSecretsInputFields>>;

    abstract canCreateUser() : boolean;
    abstract canUpdateUser() : boolean;
    abstract secretNames() : string[];
    abstract validateSecrets(params : AuthenticationParameters) : string[];
}

