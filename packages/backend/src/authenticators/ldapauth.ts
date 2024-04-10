import type { User, UserSecretsInputFields, Key, UserInputFields } from '@crossauth/common';
import { ErrorCode, CrossauthError } from '@crossauth/common';
import { setParameter, ParamType } from '../utils.ts';
import { PasswordAuthenticator, type AuthenticationParameters , type AuthenticationOptions} from '../auth.ts';
import { LdapUserStorage } from '../storage/ldapstorage.ts';

/** Optional parameters to pass to {@link LdapAuthenticator} constructor. */
export interface LdapAuthenticatorOptions extends AuthenticationOptions {
    ldapAutoCreateAccount? : boolean,
}

/**
 * Authenticates a user against LDAP.
 * 
 * Users are expected to be in local storage as well, as defined by `ldapStorage`.
 * This class can optionally auto-create a user that is not already there.
 */
export class LdapAuthenticator extends PasswordAuthenticator {

    private ldapAutoCreateAccount : boolean = false;
    private ldapStorage : LdapUserStorage;

    /**
     * Create a new authenticator.
     * 
     * @param ldapStorage the storage that defines the LDAP server and databse for storing users locally
     * @param options see {@link LdapAuthenticatorOptions}
     */
    constructor(ldapStorage : LdapUserStorage,
                options : LdapAuthenticatorOptions = {}) {
        super({friendlyName: "LDAP", ...options});
        setParameter("ldapAutoCreateAccount", ParamType.Boolean, this, options, "LDAP_AUTO_CREATE_ACCOUNT");
        this.ldapStorage = ldapStorage;
    }

    /**
     * Authenticates the user, returning a the user as a {@link User} object.
     * 
     * @param user the `username` field is required and this is used for LDAP authentication.  
     *             If `ldapAutoCreateAccount` is true, these attributes as used for user creation (see {@link LdapUserStorage.createUser}).
     * @param _secrets Ignored as secrets are stored in LDAP
     * @param params the `password` field is expected to contain the LDAP password.
     * @throws {@link @crossauth/common!CrossauthError} with {@link @crossauth/common!ErrorCode} of `Connection`, `UsernameOrPasswordInvalid`.
     */
    async authenticateUser(user : UserInputFields, _secrets: UserSecretsInputFields, params: AuthenticationParameters) : Promise<void> {
        if (!params.password) throw new CrossauthError(ErrorCode.PasswordInvalid, "Password not provided");
        await this.ldapStorage.getLdapUser(user.username, params.password);
        let localUser : User;
        if (this.ldapAutoCreateAccount) {
            try {
                const resp = await this.ldapStorage.getUserByUsername(user.username);
                localUser = resp.user;
            } catch (e) {
                localUser = await this.ldapStorage.createUser(user, params);
            }
        } else {
            const resp = await this.ldapStorage.getUserByUsername(user.username);
            localUser = resp.user;
        }
        if (localUser.state == "awaitingtwofactorsetup") throw new CrossauthError(ErrorCode.TwoFactorIncomplete);
        if (localUser.state == "awaitingemailverification") throw new CrossauthError(ErrorCode.EmailNotVerified);
        if (localUser.state == "deactivated") throw new CrossauthError(ErrorCode.UserNotActive);
    }

    /**
     * Does nothing as LDAP is responsible for password format (this class doesn't create password entries)
     */
    validateSecrets(_params : AuthenticationParameters) : string[] {
        return [];
    }

    /**
     * Does nothing in this class.
     */
    async createPersistentSecrets(_username : string,_params: AuthenticationParameters, _repeatParams: AuthenticationParameters) : Promise<Partial<UserSecretsInputFields>> {
        return {};
    }

    /**
     * Does nothing in this class.
     */
    async createOneTimeSecrets(_user : User) : Promise<Partial<UserSecretsInputFields>> {
        return { }
    }

    /**
     * @returns true - we can create a user (but not secrets)
     */
    canCreateUser() : boolean { return true; }

    /**
     * 
     * @returns true - we can update user (but not secrets).
     */
    canUpdateUser() : boolean { return true; }

    /**
     * @returns false - users cannot update secrets
     */
    canUpdateSecrets() : boolean {
        return false;
    }

    /**
     * 
     * @returns false - if email verification is enabled, it should happen for this authenticator
     */
    skipEmailVerificationOnSignup() : boolean {
        return false;
    }

    /**
     * Does nothing in this class
     */
    async prepareConfiguration(_user : UserInputFields) : Promise<{userData: {[key:string]: any}, sessionData: {[key:string]: any}}|undefined> {
        return undefined;
    }

    /**
     * Does nothing in this class
     */
    async reprepareConfiguration(_username : string, _sessionKey : Key) : Promise<{userData: {[key:string]: any}, secrets: Partial<UserSecretsInputFields>, newSessionData: {[key:string]: any}|undefined}|undefined> {
        return undefined;
    }
}
