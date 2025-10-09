// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import type { User, UserSecretsInputFields, Key, UserInputFields } from '@crossauth/common';
import { ErrorCode, CrossauthError } from '@crossauth/common';
import { UserStorage } from '../storage.ts'
import { Authenticator, type AuthenticationParameters , type AuthenticationOptions} from '../auth.ts';

/** 
 * Optional parameters to pass to {@link OidcPasswordAuthenticator} 
 * constructor. 
 */
export interface OidcAuthenticatorOptions extends AuthenticationOptions {

}

/**
 * Does no password checking - used when a user table entry has to be created
 * but authentication is done with OIDC.
 */
export class OidcAuthenticator extends Authenticator {

    /** @returns empty array */
    secretNames() {return [];}

    /** @returns an empty array */
    transientSecretNames() {return [];}

    /** @returns `none` */
    mfaType() : "none" | "oob" | "otp" { return "none"; }

    /** @returns `none` */
    mfaChannel() : "none" | "email" | "sms" { return "none"; }

    /**
     * Create a new authenticator.
     * 
     * See crypto.pbkdf2 for more information on the optional parameters.
     * 
     * @param _userStorage ignored
     * @param options see {@link LocalPasswordAuthenticatorOptions}
     */
    constructor(_userStorage : UserStorage,
                options : OidcAuthenticatorOptions = {}) {
        super({friendlyName: "OIDC", ...options});
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
    async authenticateUser(_user : UserInputFields, _secrets: UserSecretsInputFields, _params: AuthenticationParameters) : Promise<void> {
        throw new CrossauthError(ErrorCode.PasswordInvalid, "Please use OpenID Connect to log in");
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
        _params: AuthenticationParameters, 
        _repeatParams: AuthenticationParameters) : Promise<Partial<UserSecretsInputFields>> {
        return {};
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

    /**
     * Does nothing for this class
     */
    validateSecrets(_params : AuthenticationParameters) : string[] {
        return [];
    }
}
