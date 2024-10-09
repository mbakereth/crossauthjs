// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import type {
    User,
    Key,
    UserSecretsInputFields,
    UserInputFields } from '@crossauth/common';
//import { getJsonData } from '../../interfaces.ts';
import { ErrorCode, CrossauthError } from '@crossauth/common';
import {
    Authenticator,
    type AuthenticationParameters,
    type AuthenticationOptions } from '../auth.ts';
import { KeyStorage } from '../storage.ts';

/**
 * Options for `DummyFactor2Authenticator`
 */
export interface DummyFactor2AuthenticatorOptions extends AuthenticationOptions {
}

/**
 * This authenticator creates fixed one-time code
 */
export class DummyFactor2Authenticator extends Authenticator {

    readonly code : string;

    /**
     * Constructor
     * 
     * @param options see {@link EmailAuthenticatorOptions}
     */
    constructor(code : string, options : DummyFactor2AuthenticatorOptions = {}) {
        super({friendlyName : "Dummy factor2", ...options});
        this.code = code;
    }

    /**
     * Used by the OAuth password_mfa grant type.
     */
    mfaType() : "none" | "oob" | "otp" { return "oob"; }

    /**
     * Used by the OAuth password_mfa grant type.
     */
    mfaChannel() : "none" | "email" | "sms" { return "email"; }

    /**
     * Creates and emails the one-time code
     * @param user the user to create it for.  Uses the `email` field if 
     *             present, `username` otherwise (which in this case is 
     *             expected to contain an email address)
     * @returns `userData` containing `username`, `email`, `factor2`
     *          `sessionData` containing the same plus `otp` and `expiry` which 
     *           is a Unix time (number).
     */
    async prepareConfiguration(user : UserInputFields) : 
        Promise<{
            userData: { [key: string]: any },
            sessionData: { [key: string]: any }
        }|undefined> {

        if (!this.factorName) throw new CrossauthError(ErrorCode.Configuration,
            "Please set factorName on DummyFactor2AuthenticatorOptions before using");

        const now = new Date();
        const expiry = 
            new Date(now.getTime() + 
                1000*60).getTime();
        const userData = {
            username: user.username,
            factor2: this.factorName
        };
        const sessionData = {
            username: user.username,
            factor2: this.factorName,
            expiry: expiry,
            otp: this.code,
        }
        return { userData, sessionData};
    }

    /**
     * Creates and emails a new one-time code.
     * @param _username ignored
     * @param sessionKey the session containing the previously created data.
     * @returns 
     */
    async reprepareConfiguration(_username : string, sessionKey : Key) : 
        Promise<{
            userData: { [key: string]: any },
            secrets: Partial<UserSecretsInputFields>,
            newSessionData: { [key: string]: any } | undefined
            }|undefined> {
        //const data = getJsonData(sessionKey)["2fa"];
        const data = KeyStorage.decodeData(sessionKey.data)["2fa"];
        const otp = this.code;
        const now = new Date();
        const expiry = 
            new Date(now.getTime() + 
                1000*60).getTime();
        return { 
            userData: {factor2: data.factor2, otp: otp}, 
            secrets: {},
            newSessionData: {...data, otp: otp, expiry: expiry},
        }
    }

    /**
     * Authenticates the user by comparing the user-provided otp with the one 
     * in secrets.
     * 
     * Validation fails if the otp is incorrect or has expired.
     * 
     * @param _user ignored
     * @param secrets taken from the session and should contain `otp` and 
     *                `expiry`
     * @param params user input and should contain `otp`
     * @throws {@link @crossauth/common!CrossauthError} with 
     *         {@link @crossauth/common!ErrorCode} `InvalidToken` or `Expired`.
     */
    async authenticateUser(_user: User,
        secrets: UserSecretsInputFields,
        params: AuthenticationParameters) : 
        Promise<void> {
        if (params.otp != secrets?.otp) {
            throw new CrossauthError(ErrorCode.InvalidToken, "Invalid code");
        }
        const now = new Date().getTime();
        if (!secrets.expiry || now > secrets.expiry) {
            throw new CrossauthError(ErrorCode.Expired, "Token has expired");
        }
    }

    /**
     * Does nothing for this class
     */
    async createPersistentSecrets(_username: string,
        _params: AuthenticationParameters,
        _repeatParams?: AuthenticationParameters) : 
        Promise<Partial<UserSecretsInputFields>> {
        return { };
    }

    /**
     * Creates and emails a new one-time code.
     * @param _user ignored
     * @returns `otp` and `expiry` as a Unix time (number).
     */
    async createOneTimeSecrets(_user : User) : 
        Promise<Partial<UserSecretsInputFields>> {
        const otp = this.code;
        const now = new Date();
        const expiry = 
            new Date(now.getTime() + 
                1000*60).getTime();
        return { otp: otp, expiry: expiry }
    }

    /**
     * @returns true - this class can create users
     */
    canCreateUser() : boolean {
        return true;

    }

    /**
     * @returns true - this class can update users
     */
    canUpdateUser() : boolean {
        return true;
    }

    /**
     * @returns false - users cannot update secrets
     */
    canUpdateSecrets() : boolean {
        return false;
    }
    
    /**
     * @returns empty - this authenticator has no persistent secrets
     */
    secretNames() : string[] {
        return [];
    }

    /**
     * @returns otp
     */
    transientSecretNames() : string[] {
        return ["otp"];
    }

    /**
     * Does nothing for this class
     */
    validateSecrets(_params : AuthenticationParameters) : string[] {
        return [];
    }

    /**
     * @returns true - as a code is sent to the registers email address, no 
     *          additional email verification is needed
     */
    skipEmailVerificationOnSignup() : boolean {
        return false;
    }

    /**
     * Returns whether or not the passed email has a valid form.
     * @param email the email address to validate
     * @returns true if it is valid. false otherwise
     */
    static isEmailValid(email : string) : boolean {
        // https://stackoverflow.com/questions/46155/how-can-i-validate-an-email-address-in-javascript
        return String(email)
        .toLowerCase()
        .match(
          /^(([^<>()[\]\.,;:\s@"]+(\.[^<>()[\]\.,;:\s@"]+)*)|.(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
        ) != null;
    }

    /**
     * Takles a number and turns it into a zero-padded string
     * @param num number ot pad
     * @param places total number of required digits
     * @returns zero-padded string
     */
    static zeroPad(num : number, places : number) : string {
        var zero = places - num.toString().length + 1;
        return Array(+(zero > 0 && zero)).join("0") + num;
      }
      
}
