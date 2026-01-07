// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import type {
    User,
    Key,
    UserSecretsInputFields,
    UserInputFields } from '@crossauth/common';
//import { getJsonData } from '../../interfaces.ts';
import { ErrorCode, CrossauthError } from '@crossauth/common';
import { CrossauthLogger, j } from '@crossauth/common';
import {
    Authenticator,
    type AuthenticationParameters,
    type AuthenticationOptions } from '../auth.ts';
import { setParameter, ParamType } from '../utils.ts';
import { randomInt }  from 'node:crypto';
import nunjucks from "nunjucks";
import { KeyStorage } from '../storage.ts';

/**
 * Options for {@link SmsAuthenticator}
 */
export interface SmsAuthenticatorOptions extends AuthenticationOptions {

    /** The directory containing views (by default, Nunjucks templates) */
    views? : string;

    /** Template file containing page for producing the 
     * SMS message.  Default `smsauthenticationbody.njk` */
    smsAuthenticatorBody? : string,

    /** Phone number for sending sms from */
    smsAuthenticatorFrom? : string,

    /** Number of seconds before otps should expire.  Default 5 minutes */
    smsAuthenticatorTokenExpires? : number,

    /** if passed, use this instead of the default nunjucks renderer */
    render? : (template : string, data : {[key:string]:any}) => string;
}

/**
 * Abstract base class for sending OTPs by SMS
 */
export abstract class SmsAuthenticator extends Authenticator {

    protected views : string = "views";
    protected smsAuthenticatorBody : string = "smsauthenticationbody.njk";
    protected smsAuthenticatorFrom : string = "";
    protected smsAuthenticatorTokenExpires : number = 60*5;
    private render? : (template : string, data : {[key:string]:any}) => 
        string = undefined;

    /**
     * Constructor
     * @param options see {@link SmsAuthenticatorOptions}
     */
    constructor(options : SmsAuthenticatorOptions = {}) {
        super({friendlyName : "SMS otp", ...options});
        setParameter("views", ParamType.String, this, options, "VIEWS");
        setParameter("smsAuthenticatorBody", ParamType.String, this, options, "SMS_AUTHENTICATOR_BODY");
        setParameter("smsAuthenticatorFrom", ParamType.String, this, options, "SMS_AUTHENTICATOR_FROM", true);
        setParameter("smsAuthenticatorTokenExpires", ParamType.Number, this, options, "SMS_AUTHENTICATOR_TOKEN_EXPIRES");

        if (options.render) {
            this.render = options.render;
        } else {
            nunjucks.configure(this.views, { autoescape: true });
        }
    }

    /**
     * Used by the OAuth password_mfa grant type.
     */
    mfaType() : "none" | "oob" | "otp" { return "oob"; }

    /**
     * Used by the OAuth password_mfa grant type.
     */
    mfaChannel() : "none" | "email" | "sms" { return "sms"; }

    /**
     * Send an SMS 
     * 
     * @param to number to send SMS to (starting with `+`)
     * @param body text to send
     * @returns the send message ID
     */
    protected abstract sendSms(to : string, body : string) : Promise<string>;

    /**
     * Creates and sends the one-time code
     * @param user the user to create it for.  Uses the `phone` field which
     *        is expected to be a phone number starting with `+`
     * @returns `userData` containing `username`, `phone`, `factor2`
     *          `sessionData` containing the same plus `otp` and `expiry` which 
     *           is a Unix time (number).
     */
    async prepareConfiguration(user : UserInputFields) : 
        Promise<{
            userData: { [key: string]: any },
            sessionData: { [key: string]: any }
        }|undefined> {

        if (!this.factorName) throw new CrossauthError(ErrorCode.Configuration,
            "Please set factorName on SmsAuthenticator before using");

        const otp = SmsAuthenticator.zeroPad(randomInt(999999), 6);
        const number = user.phone;
        SmsAuthenticator.validatePhone(number);
        const now = new Date();
        const expiry = 
            new Date(now.getTime() + 
                1000*this.smsAuthenticatorTokenExpires).getTime();
        const userData = {
            username: user.username,
            phone: number,
            factor2: this.factorName
        };
        const sessionData = {
            username: user.username,
            factor2: this.factorName,
            expiry: expiry,
            phone: number,
            otp: otp
        }
        let data = {otp: otp};
        const body = this.render ? 
            this.render(this.smsAuthenticatorBody, data) :
            nunjucks.render(this.smsAuthenticatorBody, data);
        const messageId = this.sendSms(number, body);
        CrossauthLogger.logger.info(j({
            msg: "Sent factor otp sms",
            smsMessageId: messageId,
            phone: number
        }));
        return { userData, sessionData};
    }

    /**
     * Creates and sends a new one-time code.
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
        const otp = SmsAuthenticator.zeroPad(randomInt(999999), 6);
        const now = new Date();
        const expiry = 
            new Date(now.getTime() + 
                1000*this.smsAuthenticatorTokenExpires).getTime();
        const messageId = this.sendSms(data.phone, otp);
        CrossauthLogger.logger.info(j({
            msg: "Sent factor otp sms",
            smsMessageId: messageId,
            phone: data.phone
        }));
        return { 
            userData: {phone: data.phone, factor2: data.factor2, otp: otp}, 
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
     * Creates and sends a new one-time code.
     * @param user the user to create it for.  Uses the `phone` field which
     *        should start with `+`
     * @returns `otp` and `expiry` as a Unix time (number).
     */
    async createOneTimeSecrets(user : User) : 
        Promise<Partial<UserSecretsInputFields>> {
        const otp = SmsAuthenticator.zeroPad(randomInt(999999), 6);
        const now = new Date();
        const expiry = 
            new Date(now.getTime() + 
                1000*this.smsAuthenticatorTokenExpires).getTime();
        const phone = user.phone;
        const messageId = this.sendSms(phone, otp);
        CrossauthLogger.logger.info(j({
            msg: "Sent factor otp sms",
            smsMessageId: messageId,
            phone: phone
        }));
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
     * @returns false - doesn't replace email verification
     */
    skipEmailVerificationOnSignup() : boolean {
        return false;
    }

    /**
     * Returns whether or not the passed phone number has a valid form.
     * @param number the phone number to validate
     * @returns true if it is valid. false otherwise
     */
    static isPhoneValid(number : string) : boolean {
        return String(number)
        .match(
          /^\+[1-9][0-9]{7,14}$/
        ) != null;
    }


    /**
     * Throws an exception if a phone number doesn't have a valid form.
     * 
     * It must start with a `+` and be 8 to 15 digits
     * @param number the phone number to validate
     * @throws {@link @crossauth/common!CrossauthError} with 
     * {@link @crossauth/common!ErrorCode} `InvalidPhoneNumber`.
     */
    static validatePhone(number : string|undefined)  {
        if (number==undefined || !SmsAuthenticator.isPhoneValid(number)) {
            throw new CrossauthError(ErrorCode.InvalidPhoneNumber);
        }
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
