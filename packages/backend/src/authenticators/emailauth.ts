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
import nodemailer from 'nodemailer';
import { KeyStorage } from '../storage.ts';

/**
 * Options for `EmailAuthenticator`
 */
export interface EmailAuthenticatorOptions extends AuthenticationOptions {

    /** The directory containing views (by default, Nunjucks templates) */
    views? : string;

    /** Template file containing page for producing the text version of the 
     * email verification email body */
    emailAuthenticatorTextBody? : string,

    /** Template file containing page for producing the HTML version of the 
     * email verification email body */
    emailAuthenticatorHtmlBody? : string,

    /** Subject for the the email verification email */
    emailAuthenticatorSubject? : string,

    /** Sender for emails */
    emailFrom? : string,

    /** Hostname of the SMTP server.  No default - required parameter */
    smtpHost? : string,

    /** Port the SMTP server is running on.  Default 25 */
    smtpPort? : number,

    /** Whether or not TLS is used by the SMTP server.  Default false */
    smtpUseTls? : boolean,

    /** Username for connecting to SMTP servger.  Default undefined */
    smtpUsername? : string,

    /** Password for connecting to SMTP servger.  Default undefined */
    smtpPassword? : string,

    /** Number of seconds before otps should expire.  Default 5 minutes */
    emailAuthenticatorTokenExpires? : number,

    /** if passed, use this instead of the default nunjucks renderer */
    render? : (template : string, data : {[key:string]:any}) => string;
}

/**
 * This authenticator creates a one-time code and sends it in email
 */
export class EmailAuthenticator extends Authenticator {

    private views : string = "views";
    private emailAuthenticatorTextBody? : string = "emailauthenticationtextbody.njk";
    private emailAuthenticatorHtmlBody? : string;
    private emailAuthenticatorSubject : string = "Login code";
    private emailFrom : string = "";
    private smtpHost : string = "";
    private smtpPort : number = 587;
    private smtpUseTls? : boolean = true;
    private smtpUsername? : string;
    private smtpPassword? : string;
    private emailAuthenticatorTokenExpires : number = 60*5;
    private render? : (template : string, data : {[key:string]:any}) => 
        string = undefined;

    /**
     * Constructor
     * 
     * @param options see {@link EmailAuthenticatorOptions}
     */
    constructor(options : EmailAuthenticatorOptions = {}) {
        super({friendlyName : "Email otp", ...options});
        setParameter("views", ParamType.String, this, options, "VIEWS");
        setParameter("emailAuthenticatorTextBody", ParamType.String, this, options, "EMAIL_AUTHENTICATOR_TEXT_BODY");
        setParameter("emailAuthenticatorHtmlBody", ParamType.String, this, options, "EMAIL_AUTHENTICATOR_HTML_BODY");
        setParameter("emailAuthenticatorSubject", ParamType.String, this, options, "EMAIL_AUTHENTICATOR_SUBJECT");
        setParameter("emailFrom", ParamType.String, this, options, "EMAIL_FROM", true);
        setParameter("smtpHost", ParamType.String, this, options, "SMTP_HOST", true);
        setParameter("smtpPort", ParamType.Number, this, options, "SMTP_PORT");
        setParameter("smtpUsername", ParamType.String, this, options, "SMTP_USERNAME");
        setParameter("smtpPassword", ParamType.String, this, options, "SMTP_PASSWORD");
        setParameter("smtpUseTls", ParamType.Boolean, this, options, "SMTP_USE_TLS");
        setParameter("emailAuthenticatorTokenExpires", ParamType.Number, this, options, "EMAIL_AUTHENTICATOR_TOKEN_EXPIRES");

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
    mfaChannel() : "none" | "email" | "sms" { return "email"; }

    private createEmailer() {
        let auth : {user? : string, pass? : string}= {};
        if (this.smtpUsername) auth.user = this.smtpUsername;
        if (this.smtpPassword) auth.pass = this.smtpPassword;
        return nodemailer.createTransport({
            host: this.smtpHost,
            port: this.smtpPort,
            secure: this.smtpUseTls,
            auth: auth,
          });
    }

    private async sendToken(to : string, otp : string) : Promise<string>{
        EmailAuthenticator.validateEmail(to);
        let auth : {user? : string, pass? : string}= {};
        if (this.smtpUsername) auth.user = this.smtpUsername;
        if (this.smtpPassword) auth.pass = this.smtpPassword;
        let mail: {
            from: string,
            to: string,
            subject: string,
            text?: string,
            html?: string
        } = {
            from: this.emailFrom, 
            to: to,
            subject: this.emailAuthenticatorSubject, 
        };

        let data = {otp: otp};
        if (this.emailAuthenticatorTextBody) {
            mail.text = this.render ? 
                this.render(this.emailAuthenticatorTextBody, data) :
                nunjucks.render(this.emailAuthenticatorTextBody, data)
        }
        if (this.emailAuthenticatorHtmlBody) {
            mail.html = this.render ? 
                this.render(this.emailAuthenticatorHtmlBody, data) :
                nunjucks.render(this.emailAuthenticatorHtmlBody, data)
        }
        const transporter = this.createEmailer();
        return (await transporter.sendMail(mail)).messageId;

    }

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
            "Please set factorName on EmailAuthenticator before using");

        const otp = EmailAuthenticator.zeroPad(randomInt(999999), 6);
        const email = user.email?user.email:user.username;
        EmailAuthenticator.validateEmail(email);
        const now = new Date();
        const expiry = 
            new Date(now.getTime() + 
                1000*this.emailAuthenticatorTokenExpires).getTime();
        const userData = {
            username: user.username,
            email: email,
            factor2: this.factorName
        };
        const sessionData = {
            username: user.username,
            factor2: this.factorName,
            expiry: expiry,
            otp: otp
        }
        const messageId = this.sendToken(email, otp);
        CrossauthLogger.logger.info(j({
            msg: "Sent factor otp email",
            emailMessageId: messageId,
            email: email
        }));
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
        const otp = EmailAuthenticator.zeroPad(randomInt(999999), 6);
        const now = new Date();
        const expiry = 
            new Date(now.getTime() + 
                1000*this.emailAuthenticatorTokenExpires).getTime();
        const messageId = this.sendToken(data.email, otp);
        CrossauthLogger.logger.info(j({
            msg: "Sent factor otp email",
            emailMessageId: messageId,
            email: data.email
        }));
        return { 
            userData: {email: data.email, factor2: data.factor2, otp: otp}, 
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
     * @param user the user to create it for.  Uses the `email` field if 
     *             present, `username` otherwise (which in this case is 
     *             expected to contain an email address)
     * @returns `otp` and `expiry` as a Unix time (number).
     */
    async createOneTimeSecrets(user : User) : 
        Promise<Partial<UserSecretsInputFields>> {
        const otp = EmailAuthenticator.zeroPad(randomInt(999999), 6);
        const now = new Date();
        const expiry = 
            new Date(now.getTime() + 
                1000*this.emailAuthenticatorTokenExpires).getTime();
        const email = user.email || user.username;
        const messageId = this.sendToken(email, otp);
        CrossauthLogger.logger.info(j({
            msg: "Sent factor otp email",
            emailMessageId: messageId,
            email: email
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
     * @returns true - as a code is sent to the registers email address, no 
     *          additional email verification is needed
     */
    skipEmailVerificationOnSignup() : boolean {
        return true;
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
          /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|.(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
        ) != null;
    }


    /**
     * Throws an exception if an email address doesn't have a valid form.
     * @param email the email address to validate
     * @throws {@link @crossauth/common!CrossauthError} with {@link @crossauth/common!ErrorCode} `InvalidEmail`.
     */
    static validateEmail(email : string|undefined)  {
        if (email==undefined || !EmailAuthenticator.isEmailValid(email)) {
            throw new CrossauthError(ErrorCode.InvalidEmail);
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