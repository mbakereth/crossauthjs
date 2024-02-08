import type { User, Key, UserSecretsInputFields, UserInputFields } from '../../interfaces.ts';
import { getJsonData } from '../../interfaces.ts';
import { ErrorCode, CrossauthError } from '../../error.ts';
import { CrossauthLogger, j } from '../../logger.ts';
import { Authenticator, type AuthenticationParameters, AuthenticationOptions } from '../auth.ts';
import { setParameter, ParamType } from '../utils.ts';
import { randomInt }  from 'node:crypto';
import nunjucks from "nunjucks";
import nodemailer from 'nodemailer';

/**
 * Options for `EmailAuthenticator`
 */
export interface EmailAuthenticatorOptions extends AuthenticationOptions {

    /** The directory containing views (by default, Nunjucks templates) */
    views? : string;

    /** Template file containing page for producing the text version of the email verification email body */
    emailAuthenticatorTextBody? : string,

    /** Template file containing page for producing the HTML version of the email verification email body */
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

    /** Number of seconds before tokens should expire.  Default 5 minutes */
    emailAuthenticatorTokenExpires? : number,
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

    /**
     * Constructor
     * @param options see {@link EmailAuthenticatorOptions}
     */
    constructor(options : EmailAuthenticatorOptions = {}) {
        super({friendlyName : "Email token", ...options});
        setParameter("views", ParamType.String, this, options, "VIEWS");
        setParameter("emailAuthenticatorTextBody", ParamType.String, this, options, "EMAIL_VERIFICATION_TEXT_BODY");
        setParameter("emailAuthenticatorHtmlBody", ParamType.String, this, options, "EMAIL_VERIFICATION_HTML_BODY");
        setParameter("emailAuthenticatorSubject", ParamType.String, this, options, "EMAIL_VERIFICATION_SUBJECT");
        setParameter("emailFrom", ParamType.String, this, options, "EMAIL_FROM", true);
        setParameter("smtpHost", ParamType.String, this, options, "SMTP_HOST", true);
        setParameter("smtpPort", ParamType.Number, this, options, "SMTP_PORT");
        setParameter("smtpUsername", ParamType.String, this, options, "SMTP_USERNAME");
        setParameter("smtpPassword", ParamType.String, this, options, "SMTP_PASSWORD");
        setParameter("smtpUseTls", ParamType.Boolean, this, options, "SMTP_USE_TLS");
        setParameter("emailAuthenticatorTokenExpires", ParamType.Number, this, options, "HASHER_SECRET");

        nunjucks.configure(this.views, { autoescape: true });
    }

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

    private async sendToken(to : string, token : string) : Promise<string>{
        EmailAuthenticator.validateEmail(to);
        let auth : {user? : string, pass? : string}= {};
        if (this.smtpUsername) auth.user = this.smtpUsername;
        if (this.smtpPassword) auth.pass = this.smtpPassword;
        let mail : {from:string, to:string, subject: string, text?:string, html?:string} = {
            from: this.emailFrom, 
            to: to,
            subject: this.emailAuthenticatorSubject, 
        };

        let data = {token: token};
        if (this.emailAuthenticatorTextBody) {
            mail.text = nunjucks.render(this.emailAuthenticatorTextBody, data)
        }
        if (this.emailAuthenticatorHtmlBody) {
            mail.html = nunjucks.render(this.emailAuthenticatorHtmlBody, data)
        }
        const transporter = this.createEmailer();
        return (await transporter.sendMail(mail)).messageId;

    }

    /**
     * Creates and emails the one-time code
     * @param user the user to create it for.  Uses the `email` field if present, `username` otherwise (which in this case is expected to contain an email address)
     * @returns `userData` containing `username`, `email`, `factor2`
     *          `sessionData` containing the same plus `token` and `expiry` which is a Unix time (number).
     */
    async prepareConfiguration(user : UserInputFields) : Promise<{userData: {[key:string]: any}, sessionData: {[key:string]: any}}|undefined> {

        const token = EmailAuthenticator.zeroPad(randomInt(999999), 6);
        const email = user.email?user.email:user.username;
        EmailAuthenticator.validateEmail(email);
        const now = new Date();
        const expiry = new Date(now.getTime() + 1000*this.emailAuthenticatorTokenExpires).getTime();
        const userData = {username: user.username, email: email, factor2: this.factorName};
        const sessionData = {username: user.username, factor2: this.factorName, expiry: expiry, token: token}
        const messageId = this.sendToken(email, token);
        CrossauthLogger.logger.info(j({msg: "Sent factor token email", emailMessageId: messageId, email: email}));
        return { userData, sessionData};
    }

    /**
     * Creates and emails a new one-time code.
     * @param _username ignored
     * @param sessionKey the session containing the previously created data.
     * @returns 
     */
    async reprepareConfiguration(_username : string, sessionKey : Key) : Promise<{userData: {[key:string]: any}, secrets: Partial<UserSecretsInputFields>, newSessionData: {[key:string]: any}|undefined}|undefined> {
        const data = getJsonData(sessionKey)["2fa"];
        const token = EmailAuthenticator.zeroPad(randomInt(999999), 6);
        const now = new Date();
        const expiry = new Date(now.getTime() + 1000*this.emailAuthenticatorTokenExpires).getTime();
        const messageId = this.sendToken(data.email, token);
        CrossauthLogger.logger.info(j({msg: "Sent factor token email", emailMessageId: messageId, email: data.email}));
        return { 
            userData: {email: data.email, factor2: data.factor2, token: token}, 
            secrets: {},
            newSessionData: {...data, token: token, expiry: expiry},
        }
    }

    /**
     * Authenticates the user by comparing the user-provuded token with the one in secrets.
     * 
     * Validation fails if the token is incorrect or has expired.
     * 
     * @param _user ignored
     * @param secrets taken from the session and should contain `token` and `expiry`
     * @param params user input and should contain `token`
     * @throws {@link index!CrossauthError} with {@link index!ErrorCode} `InvalidToken` or `Expired`.
     */
    async authenticateUser(_user : User, secrets : UserSecretsInputFields, params: AuthenticationParameters) : Promise<void> {
        if (params.token != secrets?.token) {
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
    async createPersistentSecrets(_username : string, _params: AuthenticationParameters, _repeatParams?: AuthenticationParameters) : Promise<Partial<UserSecretsInputFields>> {
        return { };
    }

    /**
     * Creates adn emails a new one-time code.
     * @param user the user to create it for.  Uses the `email` field if present, `username` otherwise (which in this case is expected to contain an email address)
     * @returns `token` and `expiry` as a Unix time (number).
     */
    async createOneTimeSecrets(user : User) : Promise<Partial<UserSecretsInputFields>> {
        const token = EmailAuthenticator.zeroPad(randomInt(999999), 6);
        const now = new Date();
        const expiry = new Date(now.getTime() + 1000*this.emailAuthenticatorTokenExpires).getTime();
        const email = user.email || user.username;
        const messageId = this.sendToken(email, token);
        CrossauthLogger.logger.info(j({msg: "Sent factor token email", emailMessageId: messageId, email: email}));
        return { token: token, expiry: expiry }
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
     * @returns empty - this authenticator has no persistent secrets
     */
    secretNames() : string[] {
        return [];
    }

    /**
     * Does nothing for this class
     */
    validateSecrets(_params : AuthenticationParameters) : string[] {
        return [];
    }

    /**
     * @returns true - as a code is sent to the registers email address, no additional email verification is needed
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
     * @throws {@link index!CrossauthError} with {@link index!ErrorCode} `InvalidEmail`.
     */
    static validateEmail(email : string|undefined)  {
        if (email==undefined || !EmailAuthenticator.isEmailValid(email)) throw new CrossauthError(ErrorCode.InvalidEmail);
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