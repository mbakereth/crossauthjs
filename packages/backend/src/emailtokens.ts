import nodemailer from 'nodemailer';
import nunjucks from "nunjucks";
import { UserStorage, KeyStorage } from './storage';
import { Hasher } from './hasher';
import { CrossauthError, ErrorCode } from '@crossauth/common';
import { CrossauthLogger, j } from '@crossauth/common';
import { setParameter, ParamType } from './utils';
import { type User } from '@crossauth/common';
import { KeyPrefix, UserState } from '@crossauth/common';

const TOKEN_LENGTH = 16; // in bytes, before base64url

export interface TokenEmailerOptions {

    /** The site url, used to create a link, eg "https://mysite.com:3000".  No default - required parameter */
    siteUrl? : string,

    /** The prefix between the site url and the email verification/password reset link.  Default "/" */
    prefix? : string,

    /** The directory containing views (by default, Nunjucks templates) */
    views? : string;

    /** Template file containing page for producing the text version of the email verification email body */
    emailVerificationTextBody? : string,

    /** Template file containing page for producing the HTML version of the email verification email body */
    emailVerificationHtmlBody? : string,

    /** Subject for the the email verification email */
    emailVerificationSubject? : string,

    /** Template file containing page for producing the text version of the password reset email body */
    passwordResetTextBody? : string,

    /** Template file containing page for producing the HTML version of the password reset email body */
    passwordResetHtmlBody? : string,

    /** Subject for the the password reset email */
    passwordResetSubject? : string,

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

    /** Number of seconds befire email verification tokens should expire.  Default 1 day */
    verifyEmailExpires? : number,

    /** Number of seconds befire password reset tokens should expire.  Default 1 day */
    passwordResetExpires? : number,

    /** if passed, use this instead of the default nunjucks renderer */
    render? : (template : string, data : {[key:string]:any}) => string;
}

export class TokenEmailer {
    private userStorage : UserStorage;
    private keyStorage : KeyStorage;
    private views : string = "views";
    private siteUrl? : string;
    private prefix? : string = "/";
    private emailVerificationTextBody? : string = "emailverificationtextbody.njk";
    private emailVerificationHtmlBody? : string;
    private emailVerificationSubject : string = "Please verify your email";
    private passwordResetTextBody? : string = "passwordresettextbody.njk";
    private passwordResetHtmlBody? : string;
    private passwordResetSubject : string = "Password reset";
    private emailFrom : string = "";
    private smtpHost : string = "";
    private smtpPort : number = 587;
    private smtpUseTls? : boolean = true;
    private smtpUsername? : string;
    private smtpPassword? : string;
    private verifyEmailExpires : number = 60*60*24;
    private passwordResetExpires : number = 60*60*24;
    private render? : (template : string, data : {[key:string]:any}) => 
        string = undefined;
    /**
     * Construct a new EmailVerifier.
     * 
     * This emails tokens for email verification and password reset
     * 
     * @param userStorage : where to retrieve and update user details
     * @param keyStorage : where to store email verification tokens
     * @param options see {@link TokenEmailerOptions}
     */
    constructor(userStorage : UserStorage, 
                keyStorage : KeyStorage,
                options : TokenEmailerOptions = {}) {
        this.userStorage = userStorage;
        this.keyStorage = keyStorage;
        setParameter("siteUrl", ParamType.String, this, options, "SITE_URL", true);
        setParameter("prefix", ParamType.String, this, options, "PREFIX");
        setParameter("views", ParamType.String, this, options, "VIEWS");
        setParameter("emailVerificationTextBody", ParamType.String, this, options, "EMAIL_VERIFICATION_TEXT_BODY");
        setParameter("emailVerificationHtmlBody", ParamType.String, this, options, "EMAIL_VERIFICATION_HTML_BODY");
        setParameter("emailVerificationSubject", ParamType.String, this, options, "EMAIL_VERIFICATION_SUBJECT");
        setParameter("passwordResetTextBody", ParamType.String, this, options, "PASSWORD_RESET_TEXT_BODY");
        setParameter("passwordResetHtmlBody", ParamType.String, this, options, "PASSWORD_RESET_HTML_BODY");
        setParameter("passwordResetSubject", ParamType.String, this, options, "PASSWORD_RESET_SUBJECT");
        setParameter("emailFrom", ParamType.String, this, options, "EMAIL_FROM", true);
        setParameter("smtpHost", ParamType.String, this, options, "SMTP_HOST", true);
        setParameter("smtpPort", ParamType.Number, this, options, "SMTP_PORT");
        setParameter("smtpUsername", ParamType.String, this, options, "SMTP_USERNAME");
        setParameter("smtpPassword", ParamType.String, this, options, "SMTP_PASSWORD");
        setParameter("smtpUseTls", ParamType.Boolean, this, options, "SMTP_USE_TLS");
        setParameter("verifyEmailExpires", ParamType.Boolean, this, options, "VERIFY_EMAIL_EXPIRES");
        setParameter("passwordResetExpires", ParamType.String, this, options, "PASSWORD_RESET_EXPIRES");
    
        if (options.render) {
            this.render = options.render;
        } else {
            nunjucks.configure(this.views, { autoescape: true });
        }

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

    /**
     * Produces a hash of the given email verification token with the
     * correct prefix for inserting into storage.
     */
    static hashEmailVerificationToken(token : string) : string {
        return KeyPrefix.emailVerificationToken + Hasher.hash(token);
    }

    /**
     * Produces a hash of the given password reset token with the
     * correct prefix for inserting into storage.
     */
    static hashPasswordResetToken(token : string) : string {
        return KeyPrefix.passwordResetToken + Hasher.hash(token);
    }

    private async createAndSaveEmailVerificationToken(userId : string | number, 
                                                      newEmail : string="") : Promise<string> {
        const maxTries = 10;
        let tryNum = 0;
        const now = new Date();
        const expiry = new Date(now.getTime() + 1000*this.verifyEmailExpires);
        while (tryNum < maxTries) {
            let token = Hasher.randomValue(TOKEN_LENGTH);
            let hash = TokenEmailer.hashEmailVerificationToken(token);
            try {
                await this.keyStorage.saveKey(userId, hash, now, expiry, newEmail);
                return token;
            } catch (e) {
                token = Hasher.randomValue(TOKEN_LENGTH);
                hash = TokenEmailer.hashEmailVerificationToken(token);
                tryNum++;
            }
        }
        throw new CrossauthError(ErrorCode.Connection, "failed creating a unique key");
    }

    /**
     * Separated out for unit testing/mocking purposes
     */
    private async _sendEmailVerificationToken(token : string, email: string, extraData : {[key:string]:any}) {

        let auth : {user? : string, pass? : string}= {};
        if (this.smtpUsername) auth.user = this.smtpUsername;
        if (this.smtpPassword) auth.pass = this.smtpPassword;
        let mail : {from:string, to:string, subject: string, text?:string, html?:string} = {
            from: this.emailFrom, 
            to: email,
            subject: this.emailVerificationSubject, 
        };

        let data = {token: token, siteUrl: this.siteUrl, prefix: this.prefix};
        if (extraData) data = {...data, ...extraData};
        if (this.emailVerificationTextBody) {
            mail.text = this.render ? 
                this.render(this.emailVerificationTextBody, data) :
                nunjucks.render(this.emailVerificationTextBody, data)
        }
        if (this.emailVerificationHtmlBody) {
            mail.html = this.render ? 
                this.render(this.emailVerificationHtmlBody, data) :
                nunjucks.render(this.emailVerificationHtmlBody, data)
        }
        const transporter = this.createEmailer();
        return (await transporter.sendMail(mail)).messageId;

    }

    /**
     * Send an email verification email using the Nunjucks templates.
     * 
     * The email address to send it to will be taken from the user's record in 
     * user storage.  It will 
     * first be validated, throwing a {@link @crossauth/common!CrossauthError} 
     * with {@link @crossauth/common!ErrorCode} of
     * `InvalidEmail` if it is not valid..
     * 
     * @param userId userId to send it for
     * @param newEmail if this is a token to verify email for account 
     *        activation, leave this empty.
     *        If it is for changing an email, this will be the field it is 
     *        being changed do.
     * @param extraData : these extra variables will be passed to the Nunjucks 
     *        templates
     */
    async sendEmailVerificationToken(userId : string | number,
                                     newEmail : string="",
                                     extraData : {[key:string]:any} = {}) : Promise<void> {
        if (!this.emailVerificationTextBody && !this.emailVerificationHtmlBody) {
            let error = new CrossauthError(ErrorCode.Configuration, 
                "Either emailVerificationTextBody or emailVerificationHtmlBody must be set to send email verification emails");
                throw error;
        }
        let {user} = await this.userStorage.getUserById(userId, {skipEmailVerifiedCheck: true});
        let email = newEmail;
        if (email != "") {
            // this message is to validate a new email (email change)
            TokenEmailer.validateEmail(email);
        } else {
            email = user.email??user.username;
            if (email) {
                TokenEmailer.validateEmail(email);
            } else {
                email = user.username;
                TokenEmailer.validateEmail(email);
            }
        }
        TokenEmailer.validateEmail(email);
        const token = await this.createAndSaveEmailVerificationToken(userId, newEmail);
        const messageId = await this._sendEmailVerificationToken(token, email, extraData);
    
        CrossauthLogger.logger.info(j({msg: "Sent email verification email", emailMessageId: messageId, email: email}));
        
    }

    /**
     * Validates an email verification token.
     * 
     * The following must match:
     *     * expiry date in the key storage record must be less than current time
     *     * userId in the token must match the userId in the key storage
     *     * email address in user storage must match the email in the key.  If there is no email address,
     *       the username field is set if it is in email format.
     *     * expiry time in the key storage must match the expiry time in the key
     * 
     * Looks the token up in key storage and verifies it matches and has not expired.
     * @param token the token to validate
     * @returns the userId of the user the token is for and the email
     *          address the user is validating
     */
    async verifyEmailVerificationToken(token : string) : 
        Promise<{userId: string|number, newEmail: string}> {

        const hash = TokenEmailer.hashEmailVerificationToken(token);
        let storedToken = await this.keyStorage.getKey(hash);
        try {
            if (!storedToken.userId || !storedToken.expires) throw new CrossauthError(ErrorCode.InvalidKey);
            const {user} = await this.userStorage.getUserById(storedToken.userId, {skipEmailVerifiedCheck: true});
            let email = (user.email??user.username).toLowerCase();
            if (email) {
                TokenEmailer.validateEmail(email);
            } else {
                email = user.username.toLowerCase();
                TokenEmailer.validateEmail(email);
            }
            const now = new Date().getTime();
            if (now > storedToken.expires.getTime()) throw new CrossauthError(ErrorCode.Expired);
            await this.keyStorage.deleteKey(hash);
            return {userId: storedToken.userId, newEmail: storedToken.data??''};
        } finally {
            try {
                await this.keyStorage.deleteKey(hash);
            } catch {
                CrossauthLogger.logger.error("Couldn't delete email verification hash " + Hasher.hash(hash));
            }

        }
    }

    private async createAndSavePasswordResetToken(userId : string | number) : Promise<string> {
        const maxTries = 10;
        let tryNum = 0;
        const now = new Date();
        const expiry = new Date(now.getTime() + 1000*this.passwordResetExpires);
        while (tryNum < maxTries) {
            let token = Hasher.randomValue(TOKEN_LENGTH);
            let hash = TokenEmailer.hashPasswordResetToken(token);
            try {
                await this.keyStorage.saveKey(userId, hash, now, expiry);
                return token;
            } catch {
                token = Hasher.randomValue(TOKEN_LENGTH);
                hash = TokenEmailer.hashPasswordResetToken(token);
                tryNum++;
            }
        }
        throw new CrossauthError(ErrorCode.Connection, "failed creating a unique key");
    }

    /**
     * Validates a password reset token
     * 
     * The following must match:
     *     * expiry date in the key storage record must be less than current time
     *     * userId in the token must match the userId in the key storage
     *     * the email in the token matches either the email or username field in user storage
     *     * the password in user storage must match the password in the key
     *     * expiry time in the key storage must match the expiry time in the key
     * Looks the token up in key storage and verifies it matches and has not expired.  Also verifies
     * the user exists and password has not changed in the meantime.
     * @param token the token to validate
     * @returns the user that the token is for
     */
    async verifyPasswordResetToken(token : string) : Promise<User> {
        const hash = TokenEmailer.hashPasswordResetToken(token);
        let storedToken = await this.keyStorage.getKey(hash);
        if (!storedToken.userId) throw new CrossauthError(ErrorCode.InvalidKey);
        if (!storedToken.userId || !storedToken.expires) throw new CrossauthError(ErrorCode.InvalidKey);
        const {user} = await this.userStorage.getUserById(storedToken.userId, 
            {skipActiveCheck: true });
        if (user.state != UserState.active && user.state != UserState.passwordResetNeeded) {
            throw new CrossauthError(ErrorCode.UserNotActive);
        }
        const now = new Date().getTime();
        if (now > storedToken.expires.getTime()) throw new CrossauthError(ErrorCode.Expired);
        return user;
    }

    /**
     * Separated out for unit testing/mocking purposes
     */
    private async _sendPasswordResetToken(token : string, email: string, extraData : {[key:string]:any}) {
        if (!this.emailVerificationTextBody && !this.emailVerificationHtmlBody) {
            let error = new CrossauthError(ErrorCode.Configuration, 
                "Either emailVerificationTextBody or emailVerificationHtmlBody must be set to send email verification emails");
                throw error;
        }

        let auth : {user? : string, pass? : string}= {};
        if (this.smtpUsername) auth.user = this.smtpUsername;
        if (this.smtpPassword) auth.pass = this.smtpPassword;
        let mail : {from:string, to:string, subject: string, text?:string, html?:string} = {
            from: this.emailFrom, 
            to: email,
            subject: this.passwordResetSubject, 
        };
        let data = {token: token, siteUrl: this.siteUrl, prefix: this.prefix};
        if (extraData) data = {...data, ...extraData};
        if (this.passwordResetTextBody) {
            mail.text = this.render ? 
                this.render(this.passwordResetTextBody, data) :
                nunjucks.render(this.passwordResetTextBody, data)
        }
        if (this.passwordResetHtmlBody) {
            mail.html =  this.render ? 
                this.render(this.passwordResetHtmlBody, data) :
                nunjucks.render(this.passwordResetHtmlBody, data)
        }
        const transporter = this.createEmailer();
        return (await transporter.sendMail(mail)).messageId;

    }

    /**
     * Send a password reset token email using the Nunjucks templates
     * @param userId userId to send it for
     * @param extraData : these extra variables will be passed to the Nunjucks 
     *        templates
     */
    async sendPasswordResetToken(userId : string | number,
        extraData : {[key:string]:any} = {}) : Promise<void> {
        if (!this.passwordResetTextBody && !this.passwordResetHtmlBody) {
            let error = new CrossauthError(ErrorCode.Configuration, 
                "Either passwordResetTextBody or passwordResetTextBody must be set to send email verification emails");
                throw error;
        }
        let {user} = await this.userStorage.getUserById(userId, {
            skipActiveCheck: true
        });
        if (user.state != UserState.active && user.state != UserState.passwordResetNeeded) {
            throw new CrossauthError(ErrorCode.UserNotActive);
        }
        let email = (user.email??user.username).toLowerCase();
        if (email) {
            TokenEmailer.validateEmail(email);
        } else {
            email = user.username.toLowerCase();
            TokenEmailer.validateEmail(email);
        }
        const token = await this.createAndSavePasswordResetToken(userId);
        const messageId = await this._sendPasswordResetToken(token, email, extraData);
        CrossauthLogger.logger.info(j({msg: "Sent password reset email", emailMessageId: messageId, email: email}));
        
    }

    /**
     * Returns true if the given email has a valid format, false otherwise.
     * @param email the email to validate
     * @returns true or false
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
     * Returns if the given email has a valid format.  Throws a 
     * {@link @crossauth/common!CrossauthError} with 
     * {@link @crossauth/common!ErrorCode} `InvalidEmail` otherwise.
     * 
     * @param email the email to validate
     */
    static validateEmail(email : string|undefined)  {
        if (email==undefined || !TokenEmailer.isEmailValid(email)) throw new CrossauthError(ErrorCode.InvalidEmail);
    }

}
