import nodemailer from 'nodemailer';
import nunjucks from "nunjucks";
import { UserStorage, KeyStorage } from './storage';
import { Hasher } from './hasher';
import { CrossauthError, ErrorCode } from '../error';
import { CrossauthLogger } from '../logger';
import { setParameter, ParamType } from './utils';
import { User } from '../interfaces';

/**
 * Options for TokenEmailer.  
 * 
 * @param views Directory to find the nunjucks files for the email body.  If not set, a generic email will be sent
 * @param emailVerificationTextBody nunjucks file containing the email text body template. 
 *         If neither this nor emailVerificationHtmlBody is set, a generic body will be set.
 *         You can set both emailVerificationTextBody and emailVerificationHtmlBody
 * @param emailVerificationHtmlBody nunjucks file containing the email HTML body template.  
 *        If neither this nor emailVerificationHtmlBody is set, a generic body will be set.
 *         You can set both emailVerificationTextBody and emailVerificationHtmlBody
 * @param emailVerificationSubject subject in email verification messages,  Defaults to "Please verify your email".
 * @param passwordResetTextBody nunjucks file containing the email text body template. 
 *         If neither this nor passwordResetHtmlBody is set, a generic body will be set.
 *         You can set both passwordResetTextBody and passwordResetHtmlBody
 * @param passwordResetHtmlBody nunjucks file containing the email HTML body template.  
 *        If neither this nor passwordResetTextBody is set, a generic body will be set.
 *         You can set both passwordResetTextBody and passwordResetHtmlBody
 * @param passwordResetSubject subject in email verification messages,  Defaults to "Please verify your email".
 * @param emailFrom From address for email messages.  Must be set.
 * @param smtpHost SMTP hostname for sending emails  Must be set.
 * @param smtpPort SMTP hostname for sending emails  Default is 587.
 * @param smtpUseTls whether to use TLS when connecting to SMTP server.  Default true.
 * @param smtpUsername username for authenticated SMTP.  Default is no authentication
 * @param smtpPassword password for authenticated SMTP.  Default is no authentication
 * @param passwordResetExpires token will expire after this number of seconds. Default 24 hours
 * @param verifyEmailExpires token will expire after this number of seconds.  Default 24 hours
 * @param tokenLength: number of bytes for generated tokens (will be longer as they are base64url encoded)
 */
export interface TokenEmailerOptions {
    secret?: string,
    siteUrl? : string,
    prefix? : string,
    views? : string;
    emailVerificationTextBody? : string,
    emailVerificationHtmlBody? : string,
    emailVerificationSubject? : string,
    passwordResetTextBody? : string,
    passwordResetHtmlBody? : string,
    passwordResetSubject? : string,
    emailFrom? : string,
    smtpHost? : string,
    smtpPort? : number,
    smtpUseTls? : boolean,
    smtpUsername? : string,
    smtpPassword? : string,
    verifyEmailExpires? : number,
    passwordResetExpires? : number,
    tokenLength?: number,
}

export class TokenEmailer {
    private userStorage : UserStorage;
    private keyStorage : KeyStorage;
    private secret : string = "";
    private views : string = "";
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
    private tokenLength : number = 16;

    static Activate = 0;
    static Change = 1;

    /**
     * Construct a new EmailVerifier.
     * 
     * This emails tokens for email verification and password reset
     * @param userStorage : where to retrieve and update user details
     * @param keyStorage : where to store email verification tokens
     * @param options see {@link TokenEmailerOptions}
     */
    constructor(userStorage : UserStorage, 
                keyStorage : KeyStorage,
                options : TokenEmailerOptions = {}) {
        this.userStorage = userStorage;
        this.keyStorage = keyStorage;
        setParameter("secret", ParamType.String, this, options, "SECRET", true);
        setParameter("siteUrl", ParamType.String, this, options, "SITE_URL", true);
        setParameter("prefix", ParamType.String, this, options, "PREFIX");
        setParameter("views", ParamType.String, this, options, "VIEWS", true);
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
        setParameter("tokenLength", ParamType.Number, this, options, "EMAILED_TOKEN_LENGTH");

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

    private hashTokenForStorage(token : string, salt? : string) : string {
        const hasher = new Hasher({pepper: this.secret, keyLength: this.tokenLength});
        if (!salt) salt = hasher.randomSalt();
        return salt + "!" + hasher.hash(token, {charset: "base64url", encode: false, salt: salt});

    }

    private createEmailVerificationToken(userId : string | number, 
                                         expiry : Date, email : string, 
                                         newEmail : string = "", 
                                         salt?: string) : {key:string, salt:string} {
        email = UserStorage.normalize(email);
        const message = userId + ":" + expiry.toString() + ":" + email + ":" + newEmail;
        const hasher = new Hasher({pepper: this.secret, keyLength: this.tokenLength});
        if (!salt) salt = hasher.randomSalt();
        return {salt, key:hasher.hash(message, {charset: "base64url", encode: false, salt: salt})};
    }

    private async createAndSaveEmailVerificationToken(userId : string | number, 
                                                      email : string,
                                                      newEmail : string="") : Promise<string> {
        const maxTries = 10;
        let tryNum = 0;
        const now = new Date();
        const expiry = new Date(now.getTime() + 1000*this.verifyEmailExpires);
        let hash : string;
        let token : string = "";
        while (true) {
            let {key, salt} = this.createEmailVerificationToken(userId, expiry, email, newEmail);
            token = salt + "!" + key;
            hash = this.hashTokenForStorage(key, salt);
            try {
                await this.keyStorage.getKey(hash);
                tryNum++;
            } catch (e) {
                break;
            }
            if (tryNum >= maxTries) {
                throw new CrossauthError(ErrorCode.Connection, "failed creating a unique key");
            }
        }
        await this.keyStorage.saveKey(userId, hash, now, expiry, newEmail);
        return token;
    }

    /**
     * Send an email verification email using the Nunjucks templates.
     * 
     * The email address to send it to will be taken from the user's record in user storage.  It will 
     * first be validated, throwing a {@link index!CrossauthError} with {@link index!ErrorCode} of
     * `InvalidEmail` if it is not valid..
     * 
     * @param userId userId to send it for
     * @param newEmail if this is a token to verify email for account activation, leave this empty.
     *                 If it is for changing an email, this will be the field it is being changed do.
     * @param extraData : these extra variables will be passed to the Nunjucks templates
     */
    async sendEmailVerificationToken(userId : string | number,
                                     newEmail : string="",
                                     extraData : {[key:string]:any} = {}) : Promise<void> {
        if (!this.emailVerificationTextBody && !this.emailVerificationHtmlBody) {
            let error = new CrossauthError(ErrorCode.Configuration, 
                "Either emailVerificationTextBody or emailVerificationHtmlBody must be set to send email verification emails");
                throw error;
        }
        let user = await this.userStorage.getUserById(userId, true);
        let email = newEmail;
        if (email != "") {
            // this message is to validate a new email (email change)
            TokenEmailer.validateEmail(email);
        } else {
            email = user.email;
            if (email) {
                TokenEmailer.validateEmail(email);
            } else {
                email = user.username;
                TokenEmailer.validateEmail(email);
            }
        }
        TokenEmailer.validateEmail(email);
        const token = await this.createAndSaveEmailVerificationToken(userId, email, newEmail);
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
            mail.text = nunjucks.render(this.emailVerificationTextBody, data)
        }
        if (this.emailVerificationHtmlBody) {
            mail.html = nunjucks.render(this.emailVerificationHtmlBody, data)
        }
        const transporter = this.createEmailer();
        const info = await transporter.sendMail(mail);
    
        CrossauthLogger.logger.info("Sent email verification email " + info.messageId + " to " + email);
        
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
     */
    async verifyEmailVerificationToken(token : string) : Promise<{userId: string|number, newEmail: string}> {

        const parts = token.split("!");
        if (parts.length != 2) throw new CrossauthError(ErrorCode.InvalidHash);
        const salt = parts[0];
        const key = parts[1];
        let hashedToken = this.hashTokenForStorage(key, salt);
        let storedToken = await this.keyStorage.getKey(hashedToken);
        let newEmail = "";
        if (storedToken.data && storedToken.data != "") newEmail = storedToken.data;
        if (!storedToken.userId || !storedToken.expires) throw new CrossauthError(ErrorCode.InvalidKey);
        const user = await this.userStorage.getUserById(storedToken.userId, true);
        let email = user.email.toLowerCase();
        if (email) {
            TokenEmailer.validateEmail(email);
        } else {
            email = user.username.toLowerCase();
            TokenEmailer.validateEmail(email);
        }
        const now = new Date().getTime();
        if (now > storedToken.expires.getTime()) throw new CrossauthError(ErrorCode.Expired);
        const {key: newHash} = this.createEmailVerificationToken(storedToken.userId, storedToken.expires, email, newEmail, salt);
        if (newHash != key) throw new CrossauthError(ErrorCode.InvalidHash);
        await this.keyStorage.deleteKey(hashedToken);
        return {userId: storedToken.userId, newEmail: storedToken.data||''};
    }

    private createPasswordResetToken(userId : string | number, expiry : Date, email: string, passwordHash : string, salt?:string) : {key:string, salt:string} {

            const message = userId + ":" + expiry.toString() + ":" + email + ":" + passwordHash;
            const hasher = new Hasher({pepper: this.secret, keyLength: this.tokenLength});
            if (!salt) salt = hasher.randomSalt();
            return {salt, key:hasher.hash(message, {charset: "base64url", encode: false, salt: salt})};
        }

    private async createAndSavePasswordResetToken(userId : string | number, email: string, passwordHash : string) : Promise<string> {
        const maxTries = 10;
        let tryNum = 0;
        let hash : string;
        let token : string = "";
        const now = new Date();
        const expiry = new Date(now.getTime() + 1000*this.passwordResetExpires);
        while (true) {
            let {key, salt} = this.createPasswordResetToken(userId, expiry, email, passwordHash);
            token = salt + "!" + key;
            hash = this.hashTokenForStorage(key, salt);
            try {
                await this.keyStorage.getKey(hash);
                tryNum++;
            } catch {
                break;
            }
            if (tryNum >= maxTries) {
                throw new CrossauthError(ErrorCode.Connection, "failed creating a unique key");
            }
        }
        await this.keyStorage.saveKey(userId, hash, now, expiry);
        return token;
    }

    /**
     * Validates a password reset token
     * 
     * The following must match:
     *     * expiry date in the key storage record must be less than current time
     *     * userId in the token must match the userId in the key storage
     *     * the email in the token matches either the email or username field in user storage
     *     * the passwordHash in user storage must match the passwordHash in the key
     *     * expiry time in the key storage must match the expiry time in the key
     * Looks the token up in key storage and verifies it matches and has not expired.  Also verifies
     * the user exists and password has not changed in the meantime.
     * @param token the token to validate
     */
    async verifyPasswordResetToken(token : string) : Promise<User> {
        const parts = token.split("!");
        if (parts.length != 2) throw new CrossauthError(ErrorCode.InvalidHash);
        const salt = parts[0];
        const key = parts[1];
        let storedToken = await this.keyStorage.getKey(this.hashTokenForStorage(key, salt));
        if (!storedToken.userId) throw new CrossauthError(ErrorCode.InvalidKey);
        if (!storedToken.userId || !storedToken.expires) throw new CrossauthError(ErrorCode.InvalidKey);
        const user = await this.userStorage.getUserById(storedToken.userId);
        let email = user.email.toLowerCase();
        if (email) {
            TokenEmailer.validateEmail(email);
        } else {
            email = user.username.toLowerCase();
            TokenEmailer.validateEmail(email);
        }
        const now = new Date().getTime();
        if (now > storedToken.expires.getTime()) throw new CrossauthError(ErrorCode.Expired);
        const {key: newHash} = this.createPasswordResetToken(storedToken.userId, storedToken.expires, email, user.passwordHash, salt);
        if (newHash != key) throw new CrossauthError(ErrorCode.InvalidHash);
        return user;
    }

    /**
     * Send a password reset token email using the Nunjucks templates
     * @param userId userId to send it for
     * @param to address to send it to
     * @param extraData : these extra variables will be passed to the Nunjucks templates
     */
    async sendPasswordResetToken(userId : string | number,
        extraData : {[key:string]:any} = {}) : Promise<void> {
        if (!this.passwordResetTextBody && !this.passwordResetHtmlBody) {
            let error = new CrossauthError(ErrorCode.Configuration, 
                "Either passwordResetTextBody or passwordResetTextBody must be set to send email verification emails");
                throw error;
        }
        let user = await this.userStorage.getUserById(userId);
        let email = user.email.toLowerCase();
        if (email) {
            TokenEmailer.validateEmail(email);
        } else {
            email = user.username.toLowerCase();
            TokenEmailer.validateEmail(email);
        }
        const token = await this.createAndSavePasswordResetToken(userId, email, user.passwordHash);
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
            mail.text = nunjucks.render(this.passwordResetTextBody, data)
        }
        if (this.passwordResetHtmlBody) {
            mail.html = nunjucks.render(this.passwordResetHtmlBody, data)
        }
        const transporter = this.createEmailer();
          const info = await transporter.sendMail(mail);
        CrossauthLogger.logger.info("Sent password reset email " + info.messageId + " to " + email);
        
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
     * Returns if the given email has a valid format.  Throws a {@link CrossauthError} with 
     * {@link ErrorCode} `InvalidEmail` otherwise.
     * 
     * @param email the email to validate
     */
    static validateEmail(email : string|undefined)  {
        if (email==undefined || !TokenEmailer.isEmailValid(email)) throw new CrossauthError(ErrorCode.InvalidEmail);
    }
}