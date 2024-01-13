import type { User, Key } from '../interfaces.ts';
import { ErrorCode, CrossauthError } from '../error.ts';
import { UserStorage, KeyStorage } from './storage';
import { UsernamePasswordAuthenticator } from "./password";
import type { UsernamePasswordAuthenticatorOptions }  from "./password";
import { TokenEmailer, TokenEmailerOptions } from './email.ts';
import { CrossauthLogger } from '../logger.ts';
import { Cookie, DoubleSubmitCsrfToken, SessionCookie } from './cookieauth';
import type { DoubleSubmitCsrfTokenOptions, SessionCookieOptions } from './cookieauth';
import { setParameter, ParamType } from './utils.ts';

export interface BackendOptions extends TokenEmailerOptions {

    /** Type of csrf tokens to use.  Options are `doublesubmit` or `none`.  Default `doublesubmit` */
    csrfType? : string,

    /** options for csrf cookie manager */
    doubleSubmitCookieOptions? : DoubleSubmitCsrfTokenOptions,

    /** Type of csrf tokens to use.  Options are `doublesubmit` or `none`.  Default `doublesubmit` */
    sessionType? : string,

    /** options for session cookie manager */
    sessionCookieOptions? : SessionCookieOptions,

    /** If true, users will have to verify their email address before account is created or when changing their email address.
     * See class description for details.. Default true
     */
    enableEmailVerification? : boolean,

    /** If true, allow password reset by email token.
     * See class description for details.. Default true
     */
    enablePasswordReset? : boolean,

    /** Server secret.  Needed for emailing tokens and for csrf tokens */
    secret? : string;
}
/**
 * Class for managing sessions.
 */
export class Backend {
    userStorage : UserStorage;
    keyStorage : KeyStorage;
    private csrfType : string = "doublesubmit";
    private csrfTokens : DoubleSubmitCsrfToken|undefined = undefined;
    private sessionType : string = "cookie";
    private session : SessionCookie|undefined = undefined;
    private authenticator : UsernamePasswordAuthenticator;

    private enableEmailVerification? : boolean = false;
    private enablePasswordReset? : boolean = false;
    private tokenEmailer? : TokenEmailer;

    /**
     * Constructor
     * @param userStorage the {@link UserStorage} instance to use, eg {@link PrismaUserStorage}.
     * @param keyStorage  the {@link KeyStorage} instance to use, eg {@link PrismaSessionStorage}.
     * @param authenticator authenticator used to validate users  See {@link UsernamePasswordAuthenticatorOptions }.
     * @param options optional parameters for authentication. See {@link CookieAuthOptions }.
     */
    constructor(
        userStorage : UserStorage, 
        keyStorage : KeyStorage, 
        authenticator : UsernamePasswordAuthenticator,
        options : BackendOptions = {}) {

        this.userStorage = userStorage;
        this.keyStorage = keyStorage;
        this.authenticator = authenticator;

        setParameter("secret", ParamType.String, this, options, "SECRET");

        setParameter("csrfType", ParamType.String, this, options, "CSRF_TYPE");
        if (this.csrfType != "none") {
            this.csrfTokens = new DoubleSubmitCsrfToken({...options?.doubleSubmitCookieOptions, ...options||{}});
        }

        setParameter("sessionType", ParamType.String, this, options, "SESSION_TYPE");
        if (this.sessionType != "none") {
            this.session = new SessionCookie(this.userStorage, this.keyStorage, {...options?.sessionCookieOptions, ...options||{}});
        }

        setParameter("enableEmailVerification", ParamType.Boolean, this, options, "ENABLE_EMAIL_VERIFICATION");
        setParameter("enablePasswordReset", ParamType.Boolean, this, options, "ENABLE_PASSWORD_RESET");
        if (this.enableEmailVerification || this.enablePasswordReset) {
            this.tokenEmailer = new TokenEmailer(this.userStorage, this.keyStorage, options);
        }
    }

    /**
     * Returns the name used for session ID cookies.
     */
    get sessionCookieName() : string {
        return this.session?.cookieName||"";
    }

    /**
     * Returns the name used for CSRF token cookies.
     */
    get csrfCookieName() : string {
        return this.csrfTokens?.cookieName||"";
    }

    /**
     * Returns the name used for CSRF token cookies.
     */
    get csrfHeaderName() : string {
        return this.csrfTokens?.headerName||"";
    }

    /**
     * Performs a user login
     *    * Authenticates the username and password
     *    * Creates a session key
     *    * Returns the user (without the password hash) and the session cookie.
     * @param username the username to validate
     * @param password the password to validate
     * @param existingSessionId if this is passed, the it will be used for the new sessionId.  If not, a new random one will be created
     * @param persist if passed, overrides the persistSessionId setting.
     * @param user if this is defined, the username and password are ignored and the given user is logged in
     * @returns the user (without the password hash) and session cookie.
     * @throws {@link index!CrossauthError} with {@link ErrorCode} of `Connection`, `UserNotValid`, 
     *         `PasswordNotMatch`.
     */
    async login(username : string, password : string, existingSessionId? : string, persist? : boolean, user? : User) : Promise<{sessionCookie: Cookie, csrfCookie: Cookie|undefined, user: User}> {
        if (!this.session) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled");

        if (!user) user = await this.authenticator.authenticateUser(username, password);
        const sessionKey = await this.session.createSessionKey(user.id, existingSessionId);
        //await this.sessionStorage.saveSession(user.id, sessionKey.value, sessionKey.dateCreated, sessionKey.expires);
        let sessionCookie = this.session.makeSessionCookie(sessionKey, persist);
        let csrfCookie : Cookie|undefined = undefined;
        if (this.csrfTokens) {
            csrfCookie = this.csrfTokens.makeCsrfCookie(await this.csrfTokens.createCsrfToken(sessionKey.value));
        }
        return {
            sessionCookie: sessionCookie,
            csrfCookie: csrfCookie,
            user: user
        }
    }

    /**
     * If a valid session key does not exist, create and store an anonymous one.
     * 
     * If the session ID and/or csrfToken are passed, they are validated.  If invalid, they are recrated.
     * @returns a cookie with the session ID, a cookie with the CSRF token, a flag to indicate whether
     *          each of these was newly created and the user, which may be undefined.
     */
    async createAnonymousSessionKeyIfNoneExists(sessionId? : string, csrfToken? : string) 
    : Promise<{sessionCookie: Cookie, csrfCookie: Cookie|undefined, user : User|undefined}> {
        if (!this.session) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled");

        let {sessionKey, sessionCookie, csrfCookie, user} = await this.getValidatedSessionAndCsrf(sessionId, csrfToken);

        if (!sessionKey) {
            sessionKey = await this.session.createSessionKey(undefined);
        }
        if (!sessionCookie) {
            sessionCookie = this.session.makeSessionCookie(sessionKey);
        }  
        if (this.csrfTokens && !csrfCookie) {
            csrfToken = await this.csrfTokens.createCsrfToken(sessionKey.value);
            csrfCookie = this.csrfTokens.makeCsrfCookie(csrfToken);
        }
        return {
            sessionCookie,
            csrfCookie,
            user
        };
    }

    /**
     * Validate the sessionId and csrfToken.  Return them and the user if they are valid.  Return undefined otherwise.
     * 
     * @returns a cookie with the session ID, a cookie with the CSRF token, a flag to indicate whether
     *          each of these was newly created and the user, which may be undefined.
     */
    async getValidatedSessionAndCsrf(sessionId? : string, csrfToken? : string) 
        : Promise<{sessionKey : Key|undefined, sessionCookie: Cookie|undefined, csrfCookie: Cookie|undefined, user : User|undefined}> {
        if (!this.session) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled");

        let sessionKey : Key|undefined = undefined;
        let user : User|undefined = undefined;
        let userPromise : Promise<User|undefined>|undefined = undefined;
        if (sessionId) {
            try {
                let  {key} = await this.session.getUserForSessionKey(sessionId);
                if (key) sessionKey = key;
                userPromise = this.userForSessionKey(sessionId);
            }
            catch {
                sessionId = undefined;
                csrfToken = undefined;
            }
        }
        if (this.csrfTokens && sessionId && csrfToken) {
            try {
                this.csrfTokens.validateCsrfToken(csrfToken, sessionId);
            } catch {
                csrfToken = undefined;
            }
        }
        let sessionCookie = sessionKey ? this.session.makeSessionCookie(sessionKey) : undefined;         
        const csrfCookie = csrfToken && this.csrfTokens? this.csrfTokens.makeCsrfCookie(csrfToken) : undefined;
        if (userPromise) user = await userPromise;
        return {
            sessionKey,
            sessionCookie,
            csrfCookie,
            user
        };
    }

    /**
     * Logs a user out.
     * 
     * Removes the given session ID from the session storage.
     * @param sessionKey the session ID to remove.
     * @throws {@link index!CrossauthError} with {@link ErrorCode} of `Connection`
     */
    async logout(sessionKey : string) : Promise<void> {
        return await this.keyStorage.deleteKey(sessionKey)
    }

    /**
     * Logs a user out from all sessions.
     * 
     * Removes the given session ID from the session storage.
     * @param except Don't log out from the matching session.
     * @throws {@link index!CrossauthError} with {@link ErrorCode} of `Connection`
     */
    async logoutFromAll(userId : string | number, except? : string|undefined) : Promise<void> {
        if (!this.session) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled");
        /*await*/ return this.session.deleteAllForUser(userId, except);
    }
    
    /**
     * Returns the user (without password hash) matching the given session key.
     * 
     * If the user is undefined, or the key has expired, returns undefined.
     * 
     * @param sessionKey the session key to look up in session storage
     * @returns the {@link User} (without password hash) matching the  session key
     * @throws {@link index!CrossauthError} with {@link ErrorCode} of `Connection`,  `InvalidSessionId`
     *         `UserNotExist` or `Expired`.
     */
    async userForSessionKey(sessionKey : string) : Promise<User|undefined> {
        if (!this.session) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled");
        let error : CrossauthError | undefined;
        try {
            let {user} = await this.session.getUserForSessionKey(sessionKey);
            return user;
        } catch (e) {
            if (e instanceof CrossauthError) {
                let ce = e as CrossauthError;
                switch (ce.code) {
                    case ErrorCode.Expired:
                        return undefined;
                        break;
                    default:
                        error = ce;
                }
            }
            else {
                console.log(e);
            }
            error = new CrossauthError(ErrorCode.UnknownError);
        }
        if (error) {
            CrossauthLogger.logger.debug(error);
            throw error;
        }
    }
    
    /**
     * Creates and returns a signed CSRF token based on the session ID
     * @param sessionId the session ID
     * @returns a signed CSRF token
     */
    async createCsrfToken(sessionId : string) : Promise<Cookie> {
        if (!this.csrfTokens) throw new CrossauthError(ErrorCode.Configuration, "Csrf tokens not enabled");
        return this.csrfTokens.makeCsrfCookie(await this.csrfTokens.createCsrfToken(sessionId));
    }

    /**
     * Throws {@link index!CrossauthError} with ErrorCode.InvalidKey if the passed CSRF token is not valid for the given
     * session ID.  Otherwise returns without error
     * @param token 
     */
    validateCsrfToken(token : string, sessionId : string) {
        if (!this.csrfTokens) throw new CrossauthError(ErrorCode.Configuration, "Csrf tokens not enabled");
        this.csrfTokens.validateCsrfToken(token, sessionId);
    }

    /**
     * Throws {@link index!CrossauthError} with ErrorCode.InvalidKey if the passed CSRF token is not valid for the given
     * session ID.  Otherwise returns without error
     * @param token 
     */
    validateDoubleSubmitCsrfToken(token : string, sessionId : string, formOrHeaderValue : string) {
        if (!this.csrfTokens) throw new CrossauthError(ErrorCode.Configuration, "Csrf tokens not enabled");
        this.csrfTokens.validateDoubleSubmitCsrfToken(token, sessionId, formOrHeaderValue);
    }

    /**
     * If sessionIdleTimeout is set, update the last activcity time in key storage to current time
     * @param sessionId the session Id to update.
     */
    async updateSessionActivity(sessionId : string) : Promise<void> {
        if (!this.session) return;
        if (this.session.idleTimeout > 0) {
            this.session.updateSessionKey({
                value: sessionId,
                lastActive: new Date(),
            });
        }
    }

    /**
     * Deletes the given session ID from the key storage (not the cookie)
     * @param sessionId the session Id to delete
     */
    async deleteSessionId(sessionId : string) : Promise<void> {
        if (!this.session) return;
        return await this.keyStorage.deleteKey(sessionId);
    }

    /**
     * Creates a new user, sending an email verification message if necessary
     * 
     * @param username username to give the user
     * @param password password to give the user
     * @param extraFields and extra fields to add to the user table entry
     * @returns the userId
     */
    async createUser(username : string, 
        password : string, 
        extraFields : {[key : string]: string|number|boolean|Date|undefined})
        : Promise<string|number> {
            let passwordHash = await this.authenticator.createPasswordForStorage(password);
        if (this.enableEmailVerification && this.tokenEmailer) {
            extraFields = {...extraFields, emailVerified: false};
        }
            const userId = await this.userStorage.createUser(username, passwordHash, extraFields);
        if (this.enableEmailVerification && this.tokenEmailer) {
            await this.tokenEmailer?.sendEmailVerificationToken(userId, undefined)
        }
        return userId;
    }

    async requestPasswordReset(email : string) : Promise<void> {
        const user = await this.userStorage.getUserByEmail(email);
        await this.tokenEmailer?.sendPasswordResetToken(user.id);
    }

    /**
     * Takes an email verification token as input and applies it to the user storage.
     * 
     * The emailVerified flag is set to true.  If the token was for changing the password, the new
     * password is saved to the user in user storage.
     * 
     * @param token the token to apply
     * @returns the new user record
     */
    async applyEmailVerificationToken(token : string) : Promise<User> {
        if (!this.tokenEmailer) throw new CrossauthError(ErrorCode.Configuration, "Email verification not enabled");
        let { userId, newEmail} = await this.tokenEmailer.verifyEmailVerificationToken(token);
        let user = await this.userStorage.getUserById(userId, true);

        let newUser : Partial<User> = {
            id: user.id,
            emailVerified: true,
        }
        if (newEmail != "") {
            newUser.email = newEmail;
        }
        await this.userStorage.updateUser(newUser);
        return {...user, ...newUser};
    }

    async userForPasswordResetToken(token : string) : Promise<User> {
        if (!this.tokenEmailer) throw new CrossauthError(ErrorCode.Configuration, "Password reset not enabled");
        return await this.tokenEmailer.verifyPasswordResetToken(token);
    }

    async changePassword(username : string, oldPassword : string, newPassword : string) : Promise<User> {
        let user = await this.authenticator.authenticateUser(username, oldPassword);
        await this.userStorage.updateUser({
            id: user.id,
            passwordHash: await this.authenticator.createPasswordForStorage(newPassword),
        })
        return user;
    }

    async resetPassword(token : string, newPassword : string) : Promise<User> {
        if (!this.tokenEmailer) throw new CrossauthError(ErrorCode.Configuration, "Password reset not enabled");

        const user = await this.userForPasswordResetToken(token);
        if (!this.tokenEmailer) throw new CrossauthError(ErrorCode.Configuration);
        await this.userStorage.updateUser({
            id: user.id,
            passwordHash: await this.authenticator.createPasswordForStorage(newPassword),
        })
        this.keyStorage.deleteKey(token);
        return user;
    }

}