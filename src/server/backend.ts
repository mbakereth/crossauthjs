import { type User, type Key, getJsonData } from '../interfaces.ts';
import { ErrorCode, CrossauthError } from '../error.ts';
import { UserStorage, KeyStorage } from './storage';
import { UsernamePasswordAuthenticator } from "./password";
import type { UsernamePasswordAuthenticatorOptions }  from "./password";
import { TokenEmailer, TokenEmailerOptions } from './email.ts';
import { Totp } from './totp';
import { CrossauthLogger, j } from '../logger.ts';
import { Cookie, DoubleSubmitCsrfToken, SessionCookie } from './cookieauth';
import type { DoubleSubmitCsrfTokenOptions, SessionCookieOptions } from './cookieauth';
import { setParameter, ParamType } from './utils.ts';

export interface BackendOptions extends TokenEmailerOptions {

    /** Application name - used for Google Authenticator igf 2FA enabled */
    appName? : string;

    /** options for csrf cookie manager */
    doubleSubmitCookieOptions? : DoubleSubmitCsrfTokenOptions,

    /** Whether or not to enable session management (by cookie).  Default true */
    enableSessions? : boolean,

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

    /** Whether to turn on 2FA.  Only Google Authenticator TOTP supported at present.  Default off */
    totp? : "off" | "all" | "peruser";

    /**
     * Store for password reset and email vcerification tokens.  If not passed, the same store as
     * for sessions is used.
     */
    emailTokenStorage? : KeyStorage,
}

/**
 * Class for managing sessions.
 */
export class Backend {
    userStorage : UserStorage;
    keyStorage : KeyStorage;
    private csrfTokens? : DoubleSubmitCsrfToken;
    private enableSessions : boolean = true;
    private session? : SessionCookie;
    readonly authenticator : UsernamePasswordAuthenticator;

    private appName : string = "Crossauth";
    private enableEmailVerification : boolean = false;
    private enablePasswordReset : boolean = false;
    private totp :  "off" | "all" | "peruser" = "off";
    private tokenEmailer? : TokenEmailer;
    private totpManager? : Totp;

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
        setParameter("totp", ParamType.String, this, options, "TOTP");
        setParameter("appName", ParamType.String, this, options, "APP_NAME", this.totp!="off");

        setParameter("enableSessions", ParamType.Boolean, this, options, "ENABLE_SESSIONS");
        if (this.enableSessions) {
            this.session = new SessionCookie(this.userStorage, this.keyStorage, {...options?.sessionCookieOptions, ...options||{}});
            this.csrfTokens = new DoubleSubmitCsrfToken({...options?.doubleSubmitCookieOptions, ...options||{}});
        }


        setParameter("enableEmailVerification", ParamType.Boolean, this, options, "ENABLE_EMAIL_VERIFICATION");
        setParameter("enablePasswordReset", ParamType.Boolean, this, options, "ENABLE_PASSWORD_RESET");
        if (this.enableEmailVerification || this.enablePasswordReset) {
            let keyStorage = this.keyStorage;
            if (options.emailTokenStorage) keyStorage = options.emailTokenStorage;
            this.tokenEmailer = new TokenEmailer(this.userStorage, keyStorage, options);
        }

        if (this.totp != "off") {
            this.totpManager = new Totp(this.appName, this.keyStorage);
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
    async login(username : string, password : string, extraFields : {[key:string] : any} = {}, persist? : boolean, user? : User) : Promise<{sessionCookie: Cookie, csrfCookie: Cookie, csrfForOrHeaderValue: string, user: User}> {
        if (!this.session || !this.csrfTokens) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled"); // csrf tokens always created when using sessions

        let bypass2FA = user != undefined;

        if (!user) user = await this.authenticator.authenticateUser(username, password);
        let sessionCookie : Cookie;
        if (!bypass2FA && user.totpSecret && user.totpSecret != "") {
            // create an anonymous session and store the username in it
            const { sessionCookie: newSssionCookie } = await this.initiateTotpLogin(user);
            sessionCookie = newSssionCookie;
        } else {
            const sessionKey = await this.session.createSessionKey(user.id, extraFields);
            //await this.sessionStorage.saveSession(user.id, sessionKey.value, sessionKey.dateCreated, sessionKey.expires);
            sessionCookie = this.session.makeCookie(sessionKey, persist);
        }
        const csrfToken = this.csrfTokens.createCsrfToken();
        const csrfCookie = this.csrfTokens.makeCsrfCookie(csrfToken);
        const csrfForOrHeaderValue = this.csrfTokens.makeCsrfFormOrHeaderToken(csrfToken);
        try {
            this.keyStorage.deleteAllForUser(user.id, "p:");
        } catch (e) {
            CrossauthLogger.logger.warn(j({msg: "Couldn't delete password reset tokens while logging in", user: username}));
            CrossauthLogger.logger.debug(j({err: e}));
        }
        return {
            sessionCookie: sessionCookie,
            csrfCookie: csrfCookie,
            csrfForOrHeaderValue: csrfForOrHeaderValue,
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
    async createAnonymousSession(extraFields: {[key: string]: any} = {}) 
    : Promise<{sessionCookie: Cookie, csrfCookie: Cookie, csrfFormOrHeaderValue: string}> {
        if (!this.session || !this.csrfTokens) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled");

        const key = await this.session.createSessionKey(undefined, extraFields);
        const sessionCookie = this.session.makeCookie(key, false);
        let { csrfCookie, csrfFormOrHeaderValue } = await this.createCsrfToken();
        return {
            sessionCookie,
            csrfCookie,
            csrfFormOrHeaderValue,
        };
    }

    /**
     * Logs a user out.
     * 
     * Removes the given session ID from the session storage.
     * @param sessionKey the session ID to remove.
     * @throws {@link index!CrossauthError} with {@link ErrorCode} of `Connection`
     */
    async logout(sessionCookieValue : string) : Promise<void> {
        if (!this.session) throw new CrossauthError(ErrorCode.Configuration, "logout called but sessions not enabled");
        const key = await this.session.getSessionKey(sessionCookieValue);
        return await this.keyStorage.deleteKey(SessionCookie.hashSessionKey(key.value));
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
     * @param sessionCookieValue the session key to look up in session storage
     * @returns the {@link User} (without password hash) matching the  session key
     * @throws {@link index!CrossauthError} with {@link ErrorCode} of `Connection`,  `InvalidSessionId`
     *         `UserNotExist` or `Expired`.
     */
    async userForSessionCookieValue(sessionCookieValue : string) : Promise<{key: Key, user: User|undefined}> {
        if (!this.session) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled");
        let {key, user} = await this.session.getUserForSessionKey(sessionCookieValue);
        return {key, user};
    }

    /**
     * Returns the data object for a session key, or undefined
     * 
     * If the user is undefined, or the key has expired, returns undefined.
     * 
     * @param sessionKey the session key to look up in session storage
     * @returns a string from the data field
     * @throws {@link index!CrossauthError} with {@link ErrorCode} of `Connection`,  `InvalidSessionId`
     *         `UserNotExist` or `Expired`.
     */
    async dataForSessionKey(sessionKey : string) : Promise<string|undefined> {
        if (!this.session) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled");
        let error : CrossauthError | undefined;
        try {
            let {key} = await this.session.getUserForSessionKey(sessionKey);
            return key.data;
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
                CrossauthLogger.logger.error(j({err: e}));
            }
            error = new CrossauthError(ErrorCode.UnknownError);
        }
        if (error) {
            CrossauthLogger.logger.debug(j({err: error}));
            throw error;
        }
    }
    
    /**
     * Creates and returns a signed CSRF token based on the session ID
     * @param sessionId the session ID
     * @returns a signed CSRF token
     */
    async createCsrfToken() : Promise<{csrfCookie : Cookie, csrfFormOrHeaderValue : string}> {
        if (!this.csrfTokens) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled"); // csrf tokens always created when using sessions
         this.csrfTokens.makeCsrfCookie(await this.csrfTokens.createCsrfToken());
         const csrfToken = this.csrfTokens.createCsrfToken();
         const csrfFormOrHeaderValue = this.csrfTokens.makeCsrfFormOrHeaderToken(csrfToken);
         const csrfCookie = this.csrfTokens.makeCsrfCookie(csrfToken);
         return {
            csrfCookie,
            csrfFormOrHeaderValue,
         }
     }

    /**
     * Creates and returns a signed CSRF token based on the session ID
     * @param sessionId the session ID
     * @returns a signed CSRF token
     */
    async createCsrfFormOrHeaderValue(csrfCookieValue : string) : Promise<string> {
        if (!this.csrfTokens) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled"); // csrf tokens always created when using sessions
        const csrfToken = this.csrfTokens.unsignCookie(csrfCookieValue);
        return this.csrfTokens.makeCsrfFormOrHeaderToken(csrfToken);
    }

    /**
     * Returns the user for a session key if it is valid, or undefined if ther is none,
     * 
     * Thows an exception if the session id is not valid
     * @param sessionCookieValue the value of the session id cookie
     * @returns user or undefined
     */
    async userForSessionKey(sessionCookieValue : string) : Promise<User|undefined> {
        if (!this.session) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled");
        return (await this.session.getUserForSessionKey(sessionCookieValue)).user;
    }

    /**
     * Throws {@link index!CrossauthError} with ErrorCode.InvalidKey if the passed CSRF token is not valid for the given
     * session ID.  Otherwise returns without error
     * @param token 
     */
    validateDoubleSubmitCsrfToken(csrfCookieValue : string|undefined, csrfFormOrHeaderValue : string|undefined) {
        if (!this.csrfTokens) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled"); // csrf tokens always created when using sessions
        if (!csrfCookieValue || !csrfFormOrHeaderValue) throw new CrossauthError(ErrorCode.InvalidKey, "CSRF missing from either cookie or form/header value");
        this.csrfTokens.validateDoubleSubmitCsrfToken(csrfCookieValue, csrfFormOrHeaderValue);
    }

    /**
     * Throws {@link index!CrossauthError} with ErrorCode.InvalidKey if the passed CSRF token is not valid for the given
     * session ID.  Otherwise returns without error
     * @param token 
     */
    validateCsrfCookie(csrfCookieValue : string) {
        if (!this.session || !this.csrfTokens) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled"); // csrf tokens always created when using sessions
        this.csrfTokens.validateCsrfCookie(csrfCookieValue);
    }

    /**
     * If sessionIdleTimeout is set, update the last activcity time in key storage to current time
     * @param sessionId the session Id to update.
     */
    async updateSessionActivity(sessionCookieValue : string) : Promise<void> {
        if (!this.session) return;
        const key = await this.session.getSessionKey(sessionCookieValue);
        if (this.session.idleTimeout > 0) {
            this.session.updateSessionKey({
                value: key.value,
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

    async deleteUserByUsername(username : string ) {
        this.userStorage.deleteUserByUsername(username);
    }

    /** Creates a user with TOTP enabled.
     * 
     * The user storage entry will be enabled and the passed session key will be updated to include the
     * username.  The userId and QR Url are returned.
     * @param username : the username to create
     * @param password : the unhashed password for the new user
     * @extraFIelds extra fields to insert into the new user entry
     * @param sessionId the current session id (anonymous session)
     * @return the new userId and the QR code to display
     */
    async initiateTotpSignup(
        username : string, 
        password : string, 
        extraFields : {[key : string]: string|number|boolean|Date|undefined},
        sessionCookieValue : string) : Promise<{userId: string|number, qrUrl: string, secret: string}> {
        if (!this.session || !this.totpManager) throw new CrossauthError(ErrorCode.Configuration, "Sessions and TOTP must be enabled for 2FA");
        const sessionId = this.session.unsignCookie(sessionCookieValue);
        const { qrUrl, secret } = await this.totpManager.createAndStoreSecret(username, sessionId);

        let passwordHash = await this.authenticator.createPasswordForStorage(password);
        extraFields = {...extraFields, state: "awaitingtotpsetup"};
        if (this.enableEmailVerification && this.tokenEmailer) {
            extraFields = {...extraFields, emailVerified: false};
        }
        const userId = await this.userStorage.createUser(username, passwordHash, extraFields);
        return {userId, qrUrl, secret}
        
    }

    async repeatTotpSignup(
        username : string, 
        sessionCookieValue : string) : Promise<{userId: string|number, qrUrl: string, secret: string}> {
        if (!this.session || !this.totpManager) throw new CrossauthError(ErrorCode.Configuration, "Sessions must be enabled for 2FA");
        const sessionId = this.session.unsignCookie(sessionCookieValue);
        const { qrUrl, secret} = await this.totpManager.getSecretFromSession(username, sessionId);

        const user = await this.userStorage.getUserByUsername(username, {skipActiveCheck: true, skipEmailVerifiedCheck: true});
        return {userId: user.id, qrUrl, secret}
        
    }
    
    async completeTotpSignup(code : string, sessionId : string) : Promise<User> {
        if (!this.session || !this.totpManager) throw new CrossauthError(ErrorCode.Configuration, "verify2FA called but sessions not enabled");
        let {user, key} = await this.session.getUserForSessionKey(sessionId);
        if (!key) throw new CrossauthError(ErrorCode.InvalidKey, "Session key not found");
        const { username, secret } = await this.totpManager.validateCodeFromKey(code, key);

        if (!user) user = await this.userStorage.getUserByUsername(username, {skipActiveCheck: true, skipEmailVerifiedCheck: true});
        const newUser = {
            id: user.id,
            state: "active",
            emailVerified: !this.enableEmailVerification,
            totpSecret: secret,
        }
        await this.userStorage.updateUser(newUser);
        if (this.enableEmailVerification && this.tokenEmailer) {
            await this.tokenEmailer?.sendEmailVerificationToken(user.id, undefined)
        }
        await this.keyStorage.updateKey({value: SessionCookie.hashSessionKey(key.value), data: ""});
        return {...user, ...newUser};
    }

    /** Enables TOTP for an existing user.
     * 
     * The user storage entry will be enabled and the passed session key will be updated to include the
     * username.  The userId and QR Url are returned.
     * @param userId : the user id to update
     * @param username : the username to update
     * @param sessionId the current session id
     * @return the new userId and the QR code to display
     */
    async initiateTotpEnable(
        userId : string|number, username : string, 
        sessionCookieValue : string) : Promise<string> {
        if (!this.session || !this.totpManager) throw new CrossauthError(ErrorCode.Configuration, "Sessions must be enabled for 2FA");
        const sessionId = this.session.unsignCookie(sessionCookieValue);
        const { qrUrl, secret } = await this.totpManager.createAndStoreSecret(username, sessionId);

        await this.userStorage.updateUser({id: userId, totpSecret: secret});

        return qrUrl
        
    }

    async completeTotpEnable(code : string, sessionId : string) : Promise<User> {
        if (!this.session || !this.totpManager) throw new CrossauthError(ErrorCode.Configuration, "verify2FA called but sessions and/or TOTP not enabled");
        let {user, key} = await this.session.getUserForSessionKey(sessionId);
        if (!key) throw new CrossauthError(ErrorCode.InvalidKey, "Session key not found");
        const { username, secret } = await this.totpManager.validateCodeFromKey(code, key);
        if (!user) user = await this.userStorage.getUserByUsername(username, {skipActiveCheck: true, skipEmailVerifiedCheck: true});
        const newUser = {
            id: user.id,
            state: "active",
            totpSecret: secret,
        }
        await this.userStorage.updateUser(newUser);
        await this.keyStorage.updateKey({value: SessionCookie.hashSessionKey(key.value), data: ""});
        return {...user, ...newUser};
    }

    /** Disables TOTP for an existing user
     * 
     * The user storage entry will be enabled and the passed session key will be updated to include the
     * username.  The userId and QR Url are returned.
     * @param userId : the user id to update
     */
    async disableTotp(
        userId : string|number) {
        if (!this.session) throw new CrossauthError(ErrorCode.Configuration, "Sessions and TOTP must be enabled for 2FA");

        await this.userStorage.updateUser({id: userId, totpSecret: ""});
    }

    async initiateTotpLogin(
        user : User) : Promise<{sessionCookie: Cookie, csrfCookie: Cookie, csrfForOrHeaderValue: string}>  {
        if (!this.session || !this.csrfTokens) throw new CrossauthError(ErrorCode.Configuration, "Sessions and TOTP must be enabled for 2FA");
        const {sessionCookie} = await this.createAnonymousSession({data: JSON.stringify({username: user.username, totpInitiated: true})});
        const csrfToken = this.csrfTokens.createCsrfToken();
        const csrfCookie = this.csrfTokens.makeCsrfCookie(csrfToken);
        const csrfForOrHeaderValue = this.csrfTokens.makeCsrfFormOrHeaderToken(csrfToken);

        return {
            sessionCookie: sessionCookie,
            csrfCookie: csrfCookie,
            csrfForOrHeaderValue: csrfForOrHeaderValue,
        }
        
    }

    async completeTotpLogin(code : string, sessionCookieValue : string, extraFields : {[key:string]:any} = {}, persist? : boolean) : Promise<{sessionCookie: Cookie, csrfCookie: Cookie, csrfForOrHeaderValue: string, user: User}> {
        if (!this.session|| !this.csrfTokens || !this.totpManager) throw new CrossauthError(ErrorCode.Configuration, "Sessions and TOTP must be enabled for 2FA");
        console.log("completeTotpLogin", sessionCookieValue);
        let {key} = await this.session.getUserForSessionKey(sessionCookieValue);
        if (!key || !key.data || key.data == "") throw new CrossauthError(ErrorCode.Unauthorized);
        let { username } = getJsonData(key);
        const user = await this.userStorage.getUserByUsername(username);
        await this.totpManager.validateCodeFromUser(code, user);

        const newSessionKey = await this.session.createSessionKey(user.id, extraFields);
        await this.keyStorage.deleteKey(SessionCookie.hashSessionKey(key.value));
        const sessionCookie = this.session.makeCookie(newSessionKey, persist);

        const csrfToken = this.csrfTokens.createCsrfToken();
        const csrfCookie = this.csrfTokens.makeCsrfCookie(csrfToken);
        const csrfForOrHeaderValue = this.csrfTokens.makeCsrfFormOrHeaderToken(csrfToken);
        try {
            this.keyStorage.deleteAllForUser(user.id, "p:");
        } catch (e) {
            CrossauthLogger.logger.warn(j({msg: "Couldn't delete password reset tokens while logging in", user: username}));
            CrossauthLogger.logger.debug(j({err: e}));
        }
        return {
            sessionCookie: sessionCookie,
            csrfCookie: csrfCookie,
            csrfForOrHeaderValue: csrfForOrHeaderValue,
            user: user
        }
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
        let user = await this.userStorage.getUserById(userId, {skipEmailVerifiedCheck: true});
        let oldEmail;
        if ("email" in user && user.email != undefined) {
            oldEmail = user.email;
        } else {
            oldEmail = user.username;
        }
        let newUser : Partial<User> = {
            id: user.id,
            emailVerified: true,
        }
        if (newEmail != "") {
            newUser.email = newEmail;
        } else {
            oldEmail = undefined;
        }
        await this.userStorage.updateUser(newUser);
        return {...user, ...newUser, oldEmail: oldEmail};
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

        // delete any password reset tokens
        try {
            this.keyStorage.deleteAllForUser(user.id, "p:");
        } catch (e) {
            CrossauthLogger.logger.warn(j({msg: "Couldn't delete password reset tokens while logging in", user: username}));
            CrossauthLogger.logger.debug(j({err: e}));
        }

        return user;
    }

    async updateUser(currentUser: User, newUser : User) : Promise<boolean> {
        let newEmail = undefined;
        if (!("id" in currentUser) || currentUser.id == undefined) {
            throw new CrossauthError(ErrorCode.UserNotExist, "Please specify a user id");
        }
        if (!("username" in currentUser) || currentUser.username == undefined) {
            throw new CrossauthError(ErrorCode.UserNotExist, "Please specify a userername");
        }
        let { email, username, passwordHash, ...rest} = newUser;
        rest.userId = currentUser.userId;
        let hasEmail = false;
        if (email) {
            newEmail = email;
            TokenEmailer.validateEmail(newEmail);
            hasEmail = true;
        } else if (username) {
            newEmail = username;
            try {
                TokenEmailer.validateEmail(currentUser.username);
                hasEmail = true;
            } catch {} // not in email format - can ignore
            if (hasEmail) {
                TokenEmailer.validateEmail(newEmail);
            }
        }
        if (this.enableEmailVerification && hasEmail) {
            await this.tokenEmailer?.sendEmailVerificationToken(currentUser.id, newEmail);
        } else {
            if (email) rest.email = email;
            if (username) rest.username = username;
        }
        await this.userStorage.updateUser(rest)
        return this.enableEmailVerification && hasEmail;
    }

    async resetPassword(token : string, newPassword : string) : Promise<User> {
        if (!this.tokenEmailer) throw new CrossauthError(ErrorCode.Configuration, "Password reset not enabled");

        const user = await this.userForPasswordResetToken(token);
        if (!this.tokenEmailer) throw new CrossauthError(ErrorCode.Configuration);
        await this.userStorage.updateUser({
            id: user.id,
            passwordHash: await this.authenticator.createPasswordForStorage(newPassword),
        })
        //this.keyStorage.deleteKey(TokenEmailer.hashPasswordResetToken(token));

        // delete all password reset tokens
        try {
            this.keyStorage.deleteAllForUser(user.id, "p:");
        } catch (e) {
            CrossauthLogger.logger.warn(j({msg: "Couldn't delete password reset tokens while logging in", user: user.username}));
            CrossauthLogger.logger.debug(j({err: e}));
        }

        return user;
    }

}