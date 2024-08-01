//import { getJsonData } from '@crossauth/common';
import type {
    User,
    UserSecrets,
    Key,
    UserInputFields,
    UserSecretsInputFields } from '@crossauth/common';
import {
    ErrorCode,
    CrossauthError,
    KeyPrefix,
    UserState } from '@crossauth/common';
import { UserStorage, KeyStorage } from './storage.ts';
import { type AuthenticationParameters, Authenticator } from './auth.ts';
import type { LocalPasswordAuthenticatorOptions }  from "./authenticators/passwordauth.ts";
import { TokenEmailer, type TokenEmailerOptions } from './emailtokens.ts';
import { CrossauthLogger, j } from '@crossauth/common';
import { type Cookie, DoubleSubmitCsrfToken, SessionCookie } from './cookieauth.ts';
import type { DoubleSubmitCsrfTokenOptions, SessionCookieOptions } from './cookieauth.ts';
import { setParameter, ParamType } from './utils.ts';
import { Crypto } from './crypto.ts';

/**
 * Options for {@link SessionManager}
 */
export interface SessionManagerOptions extends TokenEmailerOptions {

    /** options for csrf cookie manager */
    doubleSubmitCookieOptions? : DoubleSubmitCsrfTokenOptions,

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

    /**
     * Store for password reset and email vcerification tokens.  If not passed, the same store as
     * for sessions is used.
     */
    emailTokenStorage? : KeyStorage,

    /**
     * Base URL for the site.
     * 
     * This is used when constructing URLs, eg for sending password reset
     * tokens.
     */
    siteUrl? : string,

    /**
     * Set of 2FA factor names a user is allowed to set.
     * 
     * The name corresponds to the key you give when adding authenticators.
     * See `authentiators` in {@link SessionManager.constructor}.
     */
    allowedFactor2? : string[],
}

/**
 * Class for managing sessions.
 */
export class SessionManager {
    userStorage : UserStorage;
    keyStorage : KeyStorage;
    emailTokenStorage : KeyStorage;
    readonly csrfTokens : DoubleSubmitCsrfToken;
    private session : SessionCookie;
    readonly authenticators : {[key:string] : Authenticator};
    //readonly authenticator : UsernamePasswordAuthenticator;

    private enableEmailVerification : boolean = false;
    private enablePasswordReset : boolean = false;
    private tokenEmailer? : TokenEmailer;
    allowedFactor2 : string[] = [];

    /**
     * Constructor
     * @param userStorage the {@link UserStorage} instance to use, eg {@link PrismaUserStorage}.
     * @param keyStorage  the {@link KeyStorage} instance to use, eg {@link PrismaKeyStorage}.
     * @param authenticators authenticators used to validate users, eg {@link LocalPasswordAuthenticatorOptions }.
     * @param options optional parameters for authentication. See {@link SessionManagerOptions }.
     */
    constructor(
        userStorage : UserStorage, 
        keyStorage : KeyStorage, 
        authenticators : {[key:string] : Authenticator},
        options : SessionManagerOptions = {}) {

        this.userStorage = userStorage;
        this.keyStorage = keyStorage;
        this.authenticators = authenticators;
        for (let authenticationName in this.authenticators) {
            this.authenticators[authenticationName].factorName = authenticationName;
        }


        this.session = new SessionCookie(this.userStorage, this.keyStorage, {...options?.sessionCookieOptions, ...options??{}});
        this.csrfTokens = new DoubleSubmitCsrfToken({...options?.doubleSubmitCookieOptions, ...options??{}});

        setParameter("allowedFactor2", ParamType.JsonArray, this, options, "ALLOWED_FACTOR2");
        setParameter("enableEmailVerification", ParamType.Boolean, this, options, "ENABLE_EMAIL_VERIFICATION");
        setParameter("enablePasswordReset", ParamType.Boolean, this, options, "ENABLE_PASSWORD_RESET");
        this.emailTokenStorage = this.keyStorage;
        if (this.enableEmailVerification || this.enablePasswordReset) {
            let keyStorage = this.keyStorage;
            if (options.emailTokenStorage) this.emailTokenStorage = options.emailTokenStorage;
            this.tokenEmailer = new TokenEmailer(this.userStorage, keyStorage, options);
        }
    }

    /**
     * Returns the name used for session ID cookies.
     */
    get sessionCookieName() : string {
        return this.session.cookieName;
    }

    /**
     * Returns the name used for session ID cookies.
     */
        get sessionCookiePath() : string {
            return this.session.path;
        }
    
    /**
     * Returns the name used for CSRF token cookies.
     */
    get csrfCookieName() : string {
        return this.csrfTokens.cookieName;
    }

    /**
     * Returns the name used for CSRF token cookies.
     */
    get csrfCookiePath() : string {
        return this.csrfTokens.path;
    }

    /**
     * Returns the name used for CSRF token cookies.
     */
    get csrfHeaderName() : string {
        return this.csrfTokens.headerName;
    }

    /**
     * Performs a user login
     * 
     *    * Authenticates the username and password
     *    * Creates a session key - if 2FA is enabled, this is an anonymous session,
     *      otherwise it is bound to the user
     *    * Returns the user (without the password hash) and the session cookie.
     * If the user object is defined, authentication (and 2FA) is bypassed
     * @param username the username to validate
     * @param params user-provided credentials (eg password) to authenticate with
     * @param extraFields add these extra fields to the session key if authentication is successful
     * @param persist if passed, overrides the persistSessionId setting.
     * @param user if this is defined, the username and password are ignored and the given user is logged in.
     *             The 2FA step is also skipped
     * @param bypass2FA if true, the 2FA step will be skipped
     * @returns the user, user secrets, and session cookie and CSRF cookie and token.
     *          if a 2fa step is needed, it will be an anonymouos session, otherwise bound to the user
     * @throws {@link @crossauth/common!CrossauthError} with 
     *         {@link @crossauth/common!ErrorCode} of `Connection`, `UserNotValid`, 
     *         `PasswordNotMatch` or `UserNotExist`.
     */
    async login(username: string,
        params: AuthenticationParameters,
        extraFields: { [key: string]: any } = {},
        persist?: boolean,
        user?: User,
        bypass2FA : boolean = false) 
        : Promise<{
            sessionCookie: Cookie,
            csrfCookie: Cookie,
            csrfFormOrHeaderValue: string,
            user: User,
            secrets: UserSecrets,
        }> {

        let secrets : UserSecrets;
        if (!user) {
            let userAndSecrets = await this.userStorage.getUserByUsername(username, {skipActiveCheck: true, skipEmailVerifiedCheck: true});
            secrets = userAndSecrets.secrets;
            user = userAndSecrets.user;
            if (!user) throw new CrossauthError(ErrorCode.UserNotExist);
            await this.authenticators[user.factor1].authenticateUser(user, secrets, params);
        } else {
            let userAndSecrets = await this.userStorage.getUserByUsername(user.username, {skipActiveCheck: true, skipEmailVerifiedCheck: true});
            secrets = userAndSecrets.secrets;

        }

        // create a session ID - bound to user if no 2FA and no password change required, anonymous otherwise
        let sessionCookie : Cookie;
        if (user.state == UserState.passwordChangeNeeded) {
            // create an anonymous session and store the username and 2FA data in it
            const resp = await this.createAnonymousSession({data: JSON.stringify({"passwordchange": {username: user.username}})});
            sessionCookie = resp.sessionCookie;
        } else if (user.state == UserState.factor2ResetNeeded) {
            const resp = await this.createAnonymousSession({data: JSON.stringify({"factor2change": {username: user.username}})});
            sessionCookie = resp.sessionCookie;
        } else if (!bypass2FA && user.factor2 && user.factor2 != "") {
            // create an anonymous session and store the username and 2FA data in it
            const { sessionCookie: newSesionCookie } = await this.initiateTwoFactorLogin(user);
            sessionCookie = newSesionCookie;
        } else {
            const sessionKey = await this.session.createSessionKey(user.id, extraFields);
            //await this.sessionStorage.saveSession(user.id, sessionKey.value, sessionKey.dateCreated, sessionKey.expires);
            sessionCookie = this.session.makeCookie(sessionKey, persist);
        }

        // create a new CSRF token, since we have a new session
        const csrfToken = this.csrfTokens.createCsrfToken();
        const csrfCookie = this.csrfTokens.makeCsrfCookie(csrfToken);
        const csrfFormOrHeaderValue = this.csrfTokens.makeCsrfFormOrHeaderToken(csrfToken);

        // delete any password reset tokens that still exist for this user.
        try {
            this.emailTokenStorage.deleteAllForUser(user.id, 
                KeyPrefix.passwordResetToken);
        } catch (e) {
            CrossauthLogger.logger.warn(j({msg: "Couldn't delete password reset tokens while logging in", user: username}));
            CrossauthLogger.logger.debug(j({err: e}));
        }

        // send back the cookies and user details
        return {
            sessionCookie: sessionCookie,
            csrfCookie: csrfCookie,
            csrfFormOrHeaderValue: csrfFormOrHeaderValue,
            user: user,
            secrets: secrets,
        }
    }

    /**
     * If a valid session key does not exist, create and store an anonymous one.
     * 
     * @param extraFields these will be added to the created session object.
     * @returns a cookie with the session ID, a cookie with the CSRF token
     *          and the CSRF value to put in the form or header value.
     */
    async createAnonymousSession(extraFields: {[key: string]: any} = {}) 
    : Promise<{sessionCookie: Cookie, csrfCookie: Cookie, csrfFormOrHeaderValue: string}> {

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
     * 
     * @param sessionId the session ID to remove.
     * @throws {@link @crossauth/common!CrossauthError} with 
     *         {@link @crossauth/common!ErrorCode} of `Connection`
     */
    async logout(sessionId : string) : Promise<void> {
        const key = await this.session.getSessionKey(sessionId);
        return await this.keyStorage.deleteKey(SessionCookie.hashSessionId(key.value));
    }

    /**
     * Logs a user out from all sessions.
     * 
     * Removes the given session ID from the session storage.
     * 
     * @param except Don't log out from the matching session.
     * @throws {@link @crossauth/common!CrossauthError} with 
     *         {@link @crossauth/common!ErrorCode} of `Connection`
     */
    async logoutFromAll(userId : string | number, except? : string|undefined) : 
        Promise<void> {
        /*await*/ return this.session.deleteAllForUser(userId, except);
    }
    
    /**
     * Returns the user (without secrets) matching the given session key.
     * 
     * If the user is undefined, or the key has expired, returns undefined.
     * 
     * @param sessionId the session key to look up in session storage
     * @returns the {@link User} (without password hash) matching the  session key
     * @throws {@link @crossauth/common!CrossauthError} with 
     *         {@link @crossauth/common!ErrorCode} of `Connection`,  
     *         `InvalidSessionId`
     *         `UserNotExist` or `Expired`.
     */
    async userForSessionId(sessionId : string) : 
        Promise<{key: Key, user: User|undefined}> {
        return await this.session.getUserForSessionId(sessionId);
    }

    /**
     * Returns the data object for a session key, or undefined, as a JSON string 
     * (which is how it is stored in the session table)
     * 
     * If the user is undefined, or the key has expired, returns undefined.
     * 
     * @param sessionId the session id to look up in session storage
     * @returns a string from the data field
     * @throws {@link @crossauth/common!CrossauthError} with 
     *         {@link @crossauth/common!ErrorCode} of `Connection`,  `InvalidSessionId`
     *         `UserNotExist` or `Expired`.
     */
    async dataStringForSessionId(sessionId : string) : 
        Promise<string|undefined> {
        try {
            let {key} = await this.session.getUserForSessionId(sessionId);
            return key.data;
        } catch (e) {
            let ce = CrossauthError.asCrossauthError(e);
            switch (ce.code) {
                case ErrorCode.Expired:
                    return undefined;
                    break;
                default:
                    throw ce;
            }
            throw ce;
        }
    }

    /**
     * Returns the data object for a session id, or undefined, as an object.
     * 
     * If the user is undefined, or the key has expired, returns undefined.
     * 
     * @param sessionId the session key to look up in session storage
     * @returns a string from the data field
     * @throws {@link @crossauth/common!CrossauthError} with 
     *         {@link @crossauth/common!ErrorCode} of `Connection`,  `InvalidSessionId`
     *         `UserNotExist` or `Expired`.
     */
    async dataForSessionId(sessionId : string) : Promise<{[key:string]:any}> {
        const str = await this.dataStringForSessionId(sessionId);
        if (!str || str.length == 0) return {};
        return JSON.parse(str);
    }

    
    /**
     * Creates and returns a signed CSRF token based on the session ID
     * @returns a CSRF cookie and value to put in the form or CSRF header
     */
    async createCsrfToken() : 
        Promise<{csrfCookie : Cookie, csrfFormOrHeaderValue : string}> {
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
     * Validates the signature on the CSRF cookie value and returns a
     * value that can be put in the form or CSRF header value.
     * 
     * @param csrfCookieValue the value from the CSRF cookie
     * @returns the value to put in the form or CSRF header
     */
    async createCsrfFormOrHeaderValue(csrfCookieValue : string) : Promise<string> {
        const csrfToken = this.csrfTokens.unsignCookie(csrfCookieValue);
        return this.csrfTokens.makeCsrfFormOrHeaderToken(csrfToken);
    }

    /**
     * Returns the session ID from the signed session cookie value
     * 
     * @param sessionCookieValue value from the session ID cookie
     * @returns the usigned cookie value.
     * @throws {@link @crossauth/common!CrossauthError} with `InvalidKey`
     *         if the signature is invalid.
     */
    getSessionId(sessionCookieValue : string) : string {
        return this.session.unsignCookie(sessionCookieValue);
    }

    /**
     * Throws {@link @crossauth/common!CrossauthError} with 
     * `InvalidKey` if the passed CSRF token is not valid for the given
     * session ID.  Otherwise returns without error
     * 
     * @param csrfCookieValue the CSRF cookie value
     * @param csrfFormOrHeaderValue the value from the form field or
     *        CSRF header
     */
    validateDoubleSubmitCsrfToken(csrfCookieValue : string|undefined, csrfFormOrHeaderValue : string|undefined) {
        if (!csrfCookieValue || !csrfFormOrHeaderValue) throw new CrossauthError(ErrorCode.InvalidCsrf, "CSRF missing from either cookie or form/header value");
        this.csrfTokens.validateDoubleSubmitCsrfToken(csrfCookieValue, csrfFormOrHeaderValue);
    }

    /**
     * Throws {@link @crossauth/common!CrossauthError} with `InvalidKey` if 
     * the passed CSRF cookie value is not valid (ie invalid signature)
     * @param csrfCookieValue the CSRF cookie value 
     */
    validateCsrfCookie(csrfCookieValue : string) {
        this.csrfTokens.validateCsrfCookie(csrfCookieValue);
    }

    /**
     * If sessionIdleTimeout is set, update the last activcity time in key 
     * storage to current time.
     * 
     * @param sessionId the session Id to update.
     */
    async updateSessionActivity(sessionId : string) : Promise<void> {
        const {key} = await this.session.getSessionKey(sessionId);
        if (this.session.idleTimeout > 0) {
            this.session.updateSessionKey({
                value: key.value,
                lastActive: new Date(),
            });
        }
    }

    /**
     * Update a field in the session data.
     * 
     * The `data` field in the session entry is assumed to be a JSON string.
     * The field with the given name is updated or set if not already set.
     * @param sessionId the session Id to update.
     * @param name of the field.
     * @param value new value to store
     */
    async updateSessionData(sessionId: string,
        name: string,
        value: { [key: string]: any }) : Promise<void> {
        //const sessionId = this.session.unsignCookie(sessionCookieValue);
        const hashedSessionKey = SessionCookie.hashSessionId(sessionId);
        CrossauthLogger.logger.debug(j({msg: `Updating session data value${name}`, hashedSessionCookie: Crypto.hash(sessionId)}));
        await this.keyStorage.updateData(hashedSessionKey, name, value);
    }
    
    /**
     * Deletes the given session ID from the key storage (not the cookie)
     * 
     * @param sessionId the session Id to delete
     */
    async deleteSession(sessionId : string) : Promise<void> {
        //const sessionId = this.session.unsignCookie(sessionCookieValue)
        return await this.keyStorage.deleteKey(SessionCookie.hashSessionId(sessionId));
    }

    /**
     * Creates a new user, sending an email verification message if necessary.
     *  
     * If email verification is enabled, the user's state is set to
     * `awaitingemailverification`. Otherwise it is set to `active`.
     * 
     * @param user fields to put in the new entry
     * @param params parameters to pass to the relevant factor 1 authenticator.
     * @param repeatParams if this is set, an exception will be raised if
     *        the values here to not match those in `params`.
     * @param skipEmailVerification if true, email verification will not be
     *        performed
     * @returns the new user
     */
    async createUser(user: UserInputFields,
        params: AuthenticationParameters,
        repeatParams?: AuthenticationParameters,
        skipEmailVerification: boolean = false,
        emptyPassword = false)
        : Promise<User> {
        if (!(this.authenticators[user.factor1])) throw new CrossauthError(ErrorCode.Configuration, "Authenticator cannot create users");
        if (this.authenticators[user.factor1].skipEmailVerificationOnSignup() == true) {
            skipEmailVerification = true;
        }
        let secrets = emptyPassword ? undefined : await this.authenticators[user.factor1].createPersistentSecrets(user.username, params, repeatParams);
        const newUser = emptyPassword ? await this.userStorage.createUser(user) : await this.userStorage.createUser(user, secrets);
        if (!skipEmailVerification && this.enableEmailVerification && this.tokenEmailer) {
            await this.tokenEmailer?.sendEmailVerificationToken(newUser.id, undefined);
        }
        return newUser;
    }

    /**
     * Deletes the user matching the given username
     * @param username user to delete
     */
    async deleteUserByUsername(username : string ) {
        this.userStorage.deleteUserByUsername(username);
    }

    /** Creates a user with 2FA enabled.
     * 
     * The user storage entry will be createed, with the state set to
     * `awaitingtwofactorsetup`.   The passed session key will be updated to 
     * include the username and details needed by 2FA during the configure step.  
     * @param user : details to save in the user table
     * @param params : params the parameters needed to authenticate with factor1
     *                   (eg password)
     * @param sessionId the anonymous session cookie 
     * @param repeatParams if passed, these will be compared with `params` and
     *                     if they don't match, `PasswordMatch` is thrown.
     * @return `userId` the id of the created user.  
     *         `userData` data that can be displayed to the user in the page to 
     *          complete 2FA set up (eg the secret key and QR codee for TOTP),
     * 
     */
    async initiateTwoFactorSignup(
        user : UserInputFields, 
        params : AuthenticationParameters, 
        sessionId : string,
        repeatParams? : AuthenticationParameters) : 
            Promise<{userId: string|number, userData : {[key:string] : any}}> {
        if (!this.authenticators[user.factor1]) throw new CrossauthError(ErrorCode.Configuration, "Authenticator cannot create users");
        if (!this.authenticators[user.factor2]) throw new CrossauthError(ErrorCode.Configuration, "Two factor authentication not enabled for user");
        const authenticator = this.authenticators[user.factor2];
        //const sessionId = this.session.unsignCookie(sessionCookieValue);
        const factor2Data = await authenticator.prepareConfiguration(user);
        const userData = (factor2Data == undefined) ? {} : factor2Data.userData;
        const sessionData = (factor2Data == undefined) ? {} : factor2Data.sessionData;

        const factor1Secrets = await this.authenticators[user.factor1].createPersistentSecrets(user.username, params, repeatParams);
        user.state = "awaitingtwofactorsetup";
        await this.keyStorage.updateData(
            SessionCookie.hashSessionId(sessionId), 
            "2fa",
            sessionData);

        const newUser = await this.userStorage.createUser(user, factor1Secrets);  
        return {userId: newUser.id, userData};
    }

    /**
     * Begins the process of setting up 2FA for a user which has already been 
     * created and activated.  Called when changing 2FA or changing its parameters.
     * @param user the logged in user
     * @param newFactor2 new second factor to change user to
     * @param sessionId the session cookie for the user
     * @returns the 2FA data that can be displayed to the user in the confifugre 2FA
     *          step (such as the secret and QR code for TOTP).
     */
    async initiateTwoFactorSetup(
        user : User, 
        newFactor2 : string|undefined,
        sessionId : string) : Promise<{[key:string] : any}> {
        //const sessionId = this.session.unsignCookie(sessionCookieValue);
        if (newFactor2 && newFactor2 != "none") {
            if (!this.authenticators[newFactor2]) throw new CrossauthError(ErrorCode.Configuration, "Two factor authentication not enabled for user");
            const authenticator = this.authenticators[newFactor2];
            const factor2Data = await authenticator.prepareConfiguration(user);
            const userData = (factor2Data == undefined) ? {} : factor2Data.userData;
            const sessionData = (factor2Data == undefined) ? {} : factor2Data.sessionData;

            await this.keyStorage.updateData(
                SessionCookie.hashSessionId(sessionId),
                "2fa",
                sessionData);
            return userData;
        } 

        // this part is for turning off 2FA
        await this.userStorage.updateUser({id: user.id, factor2: newFactor2??""});
        await this.keyStorage.updateData(
            SessionCookie.hashSessionId(sessionId), 
            "2fa",
            undefined);
        return {};



    }

    /**
     * This can be called if the user has finished signing up with factor1 but
     * closed the browser before completing factor2 setup.  Call it if the user
     * signs up again with the same factor1 credentials.
     * @param sessionId the anonymous session ID for the user
     * @returns `userId` the id of the created user
     *          `userData` data that can be displayed to the user in the page to 
     *           complete 2FA set up (eg the secret key and QR codee for TOTP),
     *          `secrets` data that is saved in the session for factor2.  In the
     *          case of TOTP, both `userData` and `secrets` contain the shared
     *          secret but only `userData` has the QR code, since it can be
     *          generated from the shared secret.
     */
    async repeatTwoFactorSignup(sessionId: string) :
        Promise<{
            userId: string | number,
            userData: { [key: string]: any },
            secrets: Partial<UserSecretsInputFields>
        }> {
        const sessionData = (await this.dataForSessionId(sessionId))["2fa"];
        const username = sessionData.username;
        const factor2 = sessionData.factor2;
        //const sessionId = this.session.unsignCookie(sessionId);
        const hashedSessionKey = SessionCookie.hashSessionId(sessionId);
        const sessionKey = await this.keyStorage.getKey(hashedSessionKey);
        const authenticator = this.authenticators[factor2];

        const resp = await authenticator.reprepareConfiguration(username, sessionKey);
        const userData = (resp == undefined) ? {} : resp.userData;
        const secrets = (resp == undefined) ? {} : resp.secrets;
        const newSessionData = (resp == undefined) ? {} : resp.newSessionData;
        if (newSessionData) {
            await this.keyStorage.updateData(hashedSessionKey, "2fa", newSessionData);
        }

        const {user} = await this.userStorage.getUserByUsername(username, {skipActiveCheck: true, skipEmailVerifiedCheck: true});
        return {userId: user.id, userData, secrets};      
    }
  
    /**
     * Authenticates with the second factor.  
     * 
     * If successful, the new user object is returned.  Otherwise an exception
     * is thrown,
     * @param params the parameters from user input needed to authenticate (eg TOTP code)
     * @param sessionId the session cookie value (ie still signed)
     * @returns the user object
     * @throws {@link @crossauth/common!CrossauthError} if authentication fails.
     */
    async completeTwoFactorSetup(params: AuthenticationParameters,
        sessionId: string) : Promise<User> {
        let newSignup = false;
        let {user, key} = 
            await this.session.getUserForSessionId(sessionId, {
                skipActiveCheck: true
            });
        if (user && (user.state != UserState.active && user.state != UserState.factor2ResetNeeded)) {
            throw new CrossauthError(ErrorCode.UserNotActive);
        }
        if (!key) throw new CrossauthError(ErrorCode.InvalidKey, "Session key not found");
        let data = KeyStorage.decodeData(key.data)["2fa"];
        //let data = getJsonData(key)["2fa"];
        if (!data?.factor2 || !data?.username) throw new CrossauthError(ErrorCode.Unauthorized, "Two factor authentication not initiated");
        let username = data.username;
        const authenticator = this.authenticators[data.factor2];
        if (!authenticator) throw new CrossauthError(ErrorCode.Configuration, "Unrecognised second factor authentication");
        const newSecrets : {[key:string] : any} = {};
        const secretNames = authenticator.secretNames();
        for (let secret in data) {
            if (secretNames.includes(secret)) newSecrets[secret] = data[secret];
        }
        await authenticator.authenticateUser(undefined, data, params);

        if (!user) {
            newSignup = true;
            const resp = await this.userStorage.getUserByUsername(username, {skipActiveCheck: true, skipEmailVerifiedCheck: true});
            user = resp.user;
        }
        const skipEmailVerification = authenticator.skipEmailVerificationOnSignup() == true;
        if (!user) throw new CrossauthError(ErrorCode.UserNotExist, "Couldn't fetch user");
        const newUser = {
            id: user.id,
            state: !skipEmailVerification && this.enableEmailVerification ? "awaitingemailverification" : "active",
            factor2: data.factor2,
        }
        await this.userStorage.updateUser(newUser, newSecrets);
        if (!skipEmailVerification && newSignup && this.enableEmailVerification && this.tokenEmailer) {
            await this.tokenEmailer?.sendEmailVerificationToken(user.id, undefined)
        }
        await this.keyStorage.updateData(SessionCookie.hashSessionId(key.value), "2fa", undefined);
        return {...user, ...newUser};
    }

    /**
     * Initiates the two factor login process.
     * 
     * Creates an anonymous session and coorresponding CSRF token
     * @param user the user, which should aleady have been authenticated with factor1
     * @returns a new anonymous session cookie and corresponding CSRF cookie and token.
     */
    private async initiateTwoFactorLogin(
        user: User): Promise<{
            sessionCookie: Cookie,
            csrfCookie: Cookie,
            csrfFormOrHeaderValue: string
        }>  {
        const authenticator = this.authenticators[user.factor2];
        const secrets = await authenticator.createOneTimeSecrets(user);
        const {sessionCookie} = await this.createAnonymousSession({data: JSON.stringify({"2fa": {username: user.username, twoFactorInitiated: true, factor2: user.factor2, ...secrets}})});
        const csrfToken = this.csrfTokens.createCsrfToken();
        const csrfCookie = this.csrfTokens.makeCsrfCookie(csrfToken);
        const csrfFormOrHeaderValue = this.csrfTokens.makeCsrfFormOrHeaderToken(csrfToken);

        return {
            sessionCookie: sessionCookie,
            csrfCookie: csrfCookie,
            csrfFormOrHeaderValue: csrfFormOrHeaderValue,
        }
        
    }

    /**
     * Initiates the two factor process when visiting a protected page.
     * 
     * Creates an anonymous session and coorresponding CSRF token
     * @param user the user, which should aleady have been authenticated with factor1
     * @param sessionId the logged in session associated with the user
     * @param requestBody the parameters from the request made before being redirected to factor2 authentication
     * @param url the requested url, including path and query parameters
     * @returns If a token was passed a new anonymous session cookie and 
     *          corresponding CSRF cookie and token.
     */
    async initiateTwoFactorPageVisit(
        user : User,
        sessionId : string,
        requestBody : {[key:string]: any},
        url: string | undefined,
        contentType? : string): Promise<{
            sessionCookie: Cookie | undefined,
            csrfCookie: Cookie | undefined,
            csrfFormOrHeaderValue: string | undefined
        }>  {
        const authenticator = this.authenticators[user.factor2];
        const secrets = await authenticator.createOneTimeSecrets(user);

        let sessionCookie : Cookie|undefined;
        let csrfCookie : Cookie|undefined;
        let csrfFormOrHeaderValue : string|undefined;
        
        //const sessionId = this.session.unsignCookie(sessionCookieValue);
        const hashedSessionId = SessionCookie.hashSessionId(sessionId);
        CrossauthLogger.logger.debug("initiateTwoFactorPageVisit " + user.username + " " + sessionId + " " + hashedSessionId);
        let newData : {[key:string]:any} = {username: user.username, factor2: user.factor2, secrets: secrets, body: requestBody, url: url};
        if (contentType) newData["content-type"] = contentType;
        await this.keyStorage.updateData(hashedSessionId, "pre2fa", newData);

        return {
            sessionCookie: sessionCookie,
            csrfCookie: csrfCookie,
            csrfFormOrHeaderValue: csrfFormOrHeaderValue,
        }
    }

    /**
     * Completes 2FA when visiting a protected page.  
     * 
     * If successful, returns.  Otherwise an exception is thrown.
     * @param params the parameters from user input needed to authenticate 
     *        (eg TOTP code).  Passed to the authenticator
     * @param sessionId the session cookie value (ie still signed)
     * @throws {@link @crossauth/common!CrossauthError} if authentication fails.
     */
    async completeTwoFactorPageVisit(params: AuthenticationParameters,
        sessionId: string) : Promise<void> {
        let {key} = await this.session.getUserForSessionId(sessionId);
        if (!key) throw new CrossauthError(ErrorCode.InvalidKey, "Session key not found");
        let data = KeyStorage.decodeData(key.data);
        // let data = getJsonData(key);
        if (!("pre2fa" in data)) throw new CrossauthError(ErrorCode.Unauthorized, "Two factor authentication not initiated");
        const {secrets} = await this.userStorage.getUserByUsername(data.pre2fa.username);

        const authenticator = this.authenticators[data.pre2fa.factor2];
        if (!authenticator) throw new CrossauthError(ErrorCode.Configuration, "Unrecognised second factor authentication");
        const newSecrets : {[key:string] : any} = {};
        const secretNames = authenticator.secretNames();
        for (let secret in secrets) {
            //if (secretNames.includes(secret)) newSecrets[secret] = data[secret];
            if (secretNames.includes(secret) && secret in secrets) newSecrets[secret] = secrets[secret];
        }
        await authenticator.authenticateUser(undefined, {...newSecrets, ...data.pre2fa.secrets}, params);
        await this.keyStorage.updateData(SessionCookie.hashSessionId(key.value), "pre2fa", undefined);
    }

    /**
     * Cancels the 2FA that was previously initiated but not completed..  
     * 
     * If successful, returns.  Otherwise an exception is thrown.
     * @param sessionId the session id (unsigned)
     * @returns the 2FA data that was created on initiation
     * @throws {@link @crossauth/common!CrossauthError} of `Unauthorized`
     *         if 2FA was not initiated.
     */
    async cancelTwoFactorPageVisit(sessionId : string) : Promise<{[key:string]:any}> {
        let {key} = await this.session.getUserForSessionId(sessionId);
        if (!key) throw new CrossauthError(ErrorCode.InvalidKey, "Session key not found");
        let data = KeyStorage.decodeData(key.data);
        //let data = getJsonData(key);
        if (!("pre2fa" in data)) throw new CrossauthError(ErrorCode.Unauthorized, "Two factor authentication not initiated");
        await this.keyStorage.updateData(SessionCookie.hashSessionId(key.value), "pre2fa", undefined);
        return data.pre2fa;
    }

    /**
     * Performs the second factor authentication as the second step of the login
     * process
     * 
     * If authentication is successful, the user's state will be set to active
     * and a new session will be created, bound to the user.  The anonymous session
     * will be deleted.
     * @param params the user-provided parameters to authenticate with (eg TOTP code).
     * @param sessionId the user's anonymous session
     * @param extraFields extra fields to add to the user-bound new session table entry
     * @param persist if true, the cookie will be perstisted (with an expiry value);
     *                otberwise it will be a session-only cookie.
     * @returns `sessionCookie` the new session cookie
     *          `csrfCookie` the new CSRF cookie
     *          `csrfToken` the new CSRF token corresponding to the cookie
     *          `user` the newly-logged in user.
     */
    async completeTwoFactorLogin(params: AuthenticationParameters,
        sessionId: string,
        extraFields: { [key: string]: any } = {},
        persist?: boolean) : 
        Promise<{
            sessionCookie: Cookie,
            csrfCookie: Cookie,
            csrfFormOrHeaderValue: string,
            user: User
        }> {
        let {key} = await this.session.getUserForSessionId(sessionId);
        if (!key || !key.data || key.data == "") throw new CrossauthError(ErrorCode.Unauthorized);
        let data = KeyStorage.decodeData(key.data)["2fa"];
        //let data = getJsonData(key)["2fa"];
        let username = data.username;
        let factor2 = data.factor2;
        const {user, secrets} = await this.userStorage.getUserByUsername(username);
        const authenticator = this.authenticators[factor2];
        if (!authenticator) throw new CrossauthError(ErrorCode.Configuration, "Second factor " + factor2 + " not enabled");
        await authenticator.authenticateUser(user, {...secrets, ...data}, params);

        const newSessionKey = await this.session.createSessionKey(user.id, extraFields);
        await this.keyStorage.deleteKey(SessionCookie.hashSessionId(key.value));
        const sessionCookie = this.session.makeCookie(newSessionKey, persist);

        const csrfToken = this.csrfTokens.createCsrfToken();
        const csrfCookie = this.csrfTokens.makeCsrfCookie(csrfToken);
        const csrfFormOrHeaderValue = this.csrfTokens.makeCsrfFormOrHeaderToken(csrfToken);
        try {
            this.emailTokenStorage.deleteAllForUser(user.id, 
                KeyPrefix.passwordResetToken);
        } catch (e) {
            CrossauthLogger.logger.warn(j({msg: "Couldn't delete password reset tokens while logging in", user: username}));
            CrossauthLogger.logger.debug(j({err: e}));
        }
        return {
            sessionCookie: sessionCookie,
            csrfCookie: csrfCookie,
            csrfFormOrHeaderValue: csrfFormOrHeaderValue,
            user: user
        }
    }

    /**
     * Sends a password reset token
     * @param email the user's email (where the token will be sent)
.     */
    async requestPasswordReset(email : string) : Promise<void> {
        const {user} = await this.userStorage.getUserByEmail(email, {
            skipActiveCheck: true
        });
        if (user.state != UserState.active && user.state != UserState.passwordResetNeeded && user.state != UserState.passwordAndFactor2ResetNeeded) {
            throw new CrossauthError(ErrorCode.UserNotActive);
        }
        await this.tokenEmailer?.sendPasswordResetToken(user.id);
    }

    /**
     * Takes an email verification token as input and applies it to the user storage.
     * 
     * The state is reset to active.  If the token was for changing the password, the new
     * password is saved to the user in user storage.
     * 
     * @param token the token to apply
     * @returns the new user record
     */
    async applyEmailVerificationToken(token : string) : Promise<User> {
        CrossauthLogger.logger.debug(j({msg: "applyEmailVerificationToken"}));
        if (!this.tokenEmailer) throw new CrossauthError(ErrorCode.Configuration, "Email verification not enabled");
        try {
            let { userId, newEmail} = await this.tokenEmailer.verifyEmailVerificationToken(token);
            let {user} = await this.userStorage.getUserById(userId, {skipEmailVerifiedCheck: true});
            let oldEmail;
            if ("email" in user && user.email != undefined) {
                oldEmail = user.email;
            } else {
                oldEmail = user.username;
            }
            let newUser : Partial<User> = {
                id: user.id,
            }
            if (user.state = "awaitingemailverification") {
                newUser.state = "active";
            }
            if (newEmail != "") {
                newUser.email = newEmail;
            } else {
                oldEmail = undefined;
            }
            await this.userStorage.updateUser(newUser);
            await this.tokenEmailer.deleteEmailVerificationToken(token);
            return {...user, ...newUser, oldEmail: oldEmail};
    
        } finally {
        }
    }

    /**
     * Returns the user associated with a password reset token
     * @param token the token that was emailed
     * @returns the user
     * @throws {@link @crossauth/common!CrossauthError} if the token is not valid.
     */
    async userForPasswordResetToken(token : string) : Promise<User> {
        CrossauthLogger.logger.debug(j({msg:"userForPasswordResetToken"}));
        if (!this.tokenEmailer) throw new CrossauthError(ErrorCode.Configuration, "Password reset not enabled");
        return await this.tokenEmailer.verifyPasswordResetToken(token);
    }

    async changeSecrets(username: string,
        factorNumber: 1 | 2,
        newParams: AuthenticationParameters,
        repeatParams?: AuthenticationParameters,
        oldParams?: AuthenticationParameters) : Promise<User> {
        let {user, secrets} = await this.userStorage.getUserByUsername(username);
        const factor = factorNumber == 1 ? user.factor1 : user.factor2;
        if (oldParams != undefined) {
            await this.authenticators[factor].authenticateUser(user, secrets, oldParams);
        }
        const newSecrets = await this.authenticators[user.factor1].createPersistentSecrets(user.username, newParams, repeatParams);
        await this.userStorage.updateUser({id: user.id}, 
            newSecrets,
        );

        // delete any password reset tokens
        try {
            this.emailTokenStorage.deleteAllForUser(user.id, 
                KeyPrefix.passwordResetToken);
        } catch (e) {
            CrossauthLogger.logger.warn(j({msg: "Couldn't delete password reset tokens while logging in", user: username}));
            CrossauthLogger.logger.debug(j({err: e}));
        }

        return user;
    }

    /**
     * Updates a user entry in storage
     * @param currentUser the current user details
     * @param newUser the new user details
     * @returns true if email verification is now needed, false otherwise
     */
    async updateUser(currentUser: User, newUser : User, skipEmailVerification = false) : Promise<boolean> {
        let newEmail : string|undefined = undefined;
        if (!("id" in currentUser) || currentUser.id == undefined) {
            throw new CrossauthError(ErrorCode.UserNotExist, "Please specify a user id");
        }
        if (!("username" in currentUser) || currentUser.username == undefined) {
            throw new CrossauthError(ErrorCode.UserNotExist, "Please specify a userername");
        }
        let { email, username, password, ...rest} = newUser;
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
        if (!skipEmailVerification && this.enableEmailVerification && hasEmail) {
            await this.tokenEmailer?.sendEmailVerificationToken(currentUser.id, newEmail);
        } else {
            if (email) rest.email = email;
            if (username) rest.username = username;
        }
        await this.userStorage.updateUser(rest)
        return !skipEmailVerification && this.enableEmailVerification && hasEmail;
    }

    /**
     * Resets the secret for factor1 or 2 (eg reset password)
     * @param token the reset password token that was emailed
     * @param factorNumber which factor to reset (1 or 2)
     * @param params the new secrets entered by the user (eg new password)
     * @param repeatParams optionally, repeat of the secrets.  If passed, 
     *                     an exception will be thrown if they do not match
     * @returns the user object
     * @throws {@link @crossauth/common!CrossauthError} if the repeatParams don't match params,
     * the token is invalid or the user storage cannot be updated.
     */
    async resetSecret(token: string,
        factorNumber: 1 | 2,
        params: AuthenticationParameters,
        repeatParams?: AuthenticationParameters) : Promise<User> {
        CrossauthLogger.logger.debug(j({msg:"resetSecret"}));
        if (!this.tokenEmailer) throw new CrossauthError(ErrorCode.Configuration, "Password reset not enabled");
        const user = await this.userForPasswordResetToken(token);
        const factor = factorNumber == 1 ? user.factor1 : user.factor2;
        if (!this.tokenEmailer) throw new CrossauthError(ErrorCode.Configuration);
        let newState = user.state == UserState.passwordAndFactor2ResetNeeded ? UserState.factor2ResetNeeded : UserState.active;
        await this.userStorage.updateUser(
            {id: user.id, state: newState},
            await this.authenticators[factor].createPersistentSecrets(user.username, params, repeatParams),
        );
        //this.keyStorage.deleteKey(TokenEmailer.hashPasswordResetToken(token));

        // delete all password reset tokens
        try {
            this.emailTokenStorage.deleteAllForUser(user.id, 
                KeyPrefix.passwordResetToken);
        } catch (e) {
            CrossauthLogger.logger.warn(j({msg: "Couldn't delete password reset tokens while logging in", user: user.username}));
            CrossauthLogger.logger.debug(j({err: e}));
        }

        return user;
    }

}