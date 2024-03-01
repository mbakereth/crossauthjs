//import { getJsonData } from '@crossauth/common';
import type { User, UserSecrets, Key, UserInputFields, UserSecretsInputFields } from '@crossauth/common';
import { ErrorCode, CrossauthError } from '@crossauth/common';
import { UserStorage, KeyStorage } from './storage.ts';
import { AuthenticationParameters, Authenticator } from './auth.ts';
import type { LocalPasswordAuthenticatorOptions }  from "./authenticators/passwordauth.ts";
import { TokenEmailer, TokenEmailerOptions } from './emailtokens.ts';
import { CrossauthLogger, j } from '@crossauth/common';
import { Cookie, DoubleSubmitCsrfToken, SessionCookie } from './cookieauth.ts';
import type { DoubleSubmitCsrfTokenOptions, SessionCookieOptions } from './cookieauth.ts';
import { setParameter, ParamType } from './utils.ts';
import { Hasher } from './hasher.ts';

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

    siteUrl? : string,
}

/**
 * Class for managing sessions.
 */
export class SessionManager {
    userStorage : UserStorage;
    keyStorage : KeyStorage;
    emailTokenStorage : KeyStorage;
    private csrfTokens : DoubleSubmitCsrfToken;
    private session : SessionCookie;
    readonly authenticators : {[key:string] : Authenticator};
    //readonly authenticator : UsernamePasswordAuthenticator;

    private enableEmailVerification : boolean = false;
    private enablePasswordReset : boolean = false;
    private tokenEmailer? : TokenEmailer;

    /**
     * Constructor
     * @param userStorage the {@link UserStorage} instance to use, eg {@link PrismaUserStorage}.
     * @param keyStorage  the {@link KeyStorage} instance to use, eg {@link PrismaSessionStorage}.
     * @param authenticator authenticator used to validate users  See {@link LocalPasswordAuthenticatorOptions }.
     * @param options optional parameters for authentication. See {@link CookieAuthOptions }.
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


        this.session = new SessionCookie(this.userStorage, this.keyStorage, {...options?.sessionCookieOptions, ...options||{}});
        this.csrfTokens = new DoubleSubmitCsrfToken({...options?.doubleSubmitCookieOptions, ...options||{}});


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
     * Returns the name used for CSRF token cookies.
     */
    get csrfCookieName() : string {
        return this.csrfTokens.cookieName;
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
     * @returns the user, user secrets, and session cookie and CSRF cookie and token.
     *          if a 2fa step is needed, it will be an anonymouos session, otherwise bound to the user
     * @throws {@link @crossauth/common!CrossauthError} with {@link ErrorCode} of `Connection`, `UserNotValid`, 
     *         `PasswordNotMatch`.
     */
    async login(username : string, params : AuthenticationParameters, extraFields : {[key:string] : any} = {}, persist? : boolean, user? : User) : Promise<{sessionCookie: Cookie, csrfCookie: Cookie, csrfFormOrHeaderValue: string, user: User, secrets: UserSecrets}> {

        let bypass2FA = user != undefined;

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

        // create a session ID - bound to user if no 2FA, anonymous otherwiyse
        let sessionCookie : Cookie;
        if (!bypass2FA && user.factor2 && user.factor2 != "") {
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
            this.emailTokenStorage.deleteAllForUser(user.id, "p:");
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
     * @returns a cookie with the session ID, a cookie with the CSRF token, a flag to indicate whether
     *          each of these was newly created and the user, which may be undefined.
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
     * @param sessionKey the session ID to remove.
     * @throws {@link @crossauth/common!CrossauthError} with {@link ErrorCode} of `Connection`
     */
    async logout(sessionCookieValue : string) : Promise<void> {
        const key = await this.session.getSessionKey(sessionCookieValue);
        return await this.keyStorage.deleteKey(SessionCookie.hashSessionKey(key.value));
    }

    /**
     * Logs a user out from all sessions.
     * 
     * Removes the given session ID from the session storage.
     * @param except Don't log out from the matching session.
     * @throws {@link @crossauth/common!CrossauthError} with {@link ErrorCode} of `Connection`
     */
    async logoutFromAll(userId : string | number, except? : string|undefined) : Promise<void> {
        /*await*/ return this.session.deleteAllForUser(userId, except);
    }
    
    /**
     * Returns the user (without secrets) matching the given session key.
     * 
     * If the user is undefined, or the key has expired, returns undefined.
     * 
     * @param sessionCookieValue the session key to look up in session storage
     * @returns the {@link User} (without password hash) matching the  session key
     * @throws {@link @crossauth/common!CrossauthError} with {@link ErrorCode} of `Connection`,  `InvalidSessionId`
     *         `UserNotExist` or `Expired`.
     */
    async userForSessionCookieValue(sessionCookieValue : string) : Promise<{key: Key, user: User|undefined}> {
        let {key, user} = await this.session.getUserForSessionKey(sessionCookieValue);
        return {key, user};
    }

    /**
     * Returns the data object for a session key, or undefined, as a JSON string 
     * (which is how it is stored in the session table)
     * 
     * If the user is undefined, or the key has expired, returns undefined.
     * 
     * @param sessionKey the session key to look up in session storage
     * @returns a string from the data field
     * @throws {@link @crossauth/common!CrossauthError} with {@link ErrorCode} of `Connection`,  `InvalidSessionId`
     *         `UserNotExist` or `Expired`.
     */
    async dataStringForSessionKey(sessionCookieValue : string) : Promise<string|undefined> {
        let error : CrossauthError | undefined;
        try {
            let {key} = await this.session.getUserForSessionKey(sessionCookieValue);
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
            error = new CrossauthError(ErrorCode.UnknownError);
        }
        if (error) {
            CrossauthLogger.logger.debug(j({err: error}));
            throw error;
        }
    }

    /**
     * Returns the data object for a session key, or undefined, as an object.
     * 
     * If the user is undefined, or the key has expired, returns undefined.
     * 
     * @param sessionKey the session key to look up in session storage
     * @returns a string from the data field
     * @throws {@link @crossauth/common!CrossauthError} with {@link ErrorCode} of `Connection`,  `InvalidSessionId`
     *         `UserNotExist` or `Expired`.
     */
    async dataForSessionKey(sessionCookieValue : string) : Promise<{[key:string]:any}> {
        const str = await this.dataStringForSessionKey(sessionCookieValue);
        if (!str || str.length == 0) return {};
        return JSON.parse(str);
    }

    
    /**
     * Creates and returns a signed CSRF token based on the session ID
     * @param sessionId the session ID
     * @returns a signed CSRF token
     */
    async createCsrfToken() : Promise<{csrfCookie : Cookie, csrfFormOrHeaderValue : string}> {
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
        return (await this.session.getUserForSessionKey(sessionCookieValue)).user;
    }

    getSessionId(sessionCookieValue : string) : string {
        return this.session.unsignCookie(sessionCookieValue);
    }

    /**
     * Throws {@link @crossauth/common!CrossauthError} with ErrorCode.InvalidKey if the passed CSRF token is not valid for the given
     * session ID.  Otherwise returns without error
     * @param token 
     */
    validateDoubleSubmitCsrfToken(csrfCookieValue : string|undefined, csrfFormOrHeaderValue : string|undefined) {
        if (!csrfCookieValue || !csrfFormOrHeaderValue) throw new CrossauthError(ErrorCode.InvalidCsrf, "CSRF missing from either cookie or form/header value");
        this.csrfTokens.validateDoubleSubmitCsrfToken(csrfCookieValue, csrfFormOrHeaderValue);
    }

    /**
     * Throws {@link @crossauth/common!CrossauthError} with ErrorCode.InvalidKey if the passed CSRF token is not valid for the given
     * session ID.  Otherwise returns without error
     * @param token 
     */
    validateCsrfCookie(csrfCookieValue : string) {
        this.csrfTokens.validateCsrfCookie(csrfCookieValue);
    }

    /**
     * If sessionIdleTimeout is set, update the last activcity time in key storage to current time
     * @param sessionId the session Id to update.
     */
    async updateSessionActivity(sessionCookieValue : string) : Promise<void> {
        const key = await this.session.getSessionKey(sessionCookieValue);
        if (this.session.idleTimeout > 0) {
            this.session.updateSessionKey({
                value: key.value,
                lastActive: new Date(),
            });
        }
    }

    /**
     * If sessionIdleTimeout is set, update the last activcity time in key storage to current time
     * @param sessionId the session Id to update.
     */
    async updateSessionData(sessionCookieValue : string, name : string, value : {[key:string]:any}) : Promise<void> {
        const sessionId = this.session.unsignCookie(sessionCookieValue);
        const hashedSessionKey = SessionCookie.hashSessionKey(sessionId);
        CrossauthLogger.logger.debug(j({msg: `Updating session data value${name}`, hashedSessionCookie: Hasher.hash(sessionCookieValue)}));
        await this.keyStorage.updateData(hashedSessionKey, name, value);
    }
    
    /**
     * Deletes the given session ID from the key storage (not the cookie)
     * @param sessionId the session Id to delete
     */
    async deleteSession(sessionCookieValue : string) : Promise<void> {
        const sessionId = this.session.unsignCookie(sessionCookieValue)
        return await this.keyStorage.deleteKey(SessionCookie.hashSessionKey(sessionId));
    }

    /**
     * Creates a new user, sending an email verification message if necessary.
     *  
     * If email verification is enabled, the user's state is set to
     * `awaitingemailverification`. Otherwise it is set to `active`.
     * 
     * @param username username to give the user
     * @param password password to give the user
     * @param extraFields and extra fields to add to the user table entry
     * @returns the userId
     */
    async createUser(user : UserInputFields, params: AuthenticationParameters, repeatParams?: AuthenticationParameters)
        : Promise<User> {
        if (!(this.authenticators[user.factor1])) throw new CrossauthError(ErrorCode.Configuration, "Authenticator cannot create users");
        const skipEmailVerification = this.authenticators[user.factor1].skipEmailVerificationOnSignup() == true;
        let secrets = await this.authenticators[user.factor1].createPersistentSecrets(user.username, params, repeatParams);
        const newUser = await this.userStorage.createUser(user, secrets);
        if (!skipEmailVerification && this.enableEmailVerification && this.tokenEmailer) {
            await this.tokenEmailer?.sendEmailVerificationToken(newUser.id, undefined);
        }
        return newUser;
    }

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
     * @param sessionCookieValue the anonymous session cookie 
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
        sessionCookieValue : string,
        repeatParams? : AuthenticationParameters) : Promise<{userId: string|number, userData : {[key:string] : any}}> {
        if (!this.authenticators[user.factor1]) throw new CrossauthError(ErrorCode.Configuration, "Authenticator cannot create users");
        if (!this.authenticators[user.factor2]) throw new CrossauthError(ErrorCode.Configuration, "Two factor authentication not enabled for user");
        const authenticator = this.authenticators[user.factor2];
        const sessionId = this.session.unsignCookie(sessionCookieValue);
        const factor2Data = await authenticator.prepareConfiguration(user);
        const userData = (factor2Data == undefined) ? {} : factor2Data.userData;
        const sessionData = (factor2Data == undefined) ? {} : factor2Data.sessionData;

        const factor1Secrets = await this.authenticators[user.factor1].createPersistentSecrets(user.username, params, repeatParams);
        user.state = "awaitingtwofactorsetup";
        await this.keyStorage.updateData(
            SessionCookie.hashSessionKey(sessionId), 
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
     * @param sessionCookieValue the session cookie for the user
     * @returns the 2FA data that can be displayed to the user in the confifugre 2FA
     *          step (such as the secret and QR code for TOTP).
     */
    async initiateTwoFactorSetup(
        user : User, 
        newFactor2 : string|undefined,
        sessionCookieValue : string) : Promise<{[key:string] : any}> {
        const sessionId = this.session.unsignCookie(sessionCookieValue);
        if (newFactor2 && newFactor2 != "none") {
            if (!this.authenticators[newFactor2]) throw new CrossauthError(ErrorCode.Configuration, "Two factor authentication not enabled for user");
            const authenticator = this.authenticators[newFactor2];
            const factor2Data = await authenticator.prepareConfiguration(user);
            const userData = (factor2Data == undefined) ? {} : factor2Data.userData;
            const sessionData = (factor2Data == undefined) ? {} : factor2Data.sessionData;

            await this.keyStorage.updateData(
                SessionCookie.hashSessionKey(sessionId),
                "2fa",
                sessionData);
            return userData;
        } 

        // this part is for turning off 2FA
        await this.userStorage.updateUser({id: user.id, factor2: newFactor2||""});
        await this.keyStorage.updateData(
            SessionCookie.hashSessionKey(sessionId), 
            "2fa",
            undefined);
        return {};



    }

    /**
     * This can be called if the user has finished signing up with factor1 but
     * closed the browser before completing factor2 setup.  Call it if the user
     * signs up again with the same factor1 credentials.
     * @param sessionCookieValue the anonymous session ID for the user
     * @returns `userId` the id of the created user
     *          `userData` data that can be displayed to the user in the page to 
     *           complete 2FA set up (eg the secret key and QR codee for TOTP),
     *          `secrets` data that is saved in the session for factor2.  In the
     *          case of TOTP, both `userData` and `secrets` contain the shared
     *          secret but only `userData` has the QR code, since it can be
     *          generated from the shared secret.
     */
    async repeatTwoFactorSignup(sessionCookieValue: string) : Promise<{userId: string|number, userData: {[key:string]: any}, secrets: Partial<UserSecretsInputFields>}> {
        const sessionData = (await this.dataForSessionKey(sessionCookieValue))["2fa"];
        const username = sessionData.username;
        const factor2 = sessionData.factor2;
        const sessionId = this.session.unsignCookie(sessionCookieValue);
        const hashedSessionKey = SessionCookie.hashSessionKey(sessionId);
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
     * @param sessionCookieValue the session cookie value (ie still signed)
     * @returns the user object
     * @throws {@link @crossauth/common!CrossauthError} if authentication fails.
     */
    async completeTwoFactorSetup(params : AuthenticationParameters, sessionCookieValue : string) : Promise<User> {
        let newSignup = false;
        let {user, key} = await this.session.getUserForSessionKey(sessionCookieValue);
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
        await this.keyStorage.updateData(SessionCookie.hashSessionKey(key.value), "2fa", undefined);
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
        user : User) : Promise<{sessionCookie: Cookie, csrfCookie: Cookie, csrfFormOrHeaderValue: string}>  {
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
     * @param sessionCookieValue the logged in session associated with the user
     * @param requestBody the parameters from the request made before being redirected to factor2 authentication
     * @param url the requested url, including path and query parameters
     * @returns If a token was passed a new anonymous session cookie and corresponding CSRF cookie and token.
     */
    async initiateTwoFactorPageVisit(
        user : User,
        sessionCookieValue : string,
        requestBody : {[key:string]: any},
        url : string|undefined) : Promise<{sessionCookie: Cookie|undefined, csrfCookie: Cookie|undefined, csrfFormOrHeaderValue: string|undefined}>  {
        const authenticator = this.authenticators[user.factor2];
        const secrets = await authenticator.createOneTimeSecrets(user);

        let sessionCookie : Cookie|undefined;
        let csrfCookie : Cookie|undefined;
        let csrfFormOrHeaderValue : string|undefined;
        if (!user) {
            // user is not logged in - create an anonymous session
            const resp = await this.createAnonymousSession({});
            sessionCookie = resp.sessionCookie;
            sessionCookieValue = sessionCookie.value;
            csrfCookie = resp.csrfCookie;
            csrfFormOrHeaderValue = resp.csrfFormOrHeaderValue
    
        }

        const sessionId = this.session.unsignCookie(sessionCookieValue);
        const hashedSessionId = SessionCookie.hashSessionKey(sessionId)
        this.keyStorage.updateData(hashedSessionId, "pre2fa", {username: user.username, factor2: user.factor2, secrets: secrets, body: requestBody, url: url});

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
     * @param params the parameters from user input needed to authenticate (eg TOTP code)
     * @param sessionCookieValue the session cookie value (ie still signed)
     * @returns the user object
     * @throws {@link @crossauth/common!CrossauthError} if authentication fails.
     */
    async completeTwoFactorPageVisit(params : AuthenticationParameters, sessionCookieValue : string) : Promise<void> {
        let {key} = await this.session.getUserForSessionKey(sessionCookieValue);
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
            if (secretNames.includes(secret)) newSecrets[secret] = data[secret];
        }
        await authenticator.authenticateUser(undefined, {...newSecrets, ...data.pre2fa.secrets}, params);
        await this.keyStorage.updateData(SessionCookie.hashSessionKey(key.value), "pre2fa", undefined);
    }

    /**
     * Completes 2FA when visiting a protected page.  
     * 
     * If successful, returns.  Otherwise an exception is thrown.
     * @param params the parameters from user input needed to authenticate (eg TOTP code)
     * @param sessionCookieValue the session cookie value (ie still signed)
     * @returns the 2FA data that was created on initiation
     * @throws {@link @crossauth/common!CrossauthError} if authentication fails.
     */
    async cancelTwoFactorPageVisit(sessionCookieValue : string) : Promise<{[key:string]:any}> {
        let {key} = await this.session.getUserForSessionKey(sessionCookieValue);
        if (!key) throw new CrossauthError(ErrorCode.InvalidKey, "Session key not found");
        let data = KeyStorage.decodeData(key.data);
        //let data = getJsonData(key);
        if (!("pre2fa" in data)) throw new CrossauthError(ErrorCode.Unauthorized, "Two factor authentication not initiated");
        await this.keyStorage.updateData(SessionCookie.hashSessionKey(key.value), "pre2fa", undefined);
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
     * @param sessionCookieValue the user's anonymous session
     * @param extraFields extra fields to add to the user-bound new session table entry
     * @param persist if true, the cookie will be perstisted (with an expiry value);
     *                otberwise it will be a session-only cookie.
     * @returns `sessionCookie` the new session cookie
     *          `csrfCookie` the new CSRF cookie
     *          `csrfToken` the new CSRF token corresponding to the cookie
     *          `user` the newly-logged in user.
     */
    async completeTwoFactorLogin(params : AuthenticationParameters, sessionCookieValue : string, extraFields : {[key:string]:any} = {}, persist? : boolean) : Promise<{sessionCookie: Cookie, csrfCookie: Cookie, csrfFormOrHeaderValue: string, user: User}> {
        let {key} = await this.session.getUserForSessionKey(sessionCookieValue);
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
        await this.keyStorage.deleteKey(SessionCookie.hashSessionKey(key.value));
        const sessionCookie = this.session.makeCookie(newSessionKey, persist);

        const csrfToken = this.csrfTokens.createCsrfToken();
        const csrfCookie = this.csrfTokens.makeCsrfCookie(csrfToken);
        const csrfFormOrHeaderValue = this.csrfTokens.makeCsrfFormOrHeaderToken(csrfToken);
        try {
            this.emailTokenStorage.deleteAllForUser(user.id, "p:");
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
        const {user} = await this.userStorage.getUserByEmail(email);
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
        if (!this.tokenEmailer) throw new CrossauthError(ErrorCode.Configuration, "Email verification not enabled");
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
        return {...user, ...newUser, oldEmail: oldEmail};
    }

    /**
     * Returns the user associated with a password reset token
     * @param token the token that was emailed
     * @returns the user
     * @throws {@link @crossauth/common!CrossauthError} if the token is not valid.
     */
    async userForPasswordResetToken(token : string) : Promise<User> {
        if (!this.tokenEmailer) throw new CrossauthError(ErrorCode.Configuration, "Password reset not enabled");
        return await this.tokenEmailer.verifyPasswordResetToken(token);
    }

    async changeSecrets(username : string, factorNumber : 1|2, oldParams: AuthenticationParameters, newParams : AuthenticationParameters, repeatParams? : AuthenticationParameters) : Promise<User> {
        let {user, secrets} = await this.userStorage.getUserByUsername(username);
        const factor = factorNumber == 1 ? user.factor1 : user.factor2;
        await this.authenticators[factor].authenticateUser(user, secrets, oldParams);
        const newSecrets = await this.authenticators[user.factor1].createPersistentSecrets(user.username, newParams, repeatParams);
        await this.userStorage.updateUser({id: user.id}, 
            newSecrets,
        );

        // delete any password reset tokens
        try {
            this.emailTokenStorage.deleteAllForUser(user.id, "p:");
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
    async updateUser(currentUser: User, newUser : User) : Promise<boolean> {
        let newEmail = undefined;
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
        if (this.enableEmailVerification && hasEmail) {
            await this.tokenEmailer?.sendEmailVerificationToken(currentUser.id, newEmail);
        } else {
            if (email) rest.email = email;
            if (username) rest.username = username;
        }
        await this.userStorage.updateUser(rest)
        return this.enableEmailVerification && hasEmail;
    }

    /**
     * Resets the secret for factor1 or 2 (eg reset password)
     * @param token the reset password token that was emailed
     * @param factorNumber which factor to reset (1 or 2)
     * @param params the new secrets entered by the user (eg new password)
     * @param repeatParams optionally, repeat of the secrets.  If passed, 
     *                     an exception will be thrown if they do not match
     * @returns the new user object
     * @throws {@link CrossauthError} if the repeatParams don't match params,
     * the token is invalid or the user storage cannot be updated.
     */
    async resetSecret(token : string, factorNumber : 1|2, params : AuthenticationParameters, repeatParams? : AuthenticationParameters) : Promise<User> {
        if (!this.tokenEmailer) throw new CrossauthError(ErrorCode.Configuration, "Password reset not enabled");
        const user = await this.userForPasswordResetToken(token);
        const factor = factorNumber == 1 ? user.factor1 : user.factor2;
        if (!this.tokenEmailer) throw new CrossauthError(ErrorCode.Configuration);
        await this.userStorage.updateUser(
            {id: user.id},
            await this.authenticators[factor].createPersistentSecrets(user.username, params, repeatParams),
        );
        //this.keyStorage.deleteKey(TokenEmailer.hashPasswordResetToken(token));

        // delete all password reset tokens
        try {
            this.emailTokenStorage.deleteAllForUser(user.id, "p:");
        } catch (e) {
            CrossauthLogger.logger.warn(j({msg: "Couldn't delete password reset tokens while logging in", user: user.username}));
            CrossauthLogger.logger.debug(j({err: e}));
        }

        return user;
    }

}