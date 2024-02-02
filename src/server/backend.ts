import { type User, UserSecrets, type Key, getJsonData, UserInputFields, UserSecretsInputFields } from '../interfaces.ts';
import { ErrorCode, CrossauthError } from '../error.ts';
import { UserStorage, KeyStorage } from './storage';
import { AuthenticationParameters, Authenticator } from './auth';
import type { UsernamePasswordAuthenticatorOptions }  from "./password";
import { TokenEmailer, TokenEmailerOptions } from './email.ts';
import { CrossauthLogger, j } from '../logger.ts';
import { Cookie, DoubleSubmitCsrfToken, SessionCookie } from './cookieauth';
import type { DoubleSubmitCsrfTokenOptions, SessionCookieOptions } from './cookieauth';
import { setParameter, ParamType } from './utils.ts';

export interface BackendOptions extends TokenEmailerOptions {

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
    readonly authenticators : {[key:string] : Authenticator};
    //readonly authenticator : UsernamePasswordAuthenticator;

    private enableEmailVerification : boolean = false;
    private enablePasswordReset : boolean = false;
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
        authenticators : {[key:string] : Authenticator},
        options : BackendOptions = {}) {

        this.userStorage = userStorage;
        this.keyStorage = keyStorage;
        this.authenticators = authenticators;
        for (let authenticationName in this.authenticators) {
            this.authenticators[authenticationName].factorName = authenticationName;
        }

        setParameter("secret", ParamType.String, this, options, "SECRET");

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
     * Authenticates a user and returns it and its secrets.
     * @param username the username to validate
     * @param params parameters to pass to the authenticator
     * @param user if this is defined, the username and authentication parameters the user and secrets are returned
     * @returns the user and its secrets
     * @throws {@link index!CrossauthError} with {@link ErrorCode} of `Connection`, `UserNotValid`, 
     *         `PasswordNotMatch`.
     */
    async authenticateUser(user : User, secrets : UserSecrets, params : AuthenticationParameters) : Promise<void> {
        if (!this.session || !this.csrfTokens) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled"); // csrf tokens always created when using sessions

        await this.authenticators[user.factor1].authenticateUser(user, secrets, params);
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
    async login(username : string, params : AuthenticationParameters, extraFields : {[key:string] : any} = {}, persist? : boolean, user? : User) : Promise<{sessionCookie: Cookie, csrfCookie: Cookie, csrfForOrHeaderValue: string, user: User, secrets: UserSecrets}> {
        if (!this.session || !this.csrfTokens) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled"); // csrf tokens always created when using sessions

        let bypass2FA = user != undefined;

        let secrets : UserSecrets;
        if (!user) {
            let userAndSecrets = await this.userStorage.getUserByUsername(username, {skipActiveCheck: true, skipEmailVerifiedCheck: true});
            secrets = userAndSecrets.secrets;
            user = userAndSecrets.user;
            await this.authenticateUser(user, secrets, params);
        } else {
            let userAndSecrets = await this.userStorage.getUserByUsername(user.username, {skipActiveCheck: true, skipEmailVerifiedCheck: true});
            secrets = userAndSecrets.secrets;

        }

        let sessionCookie : Cookie;
        if (!bypass2FA && secrets && secrets.totpSecret && secrets.totpSecret != "") {
            // create an anonymous session and store the username in it
            const { sessionCookie: newSssionCookie } = await this.initiateTwoFactorLogin(user);
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
            user: user,
            secrets: secrets,
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
    async dataStringForSessionKey(sessionKey : string) : Promise<string|undefined> {
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

    async dataForSessionKey(sessionKey : string) : Promise<{[key:string]:any}> {
        const str = await this.dataStringForSessionKey(sessionKey);
        if (!str || str.length == 0) return {};
        return JSON.parse(str);
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
    async deleteSession(sessionCookieValue : string) : Promise<void> {
        if (!this.session) return;
        const sessionId = this.session.unsignCookie(sessionCookieValue)
        return await this.keyStorage.deleteKey(SessionCookie.hashSessionKey(sessionId));
    }

    /**
     * Creates a new user, sending an email verification message if necessary
     * 
     * @param username username to give the user
     * @param password password to give the user
     * @param extraFields and extra fields to add to the user table entry
     * @returns the userId
     */
    async createUser(user : UserInputFields, params: AuthenticationParameters, repeatParams?: AuthenticationParameters)
        : Promise<User> {
        if (!(this.authenticators[user.factor1])) throw new CrossauthError(ErrorCode.Configuration, "Authenticator cannot create users");
        let secrets = await this.authenticators[user.factor1].createSecrets(user.username, params, repeatParams);
        const newUser = await this.userStorage.createUser(user, secrets);
        if (this.enableEmailVerification && this.tokenEmailer) {
            await this.tokenEmailer?.sendEmailVerificationToken(newUser.id, undefined)
        }
        return newUser;
    }

    async deleteUserByUsername(username : string ) {
        this.userStorage.deleteUserByUsername(username);
    }

    /** Creates a user with 2FA enabled.
     * 
     * The user storage entry will be enabled and the passed session key will be updated to include the
     * username.  The userId and QR Url are returned.
     * @param username : the username to create
     * @param password : the unhashed password for the new user
     * @extraFIelds extra fields to insert into the new user entry
     * @param sessionId the current session id (anonymous session)
     * @return the new userId and the QR code to display
     */
    async initiateTwoFactorSignup(
        user : UserInputFields, 
        params : AuthenticationParameters, 
        sessionCookieValue : string,
        repeatParams? : AuthenticationParameters) : Promise<{userId: string|number, userData : {[key:string] : any}}> {
        if (!this.session) throw new CrossauthError(ErrorCode.Configuration, "Sessions must be enabled for 2FA");
        if (!this.authenticators[user.factor1]) throw new CrossauthError(ErrorCode.Configuration, "Authenticator cannot create users");
        if (!this.authenticators[user.factor2]) throw new CrossauthError(ErrorCode.Configuration, "Two factor authentication not enabled for user");
        const authenticator = this.authenticators[user.factor2];
        const sessionId = this.session.unsignCookie(sessionCookieValue);
        const factor2Data = await authenticator.prepareAuthentication(user.username);
        const userData = (factor2Data == undefined) ? {} : factor2Data.userData;
        const sessionData = (factor2Data == undefined) ? {} : factor2Data.sessionData;

        const factor1Secrets = await this.authenticators[user.factor1].createSecrets(user.username, params, repeatParams);
        user.state = "awaitingtwofactorsetup";
        await this.keyStorage.updateData(
            SessionCookie.hashSessionKey(sessionId), 
            "2fa",
            sessionData);

        const newUser = await this.userStorage.createUser(user, factor1Secrets);    
        return {userId: newUser.id, userData};
    }

    async initiateTwoFactorSetup(
        user : User, 
        newFactor2 : string|undefined,
        sessionCookieValue : string) : Promise<{[key:string] : any}> {
        if (!this.session) throw new CrossauthError(ErrorCode.Configuration, "Sessions must be enabled for 2FA");
        const sessionId = this.session.unsignCookie(sessionCookieValue);
        if (newFactor2 && newFactor2 != "none") {
            if (!this.authenticators[newFactor2]) throw new CrossauthError(ErrorCode.Configuration, "Two factor authentication not enabled for user");
            const authenticator = this.authenticators[newFactor2];
            const factor2Data = await authenticator.prepareAuthentication(user.username);
            const userData = (factor2Data == undefined) ? {} : factor2Data.userData;
            const sessionData = (factor2Data == undefined) ? {} : factor2Data.sessionData;

            await this.keyStorage.updateData(
                SessionCookie.hashSessionKey(sessionId),
                "2fa",
                sessionData);
            return userData;
        } 
        await this.userStorage.updateUser({id: user.id, factor2: newFactor2||""});
        await this.keyStorage.updateData(
            SessionCookie.hashSessionKey(sessionId), 
            "2fa",
            undefined);
        return {};



    }

    async repeatTwoFactorSignup(
        username : string, 
        sessionCookieValue : string,
        factor2: string) : Promise<{userId: string|number, userData: {[key:string]: any}, secrets: Partial<UserSecretsInputFields>}> {
        if (!this.session) throw new CrossauthError(ErrorCode.Configuration, "Sessions must be enabled for 2FA");
        const sessionId = this.session.unsignCookie(sessionCookieValue);
        const sessionKey = await this.keyStorage.getKey(SessionCookie.hashSessionKey(sessionId));
        const authenticator = this.authenticators[factor2];

        const resp = await authenticator.reprepareAuthentication(username, sessionKey);
        const userData = (resp == undefined) ? {} : resp.userData;
        const secrets = (resp == undefined) ? {} : resp.secrets;

        const {user} = await this.userStorage.getUserByUsername(username, {skipActiveCheck: true, skipEmailVerifiedCheck: true});
        return {userId: user.id, userData, secrets};      
    }
    
    async completeTwoFactorSignup(secrets : Partial<UserSecretsInputFields>, sessionId : string) : Promise<User> {
        let newSignup = false;
        if (!this.session) throw new CrossauthError(ErrorCode.Configuration, "verify2FA called but sessions not enabled");
        let {user, key} = await this.session.getUserForSessionKey(sessionId);
        if (!key) throw new CrossauthError(ErrorCode.InvalidKey, "Session key not found");
        let data = getJsonData(key)["2fa"];
        if (!data?.factor2 || !data?.username) throw new CrossauthError(ErrorCode.Unauthorized, "Two factor authentication not initiated");
        let username = data.username;
        const authenticator = this.authenticators[data.factor2];
        if (!authenticator) throw new CrossauthError(ErrorCode.Configuration, "Unrecognised second factor authentication");
        const newSecrets : {[key:string] : any} = {};
        const secretNames = authenticator.secretNames();
        for (let secret in data) {
            if (secretNames.includes(secret)) newSecrets[secret] = data[secret];
        }
        await authenticator.authenticateUser(undefined, data, secrets);

        if (!user) {
            newSignup = true;
            const resp = await this.userStorage.getUserByUsername(username, {skipActiveCheck: true, skipEmailVerifiedCheck: true});
            user = resp.user;
        }
        const newUser = {
            id: user.id,
            state: this.enableEmailVerification ? "awaitingemailverification" : "active",
            factor2: data.factor2,
        }
        await this.userStorage.updateUser(newUser, newSecrets);
        if (newSignup && this.enableEmailVerification && this.tokenEmailer) {
            await this.tokenEmailer?.sendEmailVerificationToken(user.id, undefined)
        }
        await this.keyStorage.updateData(SessionCookie.hashSessionKey(key.value), "2fa", undefined);
        return {...user, ...newUser};
    }

    /** Disables 2FA for an existing user
     * 
     * The user storage entry will be enabled and the passed session key will be updated to include the
     * username.  The userId and QR Url are returned.
     * @param userId : the user id to update
     */
    async disableTwoFactor(
        userId : string|number) {
        if (!this.session) throw new CrossauthError(ErrorCode.Configuration, "Sessions and 2FA must be enabled for 2FA");

        await this.userStorage.updateUser({id: userId}, {totpSecret: ""});
    }

    async initiateTwoFactorLogin(
        user : User) : Promise<{sessionCookie: Cookie, csrfCookie: Cookie, csrfForOrHeaderValue: string}>  {
        if (!this.session || !this.csrfTokens) throw new CrossauthError(ErrorCode.Configuration, "Sessions and 2FA must be enabled for 2FA");
        const {sessionCookie} = await this.createAnonymousSession({data: JSON.stringify({"2fa": {username: user.username, twoFactorInitiated: true, factor2: user.factor2}})});
        const csrfToken = this.csrfTokens.createCsrfToken();
        const csrfCookie = this.csrfTokens.makeCsrfCookie(csrfToken);
        const csrfForOrHeaderValue = this.csrfTokens.makeCsrfFormOrHeaderToken(csrfToken);

        return {
            sessionCookie: sessionCookie,
            csrfCookie: csrfCookie,
            csrfForOrHeaderValue: csrfForOrHeaderValue,
        }
        
    }

    async completeTwoFactorLogin(params : AuthenticationParameters, sessionCookieValue : string, extraFields : {[key:string]:any} = {}, persist? : boolean) : Promise<{sessionCookie: Cookie, csrfCookie: Cookie, csrfForOrHeaderValue: string, user: User}> {
        if (!this.session|| !this.csrfTokens) throw new CrossauthError(ErrorCode.Configuration, "Sessions must be enabled for 2FA");
        let {key} = await this.session.getUserForSessionKey(sessionCookieValue);
        if (!key || !key.data || key.data == "") throw new CrossauthError(ErrorCode.Unauthorized);
        let { username, factor2 } = getJsonData(key)["2fa"];
        const {user, secrets} = await this.userStorage.getUserByUsername(username);
        const authenticator = this.authenticators[factor2];
        if (!authenticator) throw new CrossauthError(ErrorCode.Configuration, "Second factor " + factor2 + " not enabled");
        await authenticator.authenticateUser(user, secrets, params);

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

    async userForPasswordResetToken(token : string) : Promise<User> {
        if (!this.tokenEmailer) throw new CrossauthError(ErrorCode.Configuration, "Password reset not enabled");
        return await this.tokenEmailer.verifyPasswordResetToken(token);
    }

    async changeSecrets(username : string, factorNumber : 1|2, oldParams: AuthenticationParameters, newParams : AuthenticationParameters, repeatParams? : AuthenticationParameters) : Promise<User> {
        let {user, secrets} = await this.userStorage.getUserByUsername(username);
        const factor = factorNumber == 1 ? user.factor1 : user.factor2;
        await this.authenticators[factor].authenticateUser(user, secrets, oldParams);
        const newSecrets = await this.authenticators[user.factor1].createSecrets(user.username, newParams, repeatParams);
        await this.userStorage.updateUser({id: user.id}, 
            newSecrets,
        );

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

    async resetSecret(token : string, factorNumber : 1|2, params : AuthenticationParameters, repeatParams? : AuthenticationParameters) : Promise<User> {
        if (!this.tokenEmailer) throw new CrossauthError(ErrorCode.Configuration, "Password reset not enabled");
        const user = await this.userForPasswordResetToken(token);
        const factor = factorNumber == 1 ? user.factor1 : user.factor2;
        if (!this.tokenEmailer) throw new CrossauthError(ErrorCode.Configuration);
        await this.userStorage.updateUser(
            {id: user.id},
            await this.authenticators[factor].createSecrets(user.username, params, repeatParams),
        );
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