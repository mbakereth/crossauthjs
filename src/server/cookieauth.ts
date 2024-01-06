import type { 
    User,
    Key 
} from '../interfaces.ts';
import { ErrorCode, CrossauthError } from '../error.ts';
import { UserStorage, UserPasswordStorage, KeyStorage } from './storage';
import { HashedPasswordAuthenticator } from "./password";
import type { UsernamePasswordAuthenticatorOptions }  from "./password";
import { Hasher } from './hasher';
import { CrossauthLogger } from '../logger.ts';

/**
 * Optional parameters to {@link CookieAuth }.  
 */
export interface CookieAuthOptions {

    ///////// session ID settings

    /** name to use for the session cookie.  Defaults to `SESSIONID` */
    sessionCookieName? : string,

    /** Maximum age of the session cookie in seconds.  Cookie and session storage table will get an expiry date based on this.  Defaults to one month. */
    sessionMaxAge? : number,

    /** Set the `httpOnly` cookie flag for the session cookie.  Default true. */
    sessionHttpOnly? : boolean,

    /** Set the `secure` cookie flag on the session cookie.  Default false, though in production with HTTPS enabled you should set it to true. */
    sessionSecure? : boolean,

    /** Sets the cookie domain on the session cookie.  Default, no domain */
    sessionDomain? : string
 
    /** Sets the cookie path on the session cookie.  Default, "/"" */
    sessionPath? : string,

    /** Sets the `SameSite` for the session cookie.  Default `lax` if not defined, which means all cookies will have SameSite set. */
    sessionSameSite? : boolean | "lax" | "strict" | "none" | undefined,

    /** Length in bytes of random string to create for session IDs.  Actual key will be longer as it is Base64-encoded. Defaults to 16 */
    sessionIdLength? : number,

    /** If greater than zero, non-anonymous sessions will expire after this number of sessions. Must have the `lastActive` field in key storage  */
    sessionIdleTimeout? : number,

    /** If true, session IDs will be PBKDF2-hashed in the session storage. Defaults to false. */
    hashSessionIds? : boolean,

    ///////// CSRF token settings

    /** name to use for the session cookie.  Defaults to `CSRFTOKEN` */
    csrfCookieName? : string,

    /** Set the `httpOnly` cookie flag for the CSRF token cookie.  Default true. */
    csrfHttpOnly? : boolean,

    /** Set the `secure` cookie flag on the CSRF token cookie.  Default false, though in production with HTTPS enabled you should set it to true. */
    csrfSecure? : boolean,

    /** Sets the cookie domain on the CSRF token cookie.  Default, no domain */
    csrfDomain? : string
 
    /** Sets the cookie path on the CSRF token cookie.  Default, "/"" */
    csrfPath? : string,

    /** Sets the `SameSite` for the CSRF token cookie.  Default `lax` if not defined, which means all cookies will have SameSite set. */
    csrfSameSite? : boolean | "lax" | "strict" | "none" | undefined,

    /** Length in bytes of random string to create for CSRF tokens.  Actual key will be longer as it is Base64-encoded. Defaults to 16 */
    csrfLength? : number,

    //////////////// PBKDF2 settings

    /** If hashSessionIds is true, create salts of this length.  Defaults to 16 */
    saltLength? : number,

    /** If hashSessionIds is true, use this number of iterations when generating the PBKDF2 hash.  Default 100000 */
    iterations? : number;

    /** If hashSessionIds is true, use this HMAC digest algorithm.  Default 'sha512' */
    digest? : string;

    /** Length of the hash.  This is for the signature on CSRF tokens and for session IDs when hashSessionIds is true.  
     *  In bytes, default 16.  In practice higher as it is Base64Url-encoded */
    keyLength? : number;

    /** 
     * This will be called with the session key to filter sessions 
     * before returning.  Function should return true if the session is valid or false otherwise.
     */
    filterFunction? : (sessionKey : Key) => boolean;

    /**
     * If true, a session ID will be created even the user is not logged in.
     * Setting this to false means you will also not get CSRF tokens when the user it not logged in,
     * Default true
     */
    anonymousSessions? : boolean;
}

/**
 * Optional parameters when setting cookies,
 * 
 * These match the HTTP cookie parameters of the same name.
 */
export interface CookieOptions {

    domain? : string,
    expires? : Date,
    httpOnly? : boolean,
    path? : string,
    secure? : boolean,
    sameSite? : boolean | "lax" | "strict" | "none" | undefined,
}

/**
 * Object encapsulating a cookie name, value and options.
 */
export interface Cookie {
    name : string,
    value : string,
    options : CookieOptions
}

/**
 * Class implementing cookie-based authentication.
 * 
 * This class creates session ID and CSRF token cookies.  
 * 
 * Session IDs are random strings and stored in session storage. They can optionally be stored as a PBKDF2 hash 
 * (default is not to).
 * 
 * CSRF tokens use the signed double-submit cookie pattern.  The CSRF token is sent as a cookie, as a random string concatenated
 * with the session ID.  Concatenated with this is a PBKDF2 signature based on the secret.
 * 
 * Form handling code shoudl check that the unsigned part matches either a form field called `csrdToken`
 * or a header called `X-CROSSAUTH-CSRF`.  Either your code making the form submission should extract the
 * unsigned part of the CSRF token from the cookie, or else the code creating the form page should send
 * it in the `csrfToken` hidden form field.
 */
export class CookieAuth {
    private userStorage : UserStorage;
    private sessionStorage : KeyStorage;
    private secret : string;

    // session ID settings
    readonly sessionCookieName : string = "SESSIONID";
    private sessionMaxAge : number = 1209600; // two weeks
    private sessionHttpOnly : boolean = true;
    private sessionSecure : boolean = false;
    private sessionDomain : string | undefined = undefined;
    private sessionPath : string | undefined = "/";
    private sessionSameSite : boolean | "lax" | "strict" | "none" = 'lax';
    private sessionIdLength : number = 16;
    private hashSessionIds : boolean = false;
    readonly sessionIdleTimeout : number = 0;

    // CSRF token settings
    readonly csrfCookieName : string = "CSRFTOKEN";
    private csrfHttpOnly : boolean = true;
    private csrfSecure : boolean = false;
    private csrfDomain : string | undefined = undefined;
    private csrfPath : string | undefined = "/";
    private csrfSameSite : boolean | "lax" | "strict" | "none" = 'lax';
    private csrfLength : number = 16;

    // PBKDF2 settings
    private saltLength : number = 16;
    private iterations = 10000;
    private keyLength = 16;
    private digest = 'sha512';
    private filterFunction? : (sessionKey : Key) => boolean;
    /**
     * Constructor.
     * 
     * @param userStorage instance of the {@link UserStorage} object to use, eg {@link PrismaUserStorage}.
     * @param sessionStorage instance of the {@link KeyStorage} object to use, eg {@link PrismaSessionStorage}.
     * @param secret a secret password use to sign CSRF tokens and optionally for session IDs.  Must be at leat 16 bytes.  If in the Base64 character set, 22.  If in the hex charfacter set, 32.
     * @param options optional parameters.  See {@link CookieAuthOptions}.
     */
    constructor(userStorage : UserStorage, 
                sessionStorage : KeyStorage, 
                secret : string,
                options? : CookieAuthOptions) {
        this.userStorage = userStorage;
        this.sessionStorage = sessionStorage;
        this.secret = secret;

        if (options) {
            // session
            if (options.sessionCookieName) this.sessionCookieName = options.sessionCookieName;
            if (options.sessionMaxAge) this.sessionMaxAge = options.sessionMaxAge;
            if (options.sessionHttpOnly) this.sessionHttpOnly = options.sessionHttpOnly;
            if (options.sessionSecure) this.sessionSecure = options.sessionSecure;
            if (options.sessionDomain) this.sessionDomain = options.sessionDomain;
            if (options.sessionSameSite) this.sessionSameSite = options.sessionSameSite;
            if (options.sessionIdLength) this.sessionIdLength = options.sessionIdLength;
            if (options.hashSessionIds) this.hashSessionIds = options.hashSessionIds;
            if (options.sessionIdleTimeout) this.sessionIdleTimeout = options.sessionIdleTimeout;

            // CSRF
            if (options.csrfCookieName) this.csrfCookieName = options.csrfCookieName;
            if (options.csrfHttpOnly) this.csrfHttpOnly = options.csrfHttpOnly;
            if (options.csrfSecure) this.csrfSecure = options.csrfSecure;
            if (options.csrfDomain) this.csrfDomain = options.csrfDomain;
            if (options.csrfSameSite) this.csrfSameSite = options.csrfSameSite;
            if (options.csrfLength) this.csrfLength = options.csrfLength;

            // PBKDF2
            if (options.saltLength) this.saltLength = options.saltLength;
            if (options.iterations) this.iterations = options.iterations;
            if (options.digest)this.digest = options.digest;
            if (options.keyLength) this.keyLength = options.keyLength;
            this.filterFunction = options.filterFunction;
        }
    }

    private expiry(dateCreated : Date) : Date | undefined {
        let expires : Date | undefined = undefined;
        if (this.sessionMaxAge > 0) {
            expires = new Date();
            expires.setTime(dateCreated.getTime() + this.sessionMaxAge*1000);
        }
        return expires;
    }

    ///// Session IDs

    hashSessionKey(sessionKey : string) : string {
        const hasher = new Hasher({
            digest: this.digest,
            iterations: this.iterations, 
            keyLength: this.keyLength,
            saltLength: this.saltLength,
        });
        return hasher.hash(this.secret, {encode: false, charset: "base64url", salt: sessionKey});
    }

    /**
     * Creates a session key and saves in storage
     * 
     * Date created is the current date/time on the server.
     * 
     * In the unlikely event of the key already existing, it is retried up to 10 times before throwing
     * an error with ErrorCode.KeyExists
     * 
     * @param userId the user ID to store with the session key.
     * @param existingSessionId if passed, this will be used instead of a random one.  The expiry will be renewed
     * @returns the session key, date created and expiry.
     */
    async createSessionKey(userId : string | number | undefined, existingSessionId? : string) : Promise<Key> {
        const maxTries = 10;
        let numTries = 0;
        const keepSessionId =  existingSessionId != undefined;
        while (true) {
            let sessionKey;
            let hashedSessionKey = "";
            if (numTries == 0 && existingSessionId) {
                sessionKey = existingSessionId;
                hashedSessionKey = sessionKey;
            } else {
                const array = new Uint8Array(this.sessionIdLength);
                crypto.getRandomValues(array);
                sessionKey = Hasher.base64ToBase64Url(Buffer.from(array).toString('base64'));
                hashedSessionKey = sessionKey;
            }
            if (this.hashSessionIds) {
                hashedSessionKey = this.hashSessionKey(sessionKey);
            }    
            const dateCreated = new Date();
            let expires = this.expiry(dateCreated);
            try {
                if (keepSessionId && numTries == 0) {
                    // check the key exists.  If not, an error will be throws
                    let {key} = await this.getUserForSessionKey(hashedSessionKey);
                    key.expiry = this.expiry(key.created);
                    if (this.sessionIdleTimeout > 0) {
                        key.lastActive = new Date();
                    }
                    await this.updateSessionKey(key);
                } else {
                    // save the new session - if it exists, an error will be thrown
                    let extraFields = {};
                    if (this.sessionIdleTimeout > 0 && userId) {
                        extraFields = {lastActivity: new Date()};
                    }
                    await this.sessionStorage.saveKey(userId, hashedSessionKey, dateCreated, expires, extraFields);
                }
                return {
                    userId : userId,
                    value : sessionKey,
                    created : dateCreated,
                    expires : expires
                }
                } catch (e) {
                if (e instanceof CrossauthError) {
                    let ce = e as CrossauthError;
                    if (ce.code == ErrorCode.KeyExists || ce.code == ErrorCode.InvalidKey) {
                        numTries++;
                        if (numTries > maxTries) {
                            CrossauthLogger.logger.debug(e);
                            throw e;
                        }
                    } else {
                        CrossauthLogger.logger.debug(e);
                        throw e;
                    }
                } else {
                    CrossauthLogger.logger.debug(e);
                    throw e;
                }
            }    
        }
    }

    /**
     * Returns a {@link Cookie } object with the given session key.
     * 
     * This class is compatible, for example, with Express.
     * 
     * @param sessionKey the value of the session key
     * @returns a {@link Cookie } object,
     */
    makeSessionCookie(sessionKey : Key) : Cookie {
        let options : CookieOptions = {}
        if (this.sessionDomain) {
            options.domain = this.sessionDomain;
        }
        if (sessionKey.expires) {
            options.expires = sessionKey.expires;
        }
        if (this.sessionPath) {
            options.path = this.sessionPath;
        }
        if (this.sessionDomain) {
            options.domain = this.sessionDomain;
        }
        options.sameSite = this.sessionSameSite;
        if (this.sessionHttpOnly) {
            options.httpOnly = this.sessionHttpOnly;
        }
        if (this.sessionSecure) {
            options.secure = this.sessionSecure;
        }
        return {
            name : this.sessionCookieName,
            value : sessionKey.value,
            options: options
        }
    }

    /**
     * Takes a session ID and creates a string representation of the cookie (value of the HTTP `Cookie` header).
     * 
     * @param sessionKey the session key to put in the cookie
     * @returns a string representation of the cookie and options.
     */
    makeSessionCookieString(sessionKey : Key) : string {
        let cookie = this.sessionCookieName + "=" + sessionKey.value + "; SameSite=" + this.sessionSameSite;
        if (sessionKey.expires) {
            cookie += "; " + new Date(sessionKey.expires).toUTCString();
        }
        if (this.sessionDomain) {
            cookie += "; " + this.sessionDomain;
        }
        if (this.sessionPath) {
            cookie += "; " + this.sessionPath;
        }
        if (this.sessionHttpOnly) {
            cookie += "; httpOnly";
        }
        if (this.sessionSecure) {
            cookie += "; secure";
        }
        return cookie;
    }
    
    async updateSessionKey(sessionKey : Partial<Key>) : Promise<void> {
        this.sessionStorage.updateKey(sessionKey);
    }

    /**
     * Returns the user matching the given session key in session storage, or throws an exception.
     * 
     * Looks the user up in the {@link UserStorage} instance passed to the constructor.
     * 
     * Undefined will also fail is CookieAuthOptions.filterFunction is defined and returns false,
     * 
     * @param sessionKey the session key to look up
     * @returns a {@link User } object, with the password hash removed.
     * @throws a {@link index!CrossauthError } with {@link ErrorCode } set to `InvalidSessionId` or `Expired`.
     */
    async getUserForSessionKey(sessionKey: string) : Promise<{user: User|undefined, key : Key}> {
        const now = Date.now();
        if (this.hashSessionIds) {
            sessionKey = this.hashSessionKey(sessionKey);
        }
        const key = await this.sessionStorage.getKey(sessionKey);
        if (key.expires) {
            if (now > key.expires.getTime()) {
                let error = new CrossauthError(ErrorCode.Expired);
                CrossauthLogger.logger.debug(error);
                throw error;
            }
        }
        if (key.userId && this.sessionIdleTimeout > 0 && key.lastActive 
            && now > key.lastActive.getTime() + this.sessionIdleTimeout*1000) {
                let error = new CrossauthError(ErrorCode.Expired);
                CrossauthLogger.logger.debug(error);
                throw error;
        }
        if (this.filterFunction) {
            if (!this.filterFunction(key)) {
                let error = new CrossauthError(ErrorCode.InvalidKey);
                CrossauthLogger.logger.debug(error);
                throw error;
            }
        }
        if (key.userId) {
            let user = await this.userStorage.getUserById(key.userId);
            user = await UserPasswordStorage.removePasswordHash(user);
            return {user, key};
        } else {
            return {user: undefined, key};
        }
    }

    /**
     * Deletes all keys for the given user
     * @param userId the user to delete keys for
     * @param except if defined, don't delete this key
     */
    async deleteAllForUser(userId : string | number, except: string|undefined) {
        if (except && this.hashSessionIds) {
            except = this.hashSessionKey(except);
        }
        await this.sessionStorage.deleteAllForUser(userId, except);
    }

    ///// CSRF Tokens
    
    private csrfTokenSignature(token : string) : string {
        const hasher = new Hasher({
            digest: this.digest,
            iterations: this.iterations, 
            keyLength: this.keyLength,
            saltLength: this.saltLength,
        });
        return hasher.hash(this.secret, {salt: token, charset: "base64url", encode: false});
    }
    /**
     * Creates a session key and saves in storage
     * 
     * Date created is the current date/time on the server.
     * 
     * @param uniqueUserId the user ID to store with the session key.
     * @returns the session key, date created and expiry.
     */
    async createCsrfToken(sessionKey : string) : Promise<string> {
        const array = new Uint8Array(this.csrfLength);
        crypto.getRandomValues(array);
        let token = sessionKey + "!" + Hasher.base64ToBase64Url(Buffer.from(array).toString('base64'));
        let signature = this.csrfTokenSignature(token);

        return signature + "." + token;
    }

    /**
     * Returns a {@link Cookie } object with the given session key.
     * 
     * This class is compatible, for example, with Express.
     * 
     * @param token the value of the csrf token, with signature
     * @returns a {@link Cookie } object,
     */
    makeCsrfCookie(token : string) : Cookie {
        let options : CookieOptions = {}
        if (this.csrfDomain) {
            options.domain = this.csrfDomain;
        }
        if (this.csrfPath) {
            options.path = this.csrfPath;
        }
        if (this.csrfDomain) {
            options.domain = this.csrfDomain;
        }
        options.sameSite = this.csrfSameSite;
        if (this.csrfHttpOnly) {
            options.httpOnly = this.csrfHttpOnly;
        }
        if (this.csrfSecure) {
            options.secure = this.csrfSecure;
        }
        return {
            name : this.csrfCookieName,
            value : token,
            options: options
        }
    }

    /**
     * Takes a session ID and creates a string representation of the cookie (value of the HTTP `Cookie` header).
     * 
     * @param token the session key to put in the cookie
     * @returns a string representation of the cookie and options.
     */
    makeCsrfCookieString(token : string) : string {
        let cookie = this.csrfCookieName + "=" + token + "; SameSite=" + this.csrfSameSite;
        if (this.csrfDomain) {
            cookie += "; " + this.csrfDomain;
        }
        if (this.csrfPath) {
            cookie += "; " + this.csrfPath;
        }
        if (this.csrfHttpOnly) {
            cookie += "; httpOnly";
        }
        if (this.csrfSecure) {
            cookie += "; secure";
        }
        return cookie;
    }

    /**
     * Validates the passed CSRF token.  The signature must match the payload, and the payload must match the additional value from the header or form
     * 
     * @param token the token (with signature) to validate.
     * @param formOfHeaderValue the value from the csrfToken form header or the X-CROSSAUTH-CSRF header.
     */
    validateDoubleSubmitCsrfToken(token : string, sessionId : string, formOfHeaderValue: string|undefined) : void {
        let parts = token.split(".");
        if (parts.length != 2) {
            // TODO: this should raise a security issue
            CrossauthLogger.logger.warn("Invalid CSRF token " + token + " received");
            throw new CrossauthError(ErrorCode.InvalidKey);
        }
        let signature = parts[0];
        let message = parts[1];
        if (message != formOfHeaderValue) {
            // TODO: this should raise a security issue
            CrossauthLogger.logger.warn("Invalid CSRF token " + token + " received - form/header cvalue does not match.  Stack trace follows");
            let error = new CrossauthError(ErrorCode.InvalidKey);
            CrossauthLogger.logger.debug(error);
            throw error;
        }
        if (this.csrfTokenSignature(message) != signature) {
            // TODO: this should raise a security issue
            CrossauthLogger.logger.warn("Invalid CSRF token " + token + " received - signature does not match.  Stack trace follows");
            let error = new CrossauthError(ErrorCode.InvalidKey);
            CrossauthLogger.logger.debug(error);
            throw error;
        }
        parts = message.split("!");
        if (parts.length != 2) {
            // TODO: this should raise a security issue
            CrossauthLogger.logger.warn("Invalid CSRF token " + token + " received.  Stack trace follows");
            let error = new CrossauthError(ErrorCode.InvalidKey);
            CrossauthLogger.logger.debug(error);
            throw error;
        }
        let sessionIdInToken = parts[0];
        if (sessionIdInToken != sessionId) {
            // not necessarily a security issue - session ID may have changed when user logged in
            CrossauthLogger.logger.debug("Invalid CSRF token " + token + " received - session ID does not match.  Stack trace follows");
            let error = new CrossauthError(ErrorCode.InvalidKey);
            CrossauthLogger.logger.debug(error);
            throw error;

        }

    }

    /**
     * Validates the passed CSRF token.  The signature must match the payload.  
     * 
     * Doesn't check it matches a double-submit value passed from the form or headers
     * 
     * @param token the token (with signature) to validate.
     */
    validateCsrfToken(token : string, sessionId : string,) : void {
        let parts = token.split(".");
        if (parts.length != 2) {
            // TODO: this should raise a security issue
            CrossauthLogger.logger.warn("Invalid CSRF token " + token + " received");
            throw new CrossauthError(ErrorCode.InvalidKey);
        }
        let signature = parts[0];
        let message = parts[1];
        if (this.csrfTokenSignature(message) != signature) {
            // TODO: this should raise a security issue
            CrossauthLogger.logger.warn("Invalid CSRF token " + token + " received - signature does not match.  Stack trace follows");
            let error = new CrossauthError(ErrorCode.InvalidKey);
            CrossauthLogger.logger.debug(error);
            throw error;
        }
        parts = message.split("!");
        if (parts.length != 2) {
            // TODO: this should raise a security issue
            CrossauthLogger.logger.warn("Invalid CSRF token " + token + " received.  Stack trace follows");
            let error = new CrossauthError(ErrorCode.InvalidKey);
            CrossauthLogger.logger.debug(error);
            throw error;
        }
        let sessionIdInToken = parts[0];
        if (sessionIdInToken != sessionId) {
            // not necessarily a security issue - session ID may have changed when user logged in
            CrossauthLogger.logger.debug("Invalid CSRF token " + token + " received - session ID does not match.  Stack trace follows");
            let error = new CrossauthError(ErrorCode.InvalidKey);
            CrossauthLogger.logger.debug(error);
            throw error;

        }

    }
}

/**
 * Options to {@link CookieSessionManager}. 
 * 
 * See constructor of that class for details.
 */
export interface CookieSessionManagerOptions {
    cookieAuthOptions? : CookieAuthOptions;
    authenticatorOptions? : UsernamePasswordAuthenticatorOptions;
}

/**
 * Class for managing sessions with session ID cookies and username/password authentication.
 * 
 * If you implement endpoints for an authentication backend (eg {@link ExpressCookieAuthServer }), you can use
 * this class in the endpoints, returning the cookies it creates in your HTTP headers.
 */
export class CookieSessionManager {
    userStorage : UserStorage;
    sessionStorage : KeyStorage;
    private auth : CookieAuth;
    private authenticator : HashedPasswordAuthenticator;

    /**
     * Constructor
     * @param userStorage the {@link UserStorage} instance to use, eg {@link PrismaUserStorage}.
     * @param sessionStorage  the {@link KeyStorage} instance to use, eg {@link PrismaSessionStorage}.
     * @param secret a secret password use to sign CSRF tokens and optionally for session IDs.  Must be at leat 16 bytes.  If in the Base64 character set, 22.  If in the hex charfacter set, 32.
     * @param cookieAuthOptions optional parameters for authentication. See {@link CookieAuthOptions }.
     * @param authenticatorOptions optional parameters for username/password authentication.  See {@link UsernamePasswordAuthenticatorOptions }.
     */
    constructor(
        userStorage : UserStorage, 
        sessionStorage : KeyStorage, 
        secret : string,
        {cookieAuthOptions, 
        authenticatorOptions } : CookieSessionManagerOptions = {}) {
        this.userStorage = userStorage;
        this.sessionStorage = sessionStorage;
        this.auth = new CookieAuth(this.userStorage, this.sessionStorage, secret, cookieAuthOptions);

        this.authenticator = new HashedPasswordAuthenticator(this.userStorage, authenticatorOptions);

        }

        /**
         * Returns the name used for session ID cookies.
         */
        get sessionCookieName() : string {
            return this.auth.sessionCookieName;
        }

        /**
         * Returns the name used for CSRF token cookies.
         */
        get csrfCookieName() : string {
            return this.auth.csrfCookieName;
        }

        /**
         * Performs a user login
         *    * Authenticates the username and password
         *    * Creates a session key
         *    * Returns the user (without the password hash) and the session cookie.
         * @param username the username to validate
         * @param password the password to validate
         * @param existingSessionId if this is passed, the it will be used for the new sessionId.  If not, a new random one will be created
         * @returns the user (without the password hash) and session cookie.
         * @throws {@link index!CrossauthError} with {@link ErrorCode} of `Connection`, `UserNotValid`, 
         *         `PasswordNotMatch`.
         */
        async login(username : string, password : string, existingSessionId? : string) : Promise<{sessionCookie: Cookie, csrfCookie: Cookie, user: User}> {
            const user = await this.authenticator.authenticateUser(username, password);

            const sessionKey = await this.auth.createSessionKey(user.id, existingSessionId);
            //await this.sessionStorage.saveSession(user.id, sessionKey.value, sessionKey.dateCreated, sessionKey.expires);
            let sessionCookie = await this.auth.makeSessionCookie(sessionKey);
            let csrfCookie = this.auth.makeCsrfCookie(await this.auth.createCsrfToken(sessionKey.value));
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
        : Promise<{sessionCookie: Cookie, csrfCookie: Cookie, user : User|undefined}> {
            let {sessionKey, sessionCookie, csrfCookie, user} = await this.getValidatedSessionAndCsrf(sessionId, csrfToken);

            if (!sessionKey) {
                sessionKey = await this.auth.createSessionKey(undefined);
            }
            if (!sessionCookie) {
                sessionCookie = this.auth.makeSessionCookie(sessionKey);
            }  
            if (!csrfCookie) {
                csrfToken = await this.auth.createCsrfToken(sessionKey.value);
                csrfCookie = this.auth.makeCsrfCookie(csrfToken);
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
            let sessionKey : Key|undefined = undefined;
            let user : User|undefined = undefined;
            if (sessionId) {
                try {
                    let  {key} = await this.auth.getUserForSessionKey(sessionId);
                    if (key) sessionKey = key;
                    user = await this.userForSessionKey(sessionId);
                }
                catch {
                    sessionId = undefined;
                    csrfToken = undefined;
                }
            }
            if (sessionId && csrfToken) {
                try {
                    this.auth.validateCsrfToken(csrfToken, sessionId);
                } catch {
                    csrfToken = undefined;
                }
            }
            let sessionCookie = sessionKey ? await this.auth.makeSessionCookie(sessionKey) : undefined;         
            const csrfCookie = csrfToken? this.auth.makeCsrfCookie(csrfToken) : undefined;
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
            await this.sessionStorage.deleteKey(sessionKey)
        }

        /**
         * Logs a user out from all sessions.
         * 
         * Removes the given session ID from the session storage.
         * @param except Don't log out from the matching session.
         * @throws {@link index!CrossauthError} with {@link ErrorCode} of `Connection`
         */
        async logoutFromAll(userId : string | number, except? : string|undefined) : Promise<void> {
            await this.auth.deleteAllForUser(userId, except);
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
            let error : CrossauthError | undefined;
            try {
                let {user} = await this.auth.getUserForSessionKey(sessionKey);
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
            return this.auth.makeCsrfCookie(await this.auth.createCsrfToken(sessionId));
        }

        /**
         * Throws {@link index!CrossauthError} with ErrorCode.InvalidKey if the passed CSRF token is not valid for the given
         * session ID.  Otherwise returns without error
         * @param token 
         */
        validateCsrfToken(token : string, sessionId : string) {
            this.auth.validateCsrfToken(token, sessionId);
        }

        /**
         * Throws {@link index!CrossauthError} with ErrorCode.InvalidKey if the passed CSRF token is not valid for the given
         * session ID.  Otherwise returns without error
         * @param token 
         */
        validateDoubleSubmitCsrfToken(token : string, sessionId : string, formOrHeaderValue : string) {
            this.auth.validateDoubleSubmitCsrfToken(token, sessionId, formOrHeaderValue);
        }

    async updateSessionActivity(sessionId : string) : Promise<void> {
        if (this.auth.sessionIdleTimeout > 0) {
            this.auth.updateSessionKey({
                value: sessionId,
                lastActive: new Date(),
            });
        }
    }
}