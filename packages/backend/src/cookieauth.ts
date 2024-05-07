import type { User, Key } from '@crossauth/common';
import { KeyPrefix } from '@crossauth/common';
import { ErrorCode, CrossauthError } from '@crossauth/common';
import { UserStorage, KeyStorage, UserStorageGetOptions } from './storage';
import { type TokenEmailerOptions } from './emailtokens.ts';
import { Crypto } from './crypto.ts';
import { CrossauthLogger, j } from '@crossauth/common';
import { setParameter, ParamType } from './utils.ts';

const CSRF_LENGTH = 16;
const SESSIONID_LENGTH = 16;

/**
 * Optional parameters when setting cookies,
 * 
 * These match the HTTP cookie parameters of the same name.
 */
export interface CookieOptions {

    domain? : string,
    expires? : Date,
    maxAge? : number,
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
 * Options for double-submit csrf tokens
 */
export interface DoubleSubmitCsrfTokenOptions extends CookieOptions {

    /** Name of cookie.  Defaults to "CSRFTOKEN" */
    cookieName? : string,

    /** Name of header.  Defaults to X-CROSSAUTH-CSRF */
    headerName? : string,

    /** The app secret used to sign the cookie */
    secret? : string;
}

/**
 * Class for creating and validating CSRF tokens according to the double-submit cookie pattern.
 * 
 * CSRF token is send as a cookie plus either a header or a hidden form field.
 */
export class DoubleSubmitCsrfToken {

    // header settings
    /** name of the CRSF HTTP header */
    readonly headerName : string = "X-CROSSAUTH-CSRF";

    // cookie settings
    /** Name of the CSRF Cookie */
    readonly cookieName : string = "CSRFTOKEN";
    private domain : string | undefined = undefined;
    private httpOnly : boolean = false;
    private path : string = "/";
    private secure : boolean = true;
    private sameSite : boolean | "lax" | "strict" | "none" | undefined = "lax";

    // hasher settings
    private secret : string = "";

    /**
     * Constructor.
     * 
     * @param options configurable options.  See {@link DoubleSubmitCsrfTokenOptions}.  The 
     *                expires and maxAge options are ignored (cookies are session-only).
     */
    constructor(options : DoubleSubmitCsrfTokenOptions = {}) {

        // header options
        setParameter("headerName", ParamType.String, this, options, "CSRF_HEADER_NAME");

        // cookie options
        setParameter("cookieName", ParamType.String, this, options, "CSRF_COOKIE_NAME");
        setParameter("domain", ParamType.String, this, options, "CSRF_COOKIE_DOMAIN");
        setParameter("httpOnly", ParamType.Boolean, this, options, "CSRF_COOKIE_HTTPONLY");
        setParameter("path", ParamType.String, this, options, "CSRF_COOKIE_PATH");
        setParameter("secure", ParamType.Boolean, this, options, "CSRF_COOKIE_SECURE");
        setParameter("sameSite", ParamType.String, this, options, "CSRF_COOKIE_SAMESITE");

        // hasher options
        setParameter("secret", ParamType.String, this, options, "SECRET", true);
    }

    /**
     * Creates a session key and saves in storage
     * 
     * Date created is the current date/time on the server.
     * 
     * @returns a random CSRF token.
     */
    createCsrfToken() : string {
        return Crypto.randomValue(CSRF_LENGTH);
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
        const cookieValue = Crypto.sign({v: token}, this.secret, "")
        let options : CookieOptions = {}
        if (this.domain) {
            options.domain = this.domain;
        }
        if (this.path) {
            options.path = this.path;
        }
        options.sameSite = this.sameSite;
        if (this.httpOnly) {
            options.httpOnly = this.httpOnly;
        }
        if (this.secure) {
            options.secure = this.secure;
        }
        return {
            name : this.cookieName,
            value : cookieValue,
            options: options
        }
    }

    makeCsrfFormOrHeaderToken(token : string) : string {
        return this.maskCsrfToken(token);
    }

    unsignCookie(cookieValue : string) : string {
        return Crypto.unsign(cookieValue, this.secret).v;
    }

    /**
     * Takes a session ID and creates a string representation of the cookie (value of the HTTP `Cookie` header).
     * 
     * @param cookieValue the value to put in the cookie
     * @returns a string representation of the cookie and options.
     */
    makeCsrfCookieString(cookieValue : string) : string {
        let cookie = this.cookieName + "=" + cookieValue + "; SameSite=" + this.sameSite;
        if (this.domain) {
            cookie += "; " + this.domain;
        }
        if (this.path) {
            cookie += "; " + this.path;
        }
        if (this.httpOnly) {
            cookie += "; httpOnly";
        }
        if (this.secure) {
            cookie += "; secure";
        }
        return cookie;
    }

    private maskCsrfToken(token : string) : string {
        const mask = Crypto.randomValue(CSRF_LENGTH);
        const maskedToken = Crypto.xor(token, mask);
        return mask + "." + maskedToken;
    }

    private unmaskCsrfToken(maskAndToken : string) {
        const parts = maskAndToken.split(".");
        if (parts.length != 2) throw new CrossauthError(ErrorCode.InvalidCsrf, "CSRF token in header or form not in correct format");
        const mask = parts[0];
        const maskedToken = parts[1];
        return Crypto.xor(maskedToken, mask);
    }

    /**
     * Validates the passed CSRF token.  
     * 
     * To be valid:
     *     * The signature in the cookie must match the token in the cookie
     *     * The token in the cookie must matched the value in the form or header after unmasking
     * 
     * @param cookieValue the CSRDF cookie value to validate.
     * @param formOrHeaderValue the value from the csrfToken form header or the X-CROSSAUTH-CSRF header.
     * @throws {@link @crossauth/common!CrossauthError} with {@link @crossauth/common!ErrorCode} of `InvalidKey`
     */
    validateDoubleSubmitCsrfToken(cookieValue : string, formOrHeaderValue: string) :void  {
        // token in form or header contains mask and masked token.  Unmask to get token back
        const formOrHeaderToken = this.unmaskCsrfToken(formOrHeaderValue);

        // cookie contains unmasked token and signature.  Verify the signature
        let cookieToken : string;
        try {
            cookieToken = Crypto.unsign(cookieValue, this.secret).v;
        } catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            throw new CrossauthError(ErrorCode.InvalidCsrf, "Invalid CSRF cookie");
        }

        if (cookieToken != formOrHeaderToken) {
            CrossauthLogger.logger.warn(j({msg: "Invalid CSRF token received - form/header value does not match", csrfCookieHash: Crypto.hash(cookieValue)}));
            throw new CrossauthError(ErrorCode.InvalidCsrf);
        }

    }

    /**
     * Validates the passed CSRF cookie (doesn't check it matches the token, just that the cookie is valid).  
     * 
     * To be valid:
     *     * The signature in the cookie must match the token in the cookie
     *     * The token in the cookie must matched the value in the form or header after unmasking
     * 
     * @param cookieValue the CSRF cookie value to validate.
     * @throws {@link @crossauth/common!CrossauthError} with {@link @crossauth/common!ErrorCode} of `InvalidKey`
     */
    validateCsrfCookie(cookieValue : string)  {
        try {
            return Crypto.unsign(cookieValue, this.secret).v;
        } catch (e) {
            // Crypto will give us InvalidKey.  Throw a more meaningful error
            CrossauthLogger.logger.error(j({err: e}));
            throw new CrossauthError(ErrorCode.InvalidCsrf, "Invalid CSRF cookie");

        }
    }
}

/**
 * Options for double-submit csrf tokens
 */
export interface SessionCookieOptions extends CookieOptions, TokenEmailerOptions {

    /** Name of cookie.  Defaults to "CSRFTOKEN" */
    cookieName? : string,

    /** If true, session IDs are stored in hashed form in the key storage.  Default false. */
    hashSessionId? : boolean;

    /** If non zero, sessions will time out after this number of seconds have elapsed without activity.  Default 0 (no timeout) */
    idleTimeout? : number;

    /** If true, sessions cookies will be persisted between browser sessions.  Default true */
    persist? : boolean;

    /** App secret  */
    secret? : string;

    /** 
     * This will be called with the session key to filter sessions 
     * before returning.  Function should return true if the session is valid or false otherwise.
     */
    filterFunction? : (sessionKey : Key) => boolean;
}

/**
 * Class for session management using a session id cookie.
 */
export class SessionCookie {

    private userStorage : UserStorage;
    private keyStorage : KeyStorage;

    /** This is set from input options.  Number of seconds before an
     * idle session will time out
     */
    readonly idleTimeout : number = 0;

    private persist : boolean = true;
    private filterFunction? : (sessionKey : Key) => boolean;

    // cookie settings
    /** Name of the CSRF Cookie, set from input options */
    readonly cookieName : string = "SESSIONID";
    private maxAge : number = 60*60*24*4; // 4 weeks
    private domain : string | undefined = undefined;
    private httpOnly : boolean = false;
    private path : string = "/";
    private secure : boolean = true;
    private sameSite : boolean | "lax" | "strict" | "none" | undefined = "lax";

    // hasher settings
    private secret : string = "";

    /**
     * Constructor.
     * 
     * @param userStorage where to find users
     * @param keyStorage where to put session IDs
     * @param options configurable options.  See {@link SessionCookieOptions}.  The 
     *                expires option is ignored (cookies are session-only).
     */
    constructor(userStorage : UserStorage, 
        keyStorage : KeyStorage, 
        options : SessionCookieOptions = {}) {

        this.userStorage = userStorage;
        this.keyStorage = keyStorage;

        setParameter("idleTimeout", ParamType.Number, this, options, "SESSION_IDLE_TIMEOUT");
        setParameter("persist", ParamType.Boolean, this, options, "PERSIST_SESSION_ID");
        this.filterFunction = options.filterFunction;

        // cookie options
        setParameter("cookieName", ParamType.String, this, options, "SESSION_COOKIE_NAME");
        setParameter("maxAge", ParamType.String, this, options, "SESSION_COOKIE_MAX_AGE");
        setParameter("domain", ParamType.String, this, options, "SESSION_COOKIE_DOMAIN");
        setParameter("httpOnly", ParamType.Boolean, this, options, "SESSIONCOOKIE_HTTPONLY");
        setParameter("path", ParamType.String, this, options, "SESSION_COOKIE_PATH");
        setParameter("secure", ParamType.Boolean, this, options, "SESSION_COOKIE_SECURE");
        setParameter("sameSite", ParamType.String, this, options, "SESSION_COOKIE_SAMESITE");

        // hasher options
        setParameter("secret", ParamType.String, this, options, "SECRET", true);
    }

    private expiry(dateCreated : Date) : Date | undefined {
        let expires : Date | undefined = undefined;
        if (this.maxAge > 0) {
            expires = new Date();
            expires.setTime(dateCreated.getTime() + this.maxAge*1000);
        }
        return expires;
    }

    ///// Session IDs

    /**
     * Returns a hash of a session ID, with the session ID prefix for storing
     * in the storage table.
     * @param sessionId the session ID to hash
     * @returns a base64-url-encoded string that can go into the storage
     */
    static hashSessionId(sessionId : string) : string {
        return KeyPrefix.session + Crypto.hash(sessionId);
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
     * @param extraFields Any fields in here will also be added to the session
     *        record
     * @returns the new session key
     * @throws {@link @crossauth/common!CrossauthError} with 
     *         {@link @crossauth/common!ErrorCode} `KeyExists` if maximum
     *          attempts exceeded trying to create a unique session id
     */
    async createSessionKey(userId: string | number | undefined,
        extraFields: { [key: string]: any } = {}) : Promise<Key> {
        const maxTries = 10;
        let numTries = 0;
        let sessionId = Crypto.randomValue(SESSIONID_LENGTH);
        const dateCreated = new Date();
        let expires = this.expiry(dateCreated);
        let succeeded = false;
        while (numTries < maxTries && !succeeded) {
            const hashedSessionId = SessionCookie.hashSessionId(sessionId);
            try {
                // save the new session - if it exists, an error will be thrown
                if (this.idleTimeout > 0 && userId) {
                    extraFields = {...extraFields, lastActivity: new Date()};
                }
                await this.keyStorage.saveKey(userId, hashedSessionId, dateCreated, expires, undefined, extraFields);
                succeeded = true;
            } catch (e) {
                let ce = CrossauthError.asCrossauthError(e);
                if (ce.code == ErrorCode.KeyExists || ce.code == ErrorCode.InvalidKey) {
                    numTries++;
                    sessionId = Crypto.randomValue(SESSIONID_LENGTH);
                    if (numTries > maxTries) {
                        CrossauthLogger.logger.error(j({msg: "Max attempts exceeded trying to create session ID"}))
                        throw new CrossauthError(ErrorCode.KeyExists)
                    }
                } else {
                    CrossauthLogger.logger.debug(j({err: e}));
                    throw e;
                }
            }   
        }
        return {
            userId : userId,
            value : sessionId,
            created : dateCreated,
            expires : expires
        }
    }

    /**
     * Returns a {@link Cookie } object with the given session key.
     * 
     * This class is compatible, for example, with Express.
     * 
     * @param sessionKey the value of the session key
     * @param persist if passed, overrides the persistSessionId setting
     * @returns a {@link Cookie } object,
     */
    makeCookie(sessionKey : Key, persist? : boolean) : Cookie {
        let signedValue = Crypto.sign({v: sessionKey.value}, this.secret, "");
        let options : CookieOptions = {}
        if (persist == undefined) persist = this.persist;
        if (this.domain) {
            options.domain = this.domain;
        }
        if (sessionKey.expires && persist) {
            options.expires = sessionKey.expires;
        }
        if (this.path) {
            options.path = this.path;
        }
        options.sameSite = this.sameSite;
        if (this.httpOnly) {
            options.httpOnly = this.httpOnly;
        }
        if (this.secure) {
            options.secure = this.secure;
        }
        return {
            name : this.cookieName,
            value : signedValue,
            options: options
        }
    }

    /**
     * Takes a session ID and creates a string representation of the cookie
     * (value of the HTTP `Cookie` header).
     * 
     * @param cookie the cookie vlaues to make a string from
     * @returns a string representation of the cookie and options.
     */
    makeCookieString(cookie : Cookie) : string {
        let cookieString = cookie.name + "=" + cookie.value + "; SameSite=" + this.sameSite;
        if (cookie.options.expires) {
            cookieString += "; " + new Date(cookie.options.expires).toUTCString();
        }
        if (this.domain) {
            cookieString += "; " + this.domain;
        }
        if (this.path) {
            cookieString += "; " + this.path;
        }
        if (this.httpOnly) {
            cookieString += "; httpOnly";
        }
        if (this.secure) {
            cookieString += "; secure";
        }
        return cookieString;
    }
    
    /**
     * Updates a session record in storage
     * @param sessionKey the fields to update.  `value` must be set, and
     *        will not be updated.  All other defined fields will be updated.
     * @throws {@link @crossauth/common!CrossauthError} if the session does
     *         not exist. 
     */
    async updateSessionKey(sessionKey : Partial<Key>) : Promise<void> {
        if (!sessionKey.value) throw new CrossauthError(ErrorCode.InvalidKey, "No session when updating activity");
        sessionKey.value = SessionCookie.hashSessionId(sessionKey.value);
        this.keyStorage.updateKey(sessionKey);
    }

    /**
     * Unsigns a cookie and returns the original value.
     * @param cookieValue the signed cookie value
     * @returns the unsigned value
     * @throws {@link @crossauth/common!CrossauthError} if the signature
     *         is invalid. 
     */
    unsignCookie(cookieValue : string) : string {
        return Crypto.unsign(cookieValue, this.secret).v;
    }

    /**
     * Returns the user matching the given session key in session storage, or throws an exception.
     * 
     * Looks the user up in the {@link UserStorage} instance passed to the constructor.
     * 
     * Undefined will also fail is CookieAuthOptions.filterFunction is defined and returns false,
     * 
     * @param sessionId the value in the session cookie
     * @param options See {@link UserStorageGetOptions}
     * @returns a {@link @crossauth/common!User } object, with the password hash removed, and the {@link @crossauth/common!Key } with the unhashed
     *          sessionId
     * @throws a {@link @crossauth/common!CrossauthError } with {@link @crossauth/common!ErrorCode } set to `InvalidSessionId` or `Expired`.
     */
    async getUserForSessionId(sessionId: string, options? : UserStorageGetOptions) : Promise<{user: User|undefined, key : Key}> {
        const key = await this.getSessionKey(sessionId);
        if (key.userId) {
            let {user} = await this.userStorage.getUserById(key.userId, options);
            return {user, key};
        } else {
            return {user: undefined, key};
        }
    }

    /**
     * Returns the user matching the given session key in session storage, or throws an exception.
     * 
     * Looks the user up in the {@link UserStorage} instance passed to the constructor.
     * 
     * Undefined will also fail is CookieAuthOptions.filterFunction is defined and returns false,
     * 
     * @param sessionId the unsigned value of the session cookie
     * @returns a {@link User } object, with the password hash removed.
     * @throws a {@link @crossauth/common!CrossauthError } with 
     *         {@link @crossauth/common!ErrorCode } set to `InvalidSessionId`,
     *         `Expired` or `UserNotExist`.
     */
    async getSessionKey(sessionId: string) : Promise<Key> {
        //const sessionId = this.unsignCookie(cookieValue);
        const now = Date.now();
        const hashedSessionId = SessionCookie.hashSessionId(sessionId);
        const key = await this.keyStorage.getKey(hashedSessionId);
        key.value = sessionId; // storage only has hashed version
        if (key.expires) {
            if (now > key.expires.getTime()) {
                CrossauthLogger.logger.warn(j({msg: "Session id in cookie expired in key storage", hashedSessionCookie: Crypto.hash(sessionId)}));
                throw new CrossauthError(ErrorCode.Expired);
            }
        }
        if (key.userId && this.idleTimeout > 0 && key.lastActive 
            && now > key.lastActive.getTime() + this.idleTimeout*1000) {
                CrossauthLogger.logger.warn(j({msg: "Session cookie with expired idle time received", hashedSessionCookie: Crypto.hash(sessionId)}));
                throw new CrossauthError(ErrorCode.Expired);
        }
        if (this.filterFunction) {
            if (!this.filterFunction(key)) {
                CrossauthLogger.logger.warn(j({msg: "Filter function on session id in cookie failed", hashedSessionCookie: Crypto.hash(sessionId)}));
                throw new CrossauthError(ErrorCode.InvalidKey);
            }
        }
        return key;
    }

    /**
     * Deletes all keys for the given user
     * @param userId the user to delete keys for
     * @param except if defined, don't delete this key
     */
    async deleteAllForUser(userId : string | number, except: string|undefined) {
        if (except) {
            except = SessionCookie.hashSessionId(except);
        }
        await this.keyStorage.deleteAllForUser(userId, KeyPrefix.session, except);
    }
}
