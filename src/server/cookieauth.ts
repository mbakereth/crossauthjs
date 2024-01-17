import type { 
    User,
    Key 
} from '../interfaces.ts';
import { ErrorCode, CrossauthError } from '../error.ts';
import { UserStorage, UserPasswordStorage, KeyStorage } from './storage';
import { type TokenEmailerOptions } from './email.ts';
import { Hasher, HasherOptions } from './hasher';
import { CrossauthLogger } from '../logger.ts';
import { setParameter, ParamType } from './utils.ts';

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
export interface DoubleSubmitCsrfTokenOptions extends CookieOptions, HasherOptions {

    /** Name of cookie.  Defaults to "CSRFTOKEN" */
    cookieName? : string,

    /** Name of header.  Defaults to X-CROSSAUTH-CSRF */
    headerName? : string,

    /** Length of unsigned part of csrf token in bytes.  It is base64-url encoded so will be longer in practice.  Default 16 */
    length? : number,
}

/**
 * Class for creating and validating CSRF tokens according to the double-submit cookie pattern.
 * 
 * CSRF token is send as a cookie plus either a header or a hidden form field.
 */
export class DoubleSubmitCsrfToken {

    private length : number = 16;

    // header settings
    /** name of the CRSF HTTP header */
    readonly headerName : string = "X-CROSSAUTH-CSRF";

    // cookie settings
    /** Name of the CSRF Cookie */
    readonly cookieName : string = "CSRFTOKEN";
    private domain : string | undefined = undefined;
    private httpOnly : boolean = false;
    private path : string = "/";
    private secure : boolean = false;
    private sameSite : boolean | "lax" | "strict" | "none" | undefined = "lax";

    // hasher settings
    private saltLength : number = 32;
    private iterations = 10000;
    private keyLength = 16;
    private digest = 'sha512';
    private secret : string = "";

    /**
     * Constructor.
     * 
     * @param options configurable options.  See {@link DoubleSubmitCsrfTokenOptions}.  The 
     *                expires and maxAge options are ignored (cookies are session-only).
     */
    constructor(options : DoubleSubmitCsrfTokenOptions = {}) {

        setParameter("length", ParamType.String, this, options, "CSRF_LENGTH");

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
        setParameter("saltLength", ParamType.Number, this, options, "HASHER_SALT_LENGTH");
        setParameter("iterations", ParamType.Number, this, options, "HASHER_ITERATIONS");
        setParameter("keyLength", ParamType.Number, this, options, "HASHER_KEY_LENGTH");
        setParameter("digest", ParamType.Number, this, options, "HASHER_DIGEST");
        setParameter("secret", ParamType.String, this, options, "SECRET", true);
        
    }

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
    async createCsrfToken(sessionId : string) : Promise<string> {
        const array = new Uint8Array(this.length);
        crypto.getRandomValues(array);
        let token = sessionId + "!" + Hasher.base64ToBase64Url(Buffer.from(array).toString('base64'));
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
        let cookie = this.cookieName + "=" + token + "; SameSite=" + this.sameSite;
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

    /**
     * Validates the passed CSRF token.  The signature must match the payload, and the payload must match the additional value from the header or form
     * 
     * @param token the token (with signature) to validate.
     * @param formOrHeaderValue the value from the csrfToken form header or the X-CROSSAUTH-CSRF header.
     */
    validateDoubleSubmitCsrfToken(token : string, sessionId : string, formOrHeaderValue: string|undefined) : void {
        let parts = token.split(".");
        if (parts.length != 2) {
            // TODO: this should raise a security issue
            CrossauthLogger.logger.warn("Invalid CSRF token " + token + " received");
            throw new CrossauthError(ErrorCode.InvalidKey);
        }
        let signature = parts[0];
        let message = parts[1];
        if (message != formOrHeaderValue) {
            // TODO: this should raise a security issue
            CrossauthLogger.logger.debug("Mismatch between CSRF cookie " + message + " form/header " + formOrHeaderValue);
            CrossauthLogger.logger.warn("Invalid CSRF token " + token + " received - form/header value does not match.  Stack trace follows");
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
 * Options for double-submit csrf tokens
 */
export interface SessionCookieOptions extends CookieOptions, HasherOptions, TokenEmailerOptions {

    /** Name of cookie.  Defaults to "CSRFTOKEN" */
    cookieName? : string,

    /** Length of the session ID (before the optional hashing) in bytes.  It is base64-url encoded so will be longer in practice.  Default 16 */
    length? : number;

    /** If true, session IDs are stored in hashed form in the key storage.  Default false. */
    hashSessionId? : boolean;

    /** If non zero, sessions will time out after this number of seconds have elapsed without activity.  Default 0 (no timeout) */
    idleTimeout? : number;

    /** If true, sessions cookies will be persisted between browser sessions.  Default true */
    persist? : boolean;

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
    private length : number = 16;
    private hashSessionId : boolean = false;
    readonly idleTimeout : number = 0;
    private persist : boolean = true;
    private filterFunction? : (sessionKey : Key) => boolean;

    // cookie settings
    /** Name of the CSRF Cookie */
    readonly cookieName : string = "SESSIONID";
    private maxAge : number = 60*60*24*4; // 4 weeks
    private domain : string | undefined = undefined;
    private httpOnly : boolean = false;
    private path : string = "/";
    private secure : boolean = false;
    private sameSite : boolean | "lax" | "strict" | "none" | undefined = "lax";

    // hasher settings
    private saltLength : number = 16;
    private iterations = 10000;
    private keyLength = 16;
    private digest = 'sha512';
    private secret : string = "";

    /**
     * Constructor.
     * 
     * @param options configurable options.  See {@link SessionCookieOptions}.  The 
     *                expires option is ignored (cookies are session-only).
     */
    constructor(userStorage : UserStorage, 
        keyStorage : KeyStorage, 
        options : SessionCookieOptions = {}) {

        this.userStorage = userStorage;
        this.keyStorage = keyStorage;

        setParameter("length", ParamType.String, this, options, "SESSION_KEY_LENGTH");
        setParameter("hashSessionId", ParamType.String, this, options, "HASH_SESSION_ID");
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
        setParameter("saltLength", ParamType.Number, this, options, "HASHER_SALT_LENGTH");
        setParameter("iterations", ParamType.Number, this, options, "HASHER_ITERATIONS");
        setParameter("keyLength", ParamType.Number, this, options, "HASHER_KEY_LENGTH");
        setParameter("digest", ParamType.Number, this, options, "HASHER_DIGEST");
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
                const array = new Uint8Array(this.length);
                crypto.getRandomValues(array);
                sessionKey = Hasher.base64ToBase64Url(Buffer.from(array).toString('base64'));
                hashedSessionKey = sessionKey;
            }
            if (this.hashSessionId) {
                hashedSessionKey = this.hashSessionKey(sessionKey);
            }    
            const dateCreated = new Date();
            let expires = this.expiry(dateCreated);
            try {
                if (keepSessionId && numTries == 0) {
                    // check the key exists.  If not, an error will be thrown
                    let {key} = await this.getUserForSessionKey(hashedSessionKey);
                    key.expiry = expires;
                    if (this.idleTimeout > 0) {
                        key.lastActive = new Date();
                    }
                    await this.updateSessionKey(key);
                } else {
                    // save the new session - if it exists, an error will be thrown
                    let extraFields = {};
                    if (this.idleTimeout > 0 && userId) {
                        extraFields = {lastActivity: new Date()};
                    }
                    await this.keyStorage.saveKey(userId, hashedSessionKey, dateCreated, expires, undefined, extraFields);
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
     * @param persist if passed, overrides the persistSessionId setting
     * @returns a {@link Cookie } object,
     */
    makeSessionCookie(sessionKey : Key, persist? : boolean) : Cookie {
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
        let cookie = this.cookieName + "=" + sessionKey.value + "; SameSite=" + this.sameSite;
        if (sessionKey.expires) {
            cookie += "; " + new Date(sessionKey.expires).toUTCString();
        }
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
    
    async updateSessionKey(sessionKey : Partial<Key>) : Promise<void> {
        this.keyStorage.updateKey(sessionKey);
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
        if (this.hashSessionId) {
            sessionKey = this.hashSessionKey(sessionKey);
        }
        const key = await this.keyStorage.getKey(sessionKey);
        if (key.expires) {
            if (now > key.expires.getTime()) {
                let error = new CrossauthError(ErrorCode.Expired);
                CrossauthLogger.logger.debug(error);
                throw error;
            }
        }
        if (key.userId && this.idleTimeout > 0 && key.lastActive 
            && now > key.lastActive.getTime() + this.idleTimeout*1000) {
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
            user = UserPasswordStorage.removePasswordHash(user);
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
     * @param sessionId the session id to look up
     * @returns a {@link Key } object.
     * @throws a {@link index!CrossauthError } with {@link ErrorCode } set to `InvalidSessionId` or `Expired`.
     */
    async getSessionKey(sessionId: string) : Promise<Key> {
        if (this.hashSessionId) {
            sessionId = this.hashSessionKey(sessionId);
        }
        return await this.keyStorage.getKey(sessionId);
    }

    /**
     * Deletes all keys for the given user
     * @param userId the user to delete keys for
     * @param except if defined, don't delete this key
     */
    async deleteAllForUser(userId : string | number, except: string|undefined) {
        if (except && this.hashSessionId) {
            except = this.hashSessionKey(except);
        }
        await this.keyStorage.deleteAllForUser(userId, except);
    }
}
