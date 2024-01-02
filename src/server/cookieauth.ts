import type { 
    User,
    Key 
} from '../interfaces.ts';
import { ErrorCode, CrossauthError } from '../error.ts';
import { UserStorage, KeyStorage } from './storage';
import { HashedPasswordAuthenticator } from "./password";
import type { UsernamePasswordAuthenticatorOptions }  from "./password";
import { pbkdf2Sync }  from 'node:crypto';

/**
 * Optional parameters to {@link CookieAuth }.  
 */
export interface CookieAuthOptions {

    /** name of the name to use for the cookie.  Defaults to `SESSIONID` */
    cookieName? : string,

    /** Maximum age of the cookie in seconds.  Cookie and session storage table will get an expiry date based on this.  Defaults to one month. */
    maxAge? : number,

    /** Set the `httpOnly` cookie flag.  Default false. */
    httpOnly? : boolean,

    /** Set the `secure` cookie flag.  Default false. */
    secure? : boolean,

    /** Sets the cookie domain.  Default, no domain */
    domain? : string
 
    /** Sets the cookie path.  Default, no path */
    path? : string,

    /** Sets the cookie `SameSite`.  Default `lax` if not defined, which means all cookies will have SameSite set. */
    sameSite? : boolean | "lax" | "strict" | "none" | undefined,

    /** Length in bytes of random session IDs to create.  Actual key will be longer as it is Base64-encoded. Defaults to 16 */
    keyLength? : number,

    /** If true, session IDs will be PBKDF2-hashed in the session storage. Defaults to false. */
    hashSessionIDs? : boolean,

    /** If hashSessionIDs is true, create salts of this length.  Defaults to 16 */
    saltLength? : number,

    /** If hashSessionIDs is true, use this number of iterations when generating the PBKDF2 hash.  Default 100000 */
    iterations? : number | undefined;

    /** If hashSessionIDs is true, use this HMAC digest algorithm.  Default 'sha512' */
    digest? : string;

    /** If hashSessionIDs is true, make the hash this length in bytes.  Default 32 */
    hashLength? : number;
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
 */
export class CookieAuth {
    private sessionStorage : KeyStorage;

    readonly cookieName : string = "SESSIONID";
    private maxAge : number = 1209600; // two weeks
    private httpOnly : boolean = false;
    private secure : boolean = false;
    private domain : string | undefined = undefined;
    private path : string | undefined = undefined;
    private sameSite : boolean | "lax" | "strict" | "none" = 'lax';
    private keyLength : number = 16;
    private hashSessionIDs : boolean = false;
    private saltLength : number = 16;
    private iterations = 10000;
    private hashLength = 32;
    private digest = 'sha512';

    /**
     * Constructor.
     * 
     * @param sessionStorage instance of the {@link KeyStorage} object to use, eg {@link PrismaSessionStorage}.
     * @param options optional parameters.  See {@link CookieAuthOptions}.
     */
    constructor(sessionStorage : KeyStorage, options? : CookieAuthOptions) {
        this.sessionStorage = sessionStorage;
        if (options) {
            if (options.cookieName) {
                this.cookieName = options.cookieName;
            }
            if (options.maxAge) {
                this.maxAge = options.maxAge;
            }
            if (options.httpOnly) {
                this.httpOnly = options.httpOnly;
            }
            if (options.secure) {
                this.secure = options.secure;
            }
            if (options.domain) {
                this.domain = options.domain;
            }
            if (options.sameSite) {
                this.sameSite = options.sameSite;
            } else {
                this.sameSite = 'lax';
            }
            if (options.keyLength) {
                this.keyLength = options.keyLength;
            }
            if (options.hashSessionIDs) {
                this.hashSessionIDs = options.hashSessionIDs;
            }
            if (options.saltLength) {
                this.saltLength = options.saltLength;
            }
            if (options.iterations) {
                this.iterations = options.iterations;
            }
            if (options.digest) {
                this.digest = options.digest;
            }
            if (options.hashLength) {
                this.hashLength = options.hashLength;
            }

        }
    }

    private expiry(dateCreated : Date) : Date | undefined {
        let expires : Date | undefined = undefined;
        if (this.maxAge > 0) {
            expires = new Date();
            expires.setTime(dateCreated.getTime() + this.maxAge*1000);
        }
        return expires;
    }

    private hashSessionKey(sessionKey : string) : string {
        const array = new Uint8Array(this.saltLength);
        crypto.getRandomValues(array);
        let salt = Buffer.from(array).toString('base64');
        let sessionKeyHash = pbkdf2Sync(
            sessionKey, 
            salt, 
            this.iterations, 
            this.hashLength,
            this.digest 
        ).toString('base64');
        return "pbkdf2" + ":" + this.digest + ":" + String(this.hashLength) 
            + ":" + String(this.iterations) + ":" + salt + ":" + sessionKeyHash;
            
    }
    /**
     * Creates a session key and saves in storage
     * 
     * Date created is the current date/time on the server.
     * 
     * @param uniqueUserId the user ID to store with the session key.
     * @returns the session key, date created and expiry.
     */
    async createSessionKey(userId : string | number | undefined) : Promise<Key> {
        const array = new Uint8Array(this.keyLength);
        crypto.getRandomValues(array);
        let sessionKey = Buffer.from(array).toString('base64');
        if (this.hashSessionIDs) {
            sessionKey = this.hashSessionKey(sessionKey);
        }
        const dateCreated = new Date();
        let expires = this.expiry(dateCreated);
        await this.sessionStorage.saveKey(userId, sessionKey, dateCreated, expires);
        return {
            userId : userId,
            value : sessionKey,
            dateCreated : dateCreated,
            expires : expires
        }
    }

    /**
     * Takes a session ID and creates a string representation of the cookie (value of the HTTP `Cookie` header).
     * 
     * @param sessionKey the session key to put in the cookie
     * @returns a string representation of the cookie and options.
     */
    makeCookieString(sessionKey : Key) : string {
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

    /**
     * Returns a {@link Cookie } object with the given session key.
     * 
     * This class is compatible, for example, with Express.
     * 
     * @param sessionKey the value of the session key
     * @returns a {@link Cookie } object,
     */
    makeCookie(sessionKey : Key) : Cookie {
        let options : CookieOptions = {}
        if (this.domain) {
            options.domain = this.domain;
        }
        if (sessionKey.expires) {
            options.expires = sessionKey.expires;
        }
        if (this.path) {
            options.path = this.path;
        }
        if (this.domain) {
            options.domain = this.domain;
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
     * Returns the user matching the given session key in session storage, or throws an exception.
     * 
     * Looks the user up in the {@link UserStorage} instance passed to the constructor.
     * 
     * @param sessionKey the session key to look up
     * @returns a {@link User } object, with the password hash removed.
     * @throws a {@link index!CrossauthError } with {@link ErrorCode } set to `InvalidSessionId` or `Expired`.
     */
    async getUserForSessionKey(sessionKey: string) : Promise<User|undefined> {
        const now = Date.now();
        if (this.hashSessionIDs) {
            sessionKey = this.hashSessionKey(sessionKey);
        }
        const {user, key} = await this.sessionStorage.getUserForKey(sessionKey);
        if (key.expires) {
            if (now > key.expires.getTime()) {
                throw new CrossauthError(ErrorCode.Expired);
            }
        }
        return user;
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
     * @param cookieAuthOptions optional parameters for authentication. See {@link CookieAuthOptions }.
     * @param authenticatorOptions optional parameters for username/password authentication.  See {@link UsernamePasswordAuthenticatorOptions }.
     */
    constructor(
        userStorage : UserStorage, 
        sessionStorage : KeyStorage, 
        {cookieAuthOptions, 
        authenticatorOptions } : CookieSessionManagerOptions = {}) {
        this.userStorage = userStorage;
        this.sessionStorage = sessionStorage;
        this.auth = new CookieAuth(this.sessionStorage, cookieAuthOptions);

        this.authenticator = new HashedPasswordAuthenticator(this.userStorage, authenticatorOptions);

        }

        /**
         * Returns the name used for session ID cookies (taken from the {@link KeyStorage } instance).
         */
        get cookieName() : string {
            return this.auth.cookieName;
        }

        /**
         * Performs a user login
         *    * Authenticates the username and password
         *    * Creates a session key
         *    * Returns the user (without the password hash) and the session cookie.
         * @param username the username to validate
         * @param password the password to validate
         * @returns the user (without the password hash) and session cookie.
         * @throws {@link index!CrossauthError} with {@link ErrorCode} of `Connection`, `UserNotValid`, 
         *         `PasswordNotMatch`.
         */
        async login(username : string, password : string) : Promise<{cookie: Cookie, user: User}> {
            const user = await this.authenticator.authenticateUser(username, password);

            const sessionKey = await this.auth.createSessionKey(user.id);
            //await this.sessionStorage.saveSession(user.id, sessionKey.value, sessionKey.dateCreated, sessionKey.expires);
            let cookie = await this.auth.makeCookie(sessionKey);
            return {
                cookie: cookie,
                user: user
            }
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
         * Returns the user (without password hash) matching the given session key, or undefined if there isn't one
         * @param sessionKey the session key to look up in session storage
         * @returns the {@link User} (without password hash) matching the  session key
         * @throws {@link index!CrossauthError} with {@link ErrorCode} of `Connection`,  `InvalidSessionId`
         *         `UserNotExist` or `Expired`.
         */
        async userForSessionKey(sessionKey : string) : Promise<User|undefined> {
            let user = await this.auth.getUserForSessionKey(sessionKey);
            return user;
        }
    

}