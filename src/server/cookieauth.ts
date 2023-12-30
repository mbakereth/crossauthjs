import type { 
    User,
    SessionKey 
} from '../interfaces.ts';
import { ErrorCode, CrossauthError } from '../error.ts';
import { UserStorage, SessionStorage } from './storage';
import { HashedPasswordAuthenticator } from "./password";
import type { UsernamePasswordAuthenticatorOptions }  from "./password";

/**
 * Optional parameters to {@link CookieAuth }.  
 */
export interface CookieAuthOptions {

    /** name of the name to use for the cookie.  Defaults to `SESSIONID` */
    cookieName : string | undefined,

    /** Maximum age of the cookie in seconds.  Cookie and session storage table will get an expiry date based on this.  Defaults to one month. */
    maxAge : number | undefined,

    /** Set the `httpOnly` cookie flag.  Default false. */
    httpOnly : boolean | undefined,

    /** Set the `secure` cookie flag.  Default false. */
    secure : boolean | undefined,

    /** Sets the cookie domain.  Default, no domain */
    domain : string | undefined
 
    /** Sets the cookie path.  Default, no path */
    path : string | undefined,

    /** Sets the cookie `SameSite`.  Default `lax` if not defined, which means all cookies will have SameSite set. */
    sameSite : boolean | "lax" | "strict" | "none" | undefined,
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
    sameSite? : boolean | "lax" | "strict" | "none" | undefined
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
    private sessionStorage : SessionStorage;

    readonly cookieName : string = "SESSIONID";
    private maxAge : number = 1209600; // two weeks
    private httpOnly : boolean = false;
    private secure : boolean = false;
    private domain : string | undefined = undefined;
    private path : string | undefined = undefined;
    private sameSite : boolean | "lax" | "strict" | "none" = 'lax';

    /**
     * Constructor.
     * 
     * @param sessionStorage instance of the {@link SessionStorage} object to use, eg {@link PrismaSessionStorage}.
     * @param options optional parameters.  See {@link CookieAuthOptions}.
     */
    constructor(sessionStorage : SessionStorage, options? : CookieAuthOptions) {
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

    /**
     * Creates a session key.  
     * 
     * Date created is the current date/time on the server.
     * 
     * @param uniqueUserId the user ID to store with the session key.
     * @returns the session key, date created and expiry.
     */
    async createSessionKey(uniqueUserId : string | number) : Promise<SessionKey> {
        let sessionKey = crypto.randomUUID();
            const dateCreated = new Date();
            let expires = this.expiry(dateCreated);
            await this.sessionStorage.saveSession(uniqueUserId, sessionKey, dateCreated, expires);
        return {
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
    makeCookieString(sessionKey : SessionKey) : string {
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
    makeCookie(sessionKey : SessionKey) : Cookie {
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
    async getUserForSessionKey(sessionKey: string) : Promise<User> {
        const now = Date.now();
        const {user, expires} = await this.sessionStorage.getUserForSessionKey(sessionKey);
        if (expires) {
            if (now > expires.getTime()) {
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
    userStorage : UserStorage,
    sessionStorage : SessionStorage;
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
    private userStorage : UserStorage;
    private sessionStorage : SessionStorage;
    private auth : CookieAuth;
    private authenticator : HashedPasswordAuthenticator;

    /**
     * Constructor
     * @param userStorage the {@link UserStorage} instance to use, eg {@link PrismaUserStorage}.  Must be given.
     * @param sessionStorage  the {@link SessionStorage} instance to use, eg {@link PrismaSessionStorage}.  Must be given.
     * @param cookieAuthOptions optional parameters for authentication. See {@link CookieAuthOptions }.
     * @param authenticatorOptions optional parameters for username/password authentication.  See {@link UsernamePasswordAuthenticatorOptions }.
     */
    constructor({
        userStorage, 
        sessionStorage, 
        cookieAuthOptions, 
        authenticatorOptions }: CookieSessionManagerOptions) {
        this.userStorage = userStorage;
        this.sessionStorage = sessionStorage;
        this.auth = new CookieAuth(this.sessionStorage, cookieAuthOptions);

        this.authenticator = new HashedPasswordAuthenticator(this.userStorage, authenticatorOptions);

        }

        /**
         * Returns the name used for session ID cookies (taken from the {@link SessionStorage } instance).
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
            this.sessionStorage.saveSession(user.id, sessionKey.value, sessionKey.dateCreated, sessionKey.expires);
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
            await this.sessionStorage.deleteSession(sessionKey)
        }

        /**
         * Returns the user (without password hash) matching the given session key, or throws an Exception
         * @param sessionKey the session key to look up in session storage
         * @returns the {@link User} (without password hash) matching the  session key
         * @throws {@link index!CrossauthError} with {@link ErrorCode} of `Connection`,  `InvalidSessionId`
         *         `UserNotExist` or `Expired`.
         */
        async userForSessionKey(sessionKey : string) {
            return this.auth.getUserForSessionKey(sessionKey);
        }
    

}