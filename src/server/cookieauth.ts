import type { 
    User,
    SessionKey 
} from '../interfaces.ts';
import { ErrorCode, CrossauthError } from '../error.ts';
import { UserStorage, SessionStorage } from './storage';
import { HashedPasswordAuthenticator } from "./password";
import type { UsernamePasswordAuthenticatorOptions }  from "./password";

export interface CookieAuthOptions {
    cookieName : string | undefined,
    maxAge : number | undefined,
    httpOnly : boolean | undefined,
    secure : boolean | undefined,
    domain : string | undefined
    path : string | undefined,
    sameSite : boolean | "lax" | "strict" | "none" | undefined,
}

export interface CookieOptions {
    domain? : string,
    expires? : Date,
    httpOnly? : boolean,
    path? : string,
    secure? : boolean,
    sameSite? : boolean | "lax" | "strict" | "none" | undefined
}
export interface Cookie {
    name : string,
    value : string,
    options : CookieOptions
}

export class CookieAuth {
    private sessionStorage : SessionStorage;

    readonly cookieName : string = "SESSIONID";
    private maxAge : number = 1209600; // two weeks
    private httpOnly : boolean = false;
    private secure : boolean = false;
    private domain : string | undefined = undefined;
    private path : string | undefined = undefined;
    private sameSite : boolean | "lax" | "strict" | "none" | undefined;

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
        }
    }

    private expiry(dateCreated : Date) : Date | undefined {
        let expires : Date | undefined = undefined;
        if (this.maxAge > 0) {
            expires = new Date();
            expires.setSeconds(dateCreated.getSeconds() + this.maxAge);
        }
        return expires;
    }

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

    
    // throws InvalidSessionId, Expired
    async getUserForCookie(sessionKey: string) : Promise<User> {
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

export interface CookieSessionManagerOptions {
    userStorage : UserStorage,
    sessionStorage : SessionStorage;
    cookieAuthOptions? : CookieAuthOptions;
    authenticatorOptions? : UsernamePasswordAuthenticatorOptions;
}

export class CookieSessionManager {
    userStorage : UserStorage;
    sessionStorage : SessionStorage;
    auth : CookieAuth;
    authenticator : HashedPasswordAuthenticator;

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

        get cookieName() : string {
            return this.auth.cookieName;
        }

        async login(username : string, password : string) : Promise<Cookie> {

            const user = await this.authenticator.authenticateUser(username, password);

            const sessionKey = await this.auth.createSessionKey(user.id);
            this.sessionStorage.saveSession(user.id, sessionKey.value, sessionKey.dateCreated, sessionKey.expires);
            return await this.auth.makeCookie(sessionKey);
        }

        async logout(sessionKey : string) : Promise<void> {
            await this.sessionStorage.deleteSession(sessionKey)
        }
    

}