import { KeyStorage, UserStorage, SessionManager, Authenticator, Crypto, DoubleSubmitCsrfToken, setParameter, ParamType } from '@crossauth/backend';
import type { Cookie, SessionManagerOptions } from '@crossauth/backend';
import { CrossauthError, CrossauthLogger, j, ErrorCode, httpStatus } from '@crossauth/common';
import type { Key, User, UserInputFields } from '@crossauth/common';
import cookie from 'cookie';
import type { RequestEvent, MaybePromise } from '@sveltejs/kit';
import { JsonOrFormData } from './utils';
import { SvelteKitUserEndpoints} from './sveltekituserendpoints';
import type { LoginReturn, LogoutReturn } from './sveltekituserendpoints';

export const CSRFHEADER = "X-CROSSAUTH-CSRF";

type Header = {
    name: string,
    value: string
};

/*export const svelteSessionHook: Handle = async function ({ event, resolve }){
	const response = await resolve(event);
    response.headers.append('set-cookie', "TESTCOOKIE=testvalue") 
    	return response;
}*/

export interface SvelteKitSessionServerOptions extends SessionManagerOptions {

    /**
     * URL to call when factor2 authentication is required
     */
    factor2Url? : string,

    /**
     * URL to call when login is requored.  
     * 
     * Default "/"
     */
    loginUrl? : string,

    /** Function that throws a {@link @crossauth/common!CrossauthError} 
     *  with {@link @crossauth/common!ErrorCode} `FormEntry` if the user 
     * doesn't confirm to local rules.  Doesn't validate passwords  */
    validateUserFn? : (user: UserInputFields) => string[];

    /** Function that creates a user from form fields.
     * Default one takes fields that begin with `user_`, removing the `user_` 
     * prefix and filtering out anything not in the userEditableFields list in 
     * the user storage.
         */
    createUserFn?: (request: RequestEvent,
        userEditableFields: string[]) => UserInputFields;

    /** Function that updates a user from form fields.
     * Default one takes fields that begin with `user_`, removing the `user_`
     *  prefix and filtering out anything not in the userEditableFields list in 
     * the user storage.
         */
    updateUserFn?: (user: User,
        request: RequestEvent,
        userEditableFields: string[]) => User;

    /** Called when a new session token is going to be saved 
     *  Add additional fields to your session storage here.  Return a map of 
     * keys to values.  Don't consume form data.  
     * Use {@link JsonOrFormData }, which takes a copy first. */
    addToSession?: (request: RequestEvent, formData : {[key:string]:string}) => 
        {[key: string] : string|number|boolean|Date|undefined};

    /** Called after the session ID is validated.
     * Use this to add additional checks based on the request.  
     * Throw an exception if cecks fail
     */
    validateSession?: (session: Key,
        user: User | undefined,
        request: RequestEvent) => void;

    /**
     * These page endpoints need the second factor to be entered.  Visiting
     * the page redirects the user to the factor2 page.
     * 
     * You probably want to do this for things like changing password.  The
     * default is
     *   `/requestpasswordreset`,
     *   `/updateuser`,
     *   `/changepassword`,
     *   `/resetpassword`,
     *   `/changefactor2`,
     */
    factor2ProtectedPageEndpoints?: string[],

    /**
     * These page endpoints need the second factor to be entered.  Making
     * a call to these endpoints results in a response of 
     * `{"ok": true, "factor2Required": true `}.  The user should then
     * make a call to `/api/factor2`.   If the credetials are correct, the
     * response will be that of the original request.
     * 
     * You probably want to do this for things like changing password.  The
     * default is
     *   `/api/requestpasswordreset`,
     *   `/api/updateuser`,
     *   `/api/changepassword`,
     *   `/api/resetpassword`,
     *   `/api/changefactor2`,
     */
    factor2ProtectedApiEndpoints?: string[],    

    /**
     * These page endpoints need the the user to be logged in.  If not,
     * the user is directed to the login page.
     * 
     * The default is empty
     * 
     */
    loginProtectedPageEndpoints?: string[],

    /**
     * These page endpoints need the the user to be logged in.  If not,
     * the user is is sent an unauthorized response
     * 
     * The default is empty
     */
    loginProtectedApiEndpoints?: string[],    
    
}

export class SvelteKitSessionServer {
    sessionHook : (input: {event: RequestEvent}, 
        //response: Response
    ) => /*MaybePromise<Response>*/ MaybePromise<{headers: Header[]}>;
    twoFAHook : (input: {event: RequestEvent}, response: Response) => MaybePromise<{twofa: boolean, response: Response}>;
    keyStorage : KeyStorage;
    sessionManager : SessionManager;
    userStorage : UserStorage;
    authenticators: {[key:string]: Authenticator};
    private validateSession? : (session: Key, user: User|undefined, event : RequestEvent) => void;
    private factor2ProtectedPageEndpoints : string[] = [
        "/requestpasswordreset",
        "/updateuser",
        "/changepassword",
        "/resetpassword",
        "/changefactor2",
    ]
    private factor2ProtectedApiEndpoints : string[] = [];
    private loginProtectedPageEndpoints : string[] = [];
    private loginProtectedApiEndpoints : string[] = [];

    private factor2Url : string = "/factor2";

    private userEndpoints : SvelteKitUserEndpoints;

    constructor(userStorage : UserStorage, keyStorage : KeyStorage, authenticators : {[key:string]: Authenticator}, options : SvelteKitSessionServerOptions = {}) {

        this.keyStorage = keyStorage;
        this.userStorage = userStorage;
        this.authenticators = authenticators
        this.sessionManager = new SessionManager(userStorage, keyStorage, authenticators, options);

        setParameter("factor2Url", ParamType.String, this, options, "FACTOR2_URK");
        if (!this.factor2Url.endsWith("/")) this.factor2Url += "/";
        setParameter("factor2ProtectedPageEndpoints", ParamType.JsonArray, this, options, "FACTOR2_PROTECTED_PAGE_ENDPOINTS");
        setParameter("factor2ProtectedApiEndpoints", ParamType.JsonArray, this, options, "FACTOR2_PROTECTED_API_ENDPOINTS");
        setParameter("loginProtectedPageEndpoints", ParamType.JsonArray, this, options, "LOGIN_PROTECTED_PAGE_ENDPOINTS");
        setParameter("loginProtectedApiEndpoints", ParamType.JsonArray, this, options, "LOGIN_PROTECTED_API_ENDPOINTS");

        if (options.validateSession) this.validateSession = options.validateSession;

        this.userEndpoints = new SvelteKitUserEndpoints(this, options);

        this.sessionHook = async ({ event}/*, response*/) => {

            let headers : Header[] = [];

            const csrfCookieName = this.sessionManager.csrfCookieName;
            const sessionCookieName = this.sessionManager.sessionCookieName;

            //const response = await resolve(event);

            // check if CSRF token is in cookie (and signature is valid)
            // remove it if it is not.
            // we are not checking it matches the CSRF token in the header or
            // body at this stage - just removing invalid cookies
            CrossauthLogger.logger.debug(j({msg: "Getting csrf cookie"}));
            let cookieValue : string|undefined;
            try {
                 cookieValue = this.getCsrfCookieValue(event);
                 if (cookieValue) this.sessionManager.validateCsrfCookie(cookieValue);
            }
            catch (e) {
                CrossauthLogger.logger.warn(j({msg: "Invalid csrf cookie received", cerr: e, hashedCsrfCookie: this.getHashOfCsrfCookie(event)}));
                try {
                    this.clearCookie(csrfCookieName, headers);
                } catch (e2) {
                    CrossauthLogger.logger.debug(j({err: e2}));
                    CrossauthLogger.logger.error(j({cerr: e2, msg: "Couldn't delete CSRF cookie", ip: event.request.referrerPolicy, hashedCsrfCookie: this.getHashOfCsrfCookie(event)}));
                }
                cookieValue = undefined;
                event.locals.csrfToken = undefined;
            }

            if (["GET", "OPTIONS", "HEAD"].includes(event.request.method)) {
                // for get methods, create a CSRF token in the request object and response header
                try {
                    if (!cookieValue) {
                        CrossauthLogger.logger.debug(j({msg: "Invalid CSRF cookie - recreating"}));
                        const { csrfCookie, csrfFormOrHeaderValue } = await this.sessionManager.createCsrfToken();
                        this.setCsrfCookie(csrfCookie, headers );
                        event.locals.csrfToken = csrfFormOrHeaderValue;
                    } else {
                        CrossauthLogger.logger.debug(j({msg: "Valid CSRF cookie - creating token"}));
                        const csrfFormOrHeaderValue = await this.sessionManager.createCsrfFormOrHeaderValue(cookieValue);
                        event.locals.csrfToken = csrfFormOrHeaderValue;
                    }
                    this.setHeader(CSRFHEADER, event.locals.csrfToken, headers);
                    //response.headers.set(CSRFHEADER, event.locals.csrfToken);
                } catch (e) {
                    CrossauthLogger.logger.error(j({msg: "Couldn't create CSRF token", cerr: e, user: event.locals.user?.username, hashedSessionCookie: this.getHashOfSessionCookie(event)}));
                    CrossauthLogger.logger.debug(j({err: e}));
                    this.clearCookie(csrfCookieName, headers);
                    event.locals.csrfToken = undefined;
                }
            } else {
                // for other methods, create a new token only if there is already a valid one
                if (cookieValue) {
                    try {
                        await this.csrfToken(event, headers);
                    } catch (e) {
                        CrossauthLogger.logger.error(j({msg: "Couldn't create CSRF token", cerr: e, user: event.locals.user?.username, hashedSessionCookie: this.getHashOfSessionCookie(event)}));
                        CrossauthLogger.logger.debug(j({err: e}));
                    }
                }
            }

            // we now either have a valid CSRF token, or none at all
    
            // validate any session cookie.  Remove if invalid
            event.locals.user = undefined;
            const sessionCookieValue = this.getSessionCookieValue(event);
            CrossauthLogger.logger.debug(j({msg: "Getting session cookie"}));
            if (sessionCookieValue) {
                try {
                    const sessionId = this.sessionManager.getSessionId(sessionCookieValue);
                    let {key, user} = await this.sessionManager.userForSessionId(sessionId)
                    if (this.validateSession) this.validateSession(key, user, event);
    
                    event.locals.sessionId = sessionId;
                    event.locals.user = user;
                    CrossauthLogger.logger.debug(j({msg: "Valid session id", user: user?.username}));
                } catch (e) {
                    CrossauthLogger.logger.warn(j({msg: "Invalid session cookie received", hashedSessionCookie: this.getHashOfSessionCookie(event)}));
                    this.clearCookie(sessionCookieName, headers);
                }
            }

            //return response;
            return {headers};
        }

        this.twoFAHook = async ({ event }, response) => {

            const sessionCookieValue = this.getSessionCookieValue(event);
            if (sessionCookieValue && event.locals.user?.factor2 && (
                this.factor2ProtectedApiEndpoints.includes(event.request.url) || this.factor2ProtectedApiEndpoints.includes(event.request.url))) {
                if (!(["GET", "OPTIONS", "HEAD"].includes(event.request.method))) {
                    const sessionId = this.sessionManager.getSessionId(sessionCookieValue);
                    const sessionData = await this.sessionManager.dataForSessionId(sessionId);
                    if (("pre2fa") in sessionData) {
                        // 2FA has started - validate it
                        CrossauthLogger.logger.debug("Completing 2FA");

                        // get secrets from the request body 
                        const authenticator = this.authenticators[sessionData.pre2fa.factor2];
                        const secretNames = [...authenticator.secretNames(), ...authenticator.transientSecretNames()];
                        let secrets : {[key:string]:string} = {};
                        const bodyData = new JsonOrFormData();
                        await bodyData.loadData(event);
                        for (let field of bodyData.keys()) {
                            if (secretNames.includes(field)) secrets[field] = bodyData.get(field)??"";
                        }

                        const sessionCookieValue = this.getSessionCookieValue(event);
                        if (!sessionCookieValue) throw new CrossauthError(ErrorCode.Unauthorized, "No session cookie found");
                        let error : CrossauthError|undefined = undefined;
                        try {
                            await this.sessionManager.completeTwoFactorPageVisit(secrets, sessionCookieValue);
                        } catch (e) {
                            error = CrossauthError.asCrossauthError(e);
                            CrossauthLogger.logger.debug(j({err: e}));
                            const ce = CrossauthError.asCrossauthError(e);
                            CrossauthLogger.logger.error(j({msg: error.message, cerr: e, user: bodyData.get("username"), errorCode: ce.code, errorCodeName: ce.codeName}));
                        }
                        // restore original request body
                        response = SvelteKitSessionServer.responseWithNewBody(response, sessionData.pre2fa.body);
                        if (error) {
                            if (error.code == ErrorCode.Expired) {
                                // user will not be able to complete this process - delete 
                                CrossauthLogger.logger.debug("Error - cancelling 2FA");
                                // the 2FA data and start again
                                try {
                                    await this.sessionManager.cancelTwoFactorPageVisit(sessionCookieValue);
                                } catch (e) {
                                    CrossauthLogger.logger.error(j({msg: "Failed cancelling 2FA", cerr: e, user: event.locals.user?.username, hashedSessionCookie: this.getHashOfSessionCookie(event)}));
                                    CrossauthLogger.logger.debug(j({err:e}))
                                }
                                response = SvelteKitSessionServer.responseWithNewBody(response, {
                                    ...bodyData.toObject(),
                                    errorMessage: error.message,
                                    errorMessages: error.message,
                                    errorCode: ""+error.code,
                                    errorCodeName: ErrorCode[error.code],
                                });
                            } else {
                                if (this.factor2ProtectedPageEndpoints.includes(event.request.url)) {
                                    return {twofa: true, response: new Response('', {status: 302, statusText: httpStatus(302), headers: { Location: this.factor2Url+"?error="+ErrorCode[error.code] }})};

                                } else {
                                    return {twofa: true, response: new Response(JSON.stringify({
                                        ok: false,
                                        errorMessage: error.message,
                                        errorMessages: error.messages,
                                        errorCode: error.code,
                                        errorCodeName: ErrorCode[error.code]
                                    }), {
                                        status: error.httpStatus,
                                        statusText : httpStatus(error.httpStatus),
                                        headers: {
                                            ...response.headers,
                                            ...{'content-tyoe': 'application/json'},
                                        }
                                    })};
                                }
                            }
                        }
                    } else {
                        // 2FA has not started - start it
                        if (!event.locals.csrfToken) {
                            const error = new CrossauthError(ErrorCode.Forbidden, "CSRF token missing");
                            return {twofa: true, response: new Response(JSON.stringify({ok: false, errorMessage: error.message, errorMessages: error.messages, errorCode: error.code, errorCodeName: ErrorCode[error.code]}), {
                                status: error.httpStatus,
                                statusText : httpStatus(error.httpStatus),
                                headers: {
                                    ...response.headers,
                                    ...{'content-tyoe': 'application/json'},
                                }
                            })};
        
                        }
                        CrossauthLogger.logger.debug("Starting 2FA");
                        const bodyData = new JsonOrFormData();
                        bodyData.loadData(event);
                        this.sessionManager.initiateTwoFactorPageVisit(event.locals.user, sessionCookieValue, bodyData.toObject(), event.request.url.replace(/\?.*$/,""));
                        if (this.factor2ProtectedPageEndpoints.includes(event.request.url)) {
                            return {twofa: true, response: new Response('', {status: 302, statusText: httpStatus(302), headers: { Location: this.factor2Url }})};
                        } else {
                            return {twofa: true, response: new Response(JSON.stringify({
                                ok: true,
                                factor2Required: true}), {
                                headers: {
                                    ...response.headers,
                                    ...{'content-tyoe': 'application/json'},
                                }
                            })};
                        }
                    }
                } else {
                    // if we have a get request to one of the protected urls, cancel any pending 2FA
                    const sessionCookieValue = this.getSessionCookieValue(event);
                    if (sessionCookieValue) {
                        const sessionId = this.sessionManager.getSessionId(sessionCookieValue);
                        const sessionData = await this.sessionManager.dataForSessionId(sessionId);
                        if (("pre2fa") in sessionData) {
                            CrossauthLogger.logger.debug("Cancelling 2FA");
                            try {
                                await this.sessionManager.cancelTwoFactorPageVisit(sessionCookieValue);
                            } catch (e) {
                                CrossauthLogger.logger.debug(j({err:e}));
                                CrossauthLogger.logger.error(j({msg: "Failed cancelling 2FA", cerr: e, user: event.locals.user?.username, hashedSessionCookie: this.getHashOfSessionCookie(event)}));
                            }      
                        }
                    }
                }
            } 
            return {twofa: false, response};
        }
    }

    //////////////
    // Helpers

    getSessionCookieValue(event : RequestEvent) : string|undefined{
        //let allCookies = event.cookies.getAll();
        if (event.cookies && event.cookies.get(this.sessionManager.sessionCookieName)) {       
            return event.cookies.get(this.sessionManager.sessionCookieName);
        }
        return undefined;
    }

    getCsrfCookieValue(event : RequestEvent) : string|undefined {
        if (event.cookies) {  
            const cookie = event.cookies.get(this.sessionManager.csrfCookieName)     ;
            if (cookie)
                return event.cookies.get(this.sessionManager.csrfCookieName);
        }
        return undefined;
    }

    clearCookie(name : string, headers: Header[]) {
        //const cookies = resp.headers.getSetCookie()
        headers.push({
            name: "set-cookie",
            value: cookie.serialize(name, "", {expires: new Date(Date.now()-3600)}),
        });
        //resp.headers.append('set-cookie', cookie.serialize(name, "", {expires: new Date(Date.now()-3600)}));
    } 

    setHeaders(headers: Header[], resp: Response) {
        for (let header of headers) {
            resp.headers.append(header.name, header.value);
        }
    } 

    setCsrfCookie(cookie : Cookie, headers: Header[]) {
        const csrfCookie = new DoubleSubmitCsrfToken({
            cookieName : cookie.name,
            domain: cookie.options.domain,
            httpOnly: cookie.options.httpOnly,
            path: cookie.options.path,
            secure: cookie.options.secure,
            sameSite: cookie.options.sameSite
        });
        headers.push({
            name: "set-cookie",
            value: csrfCookie.makeCsrfCookieString(cookie.value)
        });
        //resp.headers.append('set-cookie', csrfCookie.makeCsrfCookieString(cookie.value));
    }

    setHeader(name: string, value: string, headers: Header[]) {
        headers.push({
            name: name,
            value: value,
        });
    }

    getHashOfSessionCookie(event : RequestEvent) : string {
        const cookieValue = this.getSessionCookieValue(event);
        if (!cookieValue) return "";
        try {
            return Crypto.hash(cookieValue);
        } catch (e) {}
        return "";
    }

    getHashOfCsrfCookie(event : RequestEvent) : string {
        const cookieValue = this.getCsrfCookieValue(event);
        if (!cookieValue) return "";
        try {
            return Crypto.hash(cookieValue);
        } catch (e) {}
        return "";
    }

    async csrfToken(event : RequestEvent, headers : Header[]) {
        let token : string|undefined = undefined;

        // first try token in header
        if (event.request.headers && event.request.headers.has(CSRFHEADER.toLowerCase())) { 
            const header = event.request.headers.get(CSRFHEADER.toLowerCase());
            if (Array.isArray(header)) token = header[0];
            else if (header) token = header;
        }

        // if not in header, try in body
        if (!token) {
            if (!event.request?.body) {
                CrossauthLogger.logger.warn(j({msg: "Received CSRF header but not token", ip: event.request.referrerPolicy, hashedCsrfCookie: this.getHashOfCsrfCookie(event)}));
                return;
            }
            const contentType = event.request.headers.get("content-type")
            if (contentType == "application/json") {
                const body = await event.request?.clone()?.json();
                token = body.csrfToken;
            } else if (contentType == "application/x-www-form-urlencoded" || contentType == "multipart/form-data") {
                const body = await event.request.clone().formData();
                const formValue = body.get("csrfToken");
                if (formValue && typeof formValue == "string") token = formValue;
            }
        }
        if (token) {
            try {
                this.sessionManager.validateDoubleSubmitCsrfToken(this.getCsrfCookieValue(event), token);
                event.locals.csrfToken = token;
                //resp.headers.set(CSRFHEADER, token);
                this.setHeader(CSRFHEADER, token, headers)
            }
            catch (e) {
                CrossauthLogger.logger.warn(j({msg: "Invalid CSRF token", hashedCsrfCookie: this.getHashOfCsrfCookie(event)}));
                this.clearCookie(this.sessionManager.csrfCookieName, headers);
                event.locals.csrfToken = undefined;
            }
        } else {
            event.locals.csrfToken = undefined;
        }

        return token;
    }

    static responseWithNewBody(origResp : Response, params : {[key:string]:string}) {
        const contentType = origResp.headers.get('content-type');
        const newContentType = contentType == 'application/json' ? 'application/json' : 'application/x-www-form-urlencoded';
        let body : string;
        if (newContentType == 'application/json') {
            body = JSON.stringify(params);
        } else {
            body = "";
            for (let name in params) {
                const value = params[name];
                if (body.length > 0) body += "&";
                body += encodeURIComponent(name) + "=" + encodeURIComponent(value);
            }
        }
        return new Response(body, {
            headers: {...origResp.headers, ...{'content-type': newContentType}},
            status: origResp.status,
            statusText : origResp.statusText,
        })
    }

    /**
     * Returns a hash of the session ID.  Used for logging (for security,
     * the actual session ID is not logged)
     * @param request the Fastify request
     * @returns hash of the session ID
     */
    getHashOfSessionId(event : RequestEvent) : string {
        if (!event.locals.sessionId) return "";
        try {
            return Crypto.hash(event.locals.sessionId);
        } catch (e) {}
        return "";
    }

    /////////////////////////////////////////////////////////////
    // login protected URLs

    isLoginPageProtected(event : RequestEvent) : boolean {
        const url = new URL(event.request.url);
        return (this.loginProtectedPageEndpoints.includes(url.pathname));
    }
 
    isLoginApiProtected(event : RequestEvent) : boolean {
        const url = new URL(event.request.url);
        return (this.loginProtectedApiEndpoints.includes(url.pathname));
    }

    /////////////////////////////////////////////////////////////
    // User Endpoints

    /**
     * Log a user in if possible.  
     * 
     * Form data is returned unless there was
     * an error extrafting it.  User is returned if log in was successful.
     * Error messge and exception are returned if not successful.
     * 
     * @param event the Sveltekit event
     * @returns user, form data, error message and exception (see above)
     */
    async login(event : RequestEvent) : Promise<LoginReturn> {
        return this.userEndpoints.login(event);
    }

    /**
     * Log a user out.  
     * 
     * Deletes the session if the user was logged in and clears session
     * and CSRF cookies
     * 
     * @param event the Sveltekit event
     * @returns success of true or false and error message if not successful
     */
    async logout(event : RequestEvent) : Promise<LogoutReturn> {
        return this.userEndpoints.logout(event);
    }
}