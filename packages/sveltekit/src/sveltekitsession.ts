import { KeyStorage, UserStorage, SessionManager, Authenticator, Crypto, DoubleSubmitCsrfToken, setParameter, ParamType } from '@crossauth/backend';
import type { Cookie, SessionManagerOptions } from '@crossauth/backend';
import { CrossauthError, CrossauthLogger, j, ErrorCode, httpStatus } from '@crossauth/common';
import type { Key, User } from '@crossauth/common';
import cookie from 'cookie';
import type { RequestEvent, MaybePromise } from '@sveltejs/kit';
import { JsonOrFormData } from './utils';

export const CSRFHEADER = "X-CROSSAUTH-CSRF";

/*export const svelteSessionHook: Handle = async function ({ event, resolve }){
	const response = await resolve(event);
    response.headers.append('set-cookie', "TESTCOOKIE=testvalue") 
    	return response;
}*/

export interface SvelteKitSessionServerOptions extends SessionManagerOptions {
    /** Called after the session ID is validated.
     * Use this to add additional checks based on the request.  
     * Throw an exception if cecks fail
     */
    validateSession? : (session: Key, user: User|undefined, event : RequestEvent) => void;

    factor2ProtectedEndpoints?: string[],

    prefix? : string,

}

export class SvelteKitSessionServer {
    sessionHook : (input: {event: RequestEvent}, response: Response) => MaybePromise<Response>;
    twoFAHook : (input: {event: RequestEvent}, response: Response) => MaybePromise<Response>;
    keyStorage : KeyStorage;
    sessionManager : SessionManager;
    userStorage : UserStorage;
    authenticators: {[key:string]: Authenticator};
    private validateSession? : (session: Key, user: User|undefined, event : RequestEvent) => void;
    private factor2ProtectedEndpoints : string[] = [
        "/requestpasswordreset",
        "/updateuser",
        "/changepassword",
        "/resetpassword",
        "/changefactor2",
    ]
    private prefix : string = "/";

    constructor(userStorage : UserStorage, keyStorage : KeyStorage, authenticators : {[key:string]: Authenticator}, options : SvelteKitSessionServerOptions = {}) {

        this.keyStorage = keyStorage;
        this.userStorage = userStorage;
        this.authenticators = authenticators
        this.sessionManager = new SessionManager(userStorage, keyStorage, authenticators, options);

        setParameter("prefix", ParamType.String, this, options, "PREFIX");
        if (!this.prefix.endsWith("/")) this.prefix += "/";
        setParameter("factor2ProtectedEndpoints", ParamType.JsonArray, this, options, "FACTOR2_PROTECTED_ENDPOINTS");

        if (options.validateSession) this.validateSession = options.validateSession;

        this.sessionHook = async ({ event}, response) => {

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
                    this.clearCookie(csrfCookieName, response);
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
                        this.setCsrfCookie(csrfCookie, response );
                        event.locals.csrfToken = csrfFormOrHeaderValue;
                    } else {
                        CrossauthLogger.logger.debug(j({msg: "Valid CSRF cookie - creating token"}));
                        const csrfFormOrHeaderValue = await this.sessionManager.createCsrfFormOrHeaderValue(cookieValue);
                        event.locals.csrfToken = csrfFormOrHeaderValue;
                    }
                    response.headers.set(CSRFHEADER, event.locals.csrfToken);
                } catch (e) {
                    CrossauthLogger.logger.error(j({msg: "Couldn't create CSRF token", cerr: e, user: event.locals.user?.username, hashedSessionCookie: this.getHashOfSessionCookie(event)}));
                    CrossauthLogger.logger.debug(j({err: e}));
                    this.clearCookie(csrfCookieName, response);
                    event.locals.csrfToken = undefined;
                }
            } else {
                // for other methods, create a new token only if there is already a valid one
                if (cookieValue) {
                    try {
                        await this.csrfToken(event, response);
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
    
                    event.locals.user = user;
                    CrossauthLogger.logger.debug(j({msg: "Valid session id", user: user?.username}));
                } catch (e) {
                    CrossauthLogger.logger.warn(j({msg: "Invalid session cookie received", hashedSessionCookie: this.getHashOfSessionCookie(event)}));
                    this.clearCookie(sessionCookieName, response);
                }
            }

            return response;
        }

        this.twoFAHook = async ({ event }, response) => {

            const sessionCookieValue = this.getSessionCookieValue(event);
            if (sessionCookieValue && event.locals.user?.factor2 && (this.factor2ProtectedEndpoints.includes(event.request.url))) {
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
                                if (this.factor2ProtectedEndpoints.includes(event.request.url)) {
                                    return new Response('', {status: 302, statusText: httpStatus(302), headers: { Location: this.prefix+"factor2?error="+ErrorCode[error.code] }});

                                } else {
                                    return new Response(JSON.stringify({ok: false, errorMessage: error.message, errorMessages: error.messages, errorCode: error.code, errorCodeName: ErrorCode[error.code]}), {
                                        status: error.httpStatus,
                                        statusText : httpStatus(error.httpStatus),
                                        headers: {
                                            ...response.headers,
                                            ...{'content-tyoe': 'application/json'},
                                        }
                                    });
                                }
                            }
                        }
                    } else {
                        // 2FA has not started - start it
                        if (!event.locals.csrfToken) {
                            const error = new CrossauthError(ErrorCode.Forbidden, "CSRF token missing");
                            return new Response(JSON.stringify({ok: false, errorMessage: error.message, errorMessages: error.messages, errorCode: error.code, errorCodeName: ErrorCode[error.code]}), {
                                status: error.httpStatus,
                                statusText : httpStatus(error.httpStatus),
                                headers: {
                                    ...response.headers,
                                    ...{'content-tyoe': 'application/json'},
                                }
                            });
        
                        }
                        CrossauthLogger.logger.debug("Starting 2FA");
                        const bodyData = new JsonOrFormData();
                        bodyData.loadData(event);
                        this.sessionManager.initiateTwoFactorPageVisit(event.locals.user, sessionCookieValue, bodyData.toObject(), event.request.url.replace(/\?.*$/,""));
                        if (this.factor2ProtectedEndpoints.includes(event.request.url)) {
                            return new Response('', {status: 302, statusText: httpStatus(302), headers: { Location: this.prefix+"factor2" }});
                        } else {
                            return new Response(JSON.stringify({ok: true, factor2Required: true}), {
                                headers: {
                                    ...response.headers,
                                    ...{'content-tyoe': 'application/json'},
                                }
                            });
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
            return response;
        }
    }

    //////////////
    // Helpers

    getSessionCookieValue(event : RequestEvent) : string|undefined{
        if (event.cookies && this.sessionManager.sessionCookieName in event.cookies) {       
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

    clearCookie(name : string, resp : Response) {
        //const cookies = resp.headers.getSetCookie()
        resp.headers.append('set-cookie', cookie.serialize(name, "", {expires: new Date(Date.now()-3600)}));
    } 

    setCsrfCookie(cookie : Cookie, resp : Response) {
        const csrfCookie = new DoubleSubmitCsrfToken({
            cookieName : cookie.name,
            domain: cookie.options.domain,
            httpOnly: cookie.options.httpOnly,
            path: cookie.options.path,
            secure: cookie.options.secure,
            sameSite: cookie.options.sameSite
        });
        resp.headers.append('set-cookie', csrfCookie.makeCsrfCookieString(cookie.value));
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

    async csrfToken(event : RequestEvent, resp : Response) {
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
                resp.headers.set(CSRFHEADER, token);
            }
            catch (e) {
                CrossauthLogger.logger.warn(j({msg: "Invalid CSRF token", hashedCsrfCookie: this.getHashOfCsrfCookie(event)}));
                this.clearCookie(this.sessionManager.csrfCookieName, resp);
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

}