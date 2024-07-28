import { minimatch } from 'minimatch';
import {
    KeyStorage,
    UserStorage,
    SessionManager,
    Authenticator,
    Crypto,
    setParameter,
    ParamType,
    toCookieSerializeOptions } from '@crossauth/backend';
import type { Cookie, SessionManagerOptions } from '@crossauth/backend';
import { CrossauthError, CrossauthLogger, j, ErrorCode, httpStatus } from '@crossauth/common';
import type { Key, User, UserInputFields } from '@crossauth/common';
import type { RequestEvent, MaybePromise } from '@sveltejs/kit';
import { error } from '@sveltejs/kit';
import { JsonOrFormData } from './utils';
import { SvelteKitUserEndpoints} from './sveltekituserendpoints';
import type {
    LoginReturn,
    LogoutReturn,
    SignupReturn,
    VerifyEmailReturn,
    ConfigureFactor2Return,
    RequestPasswordResetReturn,
    ResetPasswordReturn,
    RequestFactor2Return,
 } from './sveltekituserendpoints';
import { SvelteKitServer } from './sveltekitserver'

export const CSRFHEADER = "X-CROSSAUTH-CSRF";

export type InitiateFactor2Return = {
    success: boolean,
    factor2? : string,
    error? : string,
    exception? : CrossauthError,
};

export type CompleteFactor2Return = {
    success: boolean,
    error? : string,
    factor2? : string,
    formData?: {[key:string]:string},
    exception? : CrossauthError,
};

export type CancelFactor2Return = {
    success: boolean,
    error? : string,
    exception? : CrossauthError,
};

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
    createUserFn?: (event: RequestEvent,
        data : {[key:string]:string|undefined},
        userEditableFields: string[]) => UserInputFields;

    /** Function that updates a user from form fields.
     * Default one takes fields that begin with `user_`, removing the `user_`
     *  prefix and filtering out anything not in the userEditableFields list in 
     * the user storage.
         */
    updateUserFn?: (user: User,
        event: RequestEvent,
        data : {[key:string]:string|undefined},
        userEditableFields: string[]) => User;

    /** Called when a new session token is going to be saved 
     *  Add additional fields to your session storage here.  Return a map of 
     * keys to values.  Don't consume form data.  
     * Use {@link JsonOrFormData }, which takes a copy first. */
    addToSession?: (event: RequestEvent, formData : {[key:string]:string}) => 
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
     * You should include at least any URLs which validate a user, also
     * the url for configuring 2FA.
     * 
     * You can have wildcard which is useful for including path info,
     * eg `/resetpassword/*`
     * 
     * THe default is empty.
     */
    factor2ProtectedPageEndpoints?: string[],

    /**
     * These page endpoints need the second factor to be entered.  Making
     * a call to these endpoints results in a response of 
     * `{"ok": true, "factor2Required": true `}.  The user should then
     * make a call to `/api/factor2`.   If the credetials are correct, the
     * response will be that of the original request.
     * 
     * You can have wildcard which is useful for including path info,
     * eg `/resetpassword/*`
     */
    factor2ProtectedApiEndpoints?: string[],    

    /**
     * These page endpoints need the the user to be logged in.  If not,
     * the user is directed to the login page.
     * 
     * You can have wildcard which is useful for including path info,
     * eg `/resetpassword/*`
     * 
     * The default is empty.
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
    
    /**
     * These page endpoints need an admin user to be logged in.  
     * 
     * This
     * is defined by the isAdminFn option in {@link SvelteKitServerOptions}.
     * The default one is to check the `admin` boolean field in the user
     * object. If there is no user, or the user is not an admin, a 401 
     * page is returned,
     * 
     * The default is empty
     * 
     */
    adminEndpoints?: string[],

    /**
     * Turns on email verification.  This will cause the verification tokens to 
     * be sent when the account
     * is activated and when email is changed.  Default false.
     */
    enableEmailVerification? : boolean,

    /**
     * Turns on password reset.  Default false.
     */
    enablePasswordReset? : boolean,

    /**
     * CSRF protection is on by default but can be disabled by setting
     * this to false.
     * 
     * Sveltekit has its own CSRF protection enabled by default.  If you
     * disable it here, make sure you are not doing anything that bypasses
     * Sveltekit's own protection.
     */
    enableCsrfProtection? : boolean,
}

/////////////////////////////////////////////////////////////////////////////
// DEFAULT FUNCTIONS

/**
 * Default User validator.  Doesn't validate password
 * 
 * Username must be at least two characters.
 * @param password The password to validate
 * @returns an array of errors.  If there were no errors, returns an empty array
 */
function defaultUserValidator(user : UserInputFields) : string[] {
    let errors : string[] = [];
    if (user.username == undefined) errors.push("Username must be given");
    else if (user.username.length < 2) errors.push("Username must be at least 2 characters");
    else if (user.username.length > 254) errors.push("Username must be no longer than 254 characters");
    
    return errors;
}

/**
 * Default function for creating users.  Can be overridden.
 * 
 * Takes any field beginning with `user_` and that is also in
 * `userEditableFields` (without the `user_` prefix).
 * 
 * @param request the fastify request
 * @param userEditableFields the fields a user may edit
 * @returns the new user
 */
function defaultCreateUser(event : RequestEvent, 
    data : {[key:string]:string|undefined},
    userEditableFields: string[]) : UserInputFields {
    let state = "active";
    let user : UserInputFields = {
        username: data.username ?? "",
        state: state,
    }
    const callerIsAdmin = event.locals.user && SvelteKitServer.isAdminFn(event.locals.user);
    for (let field in data) {
        let name = field.replace(/^user_/, ""); 
        if (field.startsWith("user_") && 
            (callerIsAdmin || userEditableFields.includes(name))) {
            user[name] = data[field];
        }
    }
    user.factor1 = "localpassword";
    user.factor2 = data.factor2;
    return user;

}

/**
 * Default function for creating users.  Can be overridden.
 * 
 * Takes any field beginning with `user_` and that is also in
 * `userEditableFields` (without the `user_` prefix).
 * 
 * @param user the user to update
 * @param request the fastify request
 * @param userEditableFields the fields a user may edit
 * @returns the new user
 */
function defaultUpdateUser(user: User,
    event: RequestEvent,
    data : {[key:string]:string|undefined},
    userEditableFields: string[]) : User {
        const callerIsAdmin = event.locals.user && SvelteKitServer.isAdminFn(event.locals.user);
        for (let field in data) {
        let name = field.replace(/^user_/, ""); 
        if (field.startsWith("user_") && 
            (callerIsAdmin || userEditableFields.includes(name))) {
            user[name] = data[field];
        }
    }
    return user;

}

export class SvelteKitSessionServer {
    readonly sessionHook : (input: {event: RequestEvent}, 
        //response: Response
    ) => /*MaybePromise<Response>*/ MaybePromise<{headers: Header[]}>;
    readonly twoFAHook : (input: {event: RequestEvent}) => MaybePromise<{twofa: boolean, success: boolean, response?: Response}>;


    /**
     * Key storage taken from constructor args.
     * See {@link SvelteKitSessionServer.constructor}.
     */
    readonly keyStorage : KeyStorage;

    /**
     * Session Manager taken from constructor args.
     * See {@link SvelteKitSessionServer.constructor}.
     */
    readonly sessionManager : SessionManager;

    /**
     * User storage taken from constructor args.
     * See {@link SvelteKitSessionServer.constructor}.
     */
    readonly userStorage : UserStorage;

    /**
     * Funtion to validate users upon creation.  Taken from the options during 
     * construction or the default value.
     * See {@link FastifySessionServerOptions}.
     */
    validateUserFn : (user : UserInputFields) 
        => string[] = defaultUserValidator;

    /**
     * Funtion to create a user record from form fields.  Taken from the options during 
     * construction or the default value.
     * See {@link FastifySessionServerOptions}.
     */
    createUserFn: (event : RequestEvent,
        data : {[key:string]: string|undefined},
        userEditableFields: string[]) => UserInputFields = defaultCreateUser;

    /**
     * Funtion to update a user record from form fields.  Taken from the options during 
     * construction or the default value.
     * See {@link FastifySessionServerOptions}.
     */
    updateUserFn: (user: User,
        event: RequestEvent,
        data : {[key:string]: string|undefined},
        userEditableFields: string[]) => User = defaultUpdateUser;

    /**
     * The set of authenticators taken from constructor args.
     * See {@link FastifySessionServer.constructor}.
     */
    readonly authenticators: {[key:string]: Authenticator};

    /**
     * The set of allowed authenticators taken from the options during 
     * construction.
     */
    readonly allowedFactor2 : {name: string, friendlyName: string}[] = [];

    /**
     * The set of allowed authenticators taken from the options during 
     * construction.
     */
    readonly allowedFactor2Names : string[] = [];

    /** Called when a new session token is going to be saved 
     *  Add additional fields to your session storage here.  Return a map of 
     * keys to values  */
    addToSession?: (event: RequestEvent, formData : {[key:string]:string}) => 
        {[key: string] : string|number|boolean|Date|undefined};

    /**
     * The set of allowed authenticators taken from the options during 
     * construction.
     */
    private validateSession? : (session: Key, user: User|undefined, event : RequestEvent) => void;

    private factor2ProtectedPageEndpoints : string[] = []
    private factor2ProtectedApiEndpoints : string[] = [];
    private loginProtectedPageEndpoints : string[] = [];
    private loginProtectedApiEndpoints : string[] = [];
    private adminEndpoints : string[] = [];

    readonly enableCsrfProtection = true;

    /** Whether email verification is enabled.
     * 
     * Reads from constructor options
     */
    readonly enableEmailVerification = false;

    /** Whether password reset is enabled.
     * 
     * Reads from constructor options
     */
    readonly enablePasswordReset = false;

    private factor2Url : string = "/factor2";

    private userEndpoints : SvelteKitUserEndpoints;

    constructor(userStorage : UserStorage, keyStorage : KeyStorage, authenticators : {[key:string]: Authenticator}, options : SvelteKitSessionServerOptions = {}) {

        this.keyStorage = keyStorage;
        this.userStorage = userStorage;
        this.authenticators = authenticators;
        this.sessionManager = new SessionManager(userStorage, keyStorage, authenticators, options);

        setParameter("factor2Url", ParamType.String, this, options, "FACTOR2_URK");
        if (!this.factor2Url.endsWith("/")) this.factor2Url += "/";
        setParameter("factor2ProtectedPageEndpoints", ParamType.JsonArray, this, options, "FACTOR2_PROTECTED_PAGE_ENDPOINTS");
        setParameter("factor2ProtectedApiEndpoints", ParamType.JsonArray, this, options, "FACTOR2_PROTECTED_API_ENDPOINTS");
        setParameter("loginProtectedPageEndpoints", ParamType.JsonArray, this, options, "LOGIN_PROTECTED_PAGE_ENDPOINTS");
        setParameter("loginProtectedApiEndpoints", ParamType.JsonArray, this, options, "LOGIN_PROTECTED_API_ENDPOINTS");
        setParameter("adminEndpoints", ParamType.JsonArray, this, options, "ADMIN_ENDPOINTS");
        let options1 : {allowedFactor2?: string[]} = {}
        setParameter("allowedFactor2", ParamType.JsonArray, options1, options, "ALLOWED_FACTOR2");
        this.allowedFactor2Names = options.allowedFactor2 ?? ["none"];
        if (options1.allowedFactor2) {
            for (let factor of options1.allowedFactor2) {
                if (factor in this.authenticators) {
                    this.allowedFactor2.push({name: factor, friendlyName: this.authenticators[factor].friendlyName});
                } else if (factor == "none") {
                    this.allowedFactor2.push({name: "none", friendlyName: "None"});

                }
            }
        }
        setParameter("enableEmailVerification", ParamType.Boolean, this, options, "ENABLE_EMAIL_VERIFICATION");
        setParameter("enablePasswordReset", ParamType.Boolean, this, options, "ENABLE_PASSWORD_RESET");
        setParameter("enableCsrfProtection", ParamType.Boolean, this, options, "ENABLE_CSRF_PROTECTION");

        if (options.validateUserFn) this.validateUserFn = options.validateUserFn;
        if (options.createUserFn) this.createUserFn = options.createUserFn;
        if (options.updateUserFn) this.updateUserFn = options.updateUserFn;
        if (options.addToSession) this.addToSession = options.addToSession;
        if (options.validateSession) this.validateSession = options.validateSession;

        this.userEndpoints = new SvelteKitUserEndpoints(this, options);

        this.sessionHook = async ({ event}/*, response*/) => {
            CrossauthLogger.logger.debug("Session hook");

            let headers : Header[] = [];

            const csrfCookieName = this.sessionManager.csrfCookieName;
            const sessionCookieName = this.sessionManager.sessionCookieName;

            //const response = await resolve(event);

            // check if CSRF token is in cookie (and signature is valid)
            // remove it if it is not.
            // we are not checking it matches the CSRF token in the header or
            // body at this stage - just removing invalid cookies
            if (this.enableCsrfProtection) {
                CrossauthLogger.logger.debug(j({msg: "Getting csrf cookie"}));
                let cookieValue : string|undefined;
                try {
                    cookieValue = this.getCsrfCookieValue(event);
                    if (cookieValue) this.sessionManager.validateCsrfCookie(cookieValue);
               }
               catch (e) {
                   CrossauthLogger.logger.warn(j({msg: "Invalid csrf cookie received", cerr: e, hashedCsrfCookie: this.getHashOfCsrfCookie(event)}));
                   try {
                       this.clearCookie(csrfCookieName, this.sessionManager.csrfCookiePath, event);
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
                           this.setCsrfCookie(csrfCookie, event );
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
                       this.clearCookie(csrfCookieName, this.sessionManager.csrfCookiePath, event);
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
       
            }

            // we now either have a valid CSRF token, or none at all (or CSRF
            // protection has been disabled, in which case the CSRF cookie
            // is ignored)
    
            // validate any session cookie.  Remove if invalid
            event.locals.user = undefined;
            event.locals.authType = undefined;
            const sessionCookieValue = this.getSessionCookieValue(event);
            CrossauthLogger.logger.debug(j({msg: "Getting session cookie"}));
            if (sessionCookieValue) {
                try {
                    const sessionId = this.sessionManager.getSessionId(sessionCookieValue);
                    let {key, user} = await this.sessionManager.userForSessionId(sessionId)
                    if (this.validateSession) this.validateSession(key, user, event);
    
                    event.locals.sessionId = sessionId;
                    event.locals.user = user;
                    event.locals.authType = "cookie";
                    CrossauthLogger.logger.debug(j({msg: "Valid session id", user: user?.username}));
                } catch (e) {
                    CrossauthLogger.logger.warn(j({msg: "Invalid session cookie received", hashedSessionCookie: this.getHashOfSessionCookie(event)}));
                    this.clearCookie(sessionCookieName, this.sessionManager.sessionCookiePath, event);
                }
            }

            //return response;
            return {headers};
        }

        this.twoFAHook = async ({ event }) => {
            CrossauthLogger.logger.debug(j({msg: "twoFAHook" , username: event.locals.user?.username}) );

            const sessionCookieValue = this.getSessionCookieValue(event);
            const isFactor2PageProtected = this.isFactor2PageProtected(event);
            const isFactor2ApiProtected = this.isFactor2ApiProtected(event);
            let user : User|undefined;
            if (sessionCookieValue) {
                if (event.locals.user) user = event.locals.user;
                else {
                    const anonUser = await this.getSessionData(event, "user");
                    if (anonUser) {
                        const resp = await this.userStorage.getUserByUsername(anonUser.username);
                        user = resp.user;
                    }
                }
            }
            if (user && sessionCookieValue && user.factor2 != "" && (
                isFactor2PageProtected || isFactor2ApiProtected)) {
                    CrossauthLogger.logger.debug(j({msg:"Factor2-protected endpoint visited"}));
                    if (!(["GET", "OPTIONS", "HEAD"].includes(event.request.method))) {
                    const sessionId = this.sessionManager.getSessionId(sessionCookieValue);
                    const sessionData = await this.sessionManager.dataForSessionId(sessionId);
                    if (("pre2fa") in sessionData) {
                        // 2FA has started - validate it
                        CrossauthLogger.logger.debug(j({msg:"Completing 2FA"}));

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
                        let error1 : CrossauthError|undefined = undefined;
                        try {
                            await this.sessionManager.completeTwoFactorPageVisit(secrets, event.locals.sessionId??"");
                        } catch (e) {
                            error1 = CrossauthError.asCrossauthError(e);
                            CrossauthLogger.logger.debug(j({err: e}));
                            const ce = CrossauthError.asCrossauthError(e);
                            CrossauthLogger.logger.error(j({msg: error1.message, cerr: e, user: bodyData.get("username"), errorCode: ce.code, errorCodeName: ce.codeName}));
                        }
                        if (error1) {
                            if (error1.code == ErrorCode.Expired) {
                                // user will not be able to complete this process - delete 
                                CrossauthLogger.logger.debug(j({msg:"Error - cancelling 2FA"}));
                                // the 2FA data and start again
                                try {
                                    await this.sessionManager.cancelTwoFactorPageVisit(sessionCookieValue);
                                } catch (e) {
                                    CrossauthLogger.logger.error(j({msg: "Failed cancelling 2FA", cerr: e, user: user.username, hashedSessionCookie: this.getHashOfSessionCookie(event)}));
                                    CrossauthLogger.logger.debug(j({err:e}))
                                }
                                error(401, {message: "Sorry, your code has expired"});
                                return {success: false, twofa: true};

                            } else {
                                if (isFactor2PageProtected) {
                                    return {
                                        twofa: true, 
                                        success: false, 
                                        response: 
                                            new Response('', {
                                                status: 302, 
                                                statusText: httpStatus(302), 
                                                headers: { Location: this.factor2Url+"?error="+ErrorCode[error1.code] }})};

                                } else {
                                    return {
                                        twofa: true, 
                                        success: false, 
                                        response: new Response(JSON.stringify({
                                            ok: false,
                                            errorMessage: error1.message,
                                            errorMessages: error1.messages,
                                            errorCode: error1.code,
                                            errorCodeName: ErrorCode[error1.code]
                                        }), {
                                            status: error1.httpStatus,
                                            statusText : httpStatus(error1.httpStatus),
                                            headers: {'content-tyoe': 'application/json'},
                                        })};
                                }
                            }
                        }
                        // restore original request body
                        SvelteKitSessionServer.updateRequest(event, sessionData.pre2fa.body, sessionData.pre2fa["content-type"]);
                        return {twofa: true, success: true};
                    } else {
                        // 2FA has not started - start it
                        CrossauthLogger.logger.debug(j({msg:"Starting 2FA", username: user.username}));
                        if (this.enableCsrfProtection && !event.locals.csrfToken) {
                            const error = new CrossauthError(ErrorCode.Forbidden, "CSRF token missing");
                            return {
                                twofa: true, 
                                success: false, 
                                response: new Response(JSON.stringify({
                                    ok: false, 
                                    errorMessage: error.message, 
                                    errorMessages: error.messages, 
                                    errorCode: error.code, 
                                    errorCodeName: ErrorCode[error.code]
                                }), {
                                    status: error.httpStatus,
                                    statusText : httpStatus(error.httpStatus),
                                    headers: {
                                        ...{'content-tyoe': 'application/json'},
                                    }
                                })};
        
                        }
                        const bodyData = new JsonOrFormData();
                        await bodyData.loadData(event);
                        let contentType = event.request.headers.get("content-type");
                        await this.sessionManager.initiateTwoFactorPageVisit(user, event.locals.sessionId??"", bodyData.toObject(), event.request.url.replace(/\?.*$/,""), contentType ? contentType : undefined);
                        if (isFactor2PageProtected) {
                            return {
                                twofa: true, 
                                success: true, 
                                response: new Response('', {
                                    status: 302, 
                                    statusText: httpStatus(302), 
                                    headers: { Location: this.factor2Url }})};
                        } else {
                            return {
                                twofa: true, 
                                success: true, 
                                response: new Response(JSON.stringify({
                                    ok: true,
                                    factor2Required: true}), {
                                    headers: {
                                        ...{'content-tyoe': 'application/json'},
                                    }
                            })};
                        }
                    }
                } else {
                    CrossauthLogger.logger.debug(j({msg:"Factor2-protected GET endpoint - cancelling 2FA"}));

                    // if we have a get request to one of the protected urls, cancel any pending 2FA
                    const sessionCookieValue = this.getSessionCookieValue(event);
                    if (sessionCookieValue) {
                        const sessionId = this.sessionManager.getSessionId(sessionCookieValue);
                        const sessionData = await this.sessionManager.dataForSessionId(sessionId);
                        if (("pre2fa") in sessionData) {
                            CrossauthLogger.logger.debug(j({msg:"Cancelling 2FA"}));
                            try {
                                await this.sessionManager.cancelTwoFactorPageVisit(sessionCookieValue);
                            } catch (e) {
                                CrossauthLogger.logger.debug(j({err:e}));
                                CrossauthLogger.logger.error(j({msg: "Failed cancelling 2FA", cerr: e, user: user.username, hashedSessionCookie: this.getHashOfSessionCookie(event)}));
                            }      
                        }
                    }
                }
            } 
            return {twofa: false, success: true};
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

    clearCookie(name : string, path : string, event : RequestEvent) {
        event.cookies.delete(name, {path});
    } 

    setHeaders(headers: Header[], resp: Response) {
        for (let header of headers) {
            resp.headers.append(header.name, header.value);
        }
    } 

    setCsrfCookie(cookie : Cookie, event: RequestEvent ) {
        event.cookies.set(cookie.name, cookie.value, toCookieSerializeOptions(cookie.options) );
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
                this.clearCookie(this.sessionManager.csrfCookieName, this.sessionManager.csrfCookiePath, event);
                event.locals.csrfToken = undefined;
            }
        } else {
            event.locals.csrfToken = undefined;
        }

        return token;
    }

    static updateRequest(event: RequestEvent, params : {[key:string]:string}, contentType: string) {
        
        //const contentType = event.headers.get('content-type');
        //const newContentType = contentType == 'application/json' ? 'application/json' : 'application/x-www-form-urlencoded';
        let body : string;
        if (contentType == 'application/json') {
            body = JSON.stringify(params);
        } else {
            body = "";
            for (let name in params) {
                const value = params[name];
                if (body.length > 0) body += "&";
                body += encodeURIComponent(name) + "=" + encodeURIComponent(value);
            }
        }
        event.request = new Request(event.request.url, {
            method: "POST",
            headers: event.request.headers,
            body: body
        });
        return event;
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

    async getSessionData(event : RequestEvent, name : string) : Promise<{[key:string]: any}|undefined> {
        try {
            const data = event.locals.sessionId ? 
                await this.sessionManager.dataForSessionId(event.locals.sessionId) : 
                undefined;
            if (data && name in data) return data[name];
        } catch (e) {
            CrossauthLogger.logger.error(j({
                msg: "Couldn't get " + name + "from session",
                cerr: e
            }))
            CrossauthLogger.logger.debug(j({err: e}));
        }
        return undefined;

    }

    async factor2PageVisitStarted(event : RequestEvent) : Promise<boolean> {
        try {
            const pre2fa = this.getSessionData(event, "pre2fa");
            return pre2fa != undefined;
        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.debug(j({err: ce}));
            CrossauthLogger.logger.error(j({cerr: ce, msg: "Couldn't get pre2fa data from session"}));
            return false;
        }

    }

    /////////////////////////////////////////////////////////////
    // login protected URLs

    isLoginPageProtected(event : RequestEvent|string) : boolean {
        const url = new URL(typeof event == "string" ? event : event.request.url);
        let isProtected = false;
        return this.loginProtectedPageEndpoints.reduce(
            (accumulator : boolean, currentValue : string) => 
                accumulator || minimatch(url.pathname, currentValue),
            isProtected);

        //return (this.loginProtectedPageEndpoints.includes(url.pathname));
    }
 
    isLoginApiProtected(event : RequestEvent|string) : boolean {
        const url = new URL(typeof event == "string" ? event : event.request.url);
        //return (this.loginProtectedApiEndpoints.includes(url.pathname));
        let isProtected = false;
        return this.loginProtectedApiEndpoints.reduce(
            (accumulator : boolean, currentValue : string) => 
                accumulator || minimatch(url.pathname, currentValue),
            isProtected);
    }

    isFactor2PageProtected(event : RequestEvent|string) : boolean {
        const url = new URL(typeof event == "string" ? event : event.request.url);
        let isProtected = false;
        return this.factor2ProtectedPageEndpoints.reduce(
            (accumulator : boolean, currentValue : string) => 
                accumulator || minimatch(url.pathname, currentValue),
            isProtected);

        //return (this.loginProtectedPageEndpoints.includes(url.pathname));
    }
 
    isFactor2ApiProtected(event : RequestEvent|string) : boolean {
        const url = new URL(typeof event == "string" ? event : event.request.url);
        //return (this.loginProtectedApiEndpoints.includes(url.pathname));
        let isProtected = false;
        return this.factor2ProtectedApiEndpoints.reduce(
            (accumulator : boolean, currentValue : string) => 
                accumulator || minimatch(url.pathname, currentValue),
            isProtected);
    }

    isAdminEndpoint(event : RequestEvent|string) : boolean {
        const url = new URL(typeof event == "string" ? event : event.request.url);
        //return (this.adminEndpoints.includes(url.pathname));
        let isAdmin = false;
        return this.adminEndpoints.reduce(
            (accumulator : boolean, currentValue : string) => 
                accumulator || minimatch(url.pathname, currentValue),
            isAdmin);
    }

    /**
     * Creates an anonymous session, setting the `Set-Cookue` headers
     * in the reply.
     * 
     * An anonymous sessiin is a session cookie that is not associated
     * with a user (`userId` is undefined).  It can be used to persist
     * data between sessions just like a regular user session ID.
     * 
     * @param request the Fastify request
     * @param reply the Fastify reply
     * @param data session data to save
     * @returns the session cookie value
     */
    async createAnonymousSession(event : RequestEvent, 
        data? : {[key:string]:any}) : Promise<string> {
        CrossauthLogger.logger.debug(j({msg: "Creating anonympous session ID  "}));

        // get custom fields from implentor-provided function
        const formData = new JsonOrFormData();
        await formData.loadData(event);
        let extraFields = this.addToSession ? this.addToSession(event, formData.toObject()) : {}
        if (data) extraFields.data = JSON.stringify(data);

        // create session, setting the session cookie, CSRF cookie and CSRF token 
        let { sessionCookie, csrfCookie, csrfFormOrHeaderValue } = 
            await this.sessionManager.createAnonymousSession(extraFields);
        event.cookies.set(sessionCookie.name,
            sessionCookie.value,
            toCookieSerializeOptions(sessionCookie.options));
        if (this.enableCsrfProtection) {
            event.locals.csrfToken = csrfFormOrHeaderValue;
            event.cookies.set(csrfCookie.name, 
                csrfCookie.value, 
                toCookieSerializeOptions(csrfCookie.options))    
        }
        event.locals.user = undefined;
        const sessionId = this.sessionManager.getSessionId(sessionCookie.value);
        event.locals.sessionId = sessionId;
        return sessionCookie.value;
    };

    async initiateFactor2FromEmail(event: RequestEvent, email : string) : Promise<InitiateFactor2Return> {
        try {
            if (!this.isFactor2PageProtected(event)) return {success: true, factor2: ""};
            
            CrossauthLogger.logger.debug(j({msg:"Starting 2FA", email: email}));
            if (this.enableCsrfProtection && !event.locals.csrfToken) {
                throw new CrossauthError(ErrorCode.Forbidden, "CSRF token missing");
            }
            const bodyData = new JsonOrFormData();
            await bodyData.loadData(event);
            const {user} = await this.userStorage.getUserByEmail(email);
            if (user.factor2 != "") {
                const sessionCookieValue = await this.createAnonymousSession(event);
                await this.sessionManager.initiateTwoFactorPageVisit(user, sessionCookieValue, bodyData.toObject(), event.request.url.replace(/\?.*$/,""));
    
            }
            return {
                success: true, 
                factor2: user.factor2,
            };
    
        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);
            return {
                success: false,
                error: ce.message,
                exception: ce,
            }
        }

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
     * Call this when `login()` returns `factor2Required = true`
     */
    async loginFactor2(event : RequestEvent) : Promise<LoginReturn> {
        return this.userEndpoints.loginFactor2(event);
    }

    /**
     * Log a user out.  
     * 
     * Deletes the session if the user was logged in and clears session
     * and CSRF cookies (if CSRF protection is enabled)
     * 
     * @param event the Sveltekit event
     * @returns success of true or false and error message if not successful
     */
    async logout(event : RequestEvent) : Promise<LogoutReturn> {
        return this.userEndpoints.logout(event);
    }

    /**
     * Log a user in if possible.  
     * 
     * Form data is returned unless there was
     * an error extrafting it.  
     * 
     * If login was successful, no factor2 is needed
     * and no email verification is needed, the user is returned.
     * 
     * If email verification is needed, `emailVerificationRequired` is 
     * returned as `true`.
     * 
     * If factor2 configuration is required, `factor2Required` is returned
     * as `true`.
     * 
     * @param event the Sveltekit event
     * @returns user, form data, error message and exception (see above)
     */
    async signup(event : RequestEvent) : Promise<SignupReturn> {
        return this.userEndpoints.signup(event);
    }

    /**
     * Takes email verification token from the params on the URL and attempts 
     * email verification.
     */
    async verifyEmail(event : RequestEvent) : Promise<VerifyEmailReturn> {
        return this.userEndpoints.verifyEmail(event);
    }

    /**
     * Completes factor2 configuration using 2fa-specific form fields in the
     * request bodyand data already stores in the session when 2FA configuration
     * was initiated
     */
    async configureFactor2(event : RequestEvent) : Promise<ConfigureFactor2Return> {
        return this.userEndpoints.configureFactor2(event);
    }

    /**
     * Request a password reset.  
     * 
     * If it is enabled, emails a password reset token to the email given
     * in the form data.
     */
    async requestPasswordReset(event : RequestEvent) : Promise<RequestPasswordResetReturn> {
        return this.userEndpoints.requestPasswordReset(event);
    }

    /**
     * Call this from the GET url the user clicks on to reset their password.
     * 
     * If it is enabled, fetches the user for the token to confirm the token
     * is valid.
     */
    async validatePasswordResetToken(event : RequestEvent) : Promise<ResetPasswordReturn> {
        return this.userEndpoints.validatePasswordResetToken(event);
    }

    /**
     * Call this from the POST url the user uses to fill in a new password
     * after validating the token in the GET url with
     * {@link validatePasswordresetToken}.
     */
    async resetPassword(event : RequestEvent) : Promise<ResetPasswordReturn> {
        return this.userEndpoints.resetPassword(event);
    }

    /**
     * Call this from your factor2 endpoint to fetch the data needed to
     * display the factor2 form.
     * @param event 
     * @returns 
     */
    async requestFactor2(event : RequestEvent) : Promise<RequestFactor2Return> {
        return this.userEndpoints.requestFactor2(event);
    }
}