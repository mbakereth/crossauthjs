import { minimatch } from 'minimatch';
import {
    KeyStorage,
    UserStorage,
    OAuthClientStorage,
    SessionManager,
    Authenticator,
    Crypto,
    setParameter,
    ParamType,
    toCookieSerializeOptions } from '@crossauth/backend';
import type { Cookie, SessionManagerOptions } from '@crossauth/backend';
import { CrossauthError, CrossauthLogger, j, ErrorCode, httpStatus } from '@crossauth/common';
import type { Key, User, UserInputFields, OAuthClient } from '@crossauth/common';
import { UserState } from '@crossauth/common';
import type { RequestEvent, MaybePromise } from '@sveltejs/kit';
import { error, redirect } from '@sveltejs/kit';
import { JsonOrFormData } from './utils';
import { SvelteKitUserEndpoints} from './sveltekituserendpoints';
import { SvelteKitAdminEndpoints} from './sveltekitadminendpoints';
import { SvelteKitUserClientEndpoints} from './sveltekituserclientendpoints';
import { SvelteKitAdminClientEndpoints} from './sveltekitadminclientendpoints';
import { SvelteKitSessionAdapter } from './sveltekitsessionadapter';
import { SvelteKitServer } from './sveltekitserver';

export const CSRFHEADER = "X-CROSSAUTH-CSRF";

type Header = {
    name: string,
    value: string
};

/**
 * Options for {@link SvelteKitSessionServer}.
 */
export interface SvelteKitSessionServerOptions extends SessionManagerOptions {

    /**
     * If enabling user login, must provide the user storage
     */
    userStorage? : UserStorage,

    /**
     * If enabling client endpoints, must provide the client storage
     */
    clientStorage? : OAuthClientStorage,

    /**
     * Factor 1 and 2 authenticators.
     * 
     * The key is what appears in the `factor1` and `factor2` filed in the
     * Users table.
     */
    authenticators? : {[key:string]: Authenticator}, 

    /**
     * URL to call when factor2 authentication is required
     */
    factor2Url? : string,

    /**
     * URL to call when login is required.  
     * 
     * Default "/"
     */
    loginUrl? : string,

    /**
     * Default URL to go to after login (can be overridden by `next` POST param)  
     * 
     * Default "/"
     */
    loginRedirectUrl? : string,

    /**
     * URL to call when change password is required.
     * 
     * Default "/changepassword"
     */
    changePasswordUrl? : string,

    /**
     * URL to call when change password is required.
     * 
     * Default "/resetpassword"
     */
    requestPasswordResetUrl? : string,

    /**
     * URL to call when change factor2 is required.
     * 
     * Default "/changefactor2"
     */
    changeFactor2Url? : string,

    /** OAuth to support.  A comma-separated list from {@link @crossauth/common!OAuthFlows}.  
     * If [`all`], there must be none other in the list.  
     * 
     * This is needed not only by the authorization server but also the 
     * session server if you are creating endpoints for manipulating
     * the OAuth client table.
     * 
     * Default ['all']
     */
    validFlows? : string[],

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
     * See `adminPageEndpoints`
     */
    unauthorizedUrl? : string,

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
     * If unauthorizedUrl is defined, that will be rendered.  Otherwise
     * a simple text message will be displayed.
     * 
     */
    adminPageEndpoints?: string[],

    /**
     * Same as adminPageEndpoints but returns a JSON error instead of an
     * error page  
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
    adminApiEndpoints?: string[],

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

    /**
     * This parameter affects users who are not logged in with a session ID
     * but with an OAuth access token.  Such users can only update their user
     * record if the scoped named in this variable has been authorized by
     * that user for the client.
     * 
     * By default, no scopes are authorized to edit the user.
     */
    editUserScope? : string,

    /**
     * Admin pages provide functionality for searching for users.  By
     * default the search string must exactly match the client name
     * (after normalizing
     * and lowercasing).  Override this behaviour with this function
     * @param searchTerm the search term 
     * @param userStorage the user storage to search
     * @returns array of matching users
     */
    userSearchFn? : (searchTerm : string, userStorage : UserStorage, skip? : number, take? : number) => Promise<User[]>;

    /**
     * Admin pages provide functionality for searching for OAuth clients.  By
     * default the search string must exactly match the client_name exactly.  
     * Override this behaviour with this function
     * @param searchTerm the search term 
     * @param clientStorage the client storage to search
     * @returns array of matching users
     */
    clientSearchFn? : 
        (searchTerm : string, clientStorage : OAuthClientStorage, skip: number, take: number, userid? : string|number|null) => Promise<OAuthClient[]>;

    /** Pass the Sveltekit redirect function */
    redirect? : any,

    /** Pass the Sveltekit error function */
    error? : any,
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

/**
 * The Sveltekit session server.
 * 
 * You shouldn't have to instantiate this directly.  It is created when
 * you create a {@link SveltekitServer} object.
 */
export class SvelteKitSessionServer implements SvelteKitSessionAdapter {

    /**
     * Hook to check if the user is logged in and set data in `locals`
     * accordingly.
     */
    readonly sessionHook : (input: {event: RequestEvent}, 
        //response: Response
    ) => /*MaybePromise<Response>*/ MaybePromise<{headers: Header[]}>;
    readonly twoFAHook : (input: {event: RequestEvent}) => MaybePromise<{twofa: boolean, ok: boolean, response?: Response}>;


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
    readonly userStorage? : UserStorage;

    /**
     * User storage taken from constructor args.
     * See {@link SvelteKitSessionServer.constructor}.
     */
    readonly clientStorage? : OAuthClientStorage;

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
     * 
     * The default is `[{name: "none", friendlyName: "none"}]`
     */
    readonly allowedFactor2 : {name: string, friendlyName: string, configurable: boolean}[] = [];

    /**
     * The set of allowed authenticators taken from the options during 
     * construction.
     * 
     * The default is `["none"]`.
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
    private adminPageEndpoints : string[] = [];
    private adminApiEndpoints : string[] = [];
    readonly unauthorizedUrl : string|undefined = undefined;
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

    /**
     * Use these to access the `load` and `action` endpoints for functions
     * provided by Crossauth.  These are the ones intended for users to 
     * have access to.
     * 
     * See {@link SvelteKitUserEndpoints}
     */
    readonly userEndpoints : SvelteKitUserEndpoints;

    /**
     * Use these to access the `load` and `action` endpoints for functions
     * provided by Crossauth that relate to manipulating OAuth clients in the
     * database.  These are the ones intended for users to 
     * have access to.
     * 
     * See {@link SvelteKitUserEndpoints}
     */
    readonly userClientEndpoints : SvelteKitUserClientEndpoints;

    /**
     * Use these to access the `load` and `action` endpoints for functions
     * provided by Crossauth that relate to manipulating OAuth clients in the
     * database as admin.  These are the ones intended for users to 
     * have access to.
     * 
     * See {@link SvelteKitAdminEndpoints}
     */
    readonly adminClientEndpoints : SvelteKitAdminClientEndpoints;

    /**
     * Use these to access the `load` and `action` endpoints for functions
     * provides by Crossauth.  These are the ones intended for admins to 
     * have access to.
     * 
     * See {@link SvelteKitAdminEndpoints}
     */
    readonly adminEndpoints : SvelteKitAdminEndpoints;

    readonly redirect: any;
    readonly error: any;

    /**
     * This is read from options during construction.
     * 
     * See {@link SvelteKitServerOptions}.
     */
    readonly editUserScope? : string;

    /**
     * Constructor
     * @param keyStorage where session IDs, email verification and reset tokens are stored
     * @param authenticators valid authenticators that can be in `factor1` or `factor2`
     *    of the user.  See class documentation for {@link SvelteKitServer} for an example.
     * @param options See {@link SvelteKitSessionServerOptions}.
     */
    constructor(keyStorage : KeyStorage, authenticators : {[key:string]: Authenticator}, options : SvelteKitSessionServerOptions = {}) {

        this.keyStorage = keyStorage;
        this.userStorage = options.userStorage;
        this.clientStorage = options.clientStorage;
        this.authenticators = authenticators;
        this.sessionManager = new SessionManager(keyStorage, authenticators, options);

        this.redirect = options.redirect ?? redirect;
        this.error = options.error ?? error;

        setParameter("factor2Url", ParamType.String, this, options, "FACTOR2_URL");
        if (!this.factor2Url.endsWith("/")) this.factor2Url += "/";
        setParameter("factor2ProtectedPageEndpoints", ParamType.JsonArray, this, options, "FACTOR2_PROTECTED_PAGE_ENDPOINTS");
        setParameter("factor2ProtectedApiEndpoints", ParamType.JsonArray, this, options, "FACTOR2_PROTECTED_API_ENDPOINTS");
        setParameter("loginProtectedPageEndpoints", ParamType.JsonArray, this, options, "LOGIN_PROTECTED_PAGE_ENDPOINTS");
        setParameter("loginProtectedApiEndpoints", ParamType.JsonArray, this, options, "LOGIN_PROTECTED_API_ENDPOINTS");
        setParameter("adminPageEndpoints", ParamType.JsonArray, this, options, "ADMIN_PAGE_ENDPOINTS");
        setParameter("adminApiEndpoints", ParamType.JsonArray, this, options, "ADMIN_API_ENDPOINTS");
        setParameter("unauthorizedUrl", ParamType.JsonArray, this, options, "UNAUTHORIZED_PAGE");
        let options1 : {allowedFactor2?: string[]} = {}
        setParameter("allowedFactor2", ParamType.JsonArray, options1, options, "ALLOWED_FACTOR2");
        this.allowedFactor2Names = options.allowedFactor2 ?? ["none"];
        if (options1.allowedFactor2) {
            for (let factor of options1.allowedFactor2) {
                if (factor in this.authenticators) {
                    this.allowedFactor2.push({
                        name: factor, 
                        friendlyName: this.authenticators[factor].friendlyName,
                        configurable: this.authenticators[factor].secretNames().length > 0,
                    });
                } else if (factor == "none") {
                    this.allowedFactor2.push({
                        name: "none", 
                        friendlyName: "None", 
                        configurable: false});

                }
            }
        }
        setParameter("enableEmailVerification", ParamType.Boolean, this, options, "ENABLE_EMAIL_VERIFICATION");
        setParameter("enablePasswordReset", ParamType.Boolean, this, options, "ENABLE_PASSWORD_RESET");
        setParameter("enableCsrfProtection", ParamType.Boolean, this, options, "ENABLE_CSRF_PROTECTION");
        setParameter("editUserScope", ParamType.String, this, options, "EDIT_USER_SCOPE");

        if (options.validateUserFn) this.validateUserFn = options.validateUserFn;
        if (options.createUserFn) this.createUserFn = options.createUserFn;
        if (options.updateUserFn) this.updateUserFn = options.updateUserFn;
        if (options.addToSession) this.addToSession = options.addToSession;
        if (options.validateSession) this.validateSession = options.validateSession;


        this.userEndpoints = new SvelteKitUserEndpoints(this, options);
        this.adminEndpoints = new SvelteKitAdminEndpoints(this, options);
        this.userClientEndpoints = new SvelteKitUserClientEndpoints(this, options);
        this.adminClientEndpoints = new SvelteKitAdminClientEndpoints(this, options);

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
                       CrossauthLogger.logger.error(j({cerr: e2, msg: "Couldn't delete CSRF cookie", ip: event.request.referrer, hashedCsrfCookie: this.getHashOfCsrfCookie(event)}));
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

            if (!this.userStorage) throw this.error(500, "No user storage defined"); // shouldn't happen as checked in FastifyServer
            const sessionCookieValue = this.getSessionCookieValue(event);
            const isFactor2PageProtected = this.isFactor2PageProtected(event);
            const isFactor2ApiProtected = this.isFactor2ApiProtected(event);
            let user : User|undefined;
            if (sessionCookieValue) {
                if (event.locals.user) user = event.locals.user;
                else {
                    const anonUser = await this.getSessionData(event, "user");
                    if (anonUser) {
                        const resp = await this.userStorage.getUserByUsername(anonUser.username, {skipActiveCheck: true});
                        if (resp.user.status == UserState.active || resp.user.state == UserState.factor2ResetNeeded)
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
                                this.error(401, {message: "Sorry, your code has expired"});
                                return {ok: false, twofa: true};

                            } else {
                                if (isFactor2PageProtected) {
                                    return {
                                        twofa: true, 
                                        ok: false, 
                                        response: 
                                            new Response('', {
                                                status: 302, 
                                                statusText: httpStatus(302), 
                                                headers: { Location: this.factor2Url+"?error="+ErrorCode[error1.code] }})};

                                } else {
                                    return {
                                        twofa: true, 
                                        ok: false, 
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
                        return {twofa: true, ok: true};
                    } else {
                        // 2FA has not started - start it
                        CrossauthLogger.logger.debug(j({msg:"Starting 2FA", username: user.username}));
                        if (this.enableCsrfProtection && !event.locals.csrfToken) {
                            const error = new CrossauthError(ErrorCode.Forbidden, "CSRF token missing");
                            return {
                                twofa: true, 
                                ok: false, 
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
                                ok: true, 
                                response: new Response('', {
                                    status: 302, 
                                    statusText: httpStatus(302), 
                                    headers: { Location: this.factor2Url }})};
                        } else {
                            return {
                                twofa: true, 
                                ok: true, 
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
            return {twofa: false, ok: true};
        }
    }

    //////////////
    // Helpers

    /**
     * Returns the session cookie value from the Sveltekit request event
     * @param event the request event
     * @returns the whole cookie value
     */
    getSessionCookieValue(event : RequestEvent) : string|undefined{
        //let allCookies = event.cookies.getAll();
        if (event.cookies && event.cookies.get(this.sessionManager.sessionCookieName)) {       
            return event.cookies.get(this.sessionManager.sessionCookieName);
        }
        return undefined;
    }

    /**
     * Returns the session cookie value from the Sveltekit request event
     * @param event the request event
     * @returns the whole cookie value
     */
    getCsrfCookieValue(event : RequestEvent) : string|undefined {
        if (event.cookies) {  
            const cookie = event.cookies.get(this.sessionManager.csrfCookieName)     ;
            if (cookie)
                return event.cookies.get(this.sessionManager.csrfCookieName);
        }
        return undefined;
    }

    private clearCookie(name : string, path : string, event : RequestEvent) {
        event.cookies.delete(name, {path});
    } 

    /**
     * Sets headers in the request event.
     * 
     * Used internally by {@link SveltekitServer}.  Shouldn't be necessary
     * to call this directly.
     * @param headers the headres to set
     * @param resp the response object to set them in
     */
    setHeaders(headers: Header[], resp: Response) {
        for (let header of headers) {
            resp.headers.append(header.name, header.value);
        }
    } 

    /**
     * Sets the CSRF cookie.
     * 
     * Used internally.  Shouldn't be necessary
     * to call this directly.
     * @param cookie the new cookie and parameters
     * @param event the request event
     */
    setCsrfCookie(cookie : Cookie, event: RequestEvent ) {
        event.cookies.set(cookie.name, cookie.value, toCookieSerializeOptions(cookie.options) );
    }

    private setHeader(name: string, value: string, headers: Header[]) {
        headers.push({
            name: name,
            value: value,
        });
    }

    /**
     * Returns a hash of the session cookie value.  
     * 
     * Used only in reporting, so that logs don't contain the actual session ID.
     * 
     * @param event the Sveltelkit request event
     * @returns a stering hash of the cookie value
     */
    getHashOfSessionCookie(event : RequestEvent) : string {
        const cookieValue = this.getSessionCookieValue(event);
        if (!cookieValue) return "";
        try {
            return Crypto.hash(cookieValue);
        } catch (e) {}
        return "";
    }

    /**
     * Returns a hash of the CSRF cookie value.  
     * 
     * Used only in reporting, so that logs don't contain the actual CSRF cookie value.
     * 
     * @param event the Sveltelkit request event
     * @returns a stering hash of the cookie value
     */
    getHashOfCsrfCookie(event : RequestEvent) : string {
        const cookieValue = this.getCsrfCookieValue(event);
        if (!cookieValue) return "";
        try {
            return Crypto.hash(cookieValue);
        } catch (e) {}
        return "";
    }

    /**
     * Returns a CSRF token if the CSRF cookie is valid.
     * 
     * Used internally.  Shouldn't be necessary
     * to call this directly.
     * 
     * @param event the request event
     * @param headers headers the token will be added to, as well as
     *   adding it to locals
     * @returns the string CSRF token for inclusion in forms
     */
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

    /**
     * Used internally to update an existing Sveltekit request object with
     * a new body and headers.
     * 
     * Used when restoring a request that was interrupted for 2FA
     * 
     * @param event the request event
     * @param params JSON params to add to the new body
     * @param contentType the new content type
     * @returns the updated request event
     */
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
    
    /**
     * Returns whether or not 2FA authentication was initiated as a result
     * of visiting a page protected by it
     * @param event the request event
     * @returns true or false
     */
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

    /**
     * Returns whether a page being visited as part of a request event is
     * configured to be protected by login.  
     * 
     * See {@link SvelteKitSessionServerOptions.loginProtectedPageEndpoints}.
     * 
     * @param event the request event
     * @returns true or false
     */
    isLoginPageProtected(event : RequestEvent|string) : boolean {
        const url = new URL(typeof event == "string" ? event : event.request.url);
        let isProtected = false;
        return this.loginProtectedPageEndpoints.reduce(
            (accumulator : boolean, currentValue : string) => 
                accumulator || minimatch(url.pathname, currentValue),
            isProtected);

        //return (this.loginProtectedPageEndpoints.includes(url.pathname));
    }
 
    /**
     * Returns whether an API call is being visited as part of a request event is
     * configured to be protected by login.  
     * 
     * See {@link SvelteKitSessionServerOptions.loginProtectedApiEndpoints}.
     * 
     * @param event the request event
     * @returns true or false
     */
    isLoginApiProtected(event : RequestEvent|string) : boolean {
        const url = new URL(typeof event == "string" ? event : event.request.url);
        //return (this.loginProtectedApiEndpoints.includes(url.pathname));
        let isProtected = false;
        return this.loginProtectedApiEndpoints.reduce(
            (accumulator : boolean, currentValue : string) => 
                accumulator || minimatch(url.pathname, currentValue),
            isProtected);
    }

    /**
     * Returns whether a page being visited as part of a request event is
     * configured to be protected by 2FA.  
     * 
     * See {@link SvelteKitSessionServerOptions.factor2ProtectedPageEndpoints}.
     * 
     * @param event the request event
     * @returns true or false
     */
    isFactor2PageProtected(event : RequestEvent|string) : boolean {
        const url = new URL(typeof event == "string" ? event : event.request.url);
        let isProtected = false;
        return this.factor2ProtectedPageEndpoints.reduce(
            (accumulator : boolean, currentValue : string) => 
                accumulator || minimatch(url.pathname, currentValue),
            isProtected);

        //return (this.loginProtectedPageEndpoints.includes(url.pathname));
    }
 
    /**
     * Returns whether an API call is being visited as part of a request event is
     * configured to be protected by 2FA.  
     * 
     * See {@link SvelteKitSessionServerOptions.factor2ProtectedApiEndpoints}.
     * 
     * @param event the request event
     * @returns true or false
     */
    isFactor2ApiProtected(event : RequestEvent|string) : boolean {
        const url = new URL(typeof event == "string" ? event : event.request.url);
        //return (this.loginProtectedApiEndpoints.includes(url.pathname));
        let isProtected = false;
        return this.factor2ProtectedApiEndpoints.reduce(
            (accumulator : boolean, currentValue : string) => 
                accumulator || minimatch(url.pathname, currentValue),
            isProtected);
    }

    /**
     * Returns whether a page being visited as part of a request event is
     * configured to be protected as admin only.  
     * 
     * See {@link SvelteKitSessionServerOptions.adminPageEndpoints}.
     * 
     * @param event the request event
     * @returns true or false
     */
    isAdminPageEndpoint(event : RequestEvent|string) : boolean {
        const url = new URL(typeof event == "string" ? event : event.request.url);
        //return (this.adminEndpoints.includes(url.pathname));
        let isAdmin = false;
        return this.adminPageEndpoints.reduce(
            (accumulator : boolean, currentValue : string) => 
                accumulator || minimatch(url.pathname, currentValue),
            isAdmin);
    }

    /**
     * Returns whether an AP call being visited as part of a request event is
     * configured to be protected as admin only.  
     * 
     * See {@link SvelteKitSessionServerOptions.adminApiEndpoints}.
     * 
     * @param event the request event
     * @returns true or false
     */
    isAdminApiEndpoint(event : RequestEvent|string) : boolean {
        const url = new URL(typeof event == "string" ? event : event.request.url);
        //return (this.adminEndpoints.includes(url.pathname));
        let isAdmin = false;
        return this.adminApiEndpoints.reduce(
            (accumulator : boolean, currentValue : string) => 
                accumulator || minimatch(url.pathname, currentValue),
            isAdmin);
    }

    /**
     * Creates an anonymous session, setting the `Set-Cookue` headers
     * in the reply.
     * 
     * An anonymous sessiin is a session cookie that is not associated
     * with a user (`userid` is undefined).  It can be used to persist
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

    /**
     * Sets locals based on session and CSRF cookies.  
     * 
     * Sets things like `locals.user`.  You can call this if you need them
     * updated based on cookie settings and a page load hasn't been done
     * (ie the hooks haven't run).
     * 
     * @param event the Sveltekit request event.
     */
    async refreshLocals(event : RequestEvent) {
        try {
            const sessionCookieValue = this.getSessionCookieValue(event);
            if (sessionCookieValue) {
                const sessionId = this.sessionManager.getSessionId(sessionCookieValue);
                event.locals.sessionId = sessionId;    
                const resp = await this.sessionManager.userForSessionId(sessionId);
                event.locals.user = resp.user;
            } else {
                event.locals.sessionId = undefined;
                event.locals.user = undefined;
            }
        } catch (e) {
            CrossauthLogger.logger.error(j({errr: e}));
        }

    }

    ////////////////////////////////////////////////////////////////
    // SessionAdapter interface

    csrfProtectionEnabled() : boolean {
        return this.enableCsrfProtection;
    }


    getCsrfToken(event : RequestEvent) : string|undefined {
        return event.locals.csrfToken;
    }

    getUser(event : RequestEvent) : User|undefined {
        return event.locals.user;
    }

    /**
     * Returns the data stored along with the session server-side, with the
     * given name
     * @param event the Sveltekit request event
     * @param name tjhe data name to return
     * @returns an object or undefined.
     */
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

    /**
     * Updates or sets the given field in the session `data` field.
     * 
     * The `data` field in the session record is assumed to be JSON
     * 
     * @param event the Sveltekit request event
     * @param name the name of the field to set
     * @param value the value to set it to.
     */
    async updateSessionData(event : RequestEvent, 
        name : string, 
        value : {[key:string]:any}) {
        if (!event.locals.sessionId) throw new CrossauthError(ErrorCode.Unauthorized, 
            "No session present");
            await this.sessionManager.updateSessionData(event.locals.sessionId, name, value);
    }

    /**
     * Deletes the given field from the session `data` field.
     * 
     * The `data` field in the session record is assumed to be JSON
     * 
     * @param event the Sveltekit request event
     * @param name the name of the field to set
     */
    async deleteSessionData(event : RequestEvent, 
        name : string) {
        if (!event.locals.sessionId)  {
            CrossauthLogger.logger.debug(j({msg: `Attempting to delete session data ${name} when no session is present`}))
        } else {
            await this.sessionManager.deleteSessionData(event.locals.sessionId, name);
        }
    }
}
