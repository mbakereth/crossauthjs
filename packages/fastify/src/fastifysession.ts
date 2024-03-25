import {
    type FastifyInstance,
    type FastifyRequest,
    type FastifyReply } from 'fastify';
import { Server, IncomingMessage, ServerResponse } from 'http'
import {
    CrossauthError,
    ErrorCode,
    CrossauthLogger,
    j,
    UserState,
} from '@crossauth/common';
import type { User, Key, UserInputFields } from '@crossauth/common';
import {
    UserStorage,
    KeyStorage,
    Authenticator,
    Hasher,
    SessionManager,
    setParameter,
    ParamType } from '@crossauth/backend';
import type {
    AuthenticationParameters,
    SessionManagerOptions } from '@crossauth/backend';
import { FastifyServer } from './fastifyserver';
import { FastifyUserEndpoints, type UpdateUserBodyType } from './fastifyuserendpoints'
import { FastifyAdminEndpoints } from './fastifyadminendpoints'

export const CSRFHEADER = "X-CROSSAUTH-CSRF";

const JSONHDR : [string,string] = 
    ['Content-Type', 'application/json; charset=utf-8'];

///////////////////////////////////////////////////////////////////////////////
// OPTIONS

/**
 * Options for {@link FastifyServer }.
 * 
 * See {@link FastifyServer } constructor for description of parameters
 */
export interface FastifySessionServerOptions extends SessionManagerOptions {

    /** All endpoint URLs will be prefixed with this.  Default `/` */
    prefix? : string,

    /** Admin URLs will be prefixed with `this  Default `admin/` */
    adminPrefix? : string,

    /** List of endpoints to add to the server ("login", "api/login", etc, 
     *  prefixed by the `prefix` parameter.  Empty for all.  Default all. */
    endpoints? : string,

    /** Page to redirect to after successful login, default "/" */
    loginRedirect? : string;

    /** Page to redirect to after successful logout, default "/" */
    logoutRedirect? : string;

    /** Function that throws a {@link @crossauth/common!CrossauthError} 
     *  with {@link @crossauth/common!ErrorCode} `FormEnty` if the user 
     * doesn't confirm to local rules.  Doesn't validate passwords  */
    validateUserFn? : (user: UserInputFields) => string[];

    /** Function that creates a user from form fields.
     * Default one takes fields that begin with `user_`, removing the `user_` 
     * prefix and filtering out anything not in the userEditableFields list in 
     * the user storage.
      */
    createUserFn?: (request: FastifyRequest<{ Body: SignupBodyType }>,
        userEditableFields: string[]) => UserInputFields;

    /** Function that updates a user from form fields.
     * Default one takes fields that begin with `user_`, removing the `user_`
     *  prefix and filtering out anything not in the userEditableFields list in 
     * the user storage.
      */
    updateUserFn?: (user: User,
        request: FastifyRequest<{ Body: UpdateUserBodyType }>,
        userEditableFields: string[]) => User;

    /** Called when a new session token is going to be saved 
     *  Add additional fields to your session storage here.  Return a map of 
     * keys to values  */
    addToSession?: (request: FastifyRequest) => 
        {[key: string] : string|number|boolean|Date|undefined};

    /** Called after the session ID is validated.
     * Use this to add additional checks based on the request.  
     * Throw an exception if cecks fail
     */
    validateSession?: (session: Key,
        user: User | undefined,
        request: FastifyRequest) => void;

    /** Template file containing the login page (with without error messages).  
     * See the class documentation for {@link FastifyServer} for more info.  
     * Defaults to "login.njk".
     */
    loginPage? : string;

    /** Template file containing the page for getting the 2nd factor for 2FA 
     * protected pages.  See the class documentation for {@link FastifyServer} 
     * for more info.  Defaults to "factor2.njk".
     */
    factor2Page? : string;

    /** Template file containing the signup page (with without error messages).  
     * See the class documentation for {@link FastifyServer} for more info. 
     *  Defaults to "signup.njk".
     * Signup form should contain at least `username` and `password` and may
     * also contain `repeatPassword`.  If you have additional
     * fields in your user table you want to pass from your form, prefix 
     * them with `user_`, eg `user_email`.
     * If you want to enable email verification, set `enableEmailVerification` 
     * and set `checkEmailVerified` on the user storage.
     */
    signupPage? : string;

    /** Page to set up 2FA after sign up */
    configureFactor2Page? : string;

    /** Page to render error messages, including failed login. 
     * See the class documentation for {@link FastifyServer} for more info.  
     * Defaults to "error.njk".
     */
    errorPage? : string;

    /** Page to render for password changing.  
     * See the class documentation for {@link FastifyServer} for more info.  
     * Defaults to "changepassword.njk".
     */
    changePasswordPage? : string,

    /** Page to render for selecting a different 2FA.  
     * See the class documentation for {@link FastifyServer} for more info.  
     * Defaults to "changepassword.njk".
     */
    changeFactor2Page? : string,

    /** Page to render for updating user details.  
     * See the class documentation for {@link FastifyServer} for more info.  
     * Defaults to "updateuser.njk".
     */
    updateUserPage? : string,

    /** Page to ask user for email and reset his/her password.  
     * See the class documentation for {@link FastifyServer} for more info.  
     * Defaults to "requestpasswordreset.njk".
     */
    requestResetPasswordPage? : string,

    /** Page to render for password reset, after the emailed token has been 
     * validated.  
     * See the class documentation for {@link FastifyServer} for more info.  
     * Defaults to "resetpassword.njk".
     */
    resetPasswordPage? : string,

    /**
     * Turns on email verification.  This will cause the verification tokens to 
     * be sent when the account
     * is activated and when email is changed.  Default false.
     */
    enableEmailVerification? : boolean,

    /** Page to render for to confirm email has been verified.  Only created 
     * if `enableEmailVerification` is true.
     * See the class documentation for {@link FastifyServer} for more info.  
     * Defaults to "emailverified.njk"
     */
    emailVerifiedPage? : string,

    factor2ProtectedPageEndpoints?: string,
    factor2ProtectedApiEndpoints?: string,

    editUserScope? : string,

    ///////////////////////////////////////////
    // Admin pages

    adminCreateUserPage? : string,
    adminSelectUserPage? : string,

    userSearchFn? : (searchTerm : string, userStorage : UserStorage) => Promise<User[]>;
}

//////////////////////////////////////////////////////////////////////////////
// ENDPOINTS

/**
 * Endpoints that depend on sessions being enabled and display HTML
 */
export const SessionPageEndpoints = [
    "login",
    "logout",
    "changepassword",
    "updateuser",
];

export const SessionAdminPageEndpoints = [
    "admin/createuser",
    "admin/changepassword",
    "admin/selectuser",
    "admin/updateuser",
    "admin/changepassword",
];

/**
 * API (JSON) endpoints that depend on sessions being enabled 
 */
export const SessionApiEndpoints = [
    "api/login",
    "api/logout",
    "api/changepassword",
    "api/userforsessionkey",
    "api/getcsrftoken",
    "api/updateuser",
];

export const SessionAdminApiEndpoints = [
    "admin/api/createuser",
    "admin/api/changepassword",
    "admin/api/updateuser",
    "admin/api/changepassword",
];

/**
 * API (JSON) endpoints that depend on 2FA being enabled 
 */
export const Factor2ApiEndpoints = [
    "api/configurefactor2",
    "api/loginfactor2",
    "api/changefactor2",
    "api/factor2",
    "api/cancelfactor2",
];

/**
 * Endpoints that depend on email verification being enabled and display HTML
 */
export const EmailVerificationPageEndpoints = [
    "verifyemail",
    "emailverified",
];

/**
 * API (JSON) endpoints that depend on email verification being enabled 
 */
export const EmailVerificationApiEndpoints = [
    "api/verifyemail",
];

/**
 * Endpoints that depend on password reset being enabled and display HTML
 */
export const PasswordResetPageEndpoints = [
    "requestpasswordreset",
    "resetpassword",
];

/**
 * API (JSON) endpoints that depend on password reset being enabled 
 */
export const PasswordResetApiEndpoints = [
    "api/requestpasswordreset",
    "api/resetpassword",
];

/**
 * Endpoints for signing a user up that display HTML
 */
export const SignupPageEndpoints = [
    "signup",
]

/**
 * API (JSON) endpoints for signing a user up that display HTML
 */
export const SignupApiEndpoints = [
    "api/signup",
]

/**
 * Endpoints for signing a user up that display HTML
 */
export const Factor2PageEndpoints = [
    "configurefactor2",
    "loginfactor2",
    "changefactor2",
    "factor2",
]

/**
 * These are all the endpoints created by default by this server-
 */
export const AllEndpoints = [
    ...SignupPageEndpoints,
    ...SignupApiEndpoints,
    ...SessionPageEndpoints,
    ...SessionApiEndpoints,
    ...SessionAdminPageEndpoints,
    ...SessionAdminApiEndpoints,
    ...EmailVerificationPageEndpoints,
    ...EmailVerificationApiEndpoints,
    ...PasswordResetPageEndpoints,
    ...PasswordResetApiEndpoints,
    ...Factor2PageEndpoints,
    ...Factor2ApiEndpoints,
];



export interface CsrfBodyType {
    csrfToken?: string;
}

export interface ArbitraryBodyType {
    [key:string]: string;
}

//////////////////////////////////////////////////////////////////////////////
// REQUEST INTERFACES

interface LoginBodyType extends CsrfBodyType {
    username: string,
    password: string,
    persist? : boolean,
    next? : string,
}

interface LoginFactor2BodyType extends CsrfBodyType {
    persist? : boolean,
    next? : string,
    otp? : string,
    token? : string,
}

export interface SignupBodyType extends LoginBodyType {
    repeatPassword?: string,
    email? : string,
    factor2? : string,
    [key : string]: string|number|Date|boolean|undefined, // for extensible user object fields
}

export interface LoginQueryType {
    next? : string;
}

interface Factor2QueryType {
    error? : string;
}

export interface AuthenticatorDetails {
    name: string,
    friendlyName : string,
    hasSecrets: boolean,
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

function defaultCreateUser(request: FastifyRequest<{ Body: SignupBodyType }>,
    userEditableFields: string[]) : UserInputFields {
    let state = "active";
    let user : UserInputFields = {
        username: request.body.username,
        state: state,
    }
    const callerIsAdmin = request.user && FastifyServer.isAdmin(request.user);
    for (let field in request.body) {
        let name = field.replace(/^user_/, ""); 
        if (field.startsWith("user_") && 
            (callerIsAdmin || userEditableFields.includes(name))) {
            user[name] = request.body[field];
        }
    }
    user.factor1 = "localpassword";
    user.factor2 = request.body.factor2;
    return user;

}

function defaultUpdateUser(user: User,
    request: FastifyRequest<{ Body: UpdateUserBodyType }>,
    userEditableFields: string[]) : User {
        const callerIsAdmin = request.user && FastifyServer.isAdmin(request.user);
        for (let field in request.body) {
        let name = field.replace(/^user_/, ""); 
        if (field.startsWith("user_") && 
            (callerIsAdmin || userEditableFields.includes(name))) {
            user[name] = request.body[field];
        }
    }
    return user;

}

//////////////////////////////////////////////////////////////////////////////
// CLASSES

/**
 * This class the session management for the fastify server
 * 
 * **Endpoints that can be activated provided**
 * 
 * All POST methods are passed user, csrfToken, errorCode, errorCodeName,
 *  error and errors.
 * 
 * | METHOD | ENDPOINT                   | PATH PARAMS | GET/BODY PARAMS                          | VARIABLES PASSED         | FILE               |
 * | ------ | -------------------------- | ----------- | ---------------------------------------- | ------------------------ | ------------------ |
 * | GET    | /login                     |             | next                                     |                          | loginPage          | 
 * | POST   | /login                     |             | next, username, password                 | request params, message  | loginPage          | 
 * | POST   | /api/login                 |             | next, username, password                 |                          |                    | 
 * | POST   | /logout                    |             | next                                     |                          |                    | 
 * | POST   | /api/logout                |             | next                                     |                          |                    | 
 * | GET    | /signup                    |             | next                                     |                          | signupPage         |
 * | POST   | /signup                    |             | next, username, password, user/*         | request params, message  | signupPage         | 
 * | GET    | /changepassword            |             |                                          |                          | changePasswordPage | 
 * | POST   | /changepassword            |             | oldPassword, newPassword, repeatPassword | request params, message  | changePasswordPage | 
 * | POST   | /api/changepassword        |             | oldPassword, newPassword                 |                          |                    | 
 * | GET    | /updateuser                |             |                                          |                          | changePasswordPage | 
 * | POST   | /updateuser                |             | user_*                                   | request params, message  | changePasswordPage | 
 * | POST   | /api/updateuser            |             | user_*                                   |                          |                    | 
 * | GET    | /requestpasswordreset      |             |                                          |                          | changePasswordPage | 
 * | POST   | /requestpasswordreset      |             | email                                    | email, message           | changePasswordPage | 
 * | POST   | /api/requestpasswordreset  |             | password                                 |                          |                    | 
 * | GET    | /resetpassword             | token       |                                          |                          | changePasswordPage | 
 * | POST   | /resetpassword             |             | token, password, repeatPassword          | request params, message  | changePasswordPage | 
 * | POST   | /api/resetpassword         |             | token, password                          |                          |                    | 
 * | GET    | /verifyemail               |  token      |                                          |                          | emailVerifiedPage  | 
 * | GET    | /verifyemail               |  token      |                                          |                          | emailVerifiedPage  | 
 * | GET    | /api/userforsessionkey     |             |                                          |                          |                    | 
 * | GET    | /api/getcsrctoken          |             |                                          |                          |                    | 
 * 
 * If you have fields other than `id`, `username` and `password` in your user
 * table, add them in 
 * `extraFields` when you create your {@link UserStorage} object.  In your 
 * signup and user update pages
 * (`signupPage`, `updateUserPage`), prefix these with `user_` in field names 
 * and they will be passed
 * into the user object when processing the form.  If there is an error 
 * processing the form, they will
 * be back as psot parameters, again prefixed with `user_`.
 * 
 *  **Using your own Fastify app**
 * 
 * If you are serving other endpoints, or you want to use something other than 
 * Nunjucks, you can create
 * and pass in your own Fastify app.
 */
export class FastifySessionServer {

    readonly app : FastifyInstance<Server, IncomingMessage, ServerResponse>;
    readonly prefix : string = "/";
    private endpoints : string[] = [];
    loginRedirect = "/";
    logoutRedirect : string = "/";
    private signupPage : string = "signup.njk";
    private configureFactor2Page : string = "configurefactor2.njk";
    private loginPage : string = "login.njk";
    private factor2Page : string = "factor2.njk";
    readonly errorPage : string = "error.njk";
    private changePasswordPage : string = "changepassword.njk";
    private changeFactor2Page : string = "changefactor2.njk";
    private updateUserPage : string = "updateuser.njk";
    private resetPasswordPage: string = "resetpassword.njk";
    private requestPasswordResetPage: string = "requestpasswordreset.njk";
    private emailVerifiedPage : string = "emailverified.njk";
    validateUserFn : (user : UserInputFields) 
        => string[] = defaultUserValidator;
    createUserFn: (request: FastifyRequest<{ Body: SignupBodyType }>,
        userEditableFields: string[]) => UserInputFields = defaultCreateUser;
    updateUserFn: (user: User,
        request: FastifyRequest<{ Body: UpdateUserBodyType }>,
        userEditableFields: string[]) => User = defaultUpdateUser;
    private addToSession? : (request : FastifyRequest) => 
        {[key: string] : string|number|boolean|Date|undefined};
    private validateSession?: (session: Key,
        user: User | undefined,
        request: FastifyRequest) => void;

    readonly userStorage : UserStorage;
    readonly sessionManager : SessionManager;
    private userEndpoints : FastifyUserEndpoints;
    private adminEndpoints : FastifyAdminEndpoints;
    readonly authenticators: {[key:string]: Authenticator}
    readonly allowedFactor2 : string[] = [];

    private enableEmailVerification : boolean = true;
    private enablePasswordReset : boolean = true;
    private factor2ProtectedPageEndpoints : string[] = [
        "/requestpasswordreset",
        "/updateuser",
        "/changepassword",
        "/resetpassword",
        "/changefactor2",
    ]
    private factor2ProtectedApiEndpoints : string[] = [
        "/api/requestpasswordreset",
        "/api/updateuser",
        "/api/changepassword",
        "/api/resetpassword",
        "/api/changefactor1",
    ]
    private editUserScope? : string;

    constructor(
        app: FastifyInstance<Server, IncomingMessage, ServerResponse>,
        userStorage: UserStorage, 
        keyStorage: KeyStorage, 
        authenticators: {[key:string]: Authenticator}, 
        options: FastifySessionServerOptions = {}) {

        this.app = app;
        this.userEndpoints = new FastifyUserEndpoints(this, options);
        this.adminEndpoints = new FastifyAdminEndpoints(this, options);

        setParameter("prefix", ParamType.String, this, options, "PREFIX");
        if (!(this.prefix.endsWith("/"))) this.prefix += "/";
        if (!(this.prefix.startsWith("/"))) "/" + this.prefix;
        setParameter("signupPage", ParamType.String, this, options, "SIGNUP_PAGE");
        setParameter("configureFactor2Page", ParamType.String, this, options, "SIGNUP_FACTOR2_PAGE");
        setParameter("loginPage", ParamType.String, this, options, "LOGIN_PAGE");
        setParameter("factor2Page", ParamType.String, this, options, "FACTOR2_PAGE");
        setParameter("errorPage", ParamType.String, this, options, "ERROR_PAGE");
        setParameter("changePasswordPage", ParamType.String, this, options, "CHANGE_PASSWORD_PAGE");
        setParameter("changeFactor2Page", ParamType.String, this, options, "CHANGE_FACTOR2_PAGE");
        setParameter("updateUser", ParamType.String, this, options, "UPDATE_USER_PAGE");
        setParameter("resetPasswordPage", ParamType.String, this, options, "RESET_PASSWORD_PAGE");
        setParameter("requestPasswordResetPage", ParamType.String, this, options, "REQUEST_PASSWORD_RESET_PAGE");
        setParameter("emailVerifiedPage", ParamType.String, this, options, "EMAIL_VERIFIED_PAGE");
        setParameter("emailFrom", ParamType.String, this, options, "EMAIL_FROM");
        setParameter("persistSessionId", ParamType.Boolean, this, options, "PERSIST_SESSION_ID");
        setParameter("allowedFactor2", ParamType.StringArray, this, options, "ALLOWED_FACTOR2");
        setParameter("enableEmailVerification", ParamType.Boolean, this, options, "ENABLE_EMAIL_VERIFICATION");
        setParameter("enablePasswordReset", ParamType.Boolean, this, options, "ENABLE_PASSWORD_RESET");
        setParameter("factor2ProtectedPageEndpoints", ParamType.StringArray, this, options, "FACTOR2_PROTECTED_PAGE_ENDPOINTS");
        setParameter("factor2ProtectedApiEndpoints", ParamType.StringArray, this, options, "FACTOR2_PROTECTED_API_ENDPOINTS");


        if (options.validateUserFn) this.validateUserFn = options.validateUserFn;
        if (options.createUserFn) this.createUserFn = options.createUserFn;
        if (options.updateUserFn) this.updateUserFn = options.updateUserFn;
        if (options.addToSession) this.addToSession = options.addToSession;
        if (options.validateSession) this.validateSession = options.validateSession;

        this.endpoints = [...SignupPageEndpoints, ...SignupApiEndpoints];
        this.endpoints = [...this.endpoints, ...SessionPageEndpoints, ...SessionApiEndpoints];
        this.endpoints = [...this.endpoints, ...SessionAdminPageEndpoints, ...SessionAdminApiEndpoints];
        if (this.enableEmailVerification) this.endpoints = [...this.endpoints, ...EmailVerificationPageEndpoints, ...EmailVerificationApiEndpoints];
        if (this.enablePasswordReset) this.endpoints = [...this.endpoints, ...PasswordResetPageEndpoints, ...PasswordResetApiEndpoints];
        if (this.allowedFactor2.length > 0) this.endpoints = [...this.endpoints, ...Factor2PageEndpoints, ...Factor2ApiEndpoints];
        this.addEndpoints();

        setParameter("endpoints", ParamType.StringArray, this, options, "ENDPOINTS");

        this.userStorage = userStorage;
        this.authenticators = authenticators;
        this.sessionManager = new SessionManager(userStorage, keyStorage, authenticators, options);

        ////////////////
        // hooks

        // session management: validate session and CSRF cookies and populate 
        // request.user
        app.addHook('preHandler', async (request : FastifyRequest<{Body: CsrfBodyType}>, reply : FastifyReply) => {

            CrossauthLogger.logger.debug(j({msg: "Getting session cookie"}));
            let sessionCookieValue = this.getSessionCookieValue(request);
            let reportSession : {[key:string]:string} = {}
            if (sessionCookieValue) {
                try {
                    reportSession.hashedSessionId = 
                    Hasher.hash(this.sessionManager.getSessionId(sessionCookieValue));
                } catch {
                    reportSession.hashedSessionCookie = 
                        Hasher.hash(sessionCookieValue);
                }
            }

            // check if CSRF token is in cookie (and signature is valid)
            // remove it if it is not.
            // we are not checking it matches the CSRF token in the header or
            // body at this stage - just removing invalid cookies
            CrossauthLogger.logger.debug(j({msg: "Getting csrf cookie"}));
            let cookieValue : string|undefined;
            try {
                 cookieValue = this.getCsrfCookieValue(request);
                 if (cookieValue) this.sessionManager.validateCsrfCookie(cookieValue);
            }
            catch (e) {
                CrossauthLogger.logger.warn(j({msg: "Invalid csrf cookie received", cerr: e, hashedCsrfCookie: this.getHashOfCsrfCookie(request)}));
                reply.clearCookie(this.sessionManager.csrfCookieName);
                cookieValue = undefined;
            }
    
            if (["GET", "OPTIONS", "HEAD"].includes(request.method)) {
                // for get methods, create a CSRF token in the request object and response header
                try {
                    if (!cookieValue) {
                        CrossauthLogger.logger.debug(j({msg: "Invalid CSRF cookie - recreating"}));
                        const { csrfCookie, csrfFormOrHeaderValue } = await this.sessionManager.createCsrfToken();
                        reply.setCookie(csrfCookie.name, csrfCookie.value, csrfCookie.options );
                        request.csrfToken = csrfFormOrHeaderValue;
                    } else {
                        CrossauthLogger.logger.debug(j({msg: "Valid CSRF cookie - creating token"}));
                        const csrfFormOrHeaderValue = await this.sessionManager.createCsrfFormOrHeaderValue(cookieValue);
                        request.csrfToken = csrfFormOrHeaderValue;
                    }
                    reply.header(CSRFHEADER, request.csrfToken);
                } catch (e) {
                    CrossauthLogger.logger.error(j({
                        msg: "Couldn't create CSRF token",
                        cerr: e,
                        user: request.user?.username,
                        ...reportSession,
                    }));
                    CrossauthLogger.logger.debug(j({err: e}));
                    reply.clearCookie(this.sessionManager.csrfCookieName);
                }
            } else {
                // for other methods, create a new token only if there is 
                // already a valid one
                if (cookieValue) {
                    try {
                        this.csrfToken(request, reply);
                    } catch (e) {
                        CrossauthLogger.logger.error(j({
                            msg: "Couldn't create CSRF token",
                            cerr: e,
                            user: request.user?.username,
                            ...reportSession,
                        }));
                        CrossauthLogger.logger.debug(j({err: e}));
                    }
                }
            }

            // we now either have a valid CSRF token, or none at all
    
            // validate any session cookie.  Remove if invalid
            //request.user = undefined;
            //request.authType = undefined;
            sessionCookieValue = this.getSessionCookieValue(request);
            if (sessionCookieValue) {
                try {
                    const sessionId = this.sessionManager.getSessionId(sessionCookieValue);
                    let {key, user} = await this.sessionManager.userForSessionId(sessionId);
                    if (this.validateSession) this.validateSession(key,
                        user,
                        request);
                    request.sessionId = sessionId;
    
                    request.user = user;
                    request.authType = "cookie";
                    CrossauthLogger.logger.debug(j({
                        msg: "Valid session id",
                        user: user?.username
                    }));
                } catch (e) {
                    CrossauthLogger.logger.warn(j({
                        msg: "Invalid session cookie received",
                        hashOfSessionId: this.getHashOfSessionId(request)
                    }));
                    reply.clearCookie(this.sessionManager.sessionCookieName);
                }
            }
        });

        // 2FA for endpoints that are protected by this (other than login)
        app.addHook('preHandler', 
            async (request: FastifyRequest<{ Body: ArbitraryBodyType }>,
                reply: FastifyReply) => {
            const sessionCookieValue = this.getSessionCookieValue(request);
            if (sessionCookieValue && 
                request.user?.factor2 && 
                (this.factor2ProtectedPageEndpoints.includes(request.url) || 
                this.factor2ProtectedApiEndpoints.includes(request.url))) {
                const sessionId = this.sessionManager.getSessionId(sessionCookieValue);
                if (!(["GET", "OPTIONS", "HEAD"].includes(request.method))) {
                    const sessionData = 
                        await this.sessionManager.dataForSessionId(sessionId);
                    if (("pre2fa") in sessionData) {
                        // 2FA has started - validate it
                        CrossauthLogger.logger.debug("Completing 2FA");

                        // get secrets from the request body 
                        const authenticator = this.authenticators[sessionData.pre2fa.factor2];
                        const secretNames = [...authenticator.secretNames(), 
                            ...authenticator.transientSecretNames()];
                        let secrets : {[key:string]:string} = {};
                        for (let field in request.body) {
                            if (secretNames.includes(field)) secrets[field] = 
                                request.body[field];
                        }

                        //const sessionCookieValue = this.getSessionCookieValue(request);
                        //if (!sessionCookieValue) throw new CrossauthError(ErrorCode.Unauthorized, "No session cookie found");
                        let error : CrossauthError|undefined = undefined;
                        try {
                            //await this.sessionManager.completeTwoFactorPageVisit(request.body, sessionCookieValue);
                            await this.sessionManager.completeTwoFactorPageVisit(secrets, sessionId);
                        } catch (e) {
                            error = CrossauthError.asCrossauthError(e);
                            CrossauthLogger.logger.debug(j({err: e}));
                            const ce = CrossauthError.asCrossauthError(e);
                            CrossauthLogger.logger.error(j({
                                msg: error.message,
                                cerr: e,
                                user: request.body.username,
                                errorCode: ce.code,
                                errorCodeName: ce.codeName
                            }));
                        }
                        // restore original request body
                        request.body = sessionData.pre2fa.body;
                        if (error) {
                            if (error.code == ErrorCode.Expired) {
                                // user will not be able to complete this process - delete 
                                CrossauthLogger.logger.debug("Error - cancelling 2FA");
                                // the 2FA data and start again
                                try {
                                    await this.sessionManager.cancelTwoFactorPageVisit(sessionId);
                                } catch (e) {
                                    CrossauthLogger.logger.error(j({msg: "Failed cancelling 2FA", cerr: e, user: request.user?.username, hashOfSessionId: this.getHashOfSessionId(request)}));
                                    CrossauthLogger.logger.debug(j({err:e}))
                                }
                                request.body = {
                                    ...request.body,
                                    errorMessage: error.message,
                                    errorMessages: error.message,
                                    errorCode: ""+error.code,
                                    errorCodeName: ErrorCode[error.code],
                                }
                            } else {
                                if (this.factor2ProtectedPageEndpoints.includes(request.url)) {
                                    return reply.redirect(this.prefix+"factor2?error="+ErrorCode[error.code]);

                                } else {
                                    return reply.status(error.httpStatus)
                                        .send(JSON.stringify({
                                            ok: false,
                                            errorMessage: error.message,
                                            errorMessages: error.messages,
                                            errorCode: error.code,
                                            errorCodeName: ErrorCode[error.code]
                                    }));
                                }
                            }
                        }
                    } else {
                        // 2FA has not started - start it
                        this.validateCsrfToken(request);
                        CrossauthLogger.logger.debug("Starting 2FA");
                        this.sessionManager.initiateTwoFactorPageVisit(request.user, sessionId, request.body, request.url.replace(/\?.*$/,""));
                        if (this.factor2ProtectedPageEndpoints.includes(request.url)) {
                            return reply.redirect(this.prefix+"factor2");
                        } else {
                            return reply.send(JSON.stringify({
                                ok: true,
                                factor2Required: true
                            }));
                        }
                    }
                } else {
                    // if we have a get request to one of the protected urls, 
                    // cancel any pending 2FA
                    const sessionCookieValue = this.getSessionCookieValue(request);
                    if (sessionCookieValue) {
                        const sessionId = this.sessionManager.getSessionId(sessionCookieValue);
                        const sessionData = 
                            await this.sessionManager.dataForSessionId(sessionId);
                        if (("pre2fa") in sessionData) {
                            CrossauthLogger.logger.debug("Cancelling 2FA");
                            try {
                                await this.sessionManager.cancelTwoFactorPageVisit(sessionId);
                            } catch (e) {
                                CrossauthLogger.logger.debug(j({err:e}));
                                CrossauthLogger.logger.error(j({msg: "Failed cancelling 2FA", cerr: e, user: request.user?.username, hashOfSessionId: this.getHashOfSessionId(request)}));
                            }      
                        }
                    }
                }
            } 
        });
    }    

    //////////////////
    // page endpoints

    addEndpoints() {
        if (this.endpoints.includes("login")) {
            this.addLoginEndpoints();
        }

        if (this.endpoints.includes("loginfactor2")) {
            this.addLoginFactor2Endpoints();
        }

        if (this.endpoints.includes("factor2")) {
            this.addFactor2Endpoints();
        }

        if (this.endpoints.includes("signup")) {
            this.addSignupEndpoints();
        }

        if (this.endpoints.includes("configurefactor2")) {
            this.userEndpoints.addConfigureFactor2Endpoints(this.prefix,
                this.configureFactor2Page,
                this.signupPage);
        }

        if (this.endpoints.includes("changefactor2")) {
            this.userEndpoints.addChangeFactor2Endpoints(this.prefix,
                this.changeFactor2Page,
                this.configureFactor2Page);
        }

        if (this.endpoints.includes("changepassword")) {
            this.userEndpoints.addChangePasswordEndpoints(this.prefix,
                this.changePasswordPage);
        }

        if (this.endpoints.includes("updateuser")) {
            this.userEndpoints.addUpdateUserEndpoints(this.prefix,
                 this.updateUserPage);
        }

        if (this.endpoints.includes("requestpasswordreset")) {
            this.userEndpoints.addRequestPasswordResetEndpoints(this.prefix, 
                this.requestPasswordResetPage);
        }

        if (this.endpoints.includes("resetpassword")) {
            if (!this.enablePasswordReset) throw new CrossauthError(ErrorCode.Configuration, "Password reset must be enabled for /resetpassword");
            this.userEndpoints.addResetPasswordEndpoints(this.prefix, this.resetPasswordPage);
        }

        if (this.endpoints.includes("verifyemail")) {
            if (!this.enableEmailVerification) throw new CrossauthError(ErrorCode.Configuration, "Email verification  must be enabled for /verifyemail");
            this.userEndpoints.addVerifyEmailEndpoints(this.prefix, 
                this.emailVerifiedPage);
        }

        if (this.endpoints.includes("logout")) {
            this.addLogoutEndpoints();

        }
        if (this.endpoints.includes("api/login")) {
            this.addApiLoginEndpoints();
        }

        if (this.endpoints.includes("api/loginfactor2")) {
            this.addApiLoginFactor2Endpoints();
        }

        if (this.endpoints.includes("api/cancelfactor2")) {
            this.addApiCancelFactor2Endpoints();
        }

        if (this.endpoints.includes("api/logout")) {
            this.addApiLogoutEndpoints();
        }

        if (this.endpoints.includes("api/signup")) {
            this.addApiSignupEndpoints();
        }

        if (this.endpoints.includes("api/configurefactor2")) {
            this.userEndpoints.addApiConfigureFactor2Endpoints(this.prefix);
        }

        if (this.endpoints.includes("api/changepassword")) {
            this.userEndpoints.addApiChangePasswordEndpoints(this.prefix);
        }

        if (this.endpoints.includes("api/changefactor2")) {
            this.userEndpoints.addApiChangeFactor2Endpoints(this.prefix);
        }

        if (this.endpoints.includes("api/updateuser")) {
            this.userEndpoints.addApiUpdateUserEndpoints(this.prefix);
        }

        if (this.endpoints.includes("api/resetpassword")) {
            if (!this.enablePasswordReset) throw new CrossauthError(ErrorCode.Configuration, "Password reset must be enabled for /api/resetpassword");
            this.userEndpoints.addApiResetPasswordEndpoints(this.prefix);
        }

        if (this.endpoints.includes("api/requestpasswordreset")) {
            if (!this.enablePasswordReset) throw new CrossauthError(ErrorCode.Configuration, "Password reset must be enabled for /api/requestpasswordreset");
            this.userEndpoints.addApiRequestPasswordResetEndpoints(this.prefix);
        }

        if (this.endpoints.includes("api/verifyemail")) {
            if (!this.enableEmailVerification) throw new CrossauthError(ErrorCode.Configuration, "Email verification must be enabled for /api/verifyemail");
            this.userEndpoints.addApiVerifyEmailEndpoints(this.prefix);
        }

        if (this.endpoints.includes("api/userforsessionkey")) {
            this.addApiUserForSessionKeyEndpoints();
        }

        if (this.endpoints.includes("api/getcsrftoken")) {
            this.addApiGetCsrfTokenEndpoints();
    
        }

        ///// Admin

        if (this.endpoints.includes("admin/createuser")) {
            this.adminEndpoints.addCreateUserEndpoints();
        }
        if (this.endpoints.includes("admin/api/createuser")) {
            this.adminEndpoints.addApiCreateUserEndpoints();
        }
        if (this.endpoints.includes("admin/selectuser")) {
            this.adminEndpoints.addSelectUserEndpoints();
        }
        if (this.endpoints.includes("admin/updateuser")) {
            this.adminEndpoints.addUpdateUserEndpoints();
        }
        if (this.endpoints.includes("admin/api/updateuser")) {
            this.adminEndpoints.addApiUpdateUserEndpoints();
        }
        if (this.endpoints.includes("admin/changepassword")) {
            this.adminEndpoints.addChangePasswordEndpoints();
        }
        if (this.endpoints.includes("admin/api/changepassword")) {
            this.adminEndpoints.addApiChangePasswordEndpoints();
        }


    }

    private addLoginEndpoints() {

        this.app.get(this.prefix+'login', 
            async (request: FastifyRequest<{ Querystring: LoginQueryType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'GET',
                    url: this.prefix + 'login',
                    ip: request.ip
                }));
            if (request.user) return reply
                .redirect(request.query.next??this.loginRedirect); // already logged in

                let data: {
                    urlprefix: string,
                    next?: any,
                    csrfToken: string | undefined
                } = {
                    urlprefix: this.prefix,
                    csrfToken: request.csrfToken
                };
            if (request.query.next) {
                data["next"] = request.query.next;
            }
            return reply.view(this.loginPage, data);
        });

        this.app.post(this.prefix+'login', 
            async (request: FastifyRequest<{ Body: LoginBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.prefix + 'login',
                    ip: request.ip
                }));
            let next = 
                request.body.next && request.body.next.length > 0 ? 
                    request.body.next : this.loginRedirect;
            try {
                return await this.login(request, reply, 
                (reply, user) => {
                    if (user.state ==UserState.passwordChangeNeeded) {
                        if (this.endpoints.includes("changepassword")) {
                            CrossauthLogger.logger.debug(j({msg: "Password change needed - sending redirect"}));
                            return reply.redirect("/changepassword?required=true&next="+encodeURIComponent("login?next="+next));
                        } else {
                            const ce = new CrossauthError(ErrorCode.PasswordChangeNeeded)
                            return this.handleError(ce, request, reply, (reply, error) => {
                                return reply.view(this.loginPage, {
                                    errorMessage: error.message,
                                    errorMessages: error.messages, 
                                    errorCode: error.code, 
                                    errorCodeName: ErrorCode[error.code], 
                                    next: next, 
                                    persist: request.body.persist,
                                    username: request.body.username,
                                    csrfToken: request.csrfToken,
                                    urlprefix: this.prefix, 
                                });                      
                            });
                        }

                    } else if (user.state == UserState.passwordResetNeeded) {
                        if (this.endpoints.includes("requestpasswordreset")) {
                            CrossauthLogger.logger.debug(j({msg: "Password reset needed - sending redirect"}));
                            return reply.redirect("/requestpasswordreset?required=true&next="+encodeURIComponent("login?next="+next));
                        } else {
                            const ce = new CrossauthError(ErrorCode.PasswordResetNeeded)
                            return this.handleError(ce, request, reply, (reply, error) => {
                                return reply.view(this.loginPage, {
                                    errorMessage: error.message,
                                    errorMessages: error.messages, 
                                    errorCode: error.code, 
                                    errorCodeName: ErrorCode[error.code], 
                                    next: next, 
                                    persist: request.body.persist,
                                    username: request.body.username,
                                    csrfToken: request.csrfToken,
                                    urlprefix: this.prefix, 
                                });                      
                            });
                        }

                    } else if (this.allowedFactor2.length > 0 && 
                        (user.state == UserState.factor2ResetNeeded || 
                        !this.allowedFactor2.includes(user.factor2?user.factor2:"none"))) {
                        CrossauthLogger.logger.debug(j({msg: `Factor2 reset needed.  Factor2 is ${user.factor2}, state is ${user.state}, allowed factor2 is [${this.allowedFactor2.join(", ")}]`,
                            username: user.username}))
                        if (this.endpoints.includes("changefactor2")) {
                            CrossauthLogger.logger.debug(j({msg: "Factor 2 reset needed - sending redirect"}));
                            return reply.redirect("/changefactor2?required=true&next="+encodeURIComponent("login?next="+next));
                        } else {
                            const ce = new CrossauthError(ErrorCode.Factor2ResetNeeded)
                            return this.handleError(ce, request, reply, (reply, error) => {
                                return reply.view(this.loginPage, {
                                    errorMessage: error.message,
                                    errorMessages: error.messages, 
                                    errorCode: error.code, 
                                    errorCodeName: ErrorCode[error.code], 
                                    next: next, 
                                    persist: request.body.persist,
                                    username: request.body.username,
                                    csrfToken: request.csrfToken,
                                    urlprefix: this.prefix, 
                                });                      
                            });
                        }
                    }

                    else if (!user.factor2 || user.factor2.length == 0) {
                        CrossauthLogger.logger.debug(j({msg: "Successful login - sending redirect"}));
                        return reply.redirect(next);
                    } else {
                        let data = {
                            csrfToken: request.csrfToken,
                            next: request.body.next??this.loginRedirect,
                            persist: request.body.persist ? "on" : "",
                            urlprefix: this.prefix, 
                            factor2: user.factor2,
                            action: "loginfactor2",
                        };
                        return reply.view(this.factor2Page, data);
                    }
                });
            } catch (e) {
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, request, reply, (reply, error) => {
                    return reply.view(this.loginPage, {
                        errorMessage: error.message,
                        errorMessages: error.messages, 
                        errorCode: error.code, 
                        errorCodeName: ErrorCode[error.code], 
                        next: next, 
                        persist: request.body.persist,
                        username: request.body.username,
                        csrfToken: request.csrfToken,
                        urlprefix: this.prefix, 
                    });                      
                });
            }
        });
    }

    private addLoginFactor2Endpoints() {
        this.app.post(this.prefix+'loginfactor2', 
            async (request: FastifyRequest<{ Body: LoginFactor2BodyType }>,
                reply: FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'loginfactor2', ip: request.ip}));
            let next = 
                request.body.next && request.body.next.length > 0 ? 
                    request.body.next : this.loginRedirect;
            try {
                CrossauthLogger.logger.debug(j({msg: "Next page " + next}));

                return await this.loginFactor2(request, reply, 
                (reply, _user) => {
                    CrossauthLogger.logger.debug(j({msg: "Successful login - sending redirect to"}));
                    return reply.redirect(next);
                });
            } catch (e) {
                CrossauthLogger.logger.debug(j({err: e}));
                let factor2 : string|undefined;
                try {
                    const data = request.sessionId ? 
                        await this.sessionManager.dataForSessionId(request.sessionId) : 
                        undefined;
                    factor2 = data?.factor2;
                } catch (e) {
                    CrossauthLogger.logger.error(j({err: e}));
                }
                if (factor2 && factor2 in this.authenticators) {
                    return this.handleError(e, request, reply, (reply, error) => {
                        return reply.view(this.factor2Page, {
                            errorMessage: error.message,
                            errorMessages: error.messages, 
                            errorCode: error.code, 
                            errorCodeName: ErrorCode[error.code], 
                            next: request.body.next, 
                            persist: request.body.persist ? "on" : "",
                            csrfToken: request.csrfToken,
                            urlprefix: this.prefix, 
                            factor2 : factor2,
                            action: "loginfactor2",
                        });                      
                    });                        
                } else {
                    return this.handleError(e, request, reply, (reply, error) => {
                        return reply.view(this.loginPage, {
                            errorMessage: error.message,
                            errorMessages: error.messages, 
                            errorCode: error.code, 
                            errorCodeName: ErrorCode[error.code], 
                            next: request.body.next, 
                            persist: request.body.persist ? "on" : "",
                            csrfToken: request.csrfToken,
                            urlprefix: this.prefix, 
                        });                      
                    });
    
                }
            }
        });
    }

    private addFactor2Endpoints() {

        this.app.get(this.prefix+'factor2', 
            async (request: FastifyRequest<{ Querystring: Factor2QueryType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'GET',
                    url: this.prefix + 'factor2',
                    ip: request.ip
                }));
            if (!request.sessionId) throw new CrossauthError(ErrorCode.Unauthorized, 
                "No session cookie present");
            const sessionCookieValue = this.getSessionCookieValue(request);
            const sessionId = this.sessionManager.getSessionId(sessionCookieValue??"")
            const sessionData = 
            await this.sessionManager.dataForSessionId(sessionId);
            if (!sessionData?.pre2fa) throw new CrossauthError(ErrorCode.Unauthorized, 
                "2FA not initiated");
            let data = {
                urlprefix: this.prefix, 
                csrfToken: request.csrfToken, 
                action: sessionData.pre2fa.url, 
                errorCodeName: request.query.error,
                factor2: sessionData.pre2fa.factor2};
            return reply.view(this.factor2Page, data);
        });

    }

    private addSignupEndpoints() {
        this.app.get(this.prefix+'signup', 
            async (request: FastifyRequest<{ Querystring: LoginQueryType }>,
                reply: FastifyReply)  => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'GET',
                    url: this.prefix + 'signup',
                    ip: request.ip
                }));
                let data: {
                    urlprefix: string,
                    next?: any,
                    csrfToken: string | undefined,
                    allowedFactor2: AuthenticatorDetails[]
                } = {
                    urlprefix: this.prefix,
                    csrfToken: request.csrfToken,
                    allowedFactor2: this.allowedFactor2Details()
                };
            if (request.query.next) {
                data["next"] = request.query.next;
            }
            return reply.view(this.signupPage, data);
        });

        this.app.post(this.prefix+'signup', 
            async (request: FastifyRequest<{ Body: SignupBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.prefix + 'signup',
                    ip: request.ip,
                    user: request.body.username
                }));
            let next = 
                request.body.next && request.body.next.length > 0 ? 
                    request.body.next : this.loginRedirect;
            try {
                CrossauthLogger.logger.debug(j({msg: "Next page " + next}));

                return await this.signup(request, reply, 
                (reply, data, _user) => {
                    const authenticator = data?.userData?.factor2 ? 
                        this.authenticators[data.userData.factor2] : undefined;
                    if (data.userData?.factor2) {
                        return reply.view(this.configureFactor2Page, {
                            csrfToken: data.csrfToken,
                            ...data.userData
                        });
                    } else if (this.enableEmailVerification && 
                        (authenticator == undefined || 
                            authenticator.skipEmailVerificationOnSignup() != true)) {
                        return reply.view(this.signupPage, {
                            next: next, 
                            csrfToken: request.csrfToken,
                            message: "Please check your email to finish signing up.",
                            allowedFactor2: this.allowedFactor2Details(),
                            urlprefix: this.prefix, 
                            factor2: request.body.factor2,
                            ...data.userData,
                        });
                    } else {
                        return reply.redirect(this.loginRedirect);
                    }
                });
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.error(j({
                    msg: "Signup failure",
                    user: request.body.username,
                    errorCodeName: ce.codeName,
                    errorCode: ce.code
                }));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, request, reply, (reply, error) => {
                    let extraFields : {[key:string] : string|number|boolean|Date|undefined} = {};
                    for (let field in request.body) {
                        if (field.startsWith("user_")) extraFields[field] = request.body[field];
                    }
                    return reply.view(this.signupPage, {
                        errorMessage: error.message,
                        errorMessages: error.messages, 
                        errorCode: error.code, 
                        errorCodeName: ErrorCode[error.code], 
                        next: next, 
                        persist: request.body.persist,
                        username: request.body.username,
                        csrfToken: request.csrfToken,
                        factor2: request.body.factor2,
                        allowedFactor2: this.allowedFactor2Details(),
                        urlprefix: this.prefix, 
                        ...extraFields,
                        });
                    
                });
            }
        });
    }
    
    private addLogoutEndpoints() {
        this.app.post(this.prefix+'logout', 
            async (request: FastifyRequest<{ Body: LoginBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.prefix + 'logout',
                    ip: request.ip,
                    user: request.user?.username
                }));
            try {
                return await this.logout(request, reply, 
                (reply) => {return reply.redirect(request.body.next? 
                    request.body.next : this.logoutRedirect)});
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e); 
                CrossauthLogger.logger.error(j({
                    msg: "Logout failure",
                    user: request.user?.username,
                    errorCodeName: ce.codeName,
                    errorCode: ce.code
                }));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, request, reply, (reply, error) => {
                    return reply.view(this.errorPage, {
                        urlprefix: this.prefix,
                        errorMessage: error.message,
                        errorMessages: error.messages,
                        errorCode: error.code,
                        errorCodeName: ErrorCode[error.code]
                    });
                    
                });
            }
        });
    }

    ////////////////////
    // API endpoints

    private addApiLoginEndpoints() {

        this.app.post(this.prefix+'api/login', 
            async (request: FastifyRequest<{ Body: LoginBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.prefix + 'api/login',
                    ip: request.ip
                }));
            if (request.user) return reply.header(...JSONHDR)
                .send({ok: false, user : request.user}); // already logged in
            try {
                return await this.login(request, reply, 
                (reply, user) => {
                    if (user.state == UserState.passwordChangeNeeded) {
                            const ce = new CrossauthError(ErrorCode.PasswordChangeNeeded)
                            return this.handleError(ce, request, reply, (reply, error) => {
                                reply.status(this.errorStatus(ce)).header(...JSONHDR)
                                    .send({
                                        ok: false,
                                        errorMessage: error.message,
                                        errorMessages: error.messages,
                                        errorCode: error.code,
                                        errorCodeName: ErrorCode[error.code]
                                });                    
                            });

                    } else if (user.state == UserState.passwordResetNeeded) {
                        const ce = new CrossauthError(ErrorCode.PasswordResetNeeded)
                        return this.handleError(ce, request, reply, (reply, error) => {
                            reply.status(this.errorStatus(ce)).header(...JSONHDR)
                                .send({
                                    ok: false,
                                    errorMessage: error.message,
                                    errorMessages: error.messages,
                                    errorCode: error.code,
                                    errorCodeName: ErrorCode[error.code]
                            });                    
                        });

                    } else if (this.allowedFactor2.length > 0 && 
                        (user.state == UserState.factor2ResetNeeded || 
                        !this.allowedFactor2.includes(user.factor2 ? user.factor2 : "none"))) {
                        const ce = new CrossauthError(ErrorCode.Factor2ResetNeeded)
                        return this.handleError(ce, request, reply, (reply, error) => {
                            reply.status(this.errorStatus(ce)).header(...JSONHDR)
                                .send({
                                    ok: false,
                                    errorMessage: error.message,
                                    errorMessages: error.messages,
                                    errorCode: error.code,
                                    errorCodeName: ErrorCode[error.code]
                            });                    
                        });

                    } else if (user.twoFactorRequired) {
                        return reply.header(...JSONHDR)
                            .send({ok: true, twoFactorRequired: true});

                    } else {
                        return reply.header(...JSONHDR)
                            .send({ok: true, user : user});
                    }
                });
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e); 
                CrossauthLogger.logger.error(j({
                    msg: "Login failure",
                    user: request.body.username,
                    errorCodeName: ce.codeName,
                    errorCode: ce.code
                }));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, request, reply, (reply, error) => {
                    reply.status(this.errorStatus(e)).header(...JSONHDR)
                        .send({
                            ok: false,
                            errorMessage: error.message,
                            errorMessages: error.messages,
                            errorCode: error.code,
                            errorCodeName: ErrorCode[error.code]
                    });                    
                });
            }
        });
    }

    private addApiCancelFactor2Endpoints() {

        this.app.post(this.prefix+'api/cancelfactor2', 
            async (request: FastifyRequest<{ Body: CsrfBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.prefix + 'api/cancelfactor2',
                    ip: request.ip
                }));
            if (request.user) return reply.header(...JSONHDR)
                .send({ok: false, user : request.user}); // already logged in
            try {
                return await this.cancelFactor2(request, reply, 
                (reply) => {
                        return reply.header(...JSONHDR).send({ok: true});
                });
            } catch (e) {
                const user : User|undefined = request.user;
                const username = user || "";
                const ce = CrossauthError.asCrossauthError(e); 
                CrossauthLogger.logger.error(j({
                    msg: "Login failure",
                    user: username,
                    errorCodeName: ce.codeName,
                    errorCode: ce.code
                }));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, request, reply, (reply, error) => {
                    reply.status(this.errorStatus(e)).header(...JSONHDR)
                        .send({
                            ok: false,
                            errorMessage: error.message,
                            errorMessages: error.messages,
                            errorCode: error.code,
                            errorCodeName: ErrorCode[error.code]
                        });                    
                });
            }
        });
    }

    private addApiLoginFactor2Endpoints() {
        this.app.post(this.prefix+'api/loginfactor2', 
            async (request: FastifyRequest<{ Body: LoginFactor2BodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.prefix + 'api/loginfactor2',
                    ip: request.ip
                }));
            if (request.user) return reply.header(...JSONHDR)
                .send({ok: false, user : request.user}); // already logged in
            try {
                return await this.loginFactor2(request, reply, 
                (reply, user) => {
                    return reply.header(...JSONHDR)
                        .send({ok: true, user : user});
                });
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e); 
                CrossauthLogger.logger.error(j({
                    msg: "Login failure",
                    hashOfSessionId: this.getHashOfSessionId(request),
                    errorCodeName: ce.codeName,
                    errorCode: ce.code
                }));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e,request,  reply, (reply, error) => {
                    return reply.status(this.errorStatus(e)).header(...JSONHDR)
                        .send({
                            ok: false,
                            errorMessage: error.message,
                            errorMessages: error.messages,
                            errorCode: error.code,
                            errorCodeName: ErrorCode[error.code]
                    });                    
                });
            }
        });
    }

    private addApiLogoutEndpoints() {
        this.app.post(this.prefix+'api/logout', 
            async (request: FastifyRequest<{ Body: LoginBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.prefix + 'api/logout',
                    ip: request.ip,
                    user: request.user?.username
                }));
            if (!this.canEditUser(request)) return this.sendJsonError(reply, 
                401, "You are not authorized to access this url");

            try {
                return await this.logout(request, reply, 
                (reply) => {return reply.header(...JSONHDR).send({ok: true})});
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e); 
                CrossauthLogger.logger.error(j({
                    msg: "Logout failure",
                    user: request.user?.username,
                    errorCodeName: ce.codeName,
                    errorCode: ce.code
                }));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, request, reply, (reply, error) => {
                    reply.status(this.errorStatus(e)).header(...JSONHDR)
                        .send({
                            ok: false,
                            errorMessage: error.message,
                            errorMessages: error.messages,
                            errorCode: ErrorCode[error.code]
                    });                    
                });
            }
        });
    }

    private addApiSignupEndpoints() {
        this.app.post(this.prefix+'api/signup', 
            async (request: FastifyRequest<{ Body: SignupBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.prefix + 'api/signup',
                    ip: request.ip,
                    user: request.body.username
                }));
            try {
                return await this.signup(request, reply, 
                (reply, data, user) => {
                    return reply.header(...JSONHDR).send({
                    ok: true,
                    user : user,
                    emailVerificationNeeded: this.enableEmailVerification??false,
                    ...data.userData,
                })});
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e); 
                CrossauthLogger.logger.error(j({
                    msg: "Signup failure",
                    user: request.user?.username,
                    errorCodeName: ce.codeName,
                    errorCode: ce.code
                }));
                CrossauthLogger.logger.debug(j({err: e}));
                this.handleError(e, request, reply, (reply, error) => {
                    reply.status(this.errorStatus(e)).header(...JSONHDR)
                        .send({
                            ok: false,
                            errorMessage: error.message,
                            errorMessages: error.messages,
                            errorCode: ErrorCode[error.code]
                    });                    
                });
            }
        });
    }

    private addApiUserForSessionKeyEndpoints() {
        this.app.post(this.prefix+'api/userforsessionkey', 
            async (request: FastifyRequest<{ Body: LoginBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.prefix + 'api/userforsessionkey',
                    ip: request.ip,
                    user: request.user?.username,
                    hashOfSessionId: this.getHashOfSessionId(request)
                }));
                if (!this.canEditUser(request)) return this.sendJsonError(reply,
                    401,
                    "User not logged in");
                if (this.isSessionUser(request) && !request.csrfToken) return this.sendJsonError(reply,
                    403,
                    "No CSRF token present");
            //await this.validateCsrfToken(request)
            try {
                let user : User|undefined;
                if (request.sessionId) {
                    const resp = 
                        await this.sessionManager.userForSessionId(request.sessionId);
                    user = resp.user;
                }
                return reply.header(...JSONHDR).send({ok: true, user : user});
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                let error = ce.message;
                let code = ce.code;
                let codeName = ce.codeName;
                switch (ce.code) {
                    case ErrorCode.UserNotExist:
                    case ErrorCode.PasswordInvalid:
                        error = "Invalid username or password";
                        code = ErrorCode.UsernameOrPasswordInvalid;
                        codeName = ErrorCode[code];
                        break;
                }
                CrossauthLogger.logger.error(j({
                    msg: error,
                    user: request.user?.username,
                    hashOfSessionId: this.getHashOfSessionId(request),
                    errorCodeName: codeName,
                    errorCode: code
                }));
                CrossauthLogger.logger.debug(j({err: e}));
                return reply.status(this.errorStatus(e)).header(...JSONHDR)
                    .send({
                        ok: false,
                        errorCode: code,
                        errorCodeName: codeName
                    });
            }
        });
    }

    private addApiGetCsrfTokenEndpoints() {
        this.app.get(this.prefix+'api/getcsrftoken', 
            async (request: FastifyRequest<{ Body: LoginBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.prefix + 'api/getcsrftoken',
                    ip: request.ip,
                    user: request.user?.username
                }));
            try {
                return reply.header(...JSONHDR).send({
                    ok: true,
                    csrfToken: request.csrfToken
                });
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.error(j({
                    msg: "getcsrftoken failure",
                    user: request.user?.username,
                    hashedCsrfCookie: this.getHashOfCsrfCookie(request),
                    errorCode: ce.code,
                    errorCodeName: ce.codeName
                }));
                CrossauthLogger.logger.debug(j({err: e}));
                return reply.status(this.errorStatus(e)).header(...JSONHDR)
                    .send({
                        ok: false,
                        errorCode: ce.code,
                        errorCodeName: ce.codeName,
                        error: ce.message
                    });

            }
        });
    }

    /////////////////
    // Shared between page and API endpoints

    private async login(request : FastifyRequest<{ Body: LoginBodyType }>, 
        reply : FastifyReply, 
        successFn : (res : FastifyReply, user: User) => void) {

        if (request.user) return successFn(reply, 
                request.user); // already logged in - nothing to do

        // get data from request body
        const username = request.body.username;
        const persist = request.body.persist;

        // throw an exception if the CSRF token isn't valid
        //await this.validateCsrfToken(request);
        if (!request.csrfToken) throw new CrossauthError(ErrorCode.InvalidCsrf);

        // keep the old session ID.  If there was one, we will delete it after
        const oldSessionId = this.getSessionCookieValue(request);

        // call implementor-provided hook to add additional fields to session key
        let extraFields = this.addToSession ? this.addToSession(request) : {}

        // log user in and get new session cookie, CSRF cookie and user
        // if 2FA is enabled, it will be an anonymous session
        let { sessionCookie, csrfCookie, user } = 
            await this.sessionManager.login(username, request.body, extraFields, persist);

        // Set the new cookies in the reply
        CrossauthLogger.logger.debug(j({
            msg: "Login: set session cookie " + sessionCookie.name + " opts " + JSON.stringify(sessionCookie.options),
            user: request.body.username
        }));
        reply.cookie(sessionCookie.name,
            sessionCookie.value,
            sessionCookie.options);
        CrossauthLogger.logger.debug(j({
            msg: "Login: set csrf cookie " + csrfCookie.name + " opts " + JSON.stringify(sessionCookie.options),
            user: request.body.username
        }));
        reply.cookie(csrfCookie.name, csrfCookie.value, csrfCookie.options);
        request.csrfToken = 
            await this.sessionManager.createCsrfFormOrHeaderValue(csrfCookie.value);

        // delete the old session key if there was one
        if (oldSessionId) {
            try {
                await this.sessionManager.deleteSession(oldSessionId);
            } catch (e) {
                CrossauthLogger.logger.warn(j({
                    msg: "Couldn't delete session ID from database",
                    hashOfSessionId: this.getHashOfSessionId(request)
                }));
                CrossauthLogger.logger.debug(j({err: e}));
            }
        }

        return successFn(reply, user);
    }

    private async loginFactor2(request : FastifyRequest<{ Body: LoginFactor2BodyType }>, 
        reply : FastifyReply, 
        successFn : (res : FastifyReply, user: User) => void) {

        if (request.user) return successFn(reply, 
            request.user); // already logged in - nothing to do

        // save the old session ID so we can delete it after (the anonymous session)
        // If there isn't one it is an error - only allowed to this URL with a 
        // valid session
        const oldSessionId = request.sessionId;
        if (!oldSessionId) throw new CrossauthError(ErrorCode.Unauthorized);

        // get data from request body
        const persist = request.body.persist;

        // validate CSRF token - throw an exception if it is not valid
        //await this.validateCsrfToken(request);
        if (this.isSessionUser(request) && !request.csrfToken) throw new CrossauthError(ErrorCode.InvalidCsrf);

        let extraFields = this.addToSession ? this.addToSession(request) : {}
        const {sessionCookie, csrfCookie, user} = 
            await this.sessionManager.completeTwoFactorLogin(request.body, 
                oldSessionId, 
                extraFields, 
                persist);
        CrossauthLogger.logger.debug(j({
            msg: "Login: set session cookie " + sessionCookie.name + " opts " + JSON.stringify(sessionCookie.options),
            user: user?.username
        }));
        reply.cookie(sessionCookie.name,
            sessionCookie.value,
            sessionCookie.options);
        CrossauthLogger.logger.debug(j({
            msg: "Login: set csrf cookie " + csrfCookie.name + " opts " + JSON.stringify(sessionCookie.options),
            user: user?.username
        }));
        reply.cookie(csrfCookie.name, csrfCookie.value, csrfCookie.options);
        request.csrfToken = 
            await this.sessionManager.createCsrfFormOrHeaderValue(csrfCookie.value);
        return successFn(reply, user);
    }

    private async cancelFactor2(request : FastifyRequest<{ Body: CsrfBodyType }>, 
        reply : FastifyReply, 
        successFn : (res : FastifyReply) => void) {

        //this.validateCsrfToken(request);
        if (this.isSessionUser(request) && !request.csrfToken) throw new CrossauthError(ErrorCode.InvalidCsrf);
        const sessionCookieValue = this.getSessionCookieValue(request);
        if (sessionCookieValue) {
            this.sessionManager.cancelTwoFactorPageVisit(sessionCookieValue);
        }
        return successFn(reply);
    }

    /**
     * This is called after the user has been validated to log the user in
     */
    async loginWithUser(user: User, 
        bypass2FA : boolean, 
        request : FastifyRequest, 
        reply : FastifyReply, 
        successFn : (res : FastifyReply, user: User) => void) {

        // get old session ID so we can delete it after
        const oldSessionId = this.getSessionCookieValue(request);

        // call implementor-provided hook to add custom fields to session key
        let extraFields = this.addToSession ? this.addToSession(request) : {}

        // log user in - this doesn't do any authentication
        let { sessionCookie, csrfCookie } = 
            await this.sessionManager.login("", {}, extraFields, undefined, user, bypass2FA);

        // set the cookies
        CrossauthLogger.logger.debug(j({
            msg: "Login: set session cookie " + sessionCookie.name + " opts " + JSON.stringify(sessionCookie.options),
            user: user.username
        }));
        reply.cookie(sessionCookie.name,
            sessionCookie.value,
            sessionCookie.options);
        CrossauthLogger.logger.debug(j({
            msg: "Login: set csrf cookie " + csrfCookie.name + " opts " + JSON.stringify(sessionCookie.options),
            user: user.username
        }));
        reply.cookie(csrfCookie.name, csrfCookie.value, csrfCookie.options);

        // delete the old session
        if (oldSessionId) {
            try {
                await this.sessionManager.deleteSession(oldSessionId);
            } catch (e) {
                CrossauthLogger.logger.warn(j({
                    msg: "Couldn't delete session ID from database",
                    hashOfSessionId: this.getHashOfSessionId(request)
                }));
                CrossauthLogger.logger.debug(j({err: e}));
            }
        }

        return successFn(reply, user);
    }

    private async signup(request : FastifyRequest<{ Body: SignupBodyType }>, 
        reply : FastifyReply, 
        successFn : (res : FastifyReply, data: {[key:string]:any}, user? : User) 
        => void) {
            
        // throw an error if the CSRF token is invalid
        //await this.validateCsrfToken(request);
        if (this.isSessionUser(request) && !request.csrfToken) throw new CrossauthError(ErrorCode.InvalidCsrf);
        // get data from the request body
        // make sure the requested second factor is valid
        const username = request.body.username;
        const next = request.body.next;
        if (!request.body.factor2) {
            request.body.factor2 = this.allowedFactor2[0]; 
        }
        if (request.body.factor2 && 
            !(this.allowedFactor2.includes(request.body.factor2??"none"))) {
            throw new CrossauthError(ErrorCode.Forbidden, 
                "Illegal second factor " + request.body.factor2 + " requested");
        }
        if (request.body.factor2 == "none" || request.body.factor2 == "") {
            request.body.factor2 = undefined;
        }

        // call implementor-provided function to create the user object (or our default)
        let user = 
            this.createUserFn(request, this.userStorage.userEditableFields);

        // ask the authenticator to validate the user-provided secret
        let passwordErrors = 
            this.authenticators[user.factor1].validateSecrets(request.body);

        // get the repeat secrets (secret names prefixed with repeat_)
        const secretNames = this.authenticators[user.factor1].secretNames();
        let repeatSecrets : AuthenticationParameters|undefined = {};
        for (let field in request.body) {
            if (field.startsWith("repeat_")) {
                const name = field.replace(/^repeat_/, "");
                // @ts-ignore as it complains about request.body[field]
                if (secretNames.includes(name)) repeatSecrets[name] = 
                    request.body[field];
            }
        }
        if (Object.keys(repeatSecrets).length === 0) repeatSecrets = undefined;

        // set the user's state to active, awaitingtwofactor or 
        // awaitingemailverification
        // depending on settings for next step
        user.state = "active";
        if (request.body.factor2 && request.body.factor2!="none") {
           user. state = "awaitingtwofactor";
        } else if (this.enableEmailVerification) {
            user.state = "awaitingemailverification";
        }

        // call the implementor-provided hook to validate the user fields
        let userErrors = this.validateUserFn(user);

        // report any errors
        let errors = [...userErrors, ...passwordErrors];
        if (errors.length > 0) {
            throw new CrossauthError(ErrorCode.FormEntry, errors);
        }

        // See if the user was already created, with the correct password, and 
        // is awaiting 2FA
        // completion.  Send the same response as before, in case the user 
        // closed the browser
        let twoFactorInitiated = false;
        try {
            const {user: existingUser, secrets: existingSecrets} = 
            await this.userStorage.getUserByUsername(username);
            await this.sessionManager.authenticators[user.factor1]
                .authenticateUser(existingUser, existingSecrets, request.body);
        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);
            if (ce.code == ErrorCode.TwoFactorIncomplete) {
                twoFactorInitiated = true;
            } // all other errors are legitimate ones - we ignore them
        }

        // login (this may be just first stage of 2FA)
        if ((!request.body.factor2) && !twoFactorInitiated) {
            // not enabling 2FA
            await this.sessionManager.createUser(user,
                request.body,
                repeatSecrets);
                if (!this.enableEmailVerification) {
                return this.login(request, reply, (request, user) => {
                    return successFn(request, {}, user)});
            }
            return successFn(reply, {}, undefined);
        } else {
            // also enabling 2FA
            let userData : {[key:string] : any};
            if (twoFactorInitiated) {
                // account already created but 2FA setup not complete
                if (!request.sessionId) throw new CrossauthError(ErrorCode.Unauthorized);
                const resp = 
                    await this.sessionManager.repeatTwoFactorSignup(request.sessionId);
                userData = resp.userData;
            } else {
                // account not created - create one with state awaiting 2FA setup
                const sessionValue = 
                    await this.createAnonymousSession(request, reply);
                const sessionId = this.sessionManager.getSessionId(sessionValue);
                const resp = 
                    await this.sessionManager.initiateTwoFactorSignup(user,
                        request.body,
                        sessionId,
                        repeatSecrets);
                userData = resp.userData;
            }

            // pass caller back 2FA parameters
            try {
                let data: {
                    userData: { [key: string]: any },
                    username: string,
                    next: string,
                    csrfToken: string | undefined
                } = 
                {
                    userData: userData,
                    username: username,
                    next: next??this.loginRedirect,
                    csrfToken: request.csrfToken,
                };
                return successFn(reply, data)
            } catch (e) {
                // if there is an error, make sure we delete the user before returning
                CrossauthLogger.logger.error(j({err: e}));
                try {
                    this.sessionManager.deleteUserByUsername(username);
                } catch (e) {
                    CrossauthLogger.logger.error(j({err: e}));
                }

            }
        }
    }

    private async logout(request : FastifyRequest, reply : FastifyReply, 
        successFn : (reply : FastifyReply) => void) {

            // logout
        if (request.sessionId) {
                await this.sessionManager.logout(request.sessionId);
        }

        // clear cookies
        CrossauthLogger.logger.debug(j({msg: "Logout: clear cookie " 
            + this.sessionManager.sessionCookieName}));
        reply.clearCookie(this.sessionManager.sessionCookieName);
        reply.clearCookie(this.sessionManager.csrfCookieName);
        if (request.sessionId) {
            try {
                await this.sessionManager.deleteSession(request.sessionId);
            } catch (e) {
                CrossauthLogger.logger.warn(j({
                    msg: "Couldn't delete session ID from database",
                    hashOfSessionId: this.getHashOfSessionId(request)
                }));
                CrossauthLogger.logger.debug(j({err: e}));
            }
        }

        return successFn(reply);

    }

    async createAnonymousSession(request : FastifyRequest, 
        reply : FastifyReply, data? : {[key:string]:any}) : Promise<string> {
        CrossauthLogger.logger.debug(j({msg: "Creating session ID"}));

        // get custom fields from implentor-provided function
        let extraFields = this.addToSession ? this.addToSession(request) : {}
        if (data) extraFields.data = JSON.stringify(data);

        // create session, setting the session cookie, CSRF cookie and CSRF token 
        let { sessionCookie, csrfCookie, csrfFormOrHeaderValue } = 
            await this.sessionManager.createAnonymousSession(extraFields);
        reply.cookie(sessionCookie.name,
            sessionCookie.value,
            sessionCookie.options);
        request.csrfToken = csrfFormOrHeaderValue;
        reply.setCookie(csrfCookie.name, csrfCookie.value, csrfCookie.options);
        request.user = undefined;

        return sessionCookie.value;
    };

    // sanitise errors - user's should not be shown anything too revealing about it
    handleError(e : any, request: FastifyRequest, 
        reply : FastifyReply, 
        errorFn : (reply : FastifyReply, error : CrossauthError) => void, 
        passwordInvalidOk? : boolean) {
        try {
        let ce = CrossauthError.asCrossauthError(e);
        if (!passwordInvalidOk) {
            switch (ce.code) {
                case ErrorCode.UserNotExist:
                case ErrorCode.PasswordInvalid:
                    ce = new CrossauthError(ErrorCode.UsernameOrPasswordInvalid, 
                        "Invalid username or password");
                    break;
            }
        }
        CrossauthLogger.logger.debug(j({err: ce}));
            CrossauthLogger.logger.error(j({
                cerr: ce,
                hashOfSessionId: this.getHashOfSessionId(request),
                user: request.user?.username
            }));
        return errorFn(reply, ce);
    } catch (e) {
        CrossauthLogger.logger.error(j({err: e}));
        return errorFn(reply, new CrossauthError(ErrorCode.UnknownError));

    }

    }

    //////////////
    // Helpers

    getSessionCookieValue(request : FastifyRequest) : string|undefined{
        if (request.cookies && 
            this.sessionManager.sessionCookieName in request.cookies) {       
            return request.cookies[this.sessionManager.sessionCookieName]
        }
        return undefined;
    }

    getCsrfCookieValue(request : FastifyRequest) : string|undefined{
        if (request.cookies && 
            this.sessionManager.csrfCookieName in request.cookies) {       
            return request.cookies[this.sessionManager.csrfCookieName]
        }
        return undefined;
    }

    getHashOfSessionId(request : FastifyRequest) : string {
        if (!request.sessionId) return "";
        try {
            return Hasher.hash(request.sessionId);
        } catch (e) {}
        return "";
    }

    getHashOfCsrfCookie(request : FastifyRequest) : string {
        const cookieValue = this.getCsrfCookieValue(request);
        if (!cookieValue) return "";
        try {
            return Hasher.hash(cookieValue.split(".")[0]);
        } catch (e) {}
        return "";
    }

    validateCsrfToken(request : FastifyRequest<{ Body: CsrfBodyType }>) 
        : string|undefined {

        this.sessionManager.validateDoubleSubmitCsrfToken(this.getCsrfCookieValue(request), request.csrfToken);
        return this.getCsrfCookieValue(request);
    }

    csrfToken(request : FastifyRequest<{Body: CsrfBodyType}>, 
        reply : FastifyReply) {
        let token : string|undefined = undefined;

        // first try to get token from header
        if (request.headers && CSRFHEADER.toLowerCase() in request.headers) { 
            const header = request.headers[CSRFHEADER.toLowerCase()];
            if (Array.isArray(header)) token = header[0];
            else token = header;
        }

        // if not found, try to get token from body
        if (!token && request.body?.csrfToken) {
            token = request.body.csrfToken;
        }
        if (token) {
            try {
                this.sessionManager
                    .validateDoubleSubmitCsrfToken(this.getCsrfCookieValue(request), 
                        token);
                request.csrfToken = token;
                reply.header(CSRFHEADER, token);
            }
            catch (e) {
                CrossauthLogger.logger.warn(j({
                    msg: "Invalid CSRF token",
                    hashedCsrfCookie: this.getHashOfCsrfCookie(request)
                }));
                reply.clearCookie(this.sessionManager.csrfCookieName);
                request.csrfToken = undefined;
            }
        } else {
            request.csrfToken = undefined;
        }

        return token;
    }


    sendJsonError(reply: FastifyReply,
        status: number,
        error?: string,
        e?: any) {
        if (!error || !e) error = "Unknown error";
        const ce = CrossauthError.asCrossauthError(e);

        CrossauthLogger.logger.warn(j({
            msg: error,
            errorCode: ce.code,
            errorCodeName: ce.codeName,
            httpStatus: status
        }));
        return reply.header(...JSONHDR).status(status)
            .send({
                ok: false,
                status: status,
                errorMessage: error,
                errorCode: ce.code,
                errorCodeName: ce.codeName
            });
    }

    errorStatus(e : any) {
        if (typeof e == "object" && "httpStatus" in e) return e.httpStatus??500;
        return 500;
    }

    allowedFactor2Details() : AuthenticatorDetails[] {
        let ret : AuthenticatorDetails[] = [];
        this.allowedFactor2.forEach((authenticatorName) => {
            if (authenticatorName in this.authenticators) {
                const secrets = this.authenticators[authenticatorName].secretNames();
                ret.push({
                    name: authenticatorName, 
                    friendlyName: this.authenticators[authenticatorName].friendlyName,
                    hasSecrets: secrets && secrets.length > 0,
                });
            } else if (authenticatorName == "none") {
                ret.push({name: "none", friendlyName: "None", hasSecrets: false});

            }
        });
        return ret;
    }

    async updateSessionData(request : FastifyRequest, name : string, value : {[key:string]:any}) {
        if (!request.sessionId) throw new CrossauthError(ErrorCode.Unauthorized, "User is not logged in");
        await this.sessionManager.updateSessionData(request.sessionId, name, value);
    }

    async getSessionData(request : FastifyRequest, name : string) 
        : Promise<{[key:string]:any}|undefined>{
        try {
            const data = request.sessionId ? 
                await this.sessionManager.dataForSessionId(request.sessionId) : 
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

    async getSessionKey(request : FastifyRequest) : Promise<Key|undefined>{
        if (!request.sessionId) return undefined;
        try {
            const {key} = await this.sessionManager
                .userForSessionId(request.sessionId) 
            return key;
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
        }
        return undefined;
    }

    /** Returns whether there is a user logged in with a cookie-based session
     */
    isSessionUser(request: FastifyRequest) {
        return request.user != undefined && request.authType == "cookie";
    }

    /**
     * A user can edit his or her account if they are logged in with
     * session management, or are logged in with some other means and
     * e`ditUserScope` has been set and is included in the user's scopes.
     * @param request the Fastify request
     * @returns true or false
     */
    canEditUser(request : FastifyRequest) {
        return this.isSessionUser(request) || 
            (this.editUserScope && request.scope && 
                request.scope.includes(this.editUserScope));
    }
}
