import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { UserStorage, KeyStorage } from '../storage';
import { AuthenticationParameters, Authenticator } from '../auth';
import { Hasher } from '../hasher';
import { SessionManager, type SessionManagerOptions } from '../session';
import { CrossauthError, ErrorCode } from '@crossauth/common';
import { User, Key, UserInputFields } from '@crossauth/common';
import { CrossauthLogger, j } from '@crossauth/common';
import { setParameter, ParamType } from '../utils';
import { Server, IncomingMessage, ServerResponse } from 'http'
import { FastifyServer } from './fastifyserver';

const CSRFHEADER = "X-CROSSAUTH-CSRF";

const JSONHDR : [string,string] = ['Content-Type', 'application/json; charset=utf-8'];

/**
 * Options for {@link FastifyServer }.
 * 
 * See {@link FastifyServer } constructor for description of parameters
 */
export interface FastifySessionServerOptions extends SessionManagerOptions {

    /** All endpoint URLs will be prefixed with this.  Default `/` */
    prefix? : string,

    /** List of endpoints to add to the server ("login", "api/login", etc, prefixed by the `prefix` parameter.  Empty for all.  Default all. */
    endpoints? : string,

    /** Page to redirect to after successful login, default "/" */
    loginRedirect? : string;

    /** Page to redirect to after successful logout, default "/" */
    logoutRedirect? : string;

    /** Function that throws a {@link @crossauth/common!CrossauthError} with {@link @crossauth/common!ErrorCode} `FormEnty` if the user doesn't confirm to local rules.  Doesn't validate passwords  */
    validateUserFn? : (user: UserInputFields) => string[];

    /** Function that creates a user from form fields.
     * Default one takes fields that begin with `user_`, removing the `user_` prefix
     * and filtering out anything not in the userEditableFields list in the
     * user storage.
      */
    createUserFn? : (request : FastifyRequest<{ Body: SignupBodyType }>, userEditableFields : string[]) => UserInputFields;

    /** Function that updates a user from form fields.
     * Default one takes fields that begin with `user_`, removing the `user_` prefix
     * and filtering out anything not in the userEditableFields list in the
     * user storage.
      */
    updateUserFn? : (user : User, request : FastifyRequest<{ Body: UpdateUserBodyType }>, userEditableFields : string[]) => User;

    /** Called when a new session token is going to be saved 
     *  Add additional fields to your session storage here.  Return a map of keys to values  */
    addToSession? : (request : FastifyRequest) => {[key: string] : string|number|boolean|Date|undefined};

    /** Called after the session ID is validated.
     * Use this to add additional checks based on the request.  
     * Throw an exception if cecks fail
     */
    validateSession? : (session: Key, user: User|undefined, request : FastifyRequest) => void;

    /** Template file containing the login page (with without error messages).  
     * See the class documentation for {@link FastifyServer} for more info.  Defaults to "login.njk".
     */
    loginPage? : string;

    /** Template file containing the page for getting the 2nd factor for 2FA protected pages
     * See the class documentation for {@link FastifyServer} for more info.  Defaults to "factor2.njk".
     */
    factor2Page? : string;

    /** Template file containing the signup page (with without error messages).  
     * See the class documentation for {@link FastifyServer} for more info.  Defaults to "signup.njk".
     * Signup form should contain at least `username` and `password` and may also contain `repeatPassword`.  If you have additional
     * fields in your user table you want to pass from your form, prefix them with `user_`, eg `user_email`.
     * If you want to enable email verification, set `enableEmailVerification` and set `checkEmailVerified` 
     * on the user storage.
     */
    signupPage? : string;

    /** Page to set up 2FA after sign up */
    configureFactor2Page? : string;

    /** Page to render error messages, including failed login. 
     * See the class documentation for {@link FastifyServer} for more info.  Defaults to "error.njk".
     */
    errorPage? : string;

    /** Page to render for password changing.  
     * See the class documentation for {@link FastifyServer} for more info.  Defaults to "changepassword.njk".
     */
    changePasswordPage? : string,

    /** Page to render for selecting a different 2FA.  
     * See the class documentation for {@link FastifyServer} for more info.  Defaults to "changepassword.njk".
     */
    changeFactor2Page? : string,

    /** Page to render for updating user details.  
     * See the class documentation for {@link FastifyServer} for more info.  Defaults to "updateuser.njk".
     */
    updateUserPage? : string,

    /** Page to ask user for email and reset his/her password.  
     * See the class documentation for {@link FastifyServer} for more info.  Defaults to "requestpasswordreset.njk".
     */
    requestResetPasswordPage? : string,

    /** Page to render for password reset, after the emailed token has been validated.  
     * See the class documentation for {@link FastifyServer} for more info.  Defaults to "resetpassword.njk".
     */
    resetPasswordPage? : string,

    /**
     * Turns on email verification.  This will cause the verification tokens to be sent when the account
     * is activated and when email is changed.  Default false.
     */
    enableEmailVerification? : boolean,

    /** Page to render for to confirm email has been verified.  Only created if `enableEmailVerification` is true.
     * See the class documentation for {@link FastifyServer} for more info.  Defaults to "emailverified.njk"
     */
    emailVerifiedPage? : string,

    allowedFactor2? : string,

    factor2ProtectedPageEndpoints?: string,
    factor2ProtectedApiEndpoints?: string,
}

///////////////////////////////////////////////////////////////////////////////
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

//////////////////////////////////////////////////////////////////////////////////
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

interface SignupBodyType extends LoginBodyType {
    repeatPassword?: string,
    email? : string,
    factor2? : string,
    [key : string]: string|number|Date|boolean|undefined, // for extensible user object fields
}

interface ConfigureFactor2BodyType extends CsrfBodyType {
    next? : string,
    persist? : boolean,
    otp? : string,
    token? : string,
    [key:string] : any,
}

interface ChangePasswordBodyType extends CsrfBodyType {
    oldPassword: string,
    newPassword: string,
    repeatPassword?: string,
}

interface ChangeFactor2BodyType extends CsrfBodyType {
    factor2: string,
    next? : string,
}

interface UpdateUserBodyType extends CsrfBodyType {
    [key: string] : string|undefined,
}

interface ResetPasswordBodyType extends CsrfBodyType {
    token: string,
    newPassword: string,
    repeatPassword?: string,
}

interface RequestPasswordResetBodyType extends CsrfBodyType {
    email: string,
}

interface VerifyTokenParamType {
    token : string,
}

interface LoginQueryType {
    next? : string;
}

interface Factor2QueryType {
    error? : string;
}

interface AuthenticatorDetails {
    name: string,
    friendlyName : string,
    hasSecrets: boolean,
}

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

function defaultCreateUser(request : FastifyRequest<{ Body: SignupBodyType }>, userEditableFields : string[]) : UserInputFields {
    let state = "active";
    let user : UserInputFields = {
        username: request.body.username,
        state: state,
    }
    for (let field in request.body) {
        let name = field.replace(/^user_/, ""); 
        if (field.startsWith("user_") && userEditableFields.includes(name)) {
            user[name] = request.body[field];
        }
    }
    user.factor1 = "localpassword";
    user.factor2 = request.body.factor2;
    return user;

}

function defaultUpdateUser(user : User, request : FastifyRequest<{ Body: UpdateUserBodyType }>, userEditableFields : string[]) : User {
    for (let field in request.body) {
        let name = field.replace(/^user_/, ""); 
        if (field.startsWith("user_") && userEditableFields.includes(name)) {
            user[name] = request.body[field];
        }
    }
    return user;

}

/**
 * This class the session management for the fastify server
 * 
 * **Endpoints that can be activated provided**
 * 
 * All POST methods are passed user, csrfToken, errorCode, errorCodeName, error and errors.
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
 * If you have fields other than `id`, `username` and `password` in your user table, add them in 
 * `extraFields` when you create your {@link UserStorage} object.  In your signup and user update pages
 * (`signupPage`, `updateUserPage`), prefix these with `user_` in field names and they will be passed
 * into the user object when processing the form.  If there is an error processing the form, they will
 * be back as psot parameters, again prefixed with `user_`.
 * 
 *  **Using your own Fastify app**
 * 
 * If you are serving other endpoints, or you want to use something other than Nunjucks, you can create
 * and pass in your own Fastify app.
 */
export class FastifySessionServer {

    private app : FastifyInstance<Server, IncomingMessage, ServerResponse>;
    readonly prefix : string = "/";
    private endpoints : string[] = [];
    private loginRedirect = "/";
    private logoutRedirect : string = "/";
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
    private validateUserFn : (user : UserInputFields) => string[] = defaultUserValidator;
    private createUserFn : (request : FastifyRequest<{ Body: SignupBodyType }>, userEditableFields : string[]) => UserInputFields = defaultCreateUser;
    private updateUserFn : (user : User, request : FastifyRequest<{ Body: UpdateUserBodyType }>, userEditableFields : string[]) => User = defaultUpdateUser;
    private addToSession? : (request : FastifyRequest) => {[key: string] : string|number|boolean|Date|undefined};
    private validateSession? : (session: Key, user: User|undefined, request : FastifyRequest) => void;

    private userStorage : UserStorage;
    private sessionManager : SessionManager;
    private authenticators: {[key:string]: Authenticator}
    private allowedFactor2 : string[] = [];

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

    constructor(
        app: FastifyInstance<Server, IncomingMessage, ServerResponse>,
        userStorage: UserStorage, 
        keyStorage: KeyStorage, 
        authenticators: {[key:string]: Authenticator}, 
        options: FastifySessionServerOptions = {}) {

        this.app = app;

        setParameter("prefix", ParamType.String, this, options, "PREFIX");
        if (!(this.prefix.endsWith("/"))) this.prefix += "/";
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
        setParameter("factor2ProtectedPageEndpoints", ParamType.StringArray, this, options, "ENABLE_FACTOR2_PROTECTED_PAGE_ENDPOINTS");
        setParameter("factor2ProtectedApiEndpoints", ParamType.StringArray, this, options, "ENABLE_FACTOR2_PROTECTED_API_ENDPOINTS");


        if (options.validateUserFn) this.validateUserFn = options.validateUserFn;
        if (options.createUserFn) this.createUserFn = options.createUserFn;
        if (options.updateUserFn) this.updateUserFn = options.updateUserFn;
        if (options.addToSession) this.addToSession = options.addToSession;
        if (options.validateSession) this.validateSession = options.validateSession;

        this.endpoints = [...SignupPageEndpoints, ...SignupApiEndpoints];
        this.endpoints = [...this.endpoints, ...SessionPageEndpoints, ...SessionApiEndpoints];
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

        // session management: validate session and CSRF cookies and populate request.user
        app.addHook('preHandler', async (request : FastifyRequest<{Body: CsrfBodyType}>, reply : FastifyReply) => {

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
                    CrossauthLogger.logger.error(j({msg: "Couldn't create CSRF token", cerr: e, user: request.user?.username, hashedSessionCookie: this.getHashOfSessionCookie(request)}));
                    CrossauthLogger.logger.debug(j({err: e}));
                    reply.clearCookie(this.sessionManager.csrfCookieName);
                }
            } else {
                // for other methods, create a new token only if there is already a valid one
                if (cookieValue) {
                    try {
                        this.csrfToken(request, reply);
                    } catch (e) {
                        CrossauthLogger.logger.error(j({msg: "Couldn't create CSRF token", cerr: e, user: request.user?.username, hashedSessionCookie: this.getHashOfSessionCookie(request)}));
                        CrossauthLogger.logger.debug(j({err: e}));
                    }
                }
            }

            // we now either have a valid CSRF token, or none at all
    
            // validate any session cookie.  Remove if invalid
            request.user = undefined;
            const sessionCookieValue = this.getSessionCookieValue(request);
            CrossauthLogger.logger.debug(j({msg: "Getting session cookie"}));
            if (sessionCookieValue) {
                try {
                    let {key, user} = await this.sessionManager.userForSessionCookieValue(sessionCookieValue)
                    if (this.validateSession) this.validateSession(key, user, request);
    
                    request.user = user;
                    CrossauthLogger.logger.debug(j({msg: "Valid session id", user: user?.username}));
                } catch (e) {
                    CrossauthLogger.logger.warn(j({msg: "Invalid session cookie received", hashedSessionCookie: this.getHashOfSessionCookie(request)}));
                    reply.clearCookie(this.sessionManager.sessionCookieName);
                }
            }
        });

        // 2FA for endpoints that are protected by it (other than login)
        app.addHook('preHandler', async (request : FastifyRequest<{Body: ArbitraryBodyType}>, reply : FastifyReply) => {
            const sessionCookieValue = this.getSessionCookieValue(request);
            if (sessionCookieValue && request.user?.factor2 && (this.factor2ProtectedPageEndpoints.includes(request.url) || this.factor2ProtectedApiEndpoints.includes(request.url))) {
                if (!(["GET", "OPTIONS", "HEAD"].includes(request.method))) {
                    const sessionData = await this.sessionManager.dataForSessionKey(sessionCookieValue);
                    if (("pre2fa") in sessionData) {
                        // 2FA has started - validate it
                        CrossauthLogger.logger.debug("Completing 2FA");

                        // get secrets from the request body 
                        const authenticator = this.authenticators[sessionData.pre2fa.factor2];
                        const secretNames = authenticator.secretNames();
                        let secrets : {[key:string]:string} = {};
                        for (let field in request.body) {
                            if (secretNames.includes(field)) secrets[field] = request.body[field];
                        }

                        const sessionCookieValue = this.getSessionCookieValue(request);
                        if (!sessionCookieValue) throw new CrossauthError(ErrorCode.Unauthorized, "No session cookie found");
                        let error : CrossauthError|undefined = undefined;
                        try {
                            await this.sessionManager.completeTwoFactorPageVisit(request.body, sessionCookieValue);
                        } catch (e) {
                            if (e instanceof CrossauthError) {
                                error = e;
                            } else {
                                error = new CrossauthError(ErrorCode.UnknownError);
                            }
                            CrossauthLogger.logger.debug(j({err: e}));
                            CrossauthLogger.logger.error(j({msg: error.message, cerr: e, user: request.body.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                        }
                        // restore original request body
                        request.body = sessionData.pre2fa.body;
                        if (error) {
                            if (error.code == ErrorCode.Expired) {
                                // user will not be able to complete this process - delete 
                                CrossauthLogger.logger.debug("Error - cancelling 2FA");
                                // the 2FA data and start again
                                try {
                                    await this.sessionManager.cancelTwoFactorPageVisit(sessionCookieValue);
                                } catch (e) {
                                    CrossauthLogger.logger.error(j({msg: "Failed cancelling 2FA", cerr: e, user: request.user?.username, hashedSessionCookie: this.getHashOfSessionCookie(request)}));
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
                                    return reply.redirect("/factor2?error="+ErrorCode[error.code]);

                                } else {
                                    return reply.status(error.httpStatus).send(JSON.stringify({ok: false, errorMessage: error.message, errorMessages: error.messages, errorCode: error.code, errorCodeName: ErrorCode[error.code]}));
                                }
                            }
                        }
                    } else {
                        // 2FA has not started - start it
                        this.validateCsrfToken(request);
                        CrossauthLogger.logger.debug("Starting 2FA");
                        this.sessionManager.initiateTwoFactorPageVisit(request.user, sessionCookieValue, request.body, request.url.replace(/\?.*$/,""));
                        if (this.factor2ProtectedPageEndpoints.includes(request.url)) {
                            return reply.redirect("/factor2");
                        } else {
                            return reply.send(JSON.stringify({ok: true, factor2Required: true}));
                        }
                    }
                } else {
                    // if we have a get request to one of the protected urls, cancel any pending 2FA
                    const sessionCookieValue = this.getSessionCookieValue(request);
                    if (sessionCookieValue) {
                        const sessionData = await this.sessionManager.dataForSessionKey(sessionCookieValue);
                        if (("pre2fa") in sessionData) {
                            CrossauthLogger.logger.debug("Cancelling 2FA");
                            try {
                                await this.sessionManager.cancelTwoFactorPageVisit(sessionCookieValue);
                            } catch (e) {
                                CrossauthLogger.logger.debug(j({err:e}));
                                CrossauthLogger.logger.error(j({msg: "Failed cancelling 2FA", cerr: e, user: request.user?.username, hashedSessionCookie: this.getHashOfSessionCookie(request)}));
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
            this.addConfigureFactor2Endpoints();
        }

        if (this.endpoints.includes("changefactor2")) {
            this.addChangeFactor2Endpoints();
        }

        if (this.endpoints.includes("changepassword")) {
            this.addChangePasswordEndpoints();
        }

        if (this.endpoints.includes("updateuser")) {
            this.addUpdateUserEndpoints();
        }

        if (this.endpoints.includes("requestpasswordreset")) {
            this.addRequestPasswordResetENdpoints();
        }

        if (this.endpoints.includes("resetpassword")) {
            if (!this.enablePasswordReset) throw new CrossauthError(ErrorCode.Configuration, "Password reset must be enabled for /resetpassword");
            this.addResetPasswordEndpoints();
        }

        if (this.endpoints.includes("verifyemail")) {
            if (!this.enableEmailVerification) throw new CrossauthError(ErrorCode.Configuration, "Email verification  must be enabled for /verifyemail");
            this.addVerifyEmailEndpoints();
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
            this.addApiConfigureFactor2Endpoints();
        }

        if (this.endpoints.includes("api/changepassword")) {
            this.addApiChangePasswordEndpoints();
        }

        if (this.endpoints.includes("api/changefactor2")) {
            this.addApiChangeFactor2Endpoints();
        }

        if (this.endpoints.includes("api/updateuser")) {
            this.addApiUpdateUserEndpoints();
        }

        if (this.endpoints.includes("api/resetpassword")) {
            if (!this.enablePasswordReset) throw new CrossauthError(ErrorCode.Configuration, "Password reset must be enabled for /api/resetpassword");
            this.addApiResetPasswordEndpoints();
        }

        if (this.endpoints.includes("api/requestpasswordreset")) {
            if (!this.enablePasswordReset) throw new CrossauthError(ErrorCode.Configuration, "Password reset must be enabled for /api/requestpasswordreset");
            this.addApiRequestPasswordResetEndpoints();
        }

        if (this.endpoints.includes("api/verifyemail")) {
            if (!this.enableEmailVerification) throw new CrossauthError(ErrorCode.Configuration, "Email verification must be enabled for /api/verifyemail");
            this.addApiVerifyEmailEndpoints();
        }

        if (this.endpoints.includes("api/userforsessionkey")) {
            this.addApiUserForSessionKeyEndpoints();
        }

        if (this.endpoints.includes("api/getcsrftoken")) {
            this.addApiGetCsrfTokenEndpoints();
    
        }

    }

    private addLoginEndpoints() {

        this.app.get(this.prefix+'login', async (request : FastifyRequest<{Querystring : LoginQueryType}>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'GET', url: this.prefix+'login', ip: request.ip}));
            if (request.user) return reply.redirect(request.query.next||this.loginRedirect); // already logged in

            let data : {urlprefix: string, next? : any, csrfToken: string|undefined} = {urlprefix: this.prefix, csrfToken: request.csrfToken};
            if (request.query.next) {
                data["next"] = request.query.next;
            }
            return reply.view(this.loginPage, data);
        });

        this.app.post(this.prefix+'login', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'login', ip: request.ip}));
            let next = request.body.next || this.loginRedirect;
            try {
                return await this.login(request, reply, 
                (reply, user) => {
                    if (!user.factor2 || user.factor2.length == 0) {
                        CrossauthLogger.logger.debug(j({msg: "Successful login - sending redirect"}));
                        return reply.redirect(next);
                    } else {
                        let data = {
                            csrfToken: request.csrfToken,
                            next: request.body.next||this.loginRedirect,
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
        this.app.post(this.prefix+'loginfactor2', async (request : FastifyRequest<{ Body: LoginFactor2BodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'loginfactor2', ip: request.ip}));
            let next = request.body.next || this.loginRedirect;
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
                    const sessionKey = this.getSessionCookieValue(request);
                    const data = sessionKey ? await this.sessionManager.dataForSessionKey(sessionKey) : undefined;
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

        this.app.get(this.prefix+'factor2', async (request : FastifyRequest<{Querystring : Factor2QueryType}>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'GET', url: this.prefix+'factor2', ip: request.ip}));
            const sessionCookie = this.getSessionCookieValue(request);
            if (!sessionCookie) throw new CrossauthError(ErrorCode.Unauthorized, "No session cookie present");
            const sessionData = await this.sessionManager.dataForSessionKey(sessionCookie);
            if (!sessionData?.pre2fa) throw new CrossauthError(ErrorCode.Unauthorized, "2FA not initiated");
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
        this.app.get(this.prefix+'signup', async (request : FastifyRequest<{Querystring : LoginQueryType}>, reply : FastifyReply)  => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'GET', url: this.prefix+'signup', ip: request.ip}));
            let data : {urlprefix: string, next? : any, csrfToken: string|undefined, allowedFactor2: AuthenticatorDetails[]} = {urlprefix: this.prefix, csrfToken: request.csrfToken, allowedFactor2: this.allowedFactor2Details()};
            if (request.query.next) {
                data["next"] = request.query.next;
            }
            return reply.view(this.signupPage, data);
        });

        this.app.post(this.prefix+'signup', async (request : FastifyRequest<{ Body: SignupBodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'signup', ip: request.ip, user: request.body.username}));
            let next = request.body.next || this.loginRedirect;
            try {
                CrossauthLogger.logger.debug(j({msg: "Next page " + next}));

                return await this.signup(request, reply, 
                (reply, data, _user) => {
                    const authenticator = data?.userData?.factor2 ? this.authenticators[data.userData.factor2] : undefined;
                    if (data.userData?.factor2) {
                        return reply.view(this.configureFactor2Page, {csrfToken: data.csrfToken, ...data.userData});
                    } else if (this.enableEmailVerification && (authenticator == undefined || authenticator.skipEmailVerificationOnSignup() != true)) {
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
                CrossauthLogger.logger.error(j({msg: "Signup failure", user: request.body.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
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
    
    private addConfigureFactor2Endpoints() {

        this.app.get(this.prefix+'configurefactor2', async (request : FastifyRequest<{Querystring : LoginQueryType}>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'GET', url: this.prefix+'configurefactor2', ip: request.ip}));
            try {
                return await this.reconfigureFactor2(request, reply, 
                (reply, data, _user) => {
                    return reply.view(this.configureFactor2Page, {...data, next: request.query.next||this.loginRedirect});
                });
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: "Configure factor2 failure", user: request.user?.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, request, reply, (reply, error) => {
                    return reply.view(this.configureFactor2Page, {
                        errorMessage: error.message,
                        errorMessages: error.messages, 
                        errorCode: error.code, 
                        errorCodeName: ErrorCode[error.code], 
                        next: request.query.next||this.loginRedirect, 
                        csrfToken: request.csrfToken,
                        urlprefix: this.prefix, 
                    });
                    
                });
            }
        });

        this.app.post(this.prefix+'configurefactor2', async (request : FastifyRequest<{ Body: ConfigureFactor2BodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'configurefactor2', ip: request.ip}));
            let next = request.body.next || this.loginRedirect;
            try {
                CrossauthLogger.logger.debug(j({msg: "Next page " + next}));

                return await this.configureFactor2(request, reply, 
                (reply, user) => {

                    // success

                    const authenticator = user?.factor2 ? this.authenticators[user.factor2] : undefined;
                    if (!request.user && this.enableEmailVerification && (authenticator == undefined || authenticator.skipEmailVerificationOnSignup() != true)) {
                        // email verification has been sent - tell user
                        return reply.view(this.signupPage, {
                            next: next, 
                            csrfToken: request.csrfToken,
                            urlprefix: this.prefix, 
                            message: "Please check your email to finish signing up."
                        });
                    } else {
                        if (!request.user) {
                            // we came here as part of login in - take user to orignally requested page
                            return reply.redirect(request.body.next||this.loginRedirect);
                        } else {
                            // we came here because the user asked to change 2FA - tell them it was successful
                            return reply.view(this.configureFactor2Page, {
                                message: "Two-factor authentication updated",
                                urlprefix: this.prefix, 
                                next: next, 
                                csrfToken: request.csrfToken,
                            });
                        }
                    }
                });
            } catch (e) {

                // error

                CrossauthLogger.logger.debug(j({err: e}));
                try {
                    const sessionValue = this.getSessionCookieValue(request);
                    if (!sessionValue) {
                        // this shouldn't happen - user's cannot call this URL without having a session,
                        // user or anonymous.  However, just in case...
                        CrossauthLogger.logger.error(j({msg: "Signup second factor failure", errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                        CrossauthLogger.logger.error(j({msg: "Session not defined during two factor process"}));
                        return reply.status(500).view(this.errorPage, {status: 500, errorMessage: "An unknown error occurred", errorCode: ErrorCode.UnknownError, errorCodeName: "UnknownError"});
                    }

                    // normal error - wrong code, etc.  show the page again
                    let data = (await this.sessionManager.dataForSessionKey(sessionValue))["2fa"];
                    CrossauthLogger.logger.error(j({msg: "Signup two factor failure", user: data?.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                    const { userData } = await this.sessionManager.repeatTwoFactorSignup(sessionValue);
                    return this.handleError(e, request, reply, (reply, error) => {
                            return reply.view(this.configureFactor2Page, {
                            errorMessage: error.message,
                            errorMessages: error.messages, 
                            errorCode: error.code, 
                            errorCodeName: ErrorCode[error.code], 
                            urlprefix: this.prefix, 
                            next: next, 
                            ...userData,
                            csrfToken: this.csrfToken(request, reply),
                        });
                        
                    });
                } catch (e2) {

                    // this is reached if there is an error processing the error
                    CrossauthLogger.logger.error(j({err: e2}));
                    return reply.status(500).view(this.errorPage, {status: 500, errorMessage: "An unknown error occurred", errorCode: ErrorCode.UnknownError, errorCodeName: "UnknownError"});

                }
            }
        });
    }

    private addChangePasswordEndpoints() {
        this.app.get(this.prefix+'changepassword', async (request : FastifyRequest<{Querystring : LoginQueryType}>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'GET', url: this.prefix+'changepassword', ip: request.ip, user: request.user?.username}));
            if (!request.user) return FastifyServer.sendPageError(reply, 401, this.errorPage);
            if (this.changePasswordPage)  { // if is redundant but VC Code complains without it
                let data : {urlprefix: string, csrfToken: string|undefined} = {urlprefix: this.prefix, csrfToken: request.csrfToken};
                return reply.view(this.changePasswordPage, data);
            }
        });

        this.app.post(this.prefix+'changepassword', async (request : FastifyRequest<{ Body: ChangePasswordBodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'changepassword', ip: request.ip, user: request.user?.username}));
            if (!request.user) return FastifyServer.sendPageError(reply, 401, this.errorPage);  // not allowed here if not logged in
            try {
                return await this.changePassword(request, reply, 
                (reply, _user) => {
                    return reply.view(this.changePasswordPage, {
                        csrfToken: request.csrfToken,
                        message: "Your password has been changed.",
                        urlprefix: this.prefix, 
                    });
                });
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: "Change password failure", user: request.user.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, request, reply, (reply, error) => {
                    return reply.view(this.changePasswordPage, {
                        errorMessage: error.message,
                        errorMessages: error.messages, 
                        errorCode: error.code, 
                        errorCodeName: ErrorCode[error.code], 
                        csrfToken: request.csrfToken,
                        urlprefix: this.prefix, 
                    });
                });
            }
        });
    }

    private addChangeFactor2Endpoints() {
        this.app.get(this.prefix+'changefactor2', async (request : FastifyRequest<{Querystring : LoginQueryType}>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'GET', url: this.prefix+'changefactor2', ip: request.ip, user: request.user?.username}));
            if (!request.user) return FastifyServer.sendPageError(reply, 401, this.errorPage);
            if (this.changeFactor2Page)  { // if is redundant but VC Code complains without it
                let data = {
                    urlprefix: this.prefix, 
                    csrfToken: request.csrfToken,
                    next: request.query.next||this.loginRedirect,
                    allowedFactor2: this.allowedFactor2Details(),
                    factor2 : request.user.factor2||"none",
                };
                return reply.view(this.changeFactor2Page, data);
            }
        });

        this.app.post(this.prefix+'changefactor2', async (request : FastifyRequest<{ Body: ChangeFactor2BodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'changefactor2', ip: request.ip, user: request.user?.username}));
            if (!request.user) return FastifyServer.sendPageError(reply, 401, this.errorPage);
            try {
                return await this.changeFactor2(request, reply, 
                    (reply, data, _user) => {
                        if (data.factor2) {
                            return reply.view(this.configureFactor2Page, {csrfToken: data.csrfToken, next: request.body.next||this.loginRedirect, ...data.userData});
                        } else {
                            return reply.view(this.configureFactor2Page, {message: "Two factor authentication has been updated", next: request.body.next||this.loginRedirect, csrfToken: data.csrfToken});
                        }
                    });
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: "Change two factor authentication failure", user: request.user.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, request, reply, (reply, error) => {
                    return reply.view(this.changeFactor2Page, {
                        errorMessage: error.message,
                        errorMessages: error.messages, 
                        errorCode: error.code, 
                        errorCodeName: ErrorCode[error.code], 
                        csrfToken: request.csrfToken,
                        urlprefix: this.prefix, 
                        allowedFactor2: this.allowedFactor2Details(),
                        factor2: request.user?.factor2||"none",
                        next: request.body.next||this.loginRedirect,
                    });
                });
            }
        });
    }

    private addUpdateUserEndpoints() {
        this.app.get(this.prefix+'updateuser', async (request : FastifyRequest<{Querystring : LoginQueryType}>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'GET', url: this.prefix+'updateuser', ip: request.ip, user: request.user?.username}));
            if (!request.user) return FastifyServer.sendPageError(reply, 401, this.errorPage);
            if (this.updateUserPage)  { // if is redundant but VC Code complains without it
                let data : {urlprefix: string, csrfToken: string|undefined, user: User, allowedFactor2: {[key:string]: any}} = {
                    urlprefix: this.prefix, 
                    csrfToken: request.csrfToken, 
                    user: request.user,
                    allowedFactor2: this.allowedFactor2Details(),
                };
                return reply.view(this.updateUserPage, data);
            }
        });

        this.app.post(this.prefix+'updateuser', async (request : FastifyRequest<{ Body: UpdateUserBodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'updateuser', ip: request.ip, user: request.user?.username}));
            if (!request.user) return FastifyServer.sendPageError(reply, 401, this.errorPage);
            try {
                return await this.updateUser(request, reply, 
                (reply, _user, emailVerificationRequired) => {
                    const message = emailVerificationRequired 
                        ? "Please click on the link in your email to verify your email address."
                        : "Your details have been updated";
                    return reply.view(this.updateUserPage, {
                        csrfToken: request.csrfToken,
                        message: message,
                        urlprefix: this.prefix, 
                        allowedFactor2: this.allowedFactor2Details(),
                    });
                });
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: "Update user failure", user: request.body.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                let extraFields : { [key : string] : any }= {};
                for (let field in request.body) {
                    if (field.startsWith("user_")) extraFields[field] = request.body[field];
                }
                return this.handleError(e, request, reply, (reply, error) => {
                    return reply.view(this.updateUserPage, {
                        errorMessage: error.message,
                        errorMessages: error.messages, 
                        errorCode: error.code, 
                        errorCodeName: ErrorCode[error.code], 
                        csrfToken: request.csrfToken,
                        urlprefix: this.prefix, 
                        allowedFactor2: this.allowedFactor2Details(),
                    });
                });
            }
        });
    }

    private addRequestPasswordResetENdpoints() {
        this.app.get(this.prefix+'requestpasswordreset', async (request : FastifyRequest, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'GET', url: this.prefix+'requestpasswordreset', ip: request.ip}));
            if (this.requestPasswordResetPage)  { // if is redundant but VC Code complains without it
                let data : {csrfToken: string|undefined} = {csrfToken: request.csrfToken};
                return reply.view(this.requestPasswordResetPage, data);
            }
        });

        this.app.post(this.prefix+'requestpasswordreset', async (request : FastifyRequest<{ Body: RequestPasswordResetBodyType }>, reply : FastifyReply) => {
            const message = "If a user with exists with the email you entered, a message with "
                + " a link to reset your password has been sent."; 
                CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'requestpasswordreset', ip: request.ip}));
                try {
                    return await this.requestPasswordReset(request, reply, 
                    (reply, _user) => {
                        return reply.view(this.requestPasswordResetPage, {
                            csrfToken: request.csrfToken,
                            message: message,
                            urlprefix: this.prefix, 
                        });
                    });
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: "Request password reset faiulure user failure", email: request.body.email}));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, request, reply, (reply, error) => {
                    if (error.code == ErrorCode.EmailNotExist) {
                        return reply.view(this.requestPasswordResetPage, {
                            csrfToken: request.csrfToken,                                
                            message: message,
                            urlprefix: this.prefix, 
                        });
                    }
                    return reply.view(this.requestPasswordResetPage, {
                        errorMessage: error.message,
                        errorMessages: error.messages, 
                        errorCode: error.code, 
                        errorCodeName: ErrorCode[error.code], 
                        email: request.body.email,
                        csrfToken: request.csrfToken,
                        urlprefix: this.prefix, 
                    });
                });
            }
        });
    }

    private addResetPasswordEndpoints() {
        this.app.get(this.prefix+'resetpassword/:token', async (request : FastifyRequest<{Params : VerifyTokenParamType}>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'GET', url: this.prefix+'logresetpasswordin', ip: request.ip}));
            try {
                await this.sessionManager.userForPasswordResetToken(request.params.token);
            } catch (e) {
                let code = ErrorCode.UnknownError;
                let error = "Unknown error";
                if (e instanceof CrossauthError) {
                    code = e.code;
                    error = e.message;
                }
                return reply.view(this.errorPage, {errorMessage: error, errorCode: code, errorCodeName: ErrorCode[code]});
            }
            return reply.view(this.resetPasswordPage, {token: request.params.token, csrfToken: request.csrfToken});
        });

        this.app.post(this.prefix+'resetpassword', async (request : FastifyRequest<{ Body: ResetPasswordBodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'resetpassword', ip: request.ip}));
            try {
                return await this.resetPassword(request, reply, 
                (reply, _user) => {
                    return reply.view(this.resetPasswordPage, {
                        csrfToken: request.csrfToken,
                        message: "Your password has been changed.",
                        urlprefix: this.prefix, 
                    });
                });
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: "Reset password failure", hashedToken: Hasher.hash(request.body.token), errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, request, reply, (reply, error) => {
                    return reply.view(this.resetPasswordPage, {
                        errorMessage: error.message,
                        errorMessages: error.messages, 
                        errorCode: error.code, 
                        errorCodeName: ErrorCode[error.code], 
                        csrfToken: request.csrfToken,
                        urlprefix: this.prefix, 
                    });
                });
            }
        });
    }

    private addVerifyEmailEndpoints() {
        this.app.get(this.prefix+'verifyemail/:token', async (request : FastifyRequest<{Params: VerifyTokenParamType}>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'verifyemail', ip: request.ip}));
            try {
                return await this.verifyEmail(request, reply, 
                (reply, user) => {
                    if (!this.emailVerifiedPage)  {
                        CrossauthLogger.logger.error("verify email requested but emailVerifiedPage not defined");
                        throw new CrossauthError(ErrorCode.Configuration, "There is a configuration error - please contact us if it persists");
                    }
                    return reply.view(this.emailVerifiedPage, {urlprefix: this.prefix, user: user});
                });
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: "Verify email failed", hashedToken: Hasher.hash(request.params.token), errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, request, reply, (reply, error) => {
                    return reply.view(this.errorPage, {
                        errorCode: error.code, 
                        errorCodeName: ErrorCode[error.code], 
                        errorMessage: error.message,
                        errorMessages: error.messages,
                        urlprefix: this.prefix, 
                    });
                });
            }
        });
    }

    private addLogoutEndpoints() {
        this.app.post(this.prefix+'logout', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'logout', ip: request.ip, user: request.user?.username}));
            try {
                return await this.logout(request, reply, 
                (reply) => {return reply.redirect(request.body.next? request.body.next : this.logoutRedirect)});
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: "Logout failure", user: request.user?.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, request, reply, (reply, error) => {
                    return reply.view(this.errorPage, {urlprefix: this.prefix, errorMessage: error.message, errorMessages: error.messages, errorCode: error.code, errorCodeName: ErrorCode[error.code]});
                    
                });
            }
        });
    }

    ////////////////////
    // API endpoints

    private addApiLoginEndpoints() {

        this.app.post(this.prefix+'api/login', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/login', ip: request.ip}));
            if (request.user) return reply.header(...JSONHDR).send({ok: false, user : request.user}); // already logged in
            try {
                return await this.login(request, reply, 
                (reply, user) => {
                    if (user.twoFactorRequired) {
                        return reply.header(...JSONHDR).send({ok: true, twoFactorRequired: true});
                    } else {
                        return reply.header(...JSONHDR).send({ok: true, user : user});
                    }
                });
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: "Login failure", user: request.body.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, request, reply, (reply, error) => {
                    reply.status(this.errorStatus(e)).header(...JSONHDR).send({ok: false, errorMessage: error.message, errorMessages: error.messages, errorCode: error.code, errorCodeName: ErrorCode[error.code]});                    
                });
            }
        });
    }

    private addApiCancelFactor2Endpoints() {

        this.app.post(this.prefix+'api/cancelfactor2', async (request : FastifyRequest<{ Body: CsrfBodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/cancelfactor2', ip: request.ip}));
            if (request.user) return reply.header(...JSONHDR).send({ok: false, user : request.user}); // already logged in
            try {
                return await this.cancelFactor2(request, reply, 
                (reply) => {
                        return reply.header(...JSONHDR).send({ok: true});
                });
            } catch (e) {
                const user : User|undefined = request.user;
                const username = user || "";
                CrossauthLogger.logger.error(j({msg: "Login failure", user: username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, request, reply, (reply, error) => {
                    reply.status(this.errorStatus(e)).header(...JSONHDR).send({ok: false, errorMessage: error.message, errorMessages: error.messages, errorCode: error.code, errorCodeName: ErrorCode[error.code]});                    
                });
            }
        });
    }

    private addApiLoginFactor2Endpoints() {
        this.app.post(this.prefix+'api/loginfactor2', async (request : FastifyRequest<{ Body: LoginFactor2BodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/loginfactor2', ip: request.ip}));
            if (request.user) return reply.header(...JSONHDR).send({ok: false, user : request.user}); // already logged in
            try {
                return await this.loginFactor2(request, reply, 
                (reply, user) => {
                    return reply.header(...JSONHDR).send({ok: true, user : user});
                });
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: "Login failure", hashOfSessionCookie: this.getHashOfSessionCookie(request), errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e,request,  reply, (reply, error) => {
                    return reply.status(this.errorStatus(e)).header(...JSONHDR).send({ok: false, errorMessage: error.message, errorMessages: error.messages, errorCode: error.code, errorCodeName: ErrorCode[error.code]});                    
                });
            }
        });
    }

    private addApiLogoutEndpoints() {
        this.app.post(this.prefix+'api/logout', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/logout', ip: request.ip, user: request.user?.username}));
            if (!request.user) return this.sendJsonError(reply, 401, "You are not authorized to access this url");

            try {
                return await this.logout(request, reply, 
                (reply) => {return reply.header(...JSONHDR).send({ok: true})});
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: "Logout failure", user: request.user?.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, request, reply, (reply, error) => {
                    reply.status(this.errorStatus(e)).header(...JSONHDR).send({ok: false, errorMessage: error.message, errorMessages: error.messages, errorCode: ErrorCode[error.code]});                    
                });
            }
        });
    }

    private addApiSignupEndpoints() {
        this.app.post(this.prefix+'api/signup', async (request : FastifyRequest<{ Body: SignupBodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/signup', ip: request.ip, user: request.body.username}));
            try {
                return await this.signup(request, reply, 
                (reply, data, user) => {
                    return reply.header(...JSONHDR).send({
                    ok: true,
                    user : user,
                    emailVerificationNeeded: this.enableEmailVerification||false,
                    ...data.userData,
                })});
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: "Signup failure", user: request.user?.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                this.handleError(e, request, reply, (reply, error) => {
                    reply.status(this.errorStatus(e)).header(...JSONHDR).send({ok: false, errorMessage: error.message, errorMessages: error.messages, errorCode: ErrorCode[error.code]});                    
                });
            }
        });
    }

    private addApiConfigureFactor2Endpoints() {
        this.app.get(this.prefix+'api/configurefactor2', async (request : FastifyRequest, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "API visit", method: 'GET', url: this.prefix+'api/configurefactor2', ip: request.ip, hashOfSessionCookie: this.getHashOfSessionCookie(request)}));
            try {
                return await this.reconfigureFactor2(request, reply, 
                (reply, data, _user) => {
                    return reply.header(...JSONHDR).send({
                    ok: true,
                    ...data,
                })});
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: "Configure 2FA configuration failure", user: request.user?.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                this.handleError(e, request, reply, (reply, error) => {
                    reply.status(this.errorStatus(e)).header(...JSONHDR).send({ok: false, errorMessage: error.message, errorMessages: error.messages, errorCode: ErrorCode[error.code]});                    
                });
            }
        });

        this.app.post(this.prefix+'api/configurefactor2', async (request : FastifyRequest<{ Body: ConfigureFactor2BodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/configurefactor2', ip: request.ip, hashOfSessionCookie: this.getHashOfSessionCookie(request)}));
            try {
                return await this.configureFactor2(request, reply, 
                (reply, user) => {
                    const resp : {[key:string]: any} = {
                        ok: true,
                        user : user,    
                    };
                    if (!request.user) {
                        resp.emailVerificationNeeded = this.enableEmailVerification;
                    }
                    return reply.header(...JSONHDR).send(resp);
                });
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: "Configure 2FA configuration failure", user: request.user?.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                this.handleError(e, request, reply, (reply, error) => {
                    reply.status(this.errorStatus(e)).header(...JSONHDR).send({ok: false, errorMessage: error.message, errorMessages: error.messages, errorCode: ErrorCode[error.code]});                    
                });
            }
        });
    }

    private addApiChangePasswordEndpoints() {
        this.app.post(this.prefix+'api/changepassword', async (request : FastifyRequest<{ Body: ChangePasswordBodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/changepassword', ip: request.ip, user: request.user?.username}));
            if (!request.user) return this.sendJsonError(reply, 401);
            try {
                return await this.changePassword(request, reply, 
                (reply, _user) => {return reply.header(...JSONHDR).send({
                    ok: true,
                })});
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: "Change password failure", user: request.user?.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, request, reply, (reply, error) => {
                    return reply.status(this.errorStatus(e)).header(...JSONHDR).send({ok: false, errorMessage: error.message, errorMessages: error.messages, errorCode: error.code, errorCodeName: ErrorCode[error.code]});                    
                }, true);
            }
        });
    }

    private addApiChangeFactor2Endpoints() {
        this.app.post(this.prefix+'api/changefactor2', async (request : FastifyRequest<{ Body: ChangeFactor2BodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/changefactor2', ip: request.ip, user: request.user?.username}));
            if (!request.user) return this.sendJsonError(reply, 401);
            try {
                return await this.changeFactor2(request, reply, 
                    (reply, data, _user) => {
                        return reply.header(...JSONHDR).send({
                        ok: true,
                        ...data.userData,
                    })});
                } catch (e) {
                CrossauthLogger.logger.error(j({msg: "Change factor2 failure", user: request.user?.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, request, reply, (reply, error) => {
                    return reply.status(this.errorStatus(e)).header(...JSONHDR).send({ok: false, errorMessage: error.message, errorMessages: error.messages, errorCode: error.code, errorCodeName: ErrorCode[error.code]});                    
                }, true);
            }
        });
    }

    private addApiUpdateUserEndpoints() {
        this.app.post(this.prefix+'api/updateuser', async (request : FastifyRequest<{ Body: UpdateUserBodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/updateuser', ip: request.ip, user: request.user?.username}));
            if (!request.user) return this.sendJsonError(reply, 401);
            try {
                return await this.updateUser(request, reply, 
                (reply, _user, emailVerificationRequired) => {return reply.header(...JSONHDR).send({
                    ok: true,
                    emailVerificationRequired: emailVerificationRequired,
                })});
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: "Update user failure", user: request.user?.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, request, reply, (reply, error) => {
                    reply.status(this.errorStatus(e)).header(...JSONHDR).send({ok:false, errorMessage: error.message, errorMessages: error.messages, errorCode: error.code, errorCodeName: ErrorCode[error.code]});                    
                }, true);
            }
        });
    }

    private addApiResetPasswordEndpoints() {
        this.app.post(this.prefix+'api/resetpassword', async (request : FastifyRequest<{ Body: ResetPasswordBodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/resetpassword', ip: request.ip}));
            try {
                return await this.resetPassword(request, reply, 
                (reply, _user) => {return reply.header(...JSONHDR).send({
                    ok: true,
                })});
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: "Reset password failure", hashedToken: Hasher.hash(request.body.token), errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, request, reply, (reply, error) => {
                    reply.status(this.errorStatus(e)).header(...JSONHDR).send({ok: false, errorMessage: error.message, errorMessages: error.messages, errorCode: error.code, errorCodeName: ErrorCode[error.code]});                    
                }, true);
            }
        });
    }

    private addApiRequestPasswordResetEndpoints() {
        this.app.post(this.prefix+'api/requestpasswordreset', async (request : FastifyRequest<{ Body: RequestPasswordResetBodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/resetpasswordrequest', ip: request.ip}));
            try {
                return await this.requestPasswordReset(request, reply, 
                (reply, _user) => {return reply.header(...JSONHDR).send({
                    ok: true,
                })});
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: "Reset password failure failure", email: request.body.email, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, request, reply, (reply, error) => {
                    reply.status(this.errorStatus(e)).header(...JSONHDR).send({ok: false, errorMessage: error.message, errorMessages: error.messages, errorCode: error.code, errorCodeName: ErrorCode[error.code]});                    
                }, true);
            }
        });
    }

    private addApiVerifyEmailEndpoints() {
        this.app.get(this.prefix+'api/verifyemail/:token', async (request : FastifyRequest<{Params: VerifyTokenParamType}>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/verifyemail', ip: request.ip}));
            try {
                return await this.verifyEmail(request, reply, 
                (reply, user) => {return reply.header(...JSONHDR).send({
                    ok: true, 
                    user : user,
                })});
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: "Verify email failure", hashedToken: Hasher.hash(request.params.token), errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, request, reply, (reply, error) => {
                    reply.status(this.errorStatus(e)).header(...JSONHDR).send({ok: false, errorMessage: error.message, errorMessages: error.messages, errorCode: error.code, errorCodeName: ErrorCode[error.code]});                    
                });
            }
        });
    }

    private addApiUserForSessionKeyEndpoints() {
        this.app.post(this.prefix+'api/userforsessionkey', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/userforsessionkey', ip: request.ip, user: request.user?.username, hashedSessionCookie: this.getHashOfSessionCookie(request)}));
            if (!request.user) return this.sendJsonError(reply, 401);
            await this.validateCsrfToken(request)
            try {
                let user : User|undefined;
                const sessionId = this.getSessionCookieValue(request);
                if (sessionId) user = await this.sessionManager.userForSessionKey(sessionId);
                return reply.header(...JSONHDR).send({ok: true, user : user});
            } catch (e) {
                let error = "Unknown error";
                let code = ErrorCode.UnknownError;
                if (e instanceof CrossauthError) {
                    let ce = e as CrossauthError;
                    switch (ce.code) {
                        case ErrorCode.UserNotExist:
                        case ErrorCode.PasswordInvalid:
                            error = "Invalid username or password";
                            code = ErrorCode.UsernameOrPasswordInvalid;
                            break;
                        default:
                            error = ce.message;
                            code = ce.code;
                    }
                }
                CrossauthLogger.logger.error(j({msg: "getuserforsessionkey failure", user: request.user?.username, hashedSessionCookie: this.getHashOfSessionCookie(request), errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                return reply.status(this.errorStatus(e)).header(...JSONHDR).send({ok: false, errorCode: code, errorCodeName: ErrorCode[code], error : error});

            }
        });
    }

    private addApiGetCsrfTokenEndpoints() {
        this.app.get(this.prefix+'api/getcsrftoken', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/getcsrftoken', ip: request.ip, user: request.user?.username}));
            try {
                return reply.header(...JSONHDR).send({ok: true, csrfToken : request.csrfToken});
            } catch (e) {
                let error = "Unknown error";
                let code = ErrorCode.UnknownError;
                if (e instanceof CrossauthError) {
                    let ce = e as CrossauthError;
                    code = ce.code;
                    error = ce.message;
                }
                CrossauthLogger.logger.error(j({msg: "getcsrftoken failure", user: request.user?.username, hashedCsrfCookie: this.getHashOfCsrfCookie(request), errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                return reply.status(this.errorStatus(e)).header(...JSONHDR).send({ok: false, errorCode: code, errorCodeName: ErrorCode[code], error : error});

            }
        });
    }

    /////////////////
    // Shared between page and API endpoints

    private async login(request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, user: User) => void) {

        if (request.user) return successFn(reply, request.user); // already logged in - nothing to do

        // get data from request body
        const username = request.body.username;
        const persist = request.body.persist;

        // throw an exception if the CSRF token isn't valid
        await this.validateCsrfToken(request);

        // keep the old session ID.  If there was one, we will delete it after
        const oldSessionId = this.getSessionCookieValue(request);

        // call implementor-provided hook to add additional fields to session key
        let extraFields = this.addToSession ? this.addToSession(request) : {}

        // log user in and get new session cookie, CSRF cookie and user
        // if 2FA is enabled, it will be an anonymous session
        let { sessionCookie, csrfCookie, user } = await this.sessionManager.login(username, request.body, extraFields, persist);

        // Set the new cookies in the reply
        CrossauthLogger.logger.debug(j({msg: "Login: set session cookie " + sessionCookie.name + " opts " + JSON.stringify(sessionCookie.options), user: request.body.username}));
        reply.cookie(sessionCookie.name, sessionCookie.value, sessionCookie.options);
        CrossauthLogger.logger.debug(j({msg: "Login: set csrf cookie " + csrfCookie.name + " opts " + JSON.stringify(sessionCookie.options), user: request.body.username}));
        reply.cookie(csrfCookie.name, csrfCookie.value, csrfCookie.options);
        request.csrfToken = await this.sessionManager.createCsrfFormOrHeaderValue(csrfCookie.value);

        // delete the old session key if there was one
        if (oldSessionId) {
            try {
                await this.sessionManager.deleteSession(oldSessionId);
            } catch (e) {
                CrossauthLogger.logger.warn(j({msg: "Couldn't delete session ID from database", hashedSessionCookie: this.getHashOfSessionCookie(request)}));
                CrossauthLogger.logger.debug(j({err: e}));
            }
        }

        return successFn(reply, user);
    }

    private async loginFactor2(request : FastifyRequest<{ Body: LoginFactor2BodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, user: User) => void) {

        if (request.user) return successFn(reply, request.user); // already logged in - nothing to do

        // save the old session ID so we can delete it after (the anonymous session)
        // If there isn't one it is an error - only allowed to this URL with a valid session
        const oldSessionCookieValue = this.getSessionCookieValue(request);
        if (!oldSessionCookieValue) throw new CrossauthError(ErrorCode.Unauthorized);

        // get data from request body
        const persist = request.body.persist;

        // validate CSRF token - throw an exception if it is not valid
        await this.validateCsrfToken(request);

        let extraFields = this.addToSession ? this.addToSession(request) : {}
        const {sessionCookie, csrfCookie, user} = await this.sessionManager.completeTwoFactorLogin(request.body, oldSessionCookieValue, extraFields, persist);
        CrossauthLogger.logger.debug(j({msg: "Login: set session cookie " + sessionCookie.name + " opts " + JSON.stringify(sessionCookie.options), user: user?.username}));
        reply.cookie(sessionCookie.name, sessionCookie.value, sessionCookie.options);
        CrossauthLogger.logger.debug(j({msg: "Login: set csrf cookie " + csrfCookie.name + " opts " + JSON.stringify(sessionCookie.options), user: user?.username}));
        reply.cookie(csrfCookie.name, csrfCookie.value, csrfCookie.options);
        request.csrfToken = await this.sessionManager.createCsrfFormOrHeaderValue(csrfCookie.value);
        return successFn(reply, user);
    }

    private async cancelFactor2(request : FastifyRequest<{ Body: CsrfBodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply) => void) {

        this.validateCsrfToken(request);
        const sessionCookieValue = this.getSessionCookieValue(request);
        if (sessionCookieValue) {
            this.sessionManager.cancelTwoFactorPageVisit(sessionCookieValue);
        }
        return successFn(reply);
    }

    /**
     * This is called after the user has been validated to log the user in
     */
    private async loginWithUser(user: User, request : FastifyRequest, reply : FastifyReply, 
        successFn : (res : FastifyReply, user: User) => void) {

        // get old session ID so we can delete it after
        const oldSessionId = this.getSessionCookieValue(request);

        // call implementor-provided hook to add custom fields to session key
        let extraFields = this.addToSession ? this.addToSession(request) : {}

        // log user in - this doesn't do any authentication
        let { sessionCookie, csrfCookie } = await this.sessionManager.login("", {}, extraFields, undefined, user);

        // set the cookies
        CrossauthLogger.logger.debug(j({msg: "Login: set session cookie " + sessionCookie.name + " opts " + JSON.stringify(sessionCookie.options), user: user.username}));
        reply.cookie(sessionCookie.name, sessionCookie.value, sessionCookie.options);
        CrossauthLogger.logger.debug(j({msg: "Login: set csrf cookie " + csrfCookie.name + " opts " + JSON.stringify(sessionCookie.options), user: user.username}));
        reply.cookie(csrfCookie.name, csrfCookie.value, csrfCookie.options);

        // delete the old session
        if (oldSessionId) {
            try {
                await this.sessionManager.deleteSession(oldSessionId);
            } catch (e) {
                CrossauthLogger.logger.warn(j({msg: "Couldn't delete session ID from database", hashedSessionCookie: this.getHashOfSessionCookie(request)}));
                CrossauthLogger.logger.debug(j({err: e}));
            }
        }

        return successFn(reply, user);
    }

    private async signup(request : FastifyRequest<{ Body: SignupBodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, data: {[key:string]:any}, user? : User) => void) {
            
        // throw an error if the CSRF token is invalid
        await this.validateCsrfToken(request);

        // get data from the request body
        // make sure the requested second factor is valid
        const username = request.body.username;
        const next = request.body.next;
        if (!request.body.factor2) {
            request.body.factor2 = this.allowedFactor2[0]; 
        }
        if (request.body.factor2 && !(this.allowedFactor2.includes(request.body.factor2))) {
            throw new CrossauthError(ErrorCode.Forbidden, "Illegal second factor " + request.body.factor2 + " requested");
        }
        if (request.body.factor2 == "none" || request.body.factor2 == "") request.body.factor2 = undefined;

        // call implementor-provided function to create the user object (or our default)
        let user = this.createUserFn(request, this.userStorage.userEditableFields);

        // ask the authenticator to validate the user-provided secret
        let passwordErrors = this.authenticators[user.factor1].validateSecrets(request.body);

        // get the repeat secrets (secret names prefixed with repeat_)
        const secretNames = this.authenticators[user.factor1].secretNames();
        let repeatSecrets : AuthenticationParameters|undefined = {};
        for (let field in request.body) {
            if (field.startsWith("repeat_")) {
                const name = field.replace(/^repeat_/, "");
                // @ts-ignore as it complains about request.body[field]
                if (secretNames.includes(name)) repeatSecrets[name] = request.body[field];
            }
        }
        if (Object.keys(repeatSecrets).length === 0) repeatSecrets = undefined;

        // set the user's state to active, awaitingtwofactor or awaitingemailverification
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

        // See if the user was already created, with the correct password, and is awaiting 2FA
        // completion.  Send the same response as before, in case the user closed the browser
        let twoFactorInitiated = false;
        try {
            const {user: existingUser, secrets: existingSecrets} = await this.userStorage.getUserByUsername(username);
            await this.sessionManager.authenticators[user.factor1].authenticateUser(existingUser, existingSecrets, request.body);
        } catch (e) {
            if (e instanceof CrossauthError && e.code == ErrorCode.TwoFactorIncomplete) {
                twoFactorInitiated = true;
            } // all other errors are legitimate ones - we ignore them
        }
        
        // login (this may be just first stage of 2FA)
        if ((!request.body.factor2) && !twoFactorInitiated) {
            // not enabling 2FA
            await this.sessionManager.createUser(user, request.body, repeatSecrets);
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
                const sessionValue = this.getSessionCookieValue(request);
                if (!sessionValue) throw new CrossauthError(ErrorCode.Unauthorized);
                const resp = await this.sessionManager.repeatTwoFactorSignup(sessionValue);
                userData = resp.userData;
            } else {
                // account not created - create one with state awaiting 2FA setup
                const sessionValue = await this.createAnonymousSession(request, reply);
                const resp = await this.sessionManager.initiateTwoFactorSignup(user, request.body, sessionValue, repeatSecrets);
                userData = resp.userData;
            }

            // pass caller back 2FA parameters
            try {
                let data : {userData: {[key:string] : any}, username: string, next : string, csrfToken: string|undefined} = 
                {
                    userData: userData,
                    username: username,
                    next: next||this.loginRedirect,
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

    private async reconfigureFactor2(request : FastifyRequest, reply : FastifyReply, 
        successFn : (res : FastifyReply, data: {[key:string]:any}, user? : User) => void) {
        
        // make sure user is logged in
        const sessionValue = await this.getSessionCookieValue(request);
        if (!request.user || !sessionValue) throw new CrossauthError(ErrorCode.Unauthorized);

        // get second factor authenticator
        let factor2 : string = request.user.factor2;
        const authenticator = this.authenticators[factor2];
        if (!authenticator || authenticator.secretNames().length == 0) throw new CrossauthError(ErrorCode.BadRequest, "Selected second factor does not have configuration");
    
        // step one in 2FA setup - create secrets and get data to dispaly to user
        const userData = await this.sessionManager.initiateTwoFactorSetup(request.user, factor2, sessionValue);

        // show user result
        let data : {[key:string] : any} = 
        {
            ...userData,
            csrfToken: request.csrfToken,
        };
        return successFn(reply, data)
    }

    private async configureFactor2(request : FastifyRequest<{ Body: ConfigureFactor2BodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, user? : User) => void) {

        // validate the CSRF token
        await this.validateCsrfToken(request);

        // get the session - it may be a real user or anonymous
        const sessionCookieValue = this.getSessionCookieValue(request);
        if (!sessionCookieValue) throw new CrossauthError(ErrorCode.Unauthorized, "No session active while enabling 2FA.  Please enable cookies");
        // finish 2FA setup - validate secrets and update user
        let user = await this.sessionManager.completeTwoFactorSetup(request.body, sessionCookieValue);
        if (!request.user && !this.enableEmailVerification) {
            // we skip the login if the user is already logged in and we are not doing email verification
            return this.loginWithUser(user, request, reply, (request, user) => {
                return successFn(request, user)});
        }
        return successFn(reply, user);
    }

    private async changeFactor2(request : FastifyRequest<{ Body: ChangeFactor2BodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, data: {[key:string]:any}, user? : User) => void) {
            
        // this can only be called for logged in users
        const sessionValue = this.getSessionCookieValue(request);
        if (!sessionValue || !request.user) throw new CrossauthError(ErrorCode.Unauthorized);

        // validate the CSRF token
        await this.validateCsrfToken(request);

        // validate the requested factor2
        let newFactor2 : string|undefined = request.body.factor2;
        if (request.body.factor2 && !(this.allowedFactor2.includes(request.body.factor2))) {
            throw new CrossauthError(ErrorCode.Forbidden, "Illegal second factor " + request.body.factor2 + " requested");
        }
        if (request.body.factor2 == "none" || request.body.factor2 == "") newFactor2 = undefined;

        // get data to show user to finish 2FA setup
        const userData = await this.sessionManager.initiateTwoFactorSetup(request.user, newFactor2, sessionValue);

        // show data to user
        let data : {factor2: string|undefined, userData: {[key:string] : any}, username: string, next : string, csrfToken: string|undefined} = 
        {
            factor2: newFactor2,
            userData: userData,
            username: userData.username,
            next: request.body.next||this.loginRedirect,
            csrfToken: request.csrfToken,
        };
        return successFn(reply, data)
    }

    private async changePassword(request : FastifyRequest<{ Body: ChangePasswordBodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, user? : User) => void) {

        // can only call this if logged in and CSRF token is valid
        if (!request.user) throw new CrossauthError(ErrorCode.Unauthorized);
        await this.validateCsrfToken(request)

        // get the authenticator for factor1 (passwords on factor2 are not supported)
        const authenticator = this.authenticators[request.user.factor1];

        // the form should contain old_{secret}, new_{secret} and repeat_{secret}
        // extract them, making sure the secret is a valid one
        const secretNames = authenticator.secretNames();
        let oldSecrets : AuthenticationParameters = {};
        let newSecrets : AuthenticationParameters = {};
        let repeatSecrets : AuthenticationParameters|undefined = {};
        for (let field in request.body) {
            if (field.startsWith("new_")) {
                const name = field.replace(/^new_/, "");
                // @ts-ignore as it complains about request.body[field]
                if (secretNames.includes(name)) newSecrets[name] = request.body[field];
            } else if (field.startsWith("old_")) {
                const name = field.replace(/^old_/, "");
                // @ts-ignore as it complains about request.body[field]
                if (secretNames.includes(name)) oldSecrets[name] = request.body[field];
            } else if (field.startsWith("repeat_")) {
                const name = field.replace(/^repeat_/, "");
                // @ts-ignore as it complains about request.body[field]
                if (secretNames.includes(name)) repeatSecrets[name] = request.body[field];
            }
        }
        if (Object.keys(repeatSecrets).length === 0) repeatSecrets = undefined;

        // validate the new secret - this is through an implementor-supplied function
        let errors = authenticator.validateSecrets(newSecrets);
        if (errors.length > 0) {
            throw new CrossauthError(ErrorCode.PasswordFormat);
        }

        // validate the old secrets, check the new and repeat ones match and update if valid
        await this.sessionManager.changeSecrets(request.user.username, 1, oldSecrets, newSecrets, repeatSecrets);

        return successFn(reply, undefined);
    }

    private async updateUser(request : FastifyRequest<{ Body: UpdateUserBodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, user : User, emailVerificationRequired : boolean) => void) {

        // can only call this if logged in and CSRF token is valid
        if (!request.user) throw new CrossauthError(ErrorCode.Unauthorized);
        await this.validateCsrfToken(request);

        // get new user fields from form, including from the implementor-provided hook
        let user : User = {
            id: request.user.id,
            username: request.user.username,
            state: "active",
        };
        user = this.updateUserFn(user, request, this.userStorage.userEditableFields);

        // validate the new user using the implementor-provided function
        let errors = this.validateUserFn(user);
        if (errors.length > 0) {
            throw new CrossauthError(ErrorCode.FormEntry, errors);
        }

        // update the user
        let emailVerificationNeeded = await this.sessionManager.updateUser(request.user, user);

        return successFn(reply, request.user, emailVerificationNeeded);
    }

    private async requestPasswordReset(request : FastifyRequest<{ Body: RequestPasswordResetBodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, user? : User) => void) {

        // this has to be enabled in configuration
        if (!this.enablePasswordReset) {
            throw new CrossauthError(ErrorCode.Configuration, "password reset not enabled");
        }

        // validate the CSRDF token
        await this.validateCsrfToken(request);

        // get data from request body
        const email = request.body.email;

        // send password reset email
        try {
            await this.sessionManager.requestPasswordReset(email);
        } catch (e) {
            if (e instanceof CrossauthError && e.code == ErrorCode.UserNotExist) {
                // fail silently - don't let user know email doesn't exist
                CrossauthLogger.logger.warn(j({msg: "Password reset requested for invalid email", email: request.body.email}))
            } else {
                CrossauthLogger.logger.debug(j({err: e, msg: "Couldn't send password reset email"}));
            }
        }

        return successFn(reply, undefined);
    }

    private async verifyEmail(request : FastifyRequest<{ Params: VerifyTokenParamType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, user? : User) => void) {

        // this has to be enabled in configuration
        if (!this.enableEmailVerification) throw new CrossauthError(ErrorCode.Configuration, "Email verification reset not enabled");

        // get the email verification token
        const token = request.params.token;

        // validate the token and log the user in
        const user = await this.sessionManager.applyEmailVerificationToken(token);
        return await this.loginWithUser(user, request, reply, successFn);
    }

    private async resetPassword(request : FastifyRequest<{ Body: ResetPasswordBodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, user? : User) => void) {

        // check the CSRF token is valid
        await this.validateCsrfToken(request);

        // get the user based on ther token from the request body
        const token = request.body.token;
        const user = await this.sessionManager.userForPasswordResetToken(token);

        // get secrets from the request body 
        // there should be new_{secret} and repeat_{secret}
        const authenticator = this.authenticators[user.factor1];
        const secretNames = authenticator.secretNames();
        let newSecrets : AuthenticationParameters = {};
        let repeatSecrets : AuthenticationParameters|undefined = {};
        for (let field in request.body) {
            if (field.startsWith("new_")) {
                const name = field.replace(/^new_/, "");
                // @ts-ignore as it complains about request.body[field]
                if (secretNames.includes(name)) newSecrets[name] = request.body[field];
            } else if (field.startsWith("repeat_")) {
                const name = field.replace(/^repeat_/, "");
                // @ts-ignore as it complains about request.body[field]
                if (secretNames.includes(name)) repeatSecrets[name] = request.body[field];
            }
        }
        if (Object.keys(repeatSecrets).length === 0) repeatSecrets = undefined;

        // validate the new secrets (with the implementor-provided function)
        let errors = authenticator.validateSecrets(newSecrets);
        if (errors.length > 0) {
            throw new CrossauthError(ErrorCode.PasswordFormat);
        }

        // check new and repeat secrets are valid and update the user
        const user1 = await this.sessionManager.resetSecret(token, 1, newSecrets, repeatSecrets);

        // log the user in
        return this.loginWithUser(user1, request, reply, successFn);
    }

    private async logout(request : FastifyRequest, reply : FastifyReply, 
        successFn : (reply : FastifyReply) => void) {

            // logout
        let sessionId = this.getSessionCookieValue(request);
        if (sessionId) {
                await this.sessionManager.logout(sessionId);
        }

        // clear cookies
        CrossauthLogger.logger.debug(j({msg: "Logout: clear cookie " + this.sessionManager.sessionCookieName}));
        reply.clearCookie(this.sessionManager.sessionCookieName);
        reply.clearCookie(this.sessionManager.csrfCookieName);
        if (sessionId) {
            try {
                await this.sessionManager.deleteSession(sessionId);
            } catch (e) {
                CrossauthLogger.logger.warn(j({msg: "Couldn't delete session ID from database", hashedSessionCookie: this.getHashOfSessionCookie(request)}));
                CrossauthLogger.logger.debug(j({err: e}));
            }
        }

        return successFn(reply);

    }

    async createAnonymousSession(request : FastifyRequest, reply : FastifyReply, data? : {[key:string]:any}) : Promise<string> {
        CrossauthLogger.logger.debug(j({msg: "Creating session ID"}));

        // get custom fields from implentor-provided function
        let extraFields = this.addToSession ? this.addToSession(request) : {}
        if (data) extraFields.data = JSON.stringify(data);

        // create session, setting the session cookie, CSRF cookie and CSRF token 
        let { sessionCookie, csrfCookie, csrfFormOrHeaderValue } = await this.sessionManager.createAnonymousSession(extraFields);
        reply.cookie(sessionCookie.name, sessionCookie.value, sessionCookie.options);
        request.csrfToken = csrfFormOrHeaderValue;
        reply.setCookie(csrfCookie.name, csrfCookie.value, csrfCookie.options);
        request.user = undefined;

        return sessionCookie.value;
    };

    // sanitise errors - user's should not be shown anything too revealing about it
    private handleError(e : any, request: FastifyRequest, reply : FastifyReply, errorFn : (reply : FastifyReply, error : CrossauthError) => void, passwordInvalidOk? : boolean) {
        let error = "Unknown error";
        let code = ErrorCode.UnknownError;
        let ce;
        if (e instanceof CrossauthError) {
            ce = e as CrossauthError;
            code = ce.code;
            if (!passwordInvalidOk) {
                switch (ce.code) {
                    case ErrorCode.UserNotExist:
                    case ErrorCode.PasswordInvalid:
                        ce = new CrossauthError(ErrorCode.UsernameOrPasswordInvalid, "Invalid username or password");
                        break;
                    default:
                        error = ce.message;
                }
            }
        } else {
            ce = new CrossauthError(code, error);
        }
        CrossauthLogger.logger.debug(j({err: e}));
        CrossauthLogger.logger.error(j({cerr: e, hashedSessionCookie: this.getHashOfSessionCookie(request), user: request.user?.username}));

        return errorFn(reply, ce);

    }

    //////////////
    // Helpers

    getSessionCookieValue(request : FastifyRequest) : string|undefined{
        if (request.cookies && this.sessionManager.sessionCookieName in request.cookies) {       
            return request.cookies[this.sessionManager.sessionCookieName]
        }
        return undefined;
    }

    getCsrfCookieValue(request : FastifyRequest) : string|undefined{
        if (request.cookies && this.sessionManager.csrfCookieName in request.cookies) {       
            return request.cookies[this.sessionManager.csrfCookieName]
        }
        return undefined;
    }

    getHashOfSessionCookie(request : FastifyRequest) : string {
        const cookieValue = this.getSessionCookieValue(request);
        if (!cookieValue) return "";
        try {
            return Hasher.hash(cookieValue);
        } catch (e) {}
        return "";
    }

    getHashOfCsrfCookie(request : FastifyRequest) : string {
        const cookieValue = this.getCsrfCookieValue(request);
        if (!cookieValue) return "";
        try {
            return Hasher.hash(cookieValue);
        } catch (e) {}
        return "";
    }

    async validateCsrfToken(request : FastifyRequest<{ Body: CsrfBodyType }>) : Promise<string|undefined> {

        this.sessionManager.validateDoubleSubmitCsrfToken(this.getCsrfCookieValue(request), request.csrfToken);
        return this.getCsrfCookieValue(request);
    }

    csrfToken(request : FastifyRequest<{Body: CsrfBodyType}>, reply : FastifyReply) {
        let token = request.body.csrfToken;
        if (!token) {
            if (request.headers && CSRFHEADER in request.headers) {
                const header = request.headers[CSRFHEADER];
                if (Array.isArray(header)) token = header[0];
                else token = header;
            }
        }
        if (token) {
            try {
                this.sessionManager.validateDoubleSubmitCsrfToken(this.getCsrfCookieValue(request), token);
                request.csrfToken = token;
                reply.header(CSRFHEADER, token);
            }
            catch (e) {
                CrossauthLogger.logger.warn(j({msg: "Invalid CSRF token", hashedCsrfCookie: this.getHashOfCsrfCookie(request)}));
                reply.clearCookie(this.sessionManager.csrfCookieName);
            }
        }

        return token;
    }


    sendJsonError(reply : FastifyReply, status : number, error?: string, e? : any) {
        let code = 0;
        let codeName = "UnknownError";
        if (e instanceof CrossauthError) {
            code = e.code;
            codeName = ErrorCode[code];
            if (!error) error = e.message;
        }            
        if (!error) error = "Unknown error";
        CrossauthLogger.logger.warn(j({msg: error, errorCode: code, errorCodeName: codeName, httpStatus: status}));
        return reply.header(...JSONHDR).status(status).send({ok: false, status: status, errorMessage: error, errorCode: code, errorCodeName: codeName});
    }

    errorStatus(e : any) {
        if (typeof e == "object" && "httpStatus" in e) return e.httpStatus||500;
        return 500;
    }

    private allowedFactor2Details() : AuthenticatorDetails[] {
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
        const sessionCookieValue = this.getSessionCookieValue(request);
        if (!sessionCookieValue) throw new CrossauthError(ErrorCode.Unauthorized, "User is not logged in");
        await this.sessionManager.updateSessionData(sessionCookieValue, name, value);
    }

    async getSessionData(request : FastifyRequest, name : string) : Promise<{[key:string]:any}|undefined>{
        const sessionCookieValue = this.getSessionCookieValue(request);
        try {
            const data = sessionCookieValue ? await this.sessionManager.dataForSessionKey(sessionCookieValue) : undefined;
            if (data && name in data) return data[name];
        } catch (e) {
            CrossauthLogger.logger.error(j({msg: "Couldn't get " + name + "from session", cerr: e}))
            CrossauthLogger.logger.debug(j({err: e}));
        }
        return undefined;
    }

    async getSessionKey(request : FastifyRequest) : Promise<Key|undefined>{
        const sessionCookieValue = this.getSessionCookieValue(request);
        if (!sessionCookieValue) return undefined;
        try {
            const {key} = await this.sessionManager.userForSessionCookieValue(sessionCookieValue) 
            return key;
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
        }
        return undefined;
    }
}
