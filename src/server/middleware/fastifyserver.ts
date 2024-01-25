import fastify, { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import view from '@fastify/view';
import fastifyFormBody from '@fastify/formbody';
import type { FastifyCookieOptions } from '@fastify/cookie'
import cookie from '@fastify/cookie'
import { Server, IncomingMessage, ServerResponse } from 'http'

import nunjucks from "nunjucks";
import { UserStorage, KeyStorage } from '../storage';
import { UsernamePasswordAuthenticator } from '../password';
import { Hasher } from '../hasher';
import { Backend, type BackendOptions } from '../backend';
import { CrossauthError, ErrorCode } from "../..";
import { User, Key } from '../../interfaces';
import { CrossauthLogger, j } from '../..';
import { setParameter, ParamType } from '../utils';

const CSRFHEADER = "X-CROSSAUTH-CSRF";

const ERROR_401 = `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>401 Unauthorized</title>
</head><body>
<h1>Not Found</h1>
<p>You are not authorized to access this URL.</p>
</body></html>
`

const ERROR_500 = `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>500 Server Error</title>
</head><body>
<h1>Not Found</h1>
<p>Sorry, an unknown error has occured</p>
</body></html>
`

const JSONHDR = 'application/json; charset=utf-8';

/**
 * Options for {@link FastifyCookieAuthServer }.
 * 
 * See {@link FastifyCookieAuthServer } constructor for description of parameters
 */
export interface FastifyCookieAuthServerOptions extends BackendOptions {

    /** You can pass your own fastify instance or omit this, in which case Crossauth will create one */
    app? : FastifyInstance<Server, IncomingMessage, ServerResponse>,

    /** List of endpoints to add to the server ("login", "api/login", etc, prefixed by the `prefix` parameter.  Empty for all.  Default all. */
    endpoints? : string,

    /** Page to redirect to after successful login, default "/" */
    loginRedirect? : string;

    /** Page to redirect to after successful logout, default "/" */
    logoutRedirect? : string;

    /** Function that throws a {@link index!CrossauthError} with {@link index!ErrorCode} `PasswordFormat` if the password doesn't confirm to local rules (eg number of charafters)  */
    validatePassword? : (password: string) => string[];

    /** Function that throws a {@link index!CrossauthError} with {@link index!ErrorCode} `FormEnty` if the user doesn't confirm to local rules.  Doesn't validate passwords  */
    validateUser? : (user: User) => string[];

    /** Called when a new user is going to be saved 
     *  Add additional fields to your session storage here.  Return a map of keys to values.
     *  ALternatively you can add fields in the create user form, preceded with `user_`.  If you
     *  want to add fields which the user does not have control over, eg permissions, use this function.
     */
    addToUser? : (request : FastifyRequest) => {[key: string] : string|number|boolean|Date|undefined};

    /** Called when a new session token is going to be saved 
     *  Add additional fields to your session storage here.  Return a map of keys to values  */
    addToSession? : (request : FastifyRequest) => {[key: string] : string|number|boolean|Date|undefined};

    /** Called after the session ID is validated.
     * Use this to add additional checks based on the request.  
     * Throw an exception if cecks fail
     */
    validateSession? : (session: Key, user: User|undefined, request : FastifyRequest) => void;

    /** Template file containing the login page (with without error messages).  
     * See the class documentation for {@link FastifyCookieAuthServer} for more info.  Defaults to "login.njk".
     */
    loginPage? : string;

    /** Template file containing the page for getting the TOTP after entering username and password
     * See the class documentation for {@link FastifyCookieAuthServer} for more info.  Defaults to "login.njk".
     */
    loginTotpPage? : string;

    /** Template file containing the signup page (with without error messages).  
     * See the class documentation for {@link FastifyCookieAuthServer} for more info.  Defaults to "signup.njk".
     * Signup form should contain at least `username` and `password` and may also contain `repeatPassword`.  If you have additional
     * fields in your user table you want to pass from your form, prefix them with `user_`, eg `user_email`.
     * If you want to enable email verification, set `enableEmailVerification` and set `checkEmailVerified` 
     * on the user storage.
     */
    signupPage? : string;

    /** Page to set up TOTP after sign up */
    signupTotpPage? : string;

    /** Page to render error messages, including failed login. 
     * See the class documentation for {@link FastifyCookieAuthServer} for more info.  Defaults to "error.njk".
     */
    errorPage? : string;

    /** Page to render for password changing.  
     * See the class documentation for {@link FastifyCookieAuthServer} for more info.  Defaults to "changepassword.njk".
     */
    changePasswordPage? : string,

    /** Page to render for updating user details.  
     * See the class documentation for {@link FastifyCookieAuthServer} for more info.  Defaults to "updateuser.njk".
     */
    updateUserPage? : string,

    /** Page to ask user for email and reset his/her password.  
     * See the class documentation for {@link FastifyCookieAuthServer} for more info.  Defaults to "requestpasswordreset.njk".
     */
    requestResetPasswordPage? : string,

    /** Page to render for password reset, after the emailed token has been validated.  
     * See the class documentation for {@link FastifyCookieAuthServer} for more info.  Defaults to "resetpassword.njk".
     */
    resetPasswordPage? : string,

    /**
     * Turns on email verification.  This will cause the verification tokens to be sent when the account
     * is activated and when email is changed.  Default false.
     */
    enableEmailVerification? : boolean,

    /** Page to render for to confirm email has been verified.  Only created if `enableEmailVerification` is true.
     * See the class documentation for {@link FastifyCookieAuthServer} for more info.  Defaults to "emailverified.njk"
     */
    emailVerifiedPage? : string,
}

interface CsrfBodyType {
    csrfToken?: string;
}

interface LoginBodyType extends CsrfBodyType {
    username: string,
    password: string,
    persist? : boolean,
    next? : string,
}

interface LoginTotpBodyType extends CsrfBodyType {
    totpCode : string,
    persist? : boolean,
    next? : string,
}

interface SignupBodyType extends LoginBodyType {
    repeatPassword?: string,
    email? : string,
    totp? : string,
    [key : string]: string|number|Date|boolean|undefined,
}

interface SignupTotpBodyType extends CsrfBodyType {
    totpCode : string;
    next? : string,
    persist? : boolean,
}

interface ChangePasswordBodyType extends CsrfBodyType {
    oldPassword: string,
    newPassword: string,
    repeatPassword?: string,
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

interface CsrfBodyType {
    csrfToken? : string;
}

interface LoginParamsType {
    next? : string;
}

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
 * API (JSON) endpoints that depend on TOTP being enabled 
 */
export const TotpApiEndpoints = [
    "api/signuptotp",
    "api/logintotp",
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
export const TotpPageEndpoints = [
    "signuptotp",
    "logintotp"
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
    ...TotpPageEndpoints,
    ...TotpApiEndpoints,
];

/**
 * Default password validator.
 * 
 * Passwords must be at leat 8 characters, contain at least one lowercase character, at least one uppercase
 * chracter and at least one digit.
 * @param password The password to validate
 * @returns an array of errors.  If there were no errors, returns an empty array
 */
function defaultPasswordValidator(password : string) : string[] {
    let errors : string[] = [];
    if (password.length < 8) errors.push("Password must be at least 8 characters");
    if (password.match(/[a-z]/) == null) errors.push("Password must contain at least one lowercase character");
    if (password.match(/[A-Z]/) == null) errors.push("Password must contain at least one uppercase character");
    if (password.match(/[0-9]/) == null) errors.push("Password must contain at least one digit");
    return errors;
}

/**
 * Default User validator.  Doesn't validate password
 * 
 * Username must be at least two characters.
 * @param password The password to validate
 * @returns an array of errors.  If there were no errors, returns an empty array
 */
function defaultUserValidator(user : User) : string[] {
    let errors : string[] = [];
    if (user.username == undefined) errors.push("Username must be given");
    else if (user.username.length < 2) errors.push("Username must be at least 2 characters");
    return errors;
}

/**
 * This class provides a complete (but without HTML files) auth backend server with endpoints served using 
 * Fastify.
 * 
 * If you do not pass an Fastify app to this class, it will create one.  By default, pages are rendered
 * with Nunjucks.  If you prefer another renderer that is compatible with Fastify, create your
 * own Fastify app and configure the renderer using @fastify/view.
 * 
 * By default, all views are expected to be in a directory called `views` relative to the directory the
 * server is started in.  This can be overwritten by setting the `views` option.
 * 
 * Note that `views`, and the Nunjucls pages are not used by the API endpoints (those starting in /api).
 * 
 * **Endpoints provided**
 * 
 * All POST methods also take a csrfToken.  If user is logged in or anonymous sessions are enabled.
 * 
 * All POST methods are passed user, csrfToken, code, error and errors.
 * this is checked.
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
export class FastifyCookieAuthServer {
    readonly app : FastifyInstance<Server, IncomingMessage, ServerResponse>;
    private enableSessions : boolean = true;
    private views : string = "views";
    private prefix : string = "/";
    private endpoints : string[] = [];
    private loginRedirect = "/";
    private logoutRedirect : string = "/";
    private signupPage : string = "signup.njk";
    private signupTotpPage : string = "signuptotp.njk";
    private loginPage : string = "login.njk";
    private loginTotpPage : string = "logintotp.njk";
    private errorPage : string = "error.njk";
    private changePasswordPage : string = "changepassword.njk";
    private updateUserPage : string = "updateuser.njk";
    private resetPasswordPage: string = "resetpassword.njk";
    private requestPasswordResetPage: string = "requestpasswordreset.njk";
    private emailVerifiedPage : string = "emailverified.njk";
    private sessionManager : Backend;
    private anonymousSessions = true;
    private validatePassword : (password : string) => string[] = defaultPasswordValidator;
    private validateUser : (user : User) => string[] = defaultUserValidator;
    private addToUser? : (request : FastifyRequest) => {[key: string] : string|number|boolean|Date|undefined};
    private addToSession? : (request : FastifyRequest) => {[key: string] : string|number|boolean|Date|undefined};
    private validateSession? : (session: Key, user: User|undefined, request : FastifyRequest) => void;
    private enableEmailVerification : boolean = true;
    private enablePasswordReset : boolean = true;
    private totp :  "off" | "all" | "peruser" = "off";


    /**
     * Creates the Fastify endpoints, optionally also the Fastify app.
     * @param optoions see {@link FastifyCookieAuthServerOptions}
     */
    constructor(userStorage: UserStorage, 
                keyStorage: KeyStorage, 
                authenticator: UsernamePasswordAuthenticator, 
                options: FastifyCookieAuthServerOptions = {}) {

        setParameter("enableSessions", ParamType.Boolean, this, options, "ENABLE_SESSIONS");
        setParameter("enableEmailVerification", ParamType.Boolean, this, options, "ENABLE_EMAIL_VERIFICATION");
        setParameter("enablePasswordReset", ParamType.Boolean, this, options, "ENABLE_PASSWORD_RESET");
        setParameter("totp", ParamType.String, this, options, "TOTP");

        this.endpoints = [...SignupPageEndpoints, ...SignupApiEndpoints];
        if (this.enableSessions) this.endpoints = [...this.endpoints, ...SessionPageEndpoints, ...SessionApiEndpoints];
        if (this.enableEmailVerification) this.endpoints = [...this.endpoints, ...EmailVerificationPageEndpoints, ...EmailVerificationApiEndpoints];
        if (this.enablePasswordReset) this.endpoints = [...this.endpoints, ...PasswordResetPageEndpoints, ...PasswordResetApiEndpoints];
        if (this.totp != "off") this.endpoints = [...this.endpoints, ...TotpPageEndpoints, ...TotpApiEndpoints];
        setParameter("endpoints", ParamType.StringArray, this, options, "ENDPOINTS");

        setParameter("views", ParamType.String, this, options, "VIEWS");
        setParameter("prefix", ParamType.String, this, options, "PREFIX");
        setParameter("signupPage", ParamType.String, this, options, "SIGNUP_PAGE");
        setParameter("signupTotpPage", ParamType.String, this, options, "SIGNUP_TOTP_PAGE");
        setParameter("loginPage", ParamType.String, this, options, "LOGIN_PAGE");
        setParameter("loginTotpPage", ParamType.String, this, options, "LOGIN_TOTP_PAGE");
        setParameter("errorPage", ParamType.String, this, options, "ERROR_PAGE");
        setParameter("changePasswordPage", ParamType.String, this, options, "CHANGE_PASSWORD_PAGE");
        setParameter("updateUser", ParamType.String, this, options, "UPDATE_USER_PAGE");
        setParameter("resetPasswordPage", ParamType.String, this, options, "RESET_PASSWORD_PAGE");
        setParameter("requestPasswordResetPage", ParamType.String, this, options, "REQUEST_PASSWORD_RESET_PAGE");
        setParameter("emailVerifiedPage", ParamType.String, this, options, "EMAIL_VERIFIED_PAGE");
        setParameter("emailFrom", ParamType.String, this, options, "EMAIL_FROM");
        setParameter("persistSessionId", ParamType.Boolean, this, options, "PERSIST_SESSION_ID");

        if (options.validatePassword) this.validatePassword = options.validatePassword;
        if (options.validateUser) this.validateUser = options.validateUser;
        if (options.addToUser) this.addToUser = options.addToUser;
        if (options.addToSession) this.addToSession = options.addToSession;
        if (options.validateSession) this.validateSession = options.validateSession;

        this.sessionManager = new Backend(userStorage, keyStorage, authenticator, 
            options);

        if (options.app) {
            this.app = options.app;
        } else {
            if (this.views) {
                nunjucks.configure(this.views, {
                    autoescape: true,
                });
            }
            this.app = fastify({logger: false});
            this.app.register(view, {
                engine: {
                    nunjucks: nunjucks,
                },
                templates: [
                    "node_modules/shared-components",
                    this.views,
                ],
                });


        }

        this.app.addContentTypeParser('text/json', { parseAs: 'string' }, this.app.getDefaultJsonParser('ignore', 'ignore'))
        this.app.register(fastifyFormBody);
        this.app.register(cookie, {
            // secret: "my-secret", // for cookies signature
            parseOptions: {}     // options for parsing cookies
          } as FastifyCookieOptions)

        this.app.decorateRequest('user', undefined);
        this.app.decorateRequest('csrfToken', undefined);
                                
        // validates the session id and csrftokens, creating if necessary and putting the csrf token
        // and user in the request object.
        this.app.addHook('preHandler', async (request : FastifyRequest<{Body: CsrfBodyType}>, reply : FastifyReply) => {

            if (!this.enableSessions) return;

            // check if CSRF token is in cookie (and signature is valid)
            CrossauthLogger.logger.debug(j({msg: "Getting csrf cookie"}));
            let cookieValue : string|undefined;
            try {
                 cookieValue = this.getCsrfTokenFromCookie(request);
                 if (cookieValue) this.sessionManager.validateCsrfCookie(cookieValue);
            }
            catch (e) {
                CrossauthLogger.logger.warn(j({msg: "Invalid csrf cookie received", hashedCsrfCookie: this.getHashOfCsrfCookie(request)}));
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
                    CrossauthLogger.logger.error(j({msg: "Couldn't create CSRF token"}));
                    CrossauthLogger.logger.debug(j({err: e}));
                    reply.clearCookie(this.sessionManager.csrfCookieName);
                }
            } else {
                // for other methods, create a new token only if there is already a valid one
                if (cookieValue) {
                    try {
                        this.csrfToken(request, reply);
                    } catch (e) {
                        CrossauthLogger.logger.error(j({msg: "Couldn't create CSRF token"}));
                        CrossauthLogger.logger.debug(j({err: e}));
                    }
                }
            }


            // get existing session cookie (unvalidated)
            request.user = undefined;
            const sessionCookieValue = this.getSessionIdFromCookie(request);
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
          
        if (this.endpoints.includes("login")) {
            if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "/login enabled but sessions are not");
            this.app.get(this.prefix+'login', async (request : FastifyRequest<{Querystring : LoginParamsType}>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "Page visit", method: 'GET', url: this.prefix+'login', ip: request.ip}));
                if (request.user) return reply.redirect(request.query.next||this.loginRedirect); // already logged in

                let data : {next? : any, csrfToken: string|undefined} = {csrfToken: request.csrfToken};
                if (request.query.next) {
                    data["next"] = request.query.next;
                }
                return reply.view(this.loginPage, data);
            });

            this.app.post(this.prefix+'login', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'login', ip: request.ip}));
                let next = request.body.next || this.loginRedirect;
                try {
                    CrossauthLogger.logger.debug(j({msg: "Next page " + next}));

                    await this.login(request, reply, 
                    (reply, user) => {
                        if (!user.totpRequired) {
                            CrossauthLogger.logger.debug(j({msg: "Successful login - sending redirect"}));
                            return reply.redirect(next);
                        } else {
                            let data : {next? : any, persist? : any, csrfToken: string|undefined} = {
                                csrfToken: request.csrfToken,
                                next: request.body.next||this.loginRedirect,
                                persist: request.body.persist ? "on" : "",
                            };
                            return reply.view(this.loginTotpPage, data);
                        }
                    });
                } catch (e) {
                    CrossauthLogger.logger.debug(j({err: e}));
                    return this.handleError(e, reply, (reply, error) => {
                        return reply.view(this.loginPage, {
                            error: error.message,
                            errors: error.messages, 
                            code: error.code, 
                            errorCodeName: ErrorCode[error.code], 
                            next: next, 
                            persist: request.body.persist,
                            username: request.body.username,
                            csrfToken: request.csrfToken
                        });                      
                    });
                }
            });
        }

        if (this.endpoints.includes("logintotp")) {
            if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "/login enabled but sessions are not");
            this.app.post(this.prefix+'logintotp', async (request : FastifyRequest<{ Body: LoginTotpBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'logintotp', ip: request.ip}));
                let next = request.body.next || this.loginRedirect;
                try {
                    CrossauthLogger.logger.debug(j({msg: "Next page " + next}));

                    await this.logintotp(request, reply, 
                    (reply, _user) => {
                        CrossauthLogger.logger.debug(j({msg: "Successful login - sending redirect"}));
                        return reply.redirect(next);
                    });
                } catch (e) {
                    CrossauthLogger.logger.debug(j({err: e}));
                    return this.handleError(e, reply, (reply, error) => {
                        return reply.view(this.loginTotpPage, {
                            error: error.message,
                            errors: error.messages, 
                            code: error.code, 
                            errorCodeName: ErrorCode[error.code], 
                            next: request.body.next, 
                            persist: request.body.persist ? "on" : "",
                            csrfToken: request.csrfToken
                        });                      
                    });
                }
            });
        }

        if (this.endpoints.includes("signup")) {
            if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "/signup enabled but sessions are not");
            this.app.get(this.prefix+'signup', async (request : FastifyRequest<{Querystring : LoginParamsType}>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "Page visit", method: 'GET', url: this.prefix+'signup', ip: request.ip}));
                if (this.signupPage)  { // if is redundant but VC Code complains without it
                    let data : {next? : any, csrfToken: string|undefined, perUserTotp: boolean} = {csrfToken: request.csrfToken, perUserTotp: this.totp=="peruser"};
                    if (request.query.next) {
                        data["next"] = request.query.next;
                    }
                    return reply.view(this.signupPage, data);
                }
            });

            this.app.post(this.prefix+'signup', async (request : FastifyRequest<{ Body: SignupBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'signup', ip: request.ip, user: request.body.username}));
                let next = request.body.next || this.loginRedirect;
                try {
                    CrossauthLogger.logger.debug(j({msg: "Next page " + next}));

                    return await this.signup(request, reply, 
                    (reply, data, _user) => {
                        if (data.secret) {
                            return reply.view(this.signupTotpPage, data);
                        } else if (this.enableEmailVerification) {
                            return reply.view(this.signupPage, {
                                next: next, 
                                csrfToken: request.csrfToken,
                                message: "Please check your email to finish signing up."
                            });
                        } else {
                            return reply.redirect(this.loginRedirect);
                        }
                    });
                } catch (e) {
                    CrossauthLogger.logger.error(j({msg: "Signup failure", user: request.body.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                    CrossauthLogger.logger.debug(j({err: e}));
                    return this.handleError(e, reply, (reply, error) => {
                        let extraFields : {[key:string] : string|number|boolean|Date|undefined} = {};
                        for (let field in request.body) {
                            if (field.startsWith("user_")) extraFields[field] = request.body[field];
                        }
                        return reply.view(this.signupPage, {
                            error: error.message,
                            errors: error.messages, 
                            code: error.code, 
                            errorCodeName: ErrorCode[error.code], 
                            next: next, 
                            persist: request.body.persist,
                            username: request.body.username,
                            csrfToken: request.csrfToken,
                            totp: request.body.totp,
                            perUserTotp: this.totp == "peruser",
                            ...extraFields
                            });
                        
                    });
                }
            });
        }

        if (this.endpoints.includes("signuptotp")) {
            if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "/signuptotp enabled but sessions are not");
            this.app.post(this.prefix+'signuptotp', async (request : FastifyRequest<{ Body: SignupTotpBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'signuptotp', ip: request.ip}));
                let next = request.body.next || this.loginRedirect;
                try {
                    CrossauthLogger.logger.debug(j({msg: "Next page " + next}));

                    await this.signuptotp(request, reply, 
                    (reply, _user) => {
                        if (this.enableEmailVerification) {
                            return reply.view(this.signupPage, {
                                next: next, 
                                csrfToken: request.csrfToken,
                                message: "Please check your email to finish signing up."
                            });
                        } else {
                            return reply.redirect(this.logoutRedirect);
                        }
                    });
                } catch (e) {
                    CrossauthLogger.logger.error(j({msg: "TOTP failure", hashedsSessionCookie: this.getHashOfSessionCookie(request)}));
                    CrossauthLogger.logger.debug(j({err: e}));
                    return this.handleError(e, reply, (reply, error) => {
                        return reply.view(this.signupPage, {
                            error: error.message,
                            errors: error.messages, 
                            code: error.code, 
                            errorCodeName: ErrorCode[error.code], 
                            next: next, 
                            persist: request.body.persist,
                            csrfToken: request.csrfToken,
                        });
                        
                    });
                }
            });
        }

        if (this.endpoints.includes("changepassword")) {
            if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "/changepassword enabled but sessions are not");
            this.app.get(this.prefix+'changepassword', async (request : FastifyRequest<{Querystring : LoginParamsType}>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "Page visit", method: 'GET', url: this.prefix+'changepassword', ip: request.ip, user: request.user?.username}));
                if (!request.user) return this.sendPageError(reply, 401);
                if (this.changePasswordPage)  { // if is redundant but VC Code complains without it
                    let data : {csrfToken: string|undefined} = {csrfToken: request.csrfToken};
                    return reply.view(this.changePasswordPage, data);
                }
            });

            this.app.post(this.prefix+'changepassword', async (request : FastifyRequest<{ Body: ChangePasswordBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'changepassword', ip: request.ip, user: request.user?.username}));
                if (!request.user) return this.sendPageError(reply, 401);
                try {
                    return await this.changePassword(request, reply, 
                    (reply, _user) => {
                        return reply.view(this.changePasswordPage, {
                            csrfToken: request.csrfToken,
                            message: "Your password has been changed."
                        });
                    });
                } catch (e) {
                    CrossauthLogger.logger.error(j({msg: "Change password failure", user: request.user.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                    CrossauthLogger.logger.debug(j({err: e}));
                    return this.handleError(e, reply, (reply, error) => {
                        return reply.view(this.changePasswordPage, {
                            error: error.message,
                            errors: error.messages, 
                            code: error.code, 
                            errorCodeName: ErrorCode[error.code], 
                            csrfToken: request.csrfToken,
                        });
                    });
                }
            });
        }

        if (this.endpoints.includes("updateuser")) {
            if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "/updateuser enabled but sessions are not");
            this.app.get(this.prefix+'updateuser', async (request : FastifyRequest<{Querystring : LoginParamsType}>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "Page visit", method: 'GET', url: this.prefix+'updateuser', ip: request.ip, user: request.user?.username}));
                if (!request.user) return this.sendPageError(reply, 401);
                if (this.updateUserPage)  { // if is redundant but VC Code complains without it
                    let data : {csrfToken: string|undefined, user: User} = {csrfToken: request.csrfToken, user: request.user};
                    return reply.view(this.updateUserPage, data);
                }
            });

            this.app.post(this.prefix+'updateuser', async (request : FastifyRequest<{ Body: UpdateUserBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'updateuser', ip: request.ip, user: request.user?.username}));
                if (!request.user) return this.sendPageError(reply, 401);
                try {
                    return await this.updateUser(request, reply, 
                    (reply, _user, emailVerificationRequired) => {
                        const message = emailVerificationRequired 
                            ? "Please click on the link in your email to verify your email address."
                            : "Your details have been updated";
                        return reply.view(this.updateUserPage, {
                            csrfToken: request.csrfToken,
                            message: message,
                        });
                    });
                } catch (e) {
                    CrossauthLogger.logger.error(j({msg: "Update user failure", user: request.body.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                    CrossauthLogger.logger.debug(j({err: e}));
                    let extraFields : { [key : string] : any }= {};
                    for (let field in request.body) {
                        if (field.startsWith("user_")) extraFields[field] = request.body[field];
                    }
                    return this.handleError(e, reply, (reply, error) => {
                        return reply.view(this.updateUserPage, {
                            error: error.message,
                            errors: error.messages, 
                            code: error.code, 
                            errorCodeName: ErrorCode[error.code], 
                            csrfToken: request.csrfToken,
                        });
                    });
                }
            });
        }

        if (this.endpoints.includes("requestpasswordreset")) {
            if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "/requestpasswordreset enabled but sessions are not");
            this.app.get(this.prefix+'requestpasswordreset', async (request : FastifyRequest, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "Page visit", method: 'GET', url: this.prefix+'requestpasswordreset', ip: request.ip}));
                if (this.requestPasswordResetPage)  { // if is redundant but VC Code complains without it
                    let data : {csrfToken: string|undefined} = {csrfToken: request.csrfToken};
                    return reply.view(this.requestPasswordResetPage, data);
                }
            });

            this.app.post(this.prefix+'requestpasswordreset', async (request : FastifyRequest<{ Body: RequestPasswordResetBodyType }>, reply : FastifyReply) =>  {
                const message = "If a user with exists with the email you entered, a message with "
                    + " a link to reset your password has been sent."; 
                    CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'requestpasswordreset', ip: request.ip}));
                    try {
                        return await this.requestPasswordReset(request, reply, 
                        (reply, _user) => {
                            return reply.view(this.requestPasswordResetPage, {
                                csrfToken: request.csrfToken,
                                message: message,
                            });
                        });
                } catch (e) {
                    CrossauthLogger.logger.error(j({msg: "Request password reset faiulure user failure", email: request.body.email}));
                    CrossauthLogger.logger.debug(j({err: e}));
                    return this.handleError(e, reply, (reply, error) => {
                        if (error.code == ErrorCode.EmailNotExist) {
                            return reply.view(this.requestPasswordResetPage, {
                                csrfToken: request.csrfToken,                                
                                message: message,
                            });
                        }
                        return reply.view(this.requestPasswordResetPage, {
                            error: error.message,
                            errors: error.messages, 
                            code: error.code, 
                            errorCodeName: ErrorCode[error.code], 
                            email: request.body.email,
                            csrfToken: request.csrfToken
                        });
                    });
                }
            });
        }

        if (this.endpoints.includes("resetpassword")) {
            if (!this.enableSessions || !this.enablePasswordReset) throw new CrossauthError(ErrorCode.Configuration, "Sessions and password reset must be enabled for /resetpassword");
            this.app.get(this.prefix+'resetpassword/:token', async (request : FastifyRequest<{Params : VerifyTokenParamType}>, reply : FastifyReply) =>  {
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
                    return reply.view(this.errorPage, {error: error, code: code, errorCodeName: ErrorCode[code]});
                }
                return reply.view(this.resetPasswordPage, {token: request.params.token, csrfToken: request.csrfToken});
            });

            this.app.post(this.prefix+'resetpassword', async (request : FastifyRequest<{ Body: ResetPasswordBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'resetpassword', ip: request.ip}));
                try {
                    return await this.resetPassword(request, reply, 
                    (reply, _user) => {
                        return reply.view(this.resetPasswordPage, {
                            csrfToken: request.csrfToken,
                            message: "Your password has been changed."
                        });
                    });
                } catch (e) {
                    CrossauthLogger.logger.error(j({msg: "Reset password failure", hashedToken: Hasher.hash(request.body.token), errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                    CrossauthLogger.logger.debug(j({err: e}));
                    return this.handleError(e, reply, (reply, error) => {
                        return reply.view(this.resetPasswordPage, {
                            error: error.message,
                            errors: error.messages, 
                            code: error.code, 
                            errorCodeName: ErrorCode[error.code], 
                            csrfToken: request.csrfToken,
                        });
                    });
                }
            });
        }

        if (this.endpoints.includes("verifyemail")) {
            if (!this.enableSessions || !this.enableEmailVerification) throw new CrossauthError(ErrorCode.Configuration, "Sessions and email verification  must be enabled for /verifyemail");
            this.app.get(this.prefix+'verifyemail/:token', async (request : FastifyRequest<{Params: VerifyTokenParamType}>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'verifyemail', ip: request.ip}));
                try {
                    return await this.verifyEmail(request, reply, 
                    (reply, user) => {
                        if (!this.emailVerifiedPage)  {
                            CrossauthLogger.logger.error("verify email requested but emailVerifiedPage not defined");
                            throw new CrossauthError(ErrorCode.Configuration, "There is a configuration error - please contact us if it persists");
                        }
                        return reply.view(this.emailVerifiedPage, {user: user});
                    });
                } catch (e) {
                    CrossauthLogger.logger.error(j({msg: "Verify email failed", hashedToken: Hasher.hash(request.params.token), errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                    CrossauthLogger.logger.debug(j({err: e}));
                    return this.handleError(e, reply, (reply, error) => {
                        return reply.view(this.errorPage, {
                            code: error.code, 
                            errorCodeName: ErrorCode[error.code], 
                            error: error.message,
                            errors: error.messages,
                        });
                    });
                }
             });
        }

        if (this.endpoints.includes("logout")) {
            if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "/logout enabled but sessions are not");
            this.app.post(this.prefix+'logout', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) => {
                CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'logout', ip: request.ip, user: request.user?.username}));
                try {
                    return await this.logout(request, reply, 
                    (reply) => {return reply.redirect(this.logoutRedirect)});
                } catch (e) {
                    CrossauthLogger.logger.error(j({msg: "Logout failure", user: request.user?.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                    CrossauthLogger.logger.debug(j({err: e}));
                    return this.handleError(e, reply, (reply, error) => {
                        return reply.view(this.errorPage, {error: error.message, errors: error.messages, code: error.code, errorCodeName: ErrorCode[error.code]});
                        
                    });
                }
            });

        }

        if (this.endpoints.includes("api/login")) {
            if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "/api/login enabled but sessions are not");
            this.app.post(this.prefix+'api/login', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/login', ip: request.ip}));
                if (request.user) return reply.header('Content-Type', JSONHDR).send({ok: false, user : request.user}); // already logged in
                try {
                    return await this.login(request, reply, 
                    (reply, user) => {
                        if (user.totpRequired) {
                            return reply.header('Content-Type', JSONHDR).send({ok: true, totpRequired: true});
                        } else {
                            return reply.header('Content-Type', JSONHDR).send({ok: true, user : user});
                        }
                    });
                } catch (e) {
                    CrossauthLogger.logger.error(j({msg: "Login failure", user: request.body.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                    CrossauthLogger.logger.debug(j({err: e}));
                    return this.handleError(e, reply, (reply, error) => {
                        reply.status(this.errorStatus(e)).header('Content-Type', JSONHDR).send({ok: false, error: error.message, errors: error.messages, code: error.code, errorCodeName: ErrorCode[error.code]});                    
                    });
                }
            });
        }

        if (this.endpoints.includes("api/logintotp")) {
            if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "/api/logintotp enabled but sessions are not");
            this.app.post(this.prefix+'api/logintotp', async (request : FastifyRequest<{ Body: LoginTotpBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/logintotp', ip: request.ip}));
                if (request.user) return reply.header('Content-Type', JSONHDR).send({ok: false, user : request.user}); // already logged in
                try {
                    return await this.logintotp(request, reply, 
                    (reply, user) => {
                        return reply.header('Content-Type', JSONHDR).send({ok: true, user : user});
                    });
                } catch (e) {
                    CrossauthLogger.logger.error(j({msg: "Login failure", hashOfSessionCookie: this.getHashOfSessionCookie(request), errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                    CrossauthLogger.logger.debug(j({err: e}));
                    return this.handleError(e, reply, (reply, error) => {
                        reply.status(this.errorStatus(e)).header('Content-Type', JSONHDR).send({ok: false, error: error.message, errors: error.messages, code: error.code, errorCodeName: ErrorCode[error.code]});                    
                    });
                }
            });
        }

        if (this.endpoints.includes("api/logout")) {
            if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "/api/logout enabled but sessions are not");
            this.app.post(this.prefix+'api/logout', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) => {
                CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/logout', ip: request.ip, user: request.user?.username}));
                if (!request.user) return this.sendJsonError(reply, 401, "You are not authorized to access this url");

                try {
                    return await this.logout(request, reply, 
                    (reply) => {return reply.header('Content-Type', JSONHDR).send({ok: true})});
                } catch (e) {
                    CrossauthLogger.logger.error(j({msg: "Logout failure", user: request.user?.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                    CrossauthLogger.logger.debug(j({err: e}));
                    return this.handleError(e, reply, (reply, error) => {
                        reply.status(this.errorStatus(e)).header('Content-Type', JSONHDR).send({ok: false, error: error.message, errors: error.messages, code: ErrorCode[error.code]});                    
                    });
                }
            });
        }

        if (this.endpoints.includes("api/signup")) {
            if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "/api/signup enabled but sessions are not");
            this.app.post(this.prefix+'api/signup', async (request : FastifyRequest<{ Body: SignupBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/signup', ip: request.ip, user: request.body.username}));
                try {
                    return await this.signup(request, reply, 
                    (reply, data, user) => {
                        return reply.header('Content-Type', JSONHDR).send({
                        ok: true,
                        user : user,
                        emailVerificationNeeded: this.enableEmailVerification||false,
                        totpNeeded: data.secret!=undefined,
                        secret: data.secret,
                    })});
                } catch (e) {
                    CrossauthLogger.logger.error(j({msg: "Signup failure", user: request.user?.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                    CrossauthLogger.logger.debug(j({err: e}));
                    this.handleError(e, reply, (reply, error) => {
                        reply.status(this.errorStatus(e)).header('Content-Type', JSONHDR).send({ok: false, error: error.message, errors: error.messages, code: ErrorCode[error.code]});                    
                    });
                }
            });
        }

        if (this.endpoints.includes("api/signuptotp")) {
            if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "/api/signup enabled but sessions are not");
            this.app.post(this.prefix+'api/signuptotp', async (request : FastifyRequest<{ Body: SignupTotpBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/signup', ip: request.ip, hashOfSessionCookie: this.getHashOfSessionCookie(request)}));
                try {
                    return await this.signuptotp(request, reply, 
                    (reply, user) => {
                        return reply.header('Content-Type', JSONHDR).send({
                        ok: true,
                        user : user,
                        emailVerificationNeeded: this.enableEmailVerification,
                    })});
                } catch (e) {
                    CrossauthLogger.logger.error(j({msg: "Signup TOTP configuration failure", user: request.user?.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                    CrossauthLogger.logger.debug(j({err: e}));
                    this.handleError(e, reply, (reply, error) => {
                        reply.status(this.errorStatus(e)).header('Content-Type', JSONHDR).send({ok: false, error: error.message, errors: error.messages, code: ErrorCode[error.code]});                    
                    });
                }
            });
        }

        if (this.endpoints.includes("api/changepassword")) {
            if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "/api/changepassword enabled but sessions are not");
            this.app.post(this.prefix+'api/changepassword', async (request : FastifyRequest<{ Body: ChangePasswordBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/changepassword', ip: request.ip, user: request.user?.username}));
                if (!request.user) return this.sendJsonError(reply, 401);
                try {
                    return await this.changePassword(request, reply, 
                    (reply, _user) => {return reply.header('Content-Type', JSONHDR).send({
                        ok: true,
                    })});
                } catch (e) {
                    CrossauthLogger.logger.error(j({msg: "Change password failure", user: request.user?.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                    CrossauthLogger.logger.debug(j({err: e}));
                    return this.handleError(e, reply, (reply, error) => {
                        return reply.status(this.errorStatus(e)).header('Content-Type', JSONHDR).send({ok: false, error: error.message, errors: error.messages, code: error.code, errorCodeName: ErrorCode[error.code]});                    
                    }, true);
                }
            });
        }

        if (this.endpoints.includes("api/updateuser")) {
            if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "/api/updateuser enabled but sessions are not");
            this.app.post(this.prefix+'api/updateuser', async (request : FastifyRequest<{ Body: UpdateUserBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/updateuser', ip: request.ip, user: request.user?.username}));
                if (!request.user) return this.sendJsonError(reply, 401);
                try {
                    return await this.updateUser(request, reply, 
                    (reply, _user, emailVerificationRequired) => {return reply.header('Content-Type', JSONHDR).send({
                        ok: true,
                        emailVerificationRequired: emailVerificationRequired,
                    })});
                } catch (e) {
                    CrossauthLogger.logger.error(j({msg: "Update user failure", user: request.user?.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                    CrossauthLogger.logger.debug(j({err: e}));
                    return this.handleError(e, reply, (reply, error) => {
                        reply.status(this.errorStatus(e)).header('Content-Type', JSONHDR).send({ok:false, error: error.message, errors: error.messages, code: error.code, errorCodeName: ErrorCode[error.code]});                    
                    }, true);
                }
            });
        }

        if (this.endpoints.includes("api/resetpassword")) {
            if (!this.enableSessions || !this.enablePasswordReset) throw new CrossauthError(ErrorCode.Configuration, "Sessions and password reset must be enabled for /api/resetpassword");
            this.app.post(this.prefix+'api/resetpassword', async (request : FastifyRequest<{ Body: ResetPasswordBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/resetpassword', ip: request.ip}));
                try {
                    return await this.resetPassword(request, reply, 
                    (reply, _user) => {return reply.header('Content-Type', JSONHDR).send({
                        ok: true,
                    })});
                } catch (e) {
                    CrossauthLogger.logger.error(j({msg: "Reset password failure", hashedToken: Hasher.hash(request.body.token), errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                    CrossauthLogger.logger.debug(j({err: e}));
                    return this.handleError(e, reply, (reply, error) => {
                        reply.status(this.errorStatus(e)).header('Content-Type', JSONHDR).send({ok: false, error: error.message, errors: error.messages, code: error.code, errorCodeName: ErrorCode[error.code]});                    
                    }, true);
                }
            });
        }

        if (this.endpoints.includes("api/requestpasswordreset")) {
            if (!this.enableSessions || !this.enablePasswordReset) throw new CrossauthError(ErrorCode.Configuration, "Sessions and password reset must be enabled for /api/requestpasswordreset");
            this.app.post(this.prefix+'api/requestpasswordreset', async (request : FastifyRequest<{ Body: RequestPasswordResetBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/resetpasswordrequest', ip: request.ip}));
                try {
                    return await this.requestPasswordReset(request, reply, 
                    (reply, _user) => {return reply.header('Content-Type', JSONHDR).send({
                        ok: true,
                    })});
                } catch (e) {
                    CrossauthLogger.logger.error(j({msg: "Reset password failure failure", email: request.body.email, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                    CrossauthLogger.logger.debug(j({err: e}));
                    return this.handleError(e, reply, (reply, error) => {
                        reply.status(this.errorStatus(e)).header('Content-Type', JSONHDR).send({ok: false, error: error.message, errors: error.messages, code: error.code, errorCodeName: ErrorCode[error.code]});                    
                    }, true);
                }
            });
        }

        if (this.endpoints.includes("api/verifyemail")) {
            if (!this.enableSessions || !this.enableEmailVerification) throw new CrossauthError(ErrorCode.Configuration, "Sessions and email verification must be enabled for /api/verifyemail");
            this.app.get(this.prefix+'api/verifyemail/:token', async (request : FastifyRequest<{Params: VerifyTokenParamType}>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/verifyemail', ip: request.ip}));
                try {
                    return await this.verifyEmail(request, reply, 
                    (reply, user) => {return reply.header('Content-Type', JSONHDR).send({
                        ok: true, 
                        user : user,
                    })});
                } catch (e) {
                    CrossauthLogger.logger.error(j({msg: "Verify email failure", hashedToken: Hasher.hash(request.params.token), errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                    CrossauthLogger.logger.debug(j({err: e}));
                    return this.handleError(e, reply, (reply, error) => {
                        reply.status(this.errorStatus(e)).header('Content-Type', JSONHDR).send({ok: false, error: error.message, errors: error.messages, code: error.code, errorCodeName: ErrorCode[error.code]});                    
                    });
                }
            });
        }

        if (this.endpoints.includes("api/userforsessionkey")) {
            if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "/api/userforsessionkey enabled but sessions are not");
            this.app.post(this.prefix+'api/userforsessionkey', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/userforsessionkey', ip: request.ip, user: request.user?.username, hashedSessionCookie: this.getHashOfSessionCookie(request)}));
                if (!request.user) return this.sendJsonError(reply, 401);
                await this.validateCsrfToken(request, reply)
                try {
                    let user : User|undefined;
                    const sessionId = this.getSessionIdFromCookie(request);
                    if (sessionId) user = await this.sessionManager.userForSessionKey(sessionId);
                    return reply.header('Content-Type', JSONHDR).send({ok: true, user : user});
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
                    return reply.status(this.errorStatus(e)).header('Content-Type', JSONHDR).send({ok: false, code: code, errorCodeName: ErrorCode[code], error : error});

                }
            });
        }

        if (this.endpoints.includes("api/getcsrftoken")) {
            if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "/api/getcsrftoken enabled but sessions are not");
            this.app.get(this.prefix+'api/getcsrftoken', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/getcsrftoken', ip: request.ip, user: request.user?.username}));
                try {
                    return reply.header('Content-Type', JSONHDR).send({ok: true, csrfToken : request.csrfToken});
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
                    return reply.status(this.errorStatus(e)).header('Content-Type', JSONHDR).send({ok: false, code: code, errorCodeName: ErrorCode[code], error : error});

                }
            });
    
        }
    }
    
    private async login(request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, user: User) => void) {
        if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled");
        if (request.user) return successFn(reply, request.user); // already logged in
        const username = request.body.username;
        const password = request.body.password;
        const persist = request.body.persist;
        const csrfFormOrHeaderValue = request.body.csrfToken;
        const csrfCookieValue = this.getCsrfTokenFromCookie(request);
        await this.sessionManager.validateDoubleSubmitCsrfToken(csrfCookieValue, csrfFormOrHeaderValue);

        const oldSessionId = this.getSessionIdFromCookie(request);

        let extraFields = this.addToSession ? this.addToSession(request) : {}
        let { sessionCookie, csrfCookie, user, secrets } = await this.sessionManager.login(username, password, extraFields, persist);
        CrossauthLogger.logger.debug(j({msg: "Login: set session cookie " + sessionCookie.name + " opts " + JSON.stringify(sessionCookie.options), user: request.body.username}));
        reply.cookie(sessionCookie.name, sessionCookie.value, sessionCookie.options);
        CrossauthLogger.logger.debug(j({msg: "Login: set csrf cookie " + csrfCookie.name + " opts " + JSON.stringify(sessionCookie.options), user: request.body.username}));
        reply.cookie(csrfCookie.name, csrfCookie.value, csrfCookie.options);
        request.csrfToken = await this.sessionManager.createCsrfFormOrHeaderValue(csrfCookie.value);
        if (oldSessionId) {
            try {
                await this.sessionManager.deleteSessionId(oldSessionId);
            } catch (e) {
                CrossauthLogger.logger.warn(j({msg: "Couldn't delete session ID from database", hashedSessionCookie: this.getHashOfSessionCookie(request)}));
                CrossauthLogger.logger.debug(j({err: e}));
            }
        }
        user.totpRequired = "totpSecret" in secrets && secrets.totpSecret != "";
        return successFn(reply, user);
    }

    private async logintotp(request : FastifyRequest<{ Body: LoginTotpBodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, user: User) => void) {
        if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled");
        if (request.user) return successFn(reply, request.user); // already logged in
        const oldSessionCookieValue = this.getSessionIdFromCookie(request);
        if (!oldSessionCookieValue) throw new CrossauthError(ErrorCode.Unauthorized);
        const persist = request.body.persist;
        const csrfFormOrHeaderValue = request.body.csrfToken;
        const csrfCookieValue = this.getCsrfTokenFromCookie(request);
        await this.sessionManager.validateDoubleSubmitCsrfToken(csrfCookieValue, csrfFormOrHeaderValue);
        let extraFields = this.addToSession ? this.addToSession(request) : {}
        const {sessionCookie, csrfCookie, user} = await this.sessionManager.completeTotpLogin(request.body.totpCode, oldSessionCookieValue, extraFields, persist);
        
        CrossauthLogger.logger.debug(j({msg: "Login: set session cookie " + sessionCookie.name + " opts " + JSON.stringify(sessionCookie.options), user: user?.username}));
        reply.cookie(sessionCookie.name, sessionCookie.value, sessionCookie.options);
        CrossauthLogger.logger.debug(j({msg: "Login: set csrf cookie " + csrfCookie.name + " opts " + JSON.stringify(sessionCookie.options), user: user?.username}));
        reply.cookie(csrfCookie.name, csrfCookie.value, csrfCookie.options);
        request.csrfToken = await this.sessionManager.createCsrfFormOrHeaderValue(csrfCookie.value);
        return successFn(reply, user);
    }

    private async loginWithUser(user: User, request : FastifyRequest, reply : FastifyReply, 
        successFn : (res : FastifyReply, user: User) => void) {
        if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled");
        const oldSessionId = this.getSessionIdFromCookie(request);

        let extraFields = this.addToSession ? this.addToSession(request) : {}
        let { sessionCookie, csrfCookie } = await this.sessionManager.login("", "", extraFields, undefined, user);
        CrossauthLogger.logger.debug(j({msg: "Login: set session cookie " + sessionCookie.name + " opts " + JSON.stringify(sessionCookie.options), user: user.username}));
        reply.cookie(sessionCookie.name, sessionCookie.value, sessionCookie.options);
        CrossauthLogger.logger.debug(j({msg: "Login: set csrf cookie " + csrfCookie.name + " opts " + JSON.stringify(sessionCookie.options), user: user.username}));
        reply.cookie(csrfCookie.name, csrfCookie.value, csrfCookie.options);
        if (oldSessionId) {
            try {
                await this.sessionManager.deleteSessionId(oldSessionId);
            } catch (e) {
                CrossauthLogger.logger.warn(j({msg: "Couldn't delete session ID from database", hashedSessionCookie: this.getHashOfSessionCookie(request)}));
                CrossauthLogger.logger.debug(j({err: e}));
            }
        }
        return successFn(reply, user);
    }

    private async signup(request : FastifyRequest<{ Body: SignupBodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, data: {[key:string]:any}, user? : User) => void) {
            
        const username = request.body.username;
        const password = request.body.password;
        const repeatPassword = request.body.repeatPassword;
        const next = request.body.next;
        const totp = request.body.totp == "on";
        let extraFields : {[key:string] : string|number|boolean|Date|undefined}= {};
        for (let field in request.body) {
            let name = field.replace("user_", ""); 
            if (field.startsWith("user_")) extraFields[name] = request.body[field];
        }
        let userToValidate : User = {
            id: "",
            username: username,
            state: "active",
            ...extraFields,
        }
        let passwordErrors = this.validatePassword(password);
        let userErrors = this.validateUser(userToValidate);
        let errors = [...userErrors, ...passwordErrors];
        if (errors.length > 0) {
            throw new CrossauthError(ErrorCode.FormEntry, errors);
        }
        if (repeatPassword != undefined && repeatPassword != password) {
            throw new CrossauthError(ErrorCode.PasswordMatch);
        }

        // See if the user was already created, with the correct password, and is awaiting TOTP
        // completion.  Send the same response as before, in case the user closed the browser
        let totpInitiated = false;
        try {
            await this.sessionManager.authenticator.authenticateUser(username, password);
        } catch (e) {
            if (e instanceof CrossauthError && e.code == ErrorCode.TotpIncomplete) {
                totpInitiated = true;
            } // all other errors are legitimate ones - we ignore them
        }
        
        if ((this.totp == "off" || (this.totp == "peruser" && !totp)) && !totpInitiated) {
            // not enabling TOTP
            if (this.addToUser) extraFields = {...extraFields, ...this.addToUser(request)};
            await this.sessionManager.createUser(username, password, extraFields);
            if (!this.enableEmailVerification && this.enableSessions) {
                return this.login(request, reply, successFn);
            }
            return successFn(reply, {}, undefined);
        } else {
            // also enabling TOTP
            let qrUrl : string;
            let secret : string;
            if (totpInitiated) {
                // account already created but TOTP setup not complete
                const sessionValue = this.getSessionIdFromCookie(request);
                if (!sessionValue) throw new CrossauthError(ErrorCode.Unauthorized);
                const resp = await this.sessionManager.repeatTotpSignup(username, sessionValue);
                qrUrl = resp.qrUrl;
                secret = resp.secret;
            } else {
                // account not created - create one with state awaiting TOTP setup
                const sessionValue = await this.createAnonymousSession(request, reply);
                if (this.addToUser) extraFields = {...extraFields, ...this.addToUser(request)};
                const resp = await this.sessionManager.initiateTotpSignup(username, password, extraFields,
                sessionValue);
                qrUrl = resp.qrUrl;
                secret = resp.secret;
            }
            request.totp = {
                qr : qrUrl,
                username: username,
            }

            try {
                let data : {qr: string, username: string, next : string, csrfToken: string|undefined, secret: string} = 
                {
                    qr: qrUrl,
                    secret: secret,
                    username: username,
                    next: next||this.loginRedirect,
                    csrfToken: request.csrfToken,
                };
                //return reply.view(this.signupTotpPage, data);
                return successFn(reply, data)
            } catch (e) {
                CrossauthLogger.logger.error(j({err: e}));
                try {
                    this.sessionManager.deleteUserByUsername(username);
                } catch (e) {
                    CrossauthLogger.logger.error(j({err: e}));
                }

            }
        }
    }

    private async signuptotp(request : FastifyRequest<{ Body: SignupTotpBodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, user? : User) => void) {
        const sessionId = this.getSessionIdFromCookie(request);
        let user;
        try {
            if (!sessionId) throw new CrossauthError(ErrorCode.Unauthorized, "No session active while enabling TOTP.  Please enable cookies");
            const totpCode = request.body.totpCode;
            user = await this.sessionManager.completeTotpSignup(totpCode, sessionId);
        } catch (e) {
            CrossauthLogger.logger.error(j({msg: "Signtototp failed", hashedSessionCookie: this.getHashOfSessionCookie(request) }));
            CrossauthLogger.logger.debug(j({err: e}));
            /*try {
                if (sessionId) {
                    const data = await this.sessionManager.dataForSessionKey(sessionId);
                    const dataObj = JSON.parse(data||"");
                    if (dataObj.username)  this.sessionManager.deleteUserByUsername(dataObj.username);
                }
            } catch (e) {
                CrossauthLogger.logger.error(j({err: e}));
            }*/
            throw e;
        }
        return successFn(reply, user);
    }

    private async changePassword(request : FastifyRequest<{ Body: ChangePasswordBodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, user? : User) => void) {
        if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled");

        if (!request.user) throw new CrossauthError(ErrorCode.Unauthorized);
        await this.validateCsrfToken(request, reply)
        const oldPassword = request.body.oldPassword;
        const newPassword = request.body.newPassword;
        const repeatPassword = request.body.repeatPassword;
        if (repeatPassword != undefined && repeatPassword != newPassword) {
            throw new CrossauthError(ErrorCode.PasswordMatch);
        }
        let errors = this.validatePassword(newPassword);
        if (errors.length > 0) {
            throw new CrossauthError(ErrorCode.PasswordFormat);
        }
        await this.sessionManager.changePassword(request.user.username, oldPassword, newPassword);
        return successFn(reply, undefined);
    }

    private async updateUser(request : FastifyRequest<{ Body: UpdateUserBodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, user : User, emailVerificationRequired : boolean) => void) {
        if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled");

        if (!request.user) throw new CrossauthError(ErrorCode.Unauthorized);
        await this.validateCsrfToken(request, reply);
        let user : User = {
            id: request.user.id,
            username: request.user.username,
            state: "active",
        };
        for (let field in request.body) {
            if (field.startsWith("user_")) {
                const fieldName = field.replace("user_", "");
                user[fieldName] = request.body[field];
            }
        }
        let emailVerificationNeeded = await this.sessionManager.updateUser(request.user, user);
        return successFn(reply, request.user, emailVerificationNeeded);
    }

    private async requestPasswordReset(request : FastifyRequest<{ Body: RequestPasswordResetBodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, user? : User) => void) {
        if (!this.enablePasswordReset) {
            throw new CrossauthError(ErrorCode.Configuration, "password reset not enabled");
        }
        if (this.anonymousSessions) {
            await this.validateCsrfToken(request, reply);
        }
        const email = request.body.email;

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
        if (!this.enableEmailVerification) throw new CrossauthError(ErrorCode.Configuration, "Email verification reset not enabled");
        const token = request.params.token;
        const user = await this.sessionManager.applyEmailVerificationToken(token);
        return await this.loginWithUser(user, request, reply, successFn);
    }

    private async resetPassword(request : FastifyRequest<{ Body: ResetPasswordBodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, user? : User) => void) {
        if (this.anonymousSessions) await this.validateCsrfToken(request, reply);
        //const user = await this.sessionManager.userForPasswordResetToken(request.body.token);
        const token = request.body.token;
        const newPassword = request.body.newPassword;
        const repeatPassword = request.body.repeatPassword;
        if (repeatPassword != undefined && repeatPassword != newPassword) {
            throw new CrossauthError(ErrorCode.PasswordMatch);
        }
        let errors = this.validatePassword(newPassword);
        if (errors.length > 0) {
            throw new CrossauthError(ErrorCode.PasswordFormat);
        }
        const user = await this.sessionManager.resetPassword(token, newPassword);
        return this.loginWithUser(user, request, reply, successFn);
    }

    private async logout(request : FastifyRequest, reply : FastifyReply, 
        successFn : (reply : FastifyReply) => void) {
        if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled");
        let sessionId = this.getSessionIdFromCookie(request);
        if (sessionId) {
                await this.sessionManager.logout(sessionId);
        }
        CrossauthLogger.logger.debug(j({msg: "Logout: clear cookie " + this.sessionManager.sessionCookieName}));
        reply.clearCookie(this.sessionManager.sessionCookieName);
        reply.clearCookie(this.sessionManager.csrfCookieName);
        if (sessionId) {
            try {
                await this.sessionManager.deleteSessionId(sessionId);
            } catch (e) {
                CrossauthLogger.logger.warn(j({msg: "Couldn't delete session ID from database", hashedSessionCookie: this.getHashOfSessionCookie(request)}));
                CrossauthLogger.logger.debug(j({err: e}));
            }
        }
        return successFn(reply);

    }

    async createAnonymousSession(request : FastifyRequest, reply : FastifyReply) : Promise<string> {
        CrossauthLogger.logger.debug(j({msg: "Creating session ID"}));
        let extraFields = this.addToSession ? this.addToSession(request) : {}
        let { sessionCookie, csrfCookie, csrfFormOrHeaderValue } = await this.sessionManager.createAnonymousSession(extraFields);
        reply.cookie(sessionCookie.name, sessionCookie.value, sessionCookie.options);
        request.csrfToken = csrfFormOrHeaderValue;
        reply.setCookie(csrfCookie.name, csrfCookie.value, csrfCookie.options);
        request.user = undefined;
        return sessionCookie.value;
    };

    private handleError(e : any, reply : FastifyReply, errorFn : (reply : FastifyReply, error : CrossauthError) => void, passwordInvalidOk? : boolean) {
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
        CrossauthLogger.logger.error(j({err: e}));

        return errorFn(reply, ce);

    }

    private getSessionIdFromCookie(request : FastifyRequest) : string|undefined{
        if (request.cookies && this.sessionManager.sessionCookieName in request.cookies) {       
            return request.cookies[this.sessionManager.sessionCookieName]
        }
        return undefined;
    }

    private getCsrfTokenFromCookie(request : FastifyRequest) : string|undefined{
        if (request.cookies && this.sessionManager.csrfCookieName in request.cookies) {       
            return request.cookies[this.sessionManager.csrfCookieName]
        }
        return undefined;
    }

    private getHashOfSessionCookie(request : FastifyRequest) : string {
        const cookieValue = this.getSessionIdFromCookie(request);
        if (!cookieValue) return "";
        try {
            return Hasher.hash(cookieValue);
        } catch (e) {}
        return "";
    }

    private getHashOfCsrfCookie(request : FastifyRequest) : string {
        const cookieValue = this.getCsrfTokenFromCookie(request);
        if (!cookieValue) return "";
        try {
            return Hasher.hash(cookieValue);
        } catch (e) {}
        return "";
    }

    /**
     * Checks the CSRF token in the cookie and form field/header is valid.
     * 
     * Doesn't return a value.  Exits successfully if the token is present and valid.  Throws a
     * CrossauthError with ErrorCode.InvalidKey if it is not.
     * 
     * The token in the cookie must have a signature that matches its payload.  The payload must match
     * the value in the csrfToken form field or X-CROSSAUTH-CSRF header.
     * 
     * @param request the fastify request
     * @param _reply the fastify reply
     * @param sessionId if given, use this as the session ID.  If undefined, it is taken from the request cookie
     */
    async validateCsrfToken(request : FastifyRequest<{ Body: CsrfBodyType }>, 
                            _reply : FastifyReply) {
        let csrfCookie = this.getCsrfTokenFromCookie(request);
        if (!csrfCookie) {
            CrossauthLogger.logger.warn(j({msg: "No CSRF cookie found when validating CSRF token", hashedCsrfToken: Hasher.hash(request.body.csrfToken||"")}));
            throw new CrossauthError(ErrorCode.InvalidKey);
        }
        if (!request.csrfToken) {
            CrossauthLogger.logger.warn(j({msg: "No CSRF form or header token found when validating CSRF token", hashedCsrfCookie: this.getHashOfCsrfCookie(request)}));
            throw new CrossauthError(ErrorCode.InvalidKey);
        }
        this.sessionManager.validateDoubleSubmitCsrfToken(csrfCookie, request.csrfToken);
    }

    private csrfToken(request : FastifyRequest<{Body: CsrfBodyType}>, reply : FastifyReply) {
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
                this.sessionManager.validateDoubleSubmitCsrfToken(this.getCsrfTokenFromCookie(request), token);
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

    /**
     * Return this from a view to send back an error which is rendered as an HTML page
     * 
     * if `errorPage` is defined, it is used as a template with the variables `status`, `error`, `code`,
     * `codeName`.  Otherwise a simple default is displayed
     * @param reply ther Fastify reply obkevct
     * @param status the HTTP error status to return
     * @param error an optional error message.  If not given and `e` is defined, it will be set to `e.message`.  If not, a simple default will be displayed
     * @param e an exception.  If passed, the code and error message will be taken from it
     * @returns the fastify reply object
     */
    sendPageError(reply : FastifyReply, status : number, error?: string, e? : any) {
        let code = 0;
        let codeName = "UnknownError";
        if (e instanceof CrossauthError) {
            code = e.code;
            codeName = ErrorCode[code];
            if (!error) error = e.message;
        }   
        if (!error) {
            if (status == 401) {
                error = "You are not authorized to access this page";
                code = ErrorCode.Unauthorized;
                codeName = ErrorCode[code];
            } else if (status == 403) {
                error = "You do not have permission to access this page";
                code = ErrorCode.Forbidden;
                codeName = ErrorCode[code];
            } else {
                error = "An unknwon error has occurred"
            }
        }         
        CrossauthLogger.logger.warn(j({msg: error, code: code, errorCodeName: codeName, httpStatus: status}));
        if (this.errorPage) {
            return reply.status(status).view(this.errorPage, {status: status, error: error, code: code, errorCodeName: codeName});
        } else {
            return reply.status(status).send(status==401 ? ERROR_401 : ERROR_500);
        }
    }

    /**
     * Return this from a view to send back an error as a JSON message
     * 
     * The JSON will contain the variables `ok`, `status`, `error`, `code`,
     * `codeName`.  Otherwise a simple default is displayed
     * @param reply ther Fastify reply obkevct
     * @param status the HTTP error status to return
     * @param error an optional error message.  If not given and `e` is defined, it will be set to `e.message`.  If not, a simple default will be displayed
     * @param e an exception.  If passed, the code and error message will be taken from it
     * @returns the fastify reply object
     */
    sendJsonError(reply : FastifyReply, status : number, error?: string, e? : any) {
        let code = 0;
        let codeName = "UnknownError";
        if (e instanceof CrossauthError) {
            code = e.code;
            codeName = ErrorCode[code];
            if (!error) error = e.message;
        }            
        if (!error) error = "Unknown error";
        CrossauthLogger.logger.warn(j({msg: error, code: code, errorCodeName: codeName, httpStatus: status}));
        return reply.header('Content-Type', JSONHDR).status(status).send({ok: false, status: status, error: error, code: code, errorCodeName: codeName});
    }

    /** Simple helper function to return httpStatus from the passed object or 500 if it is not present. */
    errorStatus(e : any) {
        if (typeof e == "object" && "httpStatus" in e) return e.httpStatus||500;
        return 500;
    }

    /**
     * Starts the Fastify app on the given port.  
     * @param port the port to listen on
     */
    start(port : number = 3000) {
        this.app.listen({ port: port}, () =>
            CrossauthLogger.logger.info(j({msg: "Starting fastify server", port: port, prefix: this.prefix})),
        );

    }
}
