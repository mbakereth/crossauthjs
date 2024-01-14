import fastify, { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import view from '@fastify/view';
import fastifyFormBody from '@fastify/formbody';
import type { FastifyCookieOptions } from '@fastify/cookie'
import cookie from '@fastify/cookie'
import { Server, IncomingMessage, ServerResponse } from 'http'

import nunjucks from "nunjucks";
import { UserStorage, KeyStorage } from './storage';
import { UsernamePasswordAuthenticator } from './password';
import { Cookie } from './cookieauth';
import { Backend, type BackendOptions } from './backend';
import { CrossauthError, ErrorCode } from "..";
import { User } from '../interfaces';
import { CrossauthLogger } from '..';
import { setParameter, ParamType } from './utils';

const CSRFHEADER = "X-CROSSAUTH-CSRF";

/**
 * Options for {@link FastifyCookieAuthServer }.
 * 
 * See {@link FastifyCookieAuthServer } constructor for description of parameters
 */
export interface FastifyCookieAuthServerOptions extends BackendOptions {

    /** You can pass your own fastify instance or omit this, in which case Crossauth will create one */
    app? : FastifyInstance<Server, IncomingMessage, ServerResponse>,

    /** List of endpoints to add to the server ("login", "api/login", etc, prefixed by the `prefix` parameter.  Empty or `"all"` for all.  Default all.) */
    endpoints? : string,

    /** Page to redirect to after successful login, default "/" */
    loginRedirect? : string;

    /** Page to redirect to after successful logout, default "/" */
    logoutRedirect? : string;

    /** Function that throws a {@link index!CrossauthError} with {@link index!ErrorCode} `PasswordFormat` if the password doesn't confirm to local rules (eg number of charafters)  */
    passwordValidator? : (password: string) => string[];

    /** Function that throws a {@link index!CrossauthError} with {@link index!ErrorCode} `FormEnty` if the user doesn't confirm to local rules.  Doesn't validate passwords  */
    userValidator? : (user: User) => string[];

    /** Template file containing the login page (with without error messages).  
     * See the class documentation for {@link FastifyCookieAuthServer} for more info.  Defaults to "login.njk".
     */
    loginPage? : string;

    /** Template file containing the signup page (with without error messages).  
     * See the class documentation for {@link FastifyCookieAuthServer} for more info.  Defaults to "signup.njk".
     * You can disable this and instead have your own signup page.  Call api/signup to create the user.
     * Signup form should contain at least `username` and `password` and may also contain `repeatPassword`.  If you have additional
     * fields in your user table you want to pass from your form, prefix them with `user_`, eg `user_email`.
     * If you want to enable email verification, set `enableEmailVerification` and `checkEmailVerified` 
     * on the user storage.
     */
    signupPage? : string;

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

    /** If true, a session ID will be created even when the user is not logged in.  This enabled 
     * CSRF tokens to be sent and used even without a user being logged in.  Default true
     */
    anonymousSessions? : boolean,

    /** If true, and anonymousSessions is also true, the anonymous session ID will be kept after 
     * the user logs in.  Useful, for example, on web shops where a user can start creating a basked before
     * logging in.  Default false
     */
    keepAnonymousSessionId? : boolean,
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

interface SignupBodyType extends LoginBodyType {
    repeatPassword?: string,
    email? : string,
    [key : string]: string|number|Date|boolean|undefined,
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
 *    * GET `/login` : Renders your login page.  
 *      If there was an authentication error, this page is also rendered with `error` set to the error message
 *      (display it with `{{ error }}` in your template).
 *    * POST `/login` : processes a login.  Reads `username` and `password` from the POST parameters or JSON body.
 *      If the credentials are valid, sets a session ID cookie and sends a redirect to `loginRedirect` 
 *      (or to `/` if this wasn't set).  If there is an error, the `loginPage` is rendered with `error` set to 
 *      the error message (see GET `/login`) above.  IF `loginPage` is not set, the `errorPage` is rendered
 *      instead.  If this is also not set, a bare bones error page is displayeds.
 *    * GET `/changepassword` : Page to render
 *      for password changes.  Reads `oldPassword`, `newPassword` and `repeatPassword` fields from the form.
 *    * POST `/changepassword` : processes the password change.  If successful, the `message` variable will
 *      be set.  If unsuccessful, the `error` variable will be set.  You can only activate /changepassword
 *      if either the user storage contains an email field or else the username is in email format.
 *    * GET `/requestresetpassword` : Renders a page to request password reset.  This page should ask the user
 *      for an email address in a `email` form field.  The form should make a `POST` request to
 *      `{{ siteUrl}}{{ prefix }}resetpassword`.  Upon success, the same page will be rendered with `message`
 *      set (display it with `{{ message }}`).  On error, `error` will instead me set to be displayed
 *      with `{{ error}}`
 *    * POST `/requestresetpassword` : Called from the above `GET` method.
 *      GET `/resetpassword` : called only once the reset token has been authenticated.  Use this to ask for
 *      a new password.  Reads the `newPassword` and `repeatPassword` fields.
 *    * GET `emailVerifiedPage` : page to render when confirming user's email has been verified.  If not set,
 *      email verification will not be activated.  You should also set `checkEmailVerified` in your 
 *      {@link UserStorage} so that a user cannot log in until email has been verified.  For email verification
 *      to work, either you need an `email` field in your user storage or your username must have an email
 *      format.
 *    * POST `/api/login` takes the same parameters as POST `/login` but returns a JSON string, both upon success
 *      or failure.  If login was successful, this will be `{status: "ok"}` and the session cookie will also be
 *      sent.  If login was not successful, it will be `{"status; "error", error: message, code: code}` where
 *      code is in {@link index!ErrorCode }.  Only created if `addApiEndpoints` is true.
 *    * POST `/api/logout` logs a ser out, ie deletes the session key given in the cookie 
 *      and clears the cookie.  It returns `{status: "ok"}`.  Only created if `addApiEndpoints` is true.
 *      or  `{"status; "error", error: message, code: code}` if there was an error.
 *    * GET `/api/userforsessionke` takes the session ID in the cookie and returns the user associated with it.
 *      Returns `{status: "ok"}` or  `{"status; "error", error: message, code: code}` if there was an error.
 *      Only created if `addApiEndpoints` is true.
 * 
 *    **Using your own Fastify app**
 * 
 * If you are serving other endpoints, or you want to use something other than Nunjucks, you can create and
 * pass in your own Fastify app.
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
    private loginPage : string = "login.njk";
    private errorPage : string = "error.njk";
    private changePasswordPage : string = "changepassword.njk";
    private updateUserPage : string = "updateuser.njk";
    private resetPasswordPage: string = "resetpassword.njk";
    private requestPasswordResetPage: string = "requestpasswordreset.njk";
    private emailVerifiedPage : string = "emailverified.njk";
    private sessionManager : Backend;
    private anonymousSessions = true;
    private keepAnonymousSessionId = false;
    private passwordValidator : (password : string) => string[] = defaultPasswordValidator;
    private userValidator : (user : User) => string[] = defaultUserValidator;
    private enableEmailVerification : boolean = true;
    private enablePasswordReset : boolean = true;

    /**
     * Creates the Fastify endpoints, optionally also the Fastify app.
     * @param optoions see {@link FastifyCookieAuthServerOptions}
     */
    constructor(userStorage: UserStorage, 
                keyStorage: KeyStorage, 
                authenticator: UsernamePasswordAuthenticator, 
                options: FastifyCookieAuthServerOptions = {}) {

        setParameter("enableSessions", ParamType.Boolean, this, options, "ENABLE_SESSIONS");

        this.endpoints = [...SignupPageEndpoints, ...SignupApiEndpoints];
        if (this.enableSessions) this.endpoints = [...this.endpoints, ...SessionPageEndpoints, ...SessionApiEndpoints];
        if (this.enableEmailVerification) this.endpoints = [...this.endpoints, ...EmailVerificationPageEndpoints, ...EmailVerificationApiEndpoints];
        if (this.enablePasswordReset) this.endpoints = [...this.endpoints, ...PasswordResetPageEndpoints, ...PasswordResetApiEndpoints];
        setParameter("endpoints", ParamType.StringArray, this, options, "ENDPOINTS");

        setParameter("views", ParamType.String, this, options, "VIEWS");
        setParameter("prefix", ParamType.String, this, options, "PREFIX");
        setParameter("signupPage", ParamType.String, this, options, "SIGNUP_PAGE");
        setParameter("loginPage", ParamType.String, this, options, "LOGIN_PAGE");
        setParameter("errorPage", ParamType.String, this, options, "ERROR_PAGE");
        setParameter("changePasswordPage", ParamType.String, this, options, "CHANGE_PASSWORD_PAGE");
        setParameter("updateUser", ParamType.String, this, options, "UPDATE_USER_PAGE");
        setParameter("resetPasswordPage", ParamType.String, this, options, "RESET_PASSWORD_PAGE");
        setParameter("requestPasswordResetPage", ParamType.String, this, options, "REQUEST_PASSWORD_RESET_PAGE");
        setParameter("emailVerifiedPage", ParamType.String, this, options, "EMAIL_VERIFIED_PAGE");
        setParameter("enableEmailVerification", ParamType.Boolean, this, options, "ENABLE_EMAIL_VERIFICATION");
        setParameter("enablePasswordReset", ParamType.Boolean, this, options, "ENABLE_PASSWORD_RESET");
        setParameter("emailFrom", ParamType.String, this, options, "EMAIL_FROM");
        setParameter("anonymousSessions", ParamType.Boolean, this, options, "ANONYMOUS_SESSIONS");
        setParameter("keepAnonymousSessionId", ParamType.Boolean, this, options, "KEEP_ANONYMOUS_SESSION_ID");
        setParameter("persistSessionId", ParamType.Boolean, this, options, "PERSIST_SESSION_ID");

        if (options.passwordValidator) this.passwordValidator = options.passwordValidator;
        if (options.userValidator) this.userValidator = options.userValidator;

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
                    
        /*this.app.setErrorHandler(function (error, _request, reply) {
            CrossauthLogger.logger.error(error);
            return reply.view(this.errorPage, {error: error, code: ErrorCode[ErrorCode.UnknownError], });
        })*/
            
        // validates the session id and csrftokens, creating if necessary and putting the csrf token
        // and user in the request object.
        this.app.addHook('onRequest', async (request : FastifyRequest<{Body: CsrfBodyType}>, reply : FastifyReply) => {

            // if sessions are not enabled, nothing to do
            if (!this.enableSessions) return;

            // get existing cookies (unvalidated)
            let sessionId = this.getSessionIdFromCookie(request);
            let csrfToken = this.getCsrfTokenFromCookie(request);

            // validate the session if and csrf token
            let {sessionCookie, csrfCookie, user} = await this.sessionManager.getValidatedSessionAndCsrf(sessionId, csrfToken);

            let safeMethod = ["GET", "HEAD", "OPTIONS"].includes(request.method);
            if (!sessionCookie && !safeMethod) {
                // we don't create session ids or csrf cookies for these methods.  If the cookies
                // are not valid, delete them and return
                if (!sessionId) {
                    CrossauthLogger.logger.debug("Invalid session cookie received - deleting");
                    reply.clearCookie(this.sessionManager.sessionCookieName);
                }
                if (!csrfToken) {
                    CrossauthLogger.logger.debug("Invalid csrf cookie received - deleting");
                    reply.clearCookie(this.sessionManager.csrfCookieName);
                }
                return;
            }
            if (sessionId && !sessionCookie) {
                // session cookie exists but is invalid - delete it
                CrossauthLogger.logger.debug("Invalid session cookie received - deleting");
                reply.clearCookie(this.sessionManager.sessionCookieName);   
                if (csrfToken) {         
                    CrossauthLogger.logger.debug("Invalid csrf cookie received - deleting");
                    reply.clearCookie(this.sessionManager.csrfCookieName);
                }
            } else if (csrfToken && !csrfCookie) {
                // session id is valid but csrf token isn't - delete it
                CrossauthLogger.logger.debug("Invalid csrf cookie received - deleting");
                reply.clearCookie(this.sessionManager.csrfCookieName);
            }
            else if (!sessionCookie && csrfToken) {
                // csrf token exists but session is not valid - delete it
                CrossauthLogger.logger.debug("Invalid csrf cookie received - deleting");
                reply.clearCookie(this.sessionManager.csrfCookieName);
            }

            if (safeMethod) {

                // create cookies if they don't exist already or were invalid
                if ((!sessionCookie || !csrfToken) && this.anonymousSessions) {

                    // session cookie is not valid - create one, along with the csrf token
                    let {sessionCookie: newSessionCookie, csrfCookie: newCsrfCookie, user: newUser, sessionCookieCreated, csrfCookieCreated} = await this.sessionManager.createAnonymousSessionKeyIfNoneExists(sessionId);
                    sessionCookie = newSessionCookie;
                    csrfCookie = newCsrfCookie;
                    user = newUser;
                    if (sessionCookieCreated) {
                        CrossauthLogger.logger.debug("Creating anonymous session cookie");
                        reply.cookie(sessionCookie.name, sessionCookie.value, sessionCookie.options);
                    }
                    if (csrfCookieCreated) {
                        CrossauthLogger.logger.debug("Creating csrf cookie");
                        reply.cookie(csrfCookie.name, csrfCookie.value, csrfCookie.options);
                    }
 
                } else if (!csrfToken && sessionCookie) {

                    // session id is valid but csrf token is not - create it
                    CrossauthLogger.logger.debug("Creating csrf token for user " + user?.username);
                    csrfCookie = await this.sessionManager.createCsrfToken(sessionCookie.value);
                    reply.cookie(csrfCookie.name, csrfCookie.value, csrfCookie.options);
                    
                }
            }

            request.user = user;
            request.csrfToken = csrfCookie?csrfCookie.value.split(".")[1]:undefined; // already validated so this will work;*/



            /*// validate session if the cookies are already present
            let csrfToken = this.getCsrfTokenFromCookie(request);
            let sessionId = this.getSessionIdFromCookie(request);
            let oldSessionId = sessionId;
            let oldCsrfToken = csrfToken;
            let loggedInUser : User|undefined = undefined;
            let sessionIdValid = false;
            let csrfTokenValid = false;
            let sessionIdCreated = false;
            let csrfCookieCreated = false;

            // if there are session id and csrf token cookies, validate them
            if (sessionId) 
            {
                // there is a session ID cookie - check if it is valid
                try {
                    loggedInUser = await this.sessionManager.userForSessionKey(sessionId);
                    sessionIdValid = true;
                } catch (e) {}

                // if there is a session ID and a csrf cookie, check if the CSRF cookie is valid
                if (sessionIdValid && csrfToken) {
                    try {
                        this.sessionManager.validateCsrfToken(csrfToken, sessionId);
                        csrfTokenValid = true;
                    } catch (e) {}
                }
            }

            let sessionCookie : Cookie;
            let csrfCookie: Cookie;
            if (this.anonymousSessions && (request.method == "GET" || request.method == "HEAD" || request.method == "OPTIONS")) {
                // with these methods, we will create new cookies if they don't exist
                if (!sessionIdValid) {
                    let {sessionCookie: newSessionCookie , csrfCookie: newCsrfCookie, user: newLoggedInUser} = await this.sessionManager.createAnonymousSessionKeyIfNoneExists(sessionId, csrfToken);
                    sessionCookie = newSessionCookie;
                    csrfCookie = newCsrfCookie;
                    loggedInUser = newLoggedInUser;
                    sessionIdCreated = true;
                    csrfCookieCreated = true;
                    csrfToken = csrfCookie.value;
                } else if (!csrfTokenValid && oldSessionId) {
                    csrfCookie = await this.sessionManager.createCsrfToken(oldSessionId);
                    csrfCookieCreated = true;
                    csrfToken = csrfCookie.value;
                }
            }
            if (!sessionIdValid && !sessionIdCreated) {
                reply.clearCookie(this.sessionManager.sessionCookieName);
            } else if (sessionIdCreated) {
                reply.setCookie(this.sessionManager.sessionCookieName, sessionCookie.value, sessionCookie)
            }
            request.user = loggedInUser;
            request.csrfToken = csrfToken?csrfToken.split(".")[1]:undefined; // already validated so this will work;*/
        });
          
        if (this.endpoints.includes("login")) {
            this.app.get(this.prefix+'login', async (request : FastifyRequest<{Querystring : LoginParamsType}>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info('GET ' + this.prefix+'login ' + request.ip )
                if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "/login enabled but sessions are not");
                if (request.user) return reply.redirect(this.loginRedirect); // already logged in

                let data : {next? : any, csrfToken: string|undefined} = {csrfToken: request.csrfToken};
                if (request.query.next) {
                    data["next"] = request.query.next;
                }
                return reply.view(this.loginPage, data);
            });

            this.app.post(this.prefix+'login', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info('POST ' + this.prefix+'login ' + request.ip + ' ' + request.body.username);            
                if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "/login enabled but sessions are not");
                let next = request.body.next || this.loginRedirect;
                try {
                    CrossauthLogger.logger.debug("Next page " + next);

                    await this.login(request, reply, 
                    (reply, _user) => {return reply.redirect(next)});
                } catch (e) {
                    CrossauthLogger.logger.error(e);
                    return this.handleError(e, reply, (reply, error) => {
                        return reply.view(this.loginPage, {
                            error: error.message,
                            errors: error.messageArray, 
                            code: ErrorCode[error.code], 
                            next: next, 
                            persist: request.body.persist,
                            username: request.body.username,
                            csrfToken: request.csrfToken});
                        
                    });
                }
            });
        }

        if (this.endpoints.includes("signup")) {
            this.app.get(this.prefix+'signup', async (request : FastifyRequest<{Querystring : LoginParamsType}>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info('GET ' + this.prefix+'signup' + request.ip )
                if (this.signupPage)  { // if is redundant but VC Code complains without it
                    let data : {next? : any, csrfToken: string|undefined} = {csrfToken: request.csrfToken};
                    if (request.query.next) {
                        data["next"] = request.query.next;
                    }
                    return reply.view(this.signupPage, data);
                }
            });

            this.app.post(this.prefix+'signup', async (request : FastifyRequest<{ Body: SignupBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info('POST ' + this.prefix+'signup ' + request.ip + ' ' + request.body.username);            
                let next = request.body.next || this.loginRedirect;
                try {
                    CrossauthLogger.logger.debug("Next page " + next);

                    await this.signup(request, reply, 
                    (reply, _user) => {
                        return reply.view(this.signupPage, {
                            next: next, 
                            csrfToken: request.csrfToken,
                            message: "Please check your email to finish signing up."
                        });
                    });
                } catch (e) {
                    CrossauthLogger.logger.error(e);
                    return this.handleError(e, reply, (reply, error) => {
                        let extraFields : {[key:string] : string|number|boolean|Date|undefined} = {};
                        for (let field in request.body) {
                            if (field.startsWith("user_")) extraFields[field] = request.body[field];
                        }
                        return reply.view(this.signupPage, {
                            error: error.message,
                            errors: error.messageArray, 
                            code: ErrorCode[error.code], 
                            next: next, 
                            persist: request.body.persist,
                            username: request.body.username,
                            csrfToken: request.csrfToken,
                            ...extraFields
                            });
                        
                    });
                }
            });
        }

        if (this.endpoints.includes("changepassword")) {
            this.app.get(this.prefix+'changepassword', async (request : FastifyRequest<{Querystring : LoginParamsType}>, reply : FastifyReply) =>  {
                if (!request.user) throw new CrossauthError(ErrorCode.Unauthorized);
                CrossauthLogger.logger.info('GET ' + this.prefix+'changepassword ' + request.ip + ' ' + request.user.username);
                if (this.changePasswordPage)  { // if is redundant but VC Code complains without it
                    let data : {csrfToken: string|undefined} = {csrfToken: request.csrfToken};
                    return reply.view(this.changePasswordPage, data);
                }
            });

            this.app.post(this.prefix+'changepassword', async (request : FastifyRequest<{ Body: ChangePasswordBodyType }>, reply : FastifyReply) =>  {
                if (!request.user) throw new CrossauthError(ErrorCode.Unauthorized);
                CrossauthLogger.logger.info('POST ' + this.prefix+'changepassword ' + request.ip + ' ' + request.user.username);           
                try {
                    await this.changePassword(request, reply, 
                    (reply, _user) => {
                        return reply.view(this.changePasswordPage, {
                            csrfToken: request.csrfToken,
                            message: "Your password has been changed."
                        });
                    });
                } catch (e) {
                    CrossauthLogger.logger.error(e);
                    return this.handleError(e, reply, (reply, error) => {
                        return reply.view(this.changePasswordPage, {
                            error: error.message,
                            errors: error.messageArray, 
                            code: ErrorCode[error.code], 
                            csrfToken: request.csrfToken,
                        });
                    });
                }
            });
        }

        if (this.endpoints.includes("updateuser")) {
            this.app.get(this.prefix+'updateuser', async (request : FastifyRequest<{Querystring : LoginParamsType}>, reply : FastifyReply) =>  {
                if (!request.user) throw new CrossauthError(ErrorCode.Unauthorized);
                CrossauthLogger.logger.info('GET ' + this.prefix+'updateuser ' + request.ip + ' ' + request.user.username);
                if (this.updateUserPage)  { // if is redundant but VC Code complains without it
                    let data : {csrfToken: string|undefined, user: User} = {csrfToken: request.csrfToken, user: request.user};
                    return reply.view(this.updateUserPage, data);
                }
            });

            this.app.post(this.prefix+'updateuser', async (request : FastifyRequest<{ Body: UpdateUserBodyType }>, reply : FastifyReply) =>  {
                if (!request.user) throw new CrossauthError(ErrorCode.Unauthorized);
                CrossauthLogger.logger.info('POST ' + this.prefix+'updateuser ' + request.ip + ' ' + request.user.username);           
                try {
                    await this.updateUser(request, reply, 
                    (reply, _user, _emailVerificationRequired) => {
                        return reply.view(this.updateUserPage, {
                            csrfToken: request.csrfToken,
                            message: "Please click on the link in your email to verify your email address."
                        });
                    });
                } catch (e) {
                    CrossauthLogger.logger.error(e);
                    let extraFields : { [key : string] : any }= {};
                    for (let field in request.body) {
                        if (field.startsWith("user_")) extraFields[field] = request.body[field];
                    }
                    return this.handleError(e, reply, (reply, error) => {
                        return reply.view(this.updateUserPage, {
                            error: error.message,
                            errors: error.messageArray, 
                            code: ErrorCode[error.code], 
                            csrfToken: request.csrfToken,
                        });
                    });
                }
            });
        }

        if (this.endpoints.includes("requestpasswordreset")) {
            this.app.get(this.prefix+'requestpasswordreset', async (request : FastifyRequest, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info('GET ' + this.prefix+'requestpasswordreset' + request.ip);
                if (this.requestPasswordResetPage)  { // if is redundant but VC Code complains without it
                    let data : {csrfToken: string|undefined} = {csrfToken: request.csrfToken};
                    return reply.view(this.requestPasswordResetPage, data);
                }
            });

            this.app.post(this.prefix+'requestpasswordreset', async (request : FastifyRequest<{ Body: RequestPasswordResetBodyType }>, reply : FastifyReply) =>  {
                const message = "If a user with exists with the email you entered, a message with "
                    + " a link to reset your password has been sent."; 
                CrossauthLogger.logger.info('POST ' + this.prefix+'requestpasswordreset ' + request.ip);           
                try {
                    await this.requestPasswordReset(request, reply, 
                    (reply, _user) => {
                        return reply.view(this.requestPasswordResetPage, {
                            csrfToken: request.csrfToken,
                            message: message,
                        });
                    });
                } catch (e) {
                    CrossauthLogger.logger.error(e);
                    return this.handleError(e, reply, (reply, error) => {
                        if (error.code == ErrorCode.EmailNotExist) {
                            return reply.view(this.requestPasswordResetPage, {
                                csrfToken: request.csrfToken,
                                message: message,
                            });
                        }
                        return reply.view(this.requestPasswordResetPage, {
                            error: error.message,
                            errors: error.messageArray, 
                            code: ErrorCode[error.code], 
                            email: request.body.email,
                            csrfToken: request.csrfToken,
                        });
                    });
                }
            });
        }

        if (this.endpoints.includes("resetpassword")) {
            if (!this.enableSessions || !this.enablePasswordReset) throw new CrossauthError(ErrorCode.Configuration, "Sessions and password reset must be enabled");
            this.app.get(this.prefix+'resetpassword/:token', async (request : FastifyRequest<{Params : VerifyTokenParamType}>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info('GET ' + this.prefix+'resetpassword ' + request.ip);
                try {
                    await this.sessionManager.userForPasswordResetToken(request.params.token);
                } catch (e) {
                    let code = ErrorCode.UnknownError;
                    let error = "Unknown error";
                    if (e instanceof CrossauthError) {
                        code = e.code;
                        error = e.message;
                    }
                    return reply.view(this.errorPage, {error: error, code: ErrorCode[code]});
                }
                return reply.view(this.resetPasswordPage, {token: request.params.token, csrfToken: request.csrfToken});
            });

            this.app.post(this.prefix+'resetpassword', async (request : FastifyRequest<{ Body: ResetPasswordBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info('POST ' + this.prefix+'resetpassword ' + request.ip);           
                try {
                    await this.resetPassword(request, reply, 
                    (reply, _user) => {
                        return reply.view(this.resetPasswordPage, {
                            csrfToken: request.csrfToken,
                            message: "Your password has been changed."
                        });
                    });
                } catch (e) {
                    CrossauthLogger.logger.error(e);
                    return this.handleError(e, reply, (reply, error) => {
                        return reply.view(this.changePasswordPage, {
                            error: error.message,
                            errors: error.messageArray, 
                            code: ErrorCode[error.code], 
                            csrfToken: request.csrfToken,
                        });
                    });
                }
            });
        }

        if (this.endpoints.includes("verifyemail")) {
            this.app.get(this.prefix+'verifyemail/:token', async (request : FastifyRequest<{Params: VerifyTokenParamType}>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info('POST ' + this.prefix+'verifyemail ' + request.ip);            
                try {
                    await this.verifyEmail(request, reply, 
                    (reply, user) => {
                        if (!this.emailVerifiedPage)  {
                            CrossauthLogger.logger.error("verify email requested but emailVerifiedPage not defined");
                            throw new CrossauthError(ErrorCode.Configuration, "There is a configuration error - please contact us if it persists");
                        }
                        return reply.view(this.emailVerifiedPage, {user: user});
                    });
                } catch (e) {
                    CrossauthLogger.logger.error(e);
                    return this.handleError(e, reply, (reply, error) => {
                        return reply.view(this.errorPage, {
                            csrfToken: request.csrfToken,
                            code: ErrorCode[error.code],
                            error: error.message,
                            errors: error.messageArray,
                        });
                    });
                }
             });
        }

        if (this.endpoints.includes("logout")) {
            this.app.post(this.prefix+'logout', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) => {
                CrossauthLogger.logger.info('POST ' + this.prefix+'logout ' + request.ip + ' ' + (request.user?request.user.username:""));            
                try {
                    await this.logout(request, reply, 
                    (reply) => {return reply.redirect(this.logoutRedirect)});
                } catch (e) {
                    CrossauthLogger.logger.error(e);
                    return this.handleError(e, reply, (reply, error) => {
                        return reply.view(this.errorPage, {error: error.message, errors: error.messageArray, code: ErrorCode[error.code]});
                        
                    });
                }
            });

        }

        if (this.endpoints.includes("api/login")) {
            this.app.post(this.prefix+'api/login', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info('POST ' + this.prefix+'api/login ' + request.ip + ' ' + request.body.username);            
                if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "/api/login enabled but sessions are not");
                if (request.user) return reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "ok", user : request.user}); // already logged in
                try {
                    await this.login(request, reply, 
                    (reply, user) => {return reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "ok", user : user})});
                } catch (e) {
                    CrossauthLogger.logger.error(e);
                    return this.handleError(e, reply, (reply, error) => {
                        reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "error", error: error.message, errors: error.messageArray, code: ErrorCode[error.code]});                    
                    });
                }
            });
        }

        if (this.endpoints.includes("api/logout")) {
            this.app.post(this.prefix+'api/logout', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) => {
                CrossauthLogger.logger.info('POST ' + this.prefix+'api/logout ' + request.ip + ' ' + (request.user?request.user.username:""));            
                if (!request.user) return reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "ok"});

                try {
                    await this.logout(request, reply, 
                    (reply) => {return reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "ok"})});
                    if (this.anonymousSessions && this.enableSessions) await this.createAnonymousSessionIdIfNoneExists(request, reply);
                } catch (e) {
                    CrossauthLogger.logger.error(e);
                    return this.handleError(e, reply, (reply, error) => {
                        reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "error", error: error.message, errors: error.messageArray, code: ErrorCode[error.code]});                    
                    });
                }
            });
        }

        if (this.endpoints.includes("api/signup")) {
            this.app.post(this.prefix+'api/signup', async (request : FastifyRequest<{ Body: SignupBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info('POST ' + this.prefix+'api/signup ' + request.ip + ' ' + request.body.username);            
                try {
                    await this.signup(request, reply, 
                    (reply, user) => {return reply.header('Content-Type', 'application/json; charset=utf-8').send({
                        status: "ok", 
                        user : user,
                        emailVerificationNeeded: this.enableEmailVerification||false,
                    })});
                } catch (e) {
                    CrossauthLogger.logger.error(e);
                    this.handleError(e, reply, (reply, error) => {
                        reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "error", error: error.message, errors: error.messageArray, code: ErrorCode[error.code]});                    
                    });
                }
            });
        }

        if (this.endpoints.includes("api/changepassword")) {
            this.app.post(this.prefix+'api/changepassword', async (request : FastifyRequest<{ Body: ChangePasswordBodyType }>, reply : FastifyReply) =>  {
                if (!request.user) throw new CrossauthError(ErrorCode.Unauthorized);
                CrossauthLogger.logger.info('POST ' + this.prefix+'api/changepassword ' + request.ip + ' ' + request.user?.username);            
                try {
                    await this.changePassword(request, reply, 
                    (reply, _user) => {return reply.header('Content-Type', 'application/json; charset=utf-8').send({
                        status: "ok", 
                    })});
                } catch (e) {
                    CrossauthLogger.logger.error(e);
                    return this.handleError(e, reply, (reply, error) => {
                        reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "error", error: error.message, errors: error.messageArray, code: ErrorCode[error.code]});                    
                    }, true);
                }
            });
        }

        if (this.endpoints.includes("api/updateuser")) {
            this.app.post(this.prefix+'api/updateuser', async (request : FastifyRequest<{ Body: UpdateUserBodyType }>, reply : FastifyReply) =>  {
                if (!request.user) throw new CrossauthError(ErrorCode.Unauthorized);
                CrossauthLogger.logger.info('POST ' + this.prefix+'api/updateuser ' + request.ip + ' ' + request.user?.username);            
                try {
                    await this.updateUser(request, reply, 
                    (reply, _user, emailVerificationRequired) => {return reply.header('Content-Type', 'application/json; charset=utf-8').send({
                        status: "ok", 
                        emailVerificationRequired: emailVerificationRequired,
                    })});
                } catch (e) {
                    CrossauthLogger.logger.error(e);
                    return this.handleError(e, reply, (reply, error) => {
                        reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "error", error: error.message, errors: error.messageArray, code: ErrorCode[error.code]});                    
                    }, true);
                }
            });
        }

        if (this.endpoints.includes("api/resetpassword")) {
            this.app.post(this.prefix+'api/resetpassword', async (request : FastifyRequest<{ Body: ResetPasswordBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info('POST ' + this.prefix+'api/resetpassword ' + request.ip);            
                try {
                    await this.resetPassword(request, reply, 
                    (reply, _user) => {return reply.header('Content-Type', 'application/json; charset=utf-8').send({
                        status: "ok", 
                    })});
                } catch (e) {
                    CrossauthLogger.logger.error(e);
                    return this.handleError(e, reply, (reply, error) => {
                        reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "error", error: error.message, errors: error.messageArray, code: ErrorCode[error.code]});                    
                    }, true);
                }
            });
        }

        if (this.endpoints.includes("api/requestpasswordreset")) {
            this.app.post(this.prefix+'api/requestpasswordreset', async (request : FastifyRequest<{ Body: RequestPasswordResetBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info('POST ' + this.prefix+'api/requestpasswordreset ' + request.ip);            
                try {
                    await this.requestPasswordReset(request, reply, 
                    (reply, _user) => {return reply.header('Content-Type', 'application/json; charset=utf-8').send({
                        status: "ok", 
                    })});
                } catch (e) {
                    CrossauthLogger.logger.error(e);
                    return this.handleError(e, reply, (reply, error) => {
                        reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "error", error: error.message, errors: error.messageArray, code: ErrorCode[error.code]});                    
                    }, true);
                }
            });
        }

        if (this.endpoints.includes("api/verifyemail")) {
            this.app.get(this.prefix+'api/verifyemail/:token', async (request : FastifyRequest<{Params: VerifyTokenParamType}>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info('POST ' + this.prefix+'api/verifyemail ' + request.ip);            
                try {
                    await this.verifyEmail(request, reply, 
                    (reply, user) => {return reply.header('Content-Type', 'application/json; charset=utf-8').send({
                        status: "ok", 
                        user : user,
                    })});
                } catch (e) {
                    CrossauthLogger.logger.error(e);
                    return this.handleError(e, reply, (reply, error) => {
                        reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "error", error: error.message, errors: error.messageArray, code: ErrorCode[error.code]});                    
                    });
                }
            });
        }

        if (this.endpoints.includes("api/userforsessionkey")) {
            this.app.get(this.prefix+'api/userforsessionkey', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info('POST ' + this.prefix+'api/userforsessionkey ' + request.ip + ' ' + (request.user?request.user.username:""));            
                try {
                    let user : User|undefined;
                    const sessionId = this.getSessionIdFromCookie(request);
                    if (sessionId) user = await this.sessionManager.userForSessionKey(sessionId);
                    return reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "ok", user : user});
                } catch (e) {
                    let error = "Unknown error";
                    let code = ErrorCode.UnknownError;
                    if (e instanceof CrossauthError) {
                        let ce = e as CrossauthError;
                        switch (ce.code) {
                            case ErrorCode.UserNotExist:
                            case ErrorCode.PasswordNotMatch:
                                error = "Invalid username or password";
                                code = ErrorCode.UsernameOrPasswordInvalid;
                                break;
                            default:
                                error = ce.message;
                                code = ce.code;
                        }
                    }
                    CrossauthLogger.logger.error(e);
                    return reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "error", code: ErrorCode[code], error : error});

                }
            });
        }

        if (this.endpoints.includes("api/getcsrftoken")) {
            this.app.get(this.prefix+'api/getcsrftoken', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info('POST ' + this.prefix+'api/getcsrftoken ' + request.ip + ' ' + (request.user?request.user.username:""));            
                try {
                    const cookie = this.getCsrfTokenFromCookie(request);
                    if (!cookie) throw new CrossauthError(ErrorCode.InvalidKey);
                    const parts = cookie.split(".");
                    if (parts.length != 2) throw new CrossauthError(ErrorCode.InvalidKey);
                     reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "ok", csrfToken : parts[1]});
                } catch (e) {
                    let error = "Unknown error";
                    let code = ErrorCode.UnknownError;
                    if (e instanceof CrossauthError) {
                        let ce = e as CrossauthError;
                        code = ce.code;
                        error = ce.message;
                    }
                    CrossauthLogger.logger.error(e);
                    return reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "error", code: ErrorCode[code], error : error});

                }
            });
    
        }
    }
    
    private async login(request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, user: User) => void) {
        if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled");
        if (this.anonymousSessions) {
            await this.validateCsrfToken(request, reply)
        }
        const username = request.body.username;
        const password = request.body.password;
        const persist = request.body.persist;

        let sessionId = undefined;
        let oldSessionId : string|undefined = undefined;
        if (this.anonymousSessions && !this.keepAnonymousSessionId) 
            oldSessionId = this.getSessionIdFromCookie(request);
        if (this.anonymousSessions && this.keepAnonymousSessionId) {
            sessionId = this.getSessionIdFromCookie(request);
        }

        let { sessionCookie, csrfCookie, user } = await this.sessionManager.login(username, password, sessionId, persist);
        CrossauthLogger.logger.debug("Login: set session cookie " + sessionCookie.name + " opts " + JSON.stringify(sessionCookie.options));
        reply.cookie(sessionCookie.name, sessionCookie.value, sessionCookie.options);
        CrossauthLogger.logger.debug("Login: set csrf cookie " + csrfCookie.name + " opts " + JSON.stringify(sessionCookie.options));
        reply.cookie(csrfCookie.name, csrfCookie.value, csrfCookie.options);
        if (oldSessionId) {
            try {
                await this.sessionManager.deleteSessionId(oldSessionId);
            } catch (e) {
                CrossauthLogger.logger.warn("Couldn't delete session ID from database");
                CrossauthLogger.logger.debug(e);
            }
        }
        return successFn(reply, user);
    }

    private async loginWithUser(user: User, request : FastifyRequest, reply : FastifyReply, 
        successFn : (res : FastifyReply, user: User) => void) {
        if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled");
        let sessionId = undefined;
        let oldSessionId : string|undefined = undefined;
        if (this.anonymousSessions && !this.keepAnonymousSessionId) 
            oldSessionId = this.getSessionIdFromCookie(request);
        if (this.anonymousSessions && this.keepAnonymousSessionId) {
            sessionId = this.getSessionIdFromCookie(request);
        }

        let { sessionCookie, csrfCookie } = await this.sessionManager.login("", "", sessionId, undefined, user);
        CrossauthLogger.logger.debug("Login: set session cookie " + sessionCookie.name + " opts " + JSON.stringify(sessionCookie.options));
        reply.cookie(sessionCookie.name, sessionCookie.value, sessionCookie.options);
        CrossauthLogger.logger.debug("Login: set csrf cookie " + csrfCookie.name + " opts " + JSON.stringify(sessionCookie.options));
        reply.cookie(csrfCookie.name, csrfCookie.value, csrfCookie.options);
        if (oldSessionId) {
            try {
                await this.sessionManager.deleteSessionId(oldSessionId);
            } catch (e) {
                CrossauthLogger.logger.warn("Couldn't delete session ID from database");
                CrossauthLogger.logger.debug(e);
            }
        }
        return successFn(reply, user);
    }

    private async signup(request : FastifyRequest<{ Body: SignupBodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, user? : User) => void) {
        if (this.anonymousSessions) {
            await this.validateCsrfToken(request, reply)
        }
        const username = request.body.username;
        const password = request.body.password;
        const repeatPassword = request.body.repeatPassword;
        const extraFields : {[key:string] : string|number|boolean|Date|undefined}= {};
        for (let field in request.body) {
            let name = field.replace("user_", ""); 
            if (field.startsWith("user_")) extraFields[name] = request.body[field];
        }
        let userToValidate : User = {
            id: "",
            username: username,
            ...extraFields,
        }
        let passwordErrors = this.passwordValidator(password);
        let userErrors = this.userValidator(userToValidate);
        let errors = [...userErrors, ...passwordErrors];
        if (errors.length > 0) {
            throw new CrossauthError(ErrorCode.FormEntry, errors);
        }
        if (repeatPassword != undefined && repeatPassword != password) {
            throw new CrossauthError(ErrorCode.PasswordMatch);
        }
        await this.sessionManager.createUser(username, password, extraFields);
        if (!this.enableEmailVerification && this.enableSessions) {
            return this.login(request, reply, successFn);
        }
        return successFn(reply, undefined);
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
        let errors = this.passwordValidator(newPassword);
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

        await this.sessionManager.requestPasswordReset(email);
        return successFn(reply, undefined);
    }

    private async verifyEmail(request : FastifyRequest<{ Params: VerifyTokenParamType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, user? : User) => void) {
        if (!this.enableEmailVerification) throw new CrossauthError(ErrorCode.Configuration, "Password reset not enabled");
        const token = request.params.token;
        const user = await this.sessionManager.applyEmailVerificationToken(token);
        delete user.passwordHash;
        return this.loginWithUser(user, request, reply, successFn);
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
        let errors = this.passwordValidator(newPassword);
        if (errors.length > 0) {
            throw new CrossauthError(ErrorCode.PasswordFormat);
        }
        const user = await this.sessionManager.resetPassword(token, newPassword);
        delete user.passwordHash;
        return this.loginWithUser(user, request, reply, successFn);
    }

    private async logout(request : FastifyRequest, reply : FastifyReply, 
        successFn : (reply : FastifyReply) => void) {
        if (!this.enableSessions) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled");
        let sessionId = this.getSessionIdFromCookie(request);
        if (sessionId) {
                await this.sessionManager.logout(sessionId||"");
        }
        CrossauthLogger.logger.debug("Logout: clear cookie " + this.sessionManager.sessionCookieName);
        reply.clearCookie(this.sessionManager.sessionCookieName);
        reply.clearCookie(this.sessionManager.csrfCookieName);
        if (sessionId) {
            try {
                await this.sessionManager.deleteSessionId(sessionId);
            } catch (e) {
                CrossauthLogger.logger.warn("Couldn't delete session ID from database");
                CrossauthLogger.logger.debug(e);
            }
        }
        return successFn(reply);

    }

    private async createAnonymousSessionIdIfNoneExists(request : FastifyRequest, reply : FastifyReply) 
        : Promise<{sessionCookie: Cookie, csrfCookie: Cookie|undefined, user : User|undefined}> {
        let cookies = request.cookies;
        let sessionId : string|undefined = undefined;
        let csrfToken : string|undefined = undefined;
        if (cookies && this.sessionManager.sessionCookieName in cookies) {
            sessionId = cookies[this.sessionManager.sessionCookieName]||""
        };
        if (cookies && this.sessionManager.csrfCookieName in cookies) {
            csrfToken = cookies[this.sessionManager.csrfCookieName]||"";
        }
        let {sessionCookie, csrfCookie, user} = await this.sessionManager.createAnonymousSessionKeyIfNoneExists(sessionId, csrfToken);
        if (sessionId != sessionCookie.value) {
            CrossauthLogger.logger.debug("Creating session ID");
            reply.cookie(sessionCookie.name, sessionCookie.value, sessionCookie.options);
        }
        if (csrfToken != csrfCookie.value) {
            CrossauthLogger.logger.debug("Creating CSRF Token");
            reply.cookie(csrfCookie.name, csrfCookie.value, csrfCookie.options);
        }        
        return {sessionCookie, csrfCookie, user};
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
                    case ErrorCode.PasswordNotMatch:
                        ce = new CrossauthError(ErrorCode.UsernameOrPasswordInvalid, "Invalid username or password");
                        break;
                    default:
                        error = ce.message;
                }
            }
        } else {
            ce = new CrossauthError(code, error);
        }
        CrossauthLogger.logger.error(e);

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
                            _reply : FastifyReply,
                            sessionId? : string) {
        if (!sessionId) {
            sessionId = this.getSessionIdFromCookie(request);
            if (!sessionId) {
                CrossauthLogger.logger.debug("No session cookie found when validating CSRF token");
                throw new CrossauthError(ErrorCode.InvalidKey);
            }
        } 
        let formOrHeaderToken = this.getCsrfTokenFromFormOrHeader(request);
        if (!formOrHeaderToken) {
            CrossauthLogger.logger.debug("No CSRF form or header value found when validating CSRF token");
            throw new CrossauthError(ErrorCode.InvalidKey);
        }
        let csrfToken = this.getCsrfTokenFromCookie(request);
        if (!csrfToken) {
            CrossauthLogger.logger.debug("No CSRF cookie found when validating CSRF token");
            throw new CrossauthError(ErrorCode.InvalidKey);
        }
        this.sessionManager.validateDoubleSubmitCsrfToken(csrfToken, sessionId, formOrHeaderToken);
    }

    private getCsrfTokenFromFormOrHeader(request : FastifyRequest<{ Body: CsrfBodyType }>) : string|undefined {
        let formOrHeaderToken  : string|undefined = undefined;
        if (request.body.csrfToken) {
            formOrHeaderToken = request.body.csrfToken;
        } else if (request.headers[CSRFHEADER]) {
            let headers = request.headers[CSRFHEADER]
            if (headers && Array.isArray(headers)) {
                formOrHeaderToken = headers[0];
            } else {
                formOrHeaderToken = headers;
            }            
        }
        return formOrHeaderToken;
    }

    /**
     * Starts the Fastify app on the given port.  
     * @param port the port to listen on
     */
    start(port : number = 3000) {
        this.app.listen({ port: port}, () =>
            CrossauthLogger.logger.info(`Starting fastify server on port ${port} with prefix '${this.prefix}'`),
        );

    }
}
