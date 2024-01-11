import fastify, { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import view from '@fastify/view';
import fastifyFormBody from '@fastify/formbody';
import type { FastifyCookieOptions } from '@fastify/cookie'
import cookie from '@fastify/cookie'
import { Server, IncomingMessage, ServerResponse } from 'http'

import nunjucks from "nunjucks";
import { UserStorage, KeyStorage } from './storage';
import { UsernamePasswordAuthenticator } from './password';
import { CookieSessionManager, Cookie } from './cookieauth';
import type { CookieAuthOptions } from './cookieauth';
import type { TokenEmailerOptions } from './email';
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
export interface FastifyCookieAuthServerOptions extends CookieAuthOptions, TokenEmailerOptions {

    /** URL of your site, eg https://mysite.com.  This is only used for sending email verification and 
     * password reset tokens, and can still be omitted if your email message templates have the site
     * hardcoded into them. */
    siteUrl? : string,

    /** You can pass your own fastify instance or omit this, in which case Crossauth will create one */
    app? : FastifyInstance<Server, IncomingMessage, ServerResponse>,

    /** Prefix to apply to all endpoints.  By default it is "/" */
    prefix? : string,

    /** List of endpoints to add to the server ("login", "api/login", etc, prefixed by the `prefix` parameter.  Empty or `"all"` for all.  Default all.) */
    endpoints? : string,

    /** Page to redirect to after successful login, default "/" */
    loginRedirect? : string;

    /** Page to redirect to after successful logout, default "/" */
    logoutRedirect? : string;

    /** Directory containing views.  Defaults to "views".  See the class documentation for {@link FastifyCookieAuthServer} for more info.
     */
    views? : string;

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

    passwordValidator? : (password: string) => boolean;

    /** Page to render error messages, including failed login. 
     * See the class documentation for {@link FastifyCookieAuthServer} for more info.  Defaults to "error.njk".
     */
    errorPage? : string;

    /** Page to render for password changing.  
     * See the class documentation for {@link FastifyCookieAuthServer} for more info.  Defaults to "changepassword.njk".
     */
    changePasswordPage? : string,

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

    /** Subject line on password reset emails */
    passwordResetSubject? : string,

    /** Used for sending password reset messages.  This is rendered with Nunjucks.  The variable `token` is passed,
     * as well as `siteUrl` and `prefix`.
     * Your link should be https://yoursiite.com/{{ token }} or {{ siteUrl }}{{ prefix }}{{ token }}
     * The default is "passwordresettextbody.njk"
     */
    passwordResetTextBody? : string,

    /** HTML version of the email verification message.  Used in addition to passwordResetTextBody.  Unset by default */
    passwordResetHtmlBody? : string,

    /** Subject line on email verification emails */
    emailVerificationSubject? : string,
    
    /** Used for sending email verification messages.  To use this, your {@link UserStorage} should have 
     * `checkEmailVerified` set to `true`.  This is rendered with Nunjucks.  The variable `token` is passed,
     * as well as `siteUrl` and `prefix`.  Default "emailverificationtextbody.njk"
     * Your link should be https://yoursiite.com/{{ token }} or {{ siteUrl }}{{ prefix }}{{ token }}
     */
    emailVerificationTextBody? : string,

    /** HTML version of the email verification message.  Used in addition to emailVerificationTextBody.  Unset by default */
    emailVerificationHtmlBody? : string,

    /** HTML version of the password reset message.  You can set either, or both */
    emailFrom? : string,

    /** Hostname for SMTP.  Needed for password reset and email verification. */
    smtpHost? : string;

    /** Port for SMTP.  Default 25 */
    smtpPort? : number,

    /** Whether or not your SMTP server uses TLS.  Default talse */
    smtpUseTLS? : boolean,

    /** Optional username for SMTP authentication */
    smtpUsername? : string,

    /** Optional password for SMTP authentication */
    smtpPassword? : string,

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

interface LoginBodyType {
    username: string,
    password: string,
    persist? : boolean,
    next? : string,
    csrfToken?: string;
}

interface SignupBodyType extends LoginBodyType{
    repeartPassword?: string,
    email? : string,
    [key : string]: string|number|Date|boolean|undefined,
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

const ALL_ENDPOINTS = [
    "signup",
    "verifyemail",
    "login",
    "logout",
    "changepassword",
    "requestpasswordreset",
    "resetpassword",
    "emailverified",
    "api/login",
    "api/logout",
    "api/signup",
    "api/verifyemail",
    "api/userforsessionkey",
    "api/getCsrdToken",
];

function defaultPasswordValidator(password : string) : boolean {
    if (password.length < 8) return false;
    if (password.match(/[a-z]/) == null) return false;
    if (password.match(/[A-Z]/) == null) return false;
    if (password.match(/[0-9]/) == null) return false;
    return true;
}
/**
 * This class provides a complete (but without HTML files) auth backend server with endpoints served using Fastify.
 * 
 * If you do not pass an Fastify app to this class, it will create one.  By default, pages are rendered
 * with Nunjucks.  If you prefer another renderer that is compatible with Fastify, just create your
 * own Fastify app and configure the renderer using @fastify/view.
 * 
 * By default, all views are expected to be in a directory called `views` relative to the directory the
 * server is started in.  This can be overwritten by setting the `views` option.
 * 
 * Note that `views`, `loginPage` and `errorPage` are used only by the `/login` and `/logout` endpoints.  The
 * `/api/*` endpoints only return JSON.
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
    private secret: string = "";
    private siteUrl? : string;
    readonly app : FastifyInstance<Server, IncomingMessage, ServerResponse>;
    private views : string = "views";
    private prefix : string = "/";
    private endpoints : string = "all";
    private loginRedirect = "/";
    private logoutRedirect : string = "/";
    private signupPage : string = "signup.njk";
    private loginPage : string = "login.njk";
    private errorPage : string = "error.njk";
    private changePasswordPage : string = "changepassword.njk";
    private requestPasswordReset : string = "requestpasswordreset.njk";
    private resetPasswordPage?: string = "resetpassword.njk";
    private enableEmailVerification? : boolean = false;
    private emailVerifiedPage? : string = "emailverified.njk";
    private emailFrom? : string;
    private smtpHost? : string;
    private smtpPort : number = 25;
    private smtpUseTls : boolean = false;
    private smtpUsername : string|undefined = undefined;
    private smtpPassword : string|undefined = undefined;
    private sessionManager : CookieSessionManager;
    private anonymousSessions = true;
    private keepAnonymousSessionId = false;
    private passwordValidator : (password : string) => boolean = defaultPasswordValidator;

    /** Contains a vector of all endpoints that have been created (eg "login", ) */
    readonly activatedEndpoints : string[] = [];

    /**
     * Creates the Fastify endpoints, optionally also the Fastify app.
     * @param optoions see {@link FastifyCookieAuthServerOptions}
     */
    constructor(userStorage: UserStorage, 
                keyStorage: KeyStorage, 
                authenticator: UsernamePasswordAuthenticator, 
                options: FastifyCookieAuthServerOptions = {}) {

        setParameter("secret", ParamType.String, this, options, "SECRET", true);
        setParameter("views", ParamType.String, this, options, "VIEWS");
        setParameter("prefix", ParamType.String, this, options, "PREFIX");
        setParameter("endpoints", ParamType.String, this, options, "ENDPOINTS");
        this.endpoints = this.endpoints.toLowerCase().trim();
        this.activatedEndpoints = ALL_ENDPOINTS;
        if (this.endpoints != "all" && this.endpoints != "" ) this.activatedEndpoints = this.endpoints.split(/ *, */);
        setParameter("signupPage", ParamType.String, this, options, "SIGNUP_PAGE");
        setParameter("loginPage", ParamType.String, this, options, "LOGIN_PAGE");
        setParameter("errorPage", ParamType.String, this, options, "ERROR_PAGE");
        setParameter("changePasswordPage", ParamType.String, this, options, "CHANGE_PASSWORD_PAGE");
        setParameter("resetPasswordPage", ParamType.String, this, options, "RESET_PASSWORD_PAGE");
        setParameter("emailVerifiedPage", ParamType.String, this, options, "EMAIL_VERIFIED_PAGE");
        setParameter("enableEmailVerification", ParamType.Boolean, this, options, "ENABLE_EMAIL_VERIFICATION");
        setParameter("emailFrom", ParamType.String, this, options, "EMAIL_FROM");
        setParameter("smtpHost", ParamType.String, this, options, "SMTP_HOST");
        setParameter("smtpPort", ParamType.Number, this, options, "SMTP_PORT");
        setParameter("smtpUsername", ParamType.String, this, options, "SMTP_USERNAME");
        setParameter("smtpPassword", ParamType.String, this, options, "SMTP_PASSWORD");
        setParameter("smtpUseTls", ParamType.Boolean, this, options, "SMTP_USE_TLS");
        setParameter("anonymousSessions", ParamType.Boolean, this, options, "ANONYMOUS_SESSIONS");
        setParameter("keepAnonymousSessionId", ParamType.Boolean, this, options, "KEEP_ANONYMOUS_SESSION_ID");
        setParameter("persistSessionId", ParamType.Boolean, this, options, "PERSIST_SESSION_ID");

        this.sessionManager = new CookieSessionManager(userStorage, keyStorage, authenticator, 
            options);

        if (options.app) {
            this.app = options.app;
        } else {
            if (options.views) {
                nunjucks.configure(options.views, {
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
                    "views",
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
            
        this.app.addHook('onRequest', async (request : FastifyRequest<{Body: CsrfBodyType}>, reply : FastifyReply) => {
            let csrfToken : string|undefined = undefined;
            let loggedInUser : User|undefined = undefined;
            if (this.anonymousSessions) {
                let {csrfCookie, user} = 
                    await this.createAnonymousSessionIdIfNoneExists(request, reply);
                csrfToken = csrfCookie.value;
                loggedInUser = user;
            } else {
                let {csrfCookie, user} = 
                    await this.getValidatedCsrfTokenAndUser(request, reply);
                    csrfToken = csrfCookie ? csrfCookie.value : undefined;
                    loggedInUser = user;
                let sessionId = this.getSessionIdFromCookie(request);
                if (sessionId && loggedInUser) this.sessionManager.updateSessionActivity(sessionId);
            }
            request.user = loggedInUser;
            request.csrfToken = csrfToken?csrfToken.split(".")[1]:undefined; // already validated so this will work;
        });
          
        if (this.activatedEndpoints.includes("login")) {
            this.app.get(this.prefix+'login', async (request : FastifyRequest<{Querystring : LoginParamsType}>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info('GET ' + this.prefix+'login ' + request.ip )
                let data : {next? : any, csrfToken: string|undefined} = {csrfToken: request.csrfToken};
                if (request.query.next) {
                    data["next"] = request.query.next;
                }
                return reply.view(this.loginPage, data);
            });

            this.app.post(this.prefix+'login', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info('POST ' + this.prefix+'login' + request.ip + ' ' + request.body.username);            
                let next = request.body.next || this.loginRedirect;
                try {
                    CrossauthLogger.logger.debug("Next page " + next);

                    await this.login(request, reply, 
                    (reply, _user) => {return reply.redirect(next)});
                } catch (e) {
                    CrossauthLogger.logger.error(e);
                    return this.handleError(e, reply, (reply, code, error) => {
                        if (this.loginPage) {
                            return reply.view(this.loginPage, {
                                error: error, 
                                code: ErrorCode[code], 
                                next: next, 
                                persist: request.body.persist,
                                username: request.body.username,
                                csrfToken: request.csrfToken});
                        } else {
                            return reply.view(this.errorPage, {error: error, code: ErrorCode[code], csrfToken: request.csrfToken});
                        }
                        
                    });
                }
            });
        }

        if (this.activatedEndpoints.includes("signup")) {
            this.app.get(this.prefix+'signup', async (request : FastifyRequest<{Querystring : LoginParamsType}>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info('GET ' + this.prefix+'signup ' + request.ip )
                if (this.signupPage)  { // if is redundant but VC Code complains without it
                    let data : {next? : any, csrfToken: string|undefined} = {csrfToken: request.csrfToken};
                    if (request.query.next) {
                        data["next"] = request.query.next;
                    }
                    return reply.view(this.signupPage, data);
                }
            });

            this.app.post(this.prefix+'signup', async (request : FastifyRequest<{ Body: SignupBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info('POST ' + this.prefix+'signup' + request.ip + ' ' + request.body.username);            
                let next = request.body.next || this.loginRedirect;
                try {
                    CrossauthLogger.logger.debug("Next page " + next);

                    await this.signup(request, reply, 
                    (reply, _user) => {
                        if (this.enableEmailVerification) {
                            if (this.signupPage) {
                                return reply.view(this.signupPage, {
                                    next: next, 
                                    csrfToken: request.csrfToken,
                                    message: "Please check your email to finish signing up."
                                });
                            } else {
                                return reply.redirect(next);
                            }

                            } else {
                                return reply.redirect(next)}
                            });
                } catch (e) {
                    CrossauthLogger.logger.error(e);
                    return this.handleError(e, reply, (reply, code, error) => {
                        if (this.signupPage) {
                            let extraFields : {[key:string] : string|number|boolean|Date|undefined} = {};
                            for (let field in request.body) {
                                if (field.startsWith("user_")) extraFields[field] = request.body[field];
                            }
                            return reply.view(this.signupPage, {
                                error: error, 
                                code: ErrorCode[code], 
                                next: next, 
                                persist: request.body.persist,
                                username: request.body.username,
                                csrfToken: request.csrfToken,
                                ...extraFields
                                });
                        } else {
                            return reply.view(this.errorPage, {
                                error: error, 
                                code: ErrorCode[code], 
                                csrfToken: request.csrfToken,
                            });
                        }
                        
                    });
                }
            });
        }

        if (this.activatedEndpoints.includes("verifyemail")) {
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
                    return this.handleError(e, reply, (reply, code, error) => {
                        return reply.view(this.errorPage, {
                            error: error, 
                            code: ErrorCode[code], 
                            csrfToken: request.csrfToken,
                        });
                    });
                }
             });
        }

        if (this.activatedEndpoints.includes("logout")) {
            this.app.post(this.prefix+'logout', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) => {
                CrossauthLogger.logger.info('POST ' + this.prefix+'logout ' + request.ip + ' ' + (request.user?request.user.username:""));            
                try {
                    await this.logout(request, reply, 
                    (reply) => {return reply.redirect(this.logoutRedirect)});
                } catch (e) {
                    CrossauthLogger.logger.error(e);
                    return this.handleError(e, reply, (reply, code, error) => {
                        return reply.view(this.errorPage, {error: error, code: ErrorCode[code]});
                        
                    });
                }
            });

        }

        if (this.activatedEndpoints.includes("api/login")) {
            this.app.post(this.prefix+'api/login', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info('POST ' + this.prefix+'api/login ' + request.ip + ' ' + request.body.username);            
                try {
                    await this.login(request, reply, 
                    (reply, user) => {return reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "ok", user : user})});
                } catch (e) {
                    CrossauthLogger.logger.error(e);
                    return this.handleError(e, reply, (reply, code, error) => {
                        reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "error", error: error, code: ErrorCode[code]});                    
                    });
                }
            });
        }

        if (this.activatedEndpoints.includes("api/logout")) {
            this.app.post(this.prefix+'api/logout', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) => {
                CrossauthLogger.logger.info('POST ' + this.prefix+'api/logout ' + request.ip + ' ' + (request.user?request.user.username:""));            
                try {
                    await this.logout(request, reply, 
                    (reply) => {return reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "ok"})});
                    if (this.anonymousSessions) await this.createAnonymousSessionIdIfNoneExists(request, reply);
                } catch (e) {
                    CrossauthLogger.logger.error(e);
                    return this.handleError(e, reply, (reply, code, error) => {
                        reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "error", error: error, code: ErrorCode[code]});                    
                    });
                }
            });
        }

        if (this.activatedEndpoints.includes("api/signup")) {
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
                    this.handleError(e, reply, (reply, code, error) => {
                        reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "error", error: error, code: ErrorCode[code]});                    
                    });
                }
            });
        }

        if (this.activatedEndpoints.includes("api/verifyemail")) {
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
                    return this.handleError(e, reply, (reply, code, error) => {
                        reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "error", error: error, code: ErrorCode[code]});                    
                    });
                }
            });
        }

        if (this.activatedEndpoints.includes("api/userforsessionkey")) {
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

        if (this.activatedEndpoints.includes("api/getcsrftoken")) {
            this.app.get(this.prefix+'api/getcsrftoken', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info('POST ' + this.prefix+'api/getcsrftoken ' + request.ip + ' ' + (request.user?request.user.username:""));            
                try {
                    return reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "ok", csrfToken : this.getCsrfTokenFromCookie(request)});
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
        CrossauthLogger.logger.debug("Login: set csrf cookie " + csrfCookie.name + " opts " + JSON.stringify(sessionCookie.options));
        reply.cookie(sessionCookie.name, sessionCookie.value, sessionCookie.options);
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
        let sessionId = undefined;
        let oldSessionId : string|undefined = undefined;
        if (this.anonymousSessions && !this.keepAnonymousSessionId) 
            oldSessionId = this.getSessionIdFromCookie(request);
        if (this.anonymousSessions && this.keepAnonymousSessionId) {
            sessionId = this.getSessionIdFromCookie(request);
        }

        let { sessionCookie, csrfCookie } = await this.sessionManager.login("", "", sessionId, undefined, user);
        CrossauthLogger.logger.debug("Login: set session cookie " + sessionCookie.name + " opts " + JSON.stringify(sessionCookie.options));
        CrossauthLogger.logger.debug("Login: set csrf cookie " + csrfCookie.name + " opts " + JSON.stringify(sessionCookie.options));
        reply.cookie(sessionCookie.name, sessionCookie.value, sessionCookie.options);
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
        if (!this.passwordValidator(password)) {
            throw new CrossauthError(ErrorCode.PasswordFormat);
        }
        if (repeatPassword != undefined && repeatPassword != password) {
            throw new CrossauthError(ErrorCode.PasswordMatch);
        }
        await this.sessionManager.createUser(username, password, extraFields);
        if (!this.enableEmailVerification) {
            return this.login(request, reply, successFn);
        }
        return successFn(reply, undefined);
    }

    private async verifyEmail(request : FastifyRequest<{ Params: VerifyTokenParamType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, user? : User) => void) {
        const token = request.params.token;
        const user = await this.sessionManager.applyEmailVerificationToken(token);
        delete user.passwordHash;
        return this.loginWithUser(user, request, reply, successFn);
    }

    private async logout(request : FastifyRequest, reply : FastifyReply, 
        successFn : (reply : FastifyReply) => void) {
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
        : Promise<{sessionCookie: Cookie, csrfCookie: Cookie, user : User|undefined}> {
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

    private async getValidatedCsrfTokenAndUser(request : FastifyRequest, reply : FastifyReply) 
        : Promise<{sessionCookie: Cookie|undefined, csrfCookie: Cookie|undefined, user : User|undefined}> {
        let cookies = request.cookies;
        let sessionId : string|undefined = undefined;
        let csrfToken : string|undefined = undefined;
        if (cookies && this.sessionManager.sessionCookieName in cookies) {
            sessionId = cookies[this.sessionManager.sessionCookieName]||""
        };
        if (cookies && this.sessionManager.csrfCookieName in cookies) {
            csrfToken = cookies[this.sessionManager.csrfCookieName]||"";
        }
        let {sessionCookie, csrfCookie, user} = await this.sessionManager.getValidatedSessionAndCsrf(sessionId, csrfToken);
        if (sessionCookie && sessionId != sessionCookie.value) {
            CrossauthLogger.logger.debug("Creating session ID");
            reply.cookie(sessionCookie.name, sessionCookie.value, sessionCookie.options);
        }
        if (csrfCookie && csrfToken != csrfCookie.value) {
            CrossauthLogger.logger.debug("Creating CSRF Token");
            reply.cookie(csrfCookie.name, csrfCookie.value, csrfCookie.options);
        }        
        return {sessionCookie, csrfCookie, user};
    };

    private handleError(e : any, reply : FastifyReply, errorFn : (reply : FastifyReply, code : ErrorCode, error : string) => void) {
        let error = "Unknown error";
        let code = ErrorCode.UnknownError;
        if (e instanceof CrossauthError) {
            let ce = e as CrossauthError;
            code = ce.code;
            switch (ce.code) {
                case ErrorCode.UserNotExist:
                case ErrorCode.PasswordNotMatch:
                    error = "Invalid username or password";
                    code = ErrorCode.UsernameOrPasswordInvalid;
                    break;
                default:
                    error = ce.message;
            }
        }
        CrossauthLogger.logger.error(e);

        return errorFn(reply, code, error);

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
