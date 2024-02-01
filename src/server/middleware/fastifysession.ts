import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { UserStorage, KeyStorage } from '../storage';
import { AuthenticationParameters, Authenticator } from '../auth';
import { Hasher } from '../hasher';
import { Backend, type BackendOptions } from '../backend';
import { CrossauthError, ErrorCode } from "../..";
import { User, Key, UserInputFields } from '../../interfaces';
import { CrossauthLogger, j } from '../..';
import { setParameter, ParamType } from '../utils';
import { Server, IncomingMessage, ServerResponse } from 'http'

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
 * Options for {@link FastifyServer }.
 * 
 * See {@link FastifyServer } constructor for description of parameters
 */
export interface FastifySessionServerOptions extends BackendOptions {

    /** Page to redirect to after successful login, default "/" */
    loginRedirect? : string;

    /** Page to redirect to after successful logout, default "/" */
    logoutRedirect? : string;

    /** Function that throws a {@link index!CrossauthError} with {@link index!ErrorCode} `FormEnty` if the user doesn't confirm to local rules.  Doesn't validate passwords  */
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

    /** Template file containing the page for getting the 2nd factor after entering username and password
     * See the class documentation for {@link FastifyServer} for more info.  Defaults to "login.njk".
     */
    loginFactor2Page? : string;

    /** Template file containing the signup page (with without error messages).  
     * See the class documentation for {@link FastifyServer} for more info.  Defaults to "signup.njk".
     * Signup form should contain at least `username` and `password` and may also contain `repeatPassword`.  If you have additional
     * fields in your user table you want to pass from your form, prefix them with `user_`, eg `user_email`.
     * If you want to enable email verification, set `enableEmailVerification` and set `checkEmailVerified` 
     * on the user storage.
     */
    signupPage? : string;

    /** Page to set up 2FA after sign up */
    signupFactor2Page? : string;

    /** Page to render error messages, including failed login. 
     * See the class documentation for {@link FastifyServer} for more info.  Defaults to "error.njk".
     */
    errorPage? : string;

    /** Page to render for password changing.  
     * See the class documentation for {@link FastifyServer} for more info.  Defaults to "changepassword.njk".
     */
    changePasswordPage? : string,

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
}

export interface CsrfBodyType {
    csrfToken?: string;
}

interface LoginBodyType extends CsrfBodyType {
    username: string,
    password: string,
    persist? : boolean,
    next? : string,
}

interface LoginFactor2BodyType extends CsrfBodyType {
    persist? : boolean,
    next? : string,
    [key : string]: string|number|Date|boolean|undefined,
}

interface SignupBodyType extends LoginBodyType {
    repeatPassword?: string,
    email? : string,
    factor2? : string,
    [key : string]: string|number|Date|boolean|undefined,
}

interface SignupFactor2BodyType extends LoginBodyType {
    next? : string,
    persist? : boolean,
    [key:string] : any,
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

interface LoginParamsType {
    next? : string;
}

interface AuthenticatorDetails {
    name: string,
    friendlyName : string,
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

export class FastifySessionServer {

    private app : FastifyInstance<Server, IncomingMessage, ServerResponse>;
    private prefix : string;
    private loginRedirect = "/";
    private logoutRedirect : string = "/";
    private signupPage : string = "signup.njk";
    private signupFactor2Page : string = "signupfactor2.njk";
    private loginPage : string = "login.njk";
    private loginFactor2Page : string = "loginfactor2.njk";
    private errorPage : string = "error.njk";
    private changePasswordPage : string = "changepassword.njk";
    private updateUserPage : string = "updateuser.njk";
    private resetPasswordPage: string = "resetpassword.njk";
    private requestPasswordResetPage: string = "requestpasswordreset.njk";
    private emailVerifiedPage : string = "emailverified.njk";
    private anonymousSessions = true;
    private validateUserFn : (user : UserInputFields) => string[] = defaultUserValidator;
    private createUserFn : (request : FastifyRequest<{ Body: SignupBodyType }>, userEditableFields : string[]) => UserInputFields = defaultCreateUser;
    private updateUserFn : (user : User, request : FastifyRequest<{ Body: UpdateUserBodyType }>, userEditableFields : string[]) => User = defaultUpdateUser;
    private addToSession? : (request : FastifyRequest) => {[key: string] : string|number|boolean|Date|undefined};
    private validateSession? : (session: Key, user: User|undefined, request : FastifyRequest) => void;

    private userStorage : UserStorage;
    private sessionManager : Backend;
    private authenticators: {[key:string]: Authenticator}
    private allowedFactor2 : string[] = [];

    private enableEmailVerification : boolean = true;
    private enablePasswordReset : boolean = true;

    constructor(
        app: FastifyInstance<Server, IncomingMessage, ServerResponse>,
        prefix : string,
        userStorage: UserStorage, 
        keyStorage: KeyStorage, 
        authenticators: {[key:string]: Authenticator}, 
        options: FastifySessionServerOptions = {}) {

        this.app = app;

        setParameter("signupPage", ParamType.String, this, options, "SIGNUP_PAGE");
        setParameter("signupFactor2Page", ParamType.String, this, options, "SIGNUP_FACTOR2_PAGE");
        setParameter("loginPage", ParamType.String, this, options, "LOGIN_PAGE");
        setParameter("loginFactor2Page", ParamType.String, this, options, "LOGIN_FACTOR2_PAGE");
        setParameter("errorPage", ParamType.String, this, options, "ERROR_PAGE");
        setParameter("changePasswordPage", ParamType.String, this, options, "CHANGE_PASSWORD_PAGE");
        setParameter("updateUser", ParamType.String, this, options, "UPDATE_USER_PAGE");
        setParameter("resetPasswordPage", ParamType.String, this, options, "RESET_PASSWORD_PAGE");
        setParameter("requestPasswordResetPage", ParamType.String, this, options, "REQUEST_PASSWORD_RESET_PAGE");
        setParameter("emailVerifiedPage", ParamType.String, this, options, "EMAIL_VERIFIED_PAGE");
        setParameter("emailFrom", ParamType.String, this, options, "EMAIL_FROM");
        setParameter("persistSessionId", ParamType.Boolean, this, options, "PERSIST_SESSION_ID");
        setParameter("allowedFactor2", ParamType.StringArray, this, options, "ALLOWED_FACTOR2");
        setParameter("enableEmailVerification", ParamType.Boolean, this, options, "ENABLE_EMAIL_VERIFICATION");
        setParameter("enablePasswordReset", ParamType.Boolean, this, options, "ENABLE_PASSWORD_RESET");

        if (options.validateUserFn) this.validateUserFn = options.validateUserFn;
        if (options.createUserFn) this.createUserFn = options.createUserFn;
        if (options.updateUserFn) this.updateUserFn = options.updateUserFn;
        if (options.addToSession) this.addToSession = options.addToSession;
        if (options.validateSession) this.validateSession = options.validateSession;

        this.prefix = prefix;
        this.userStorage = userStorage;
        this.authenticators = authenticators;
        this.sessionManager = new Backend(userStorage, keyStorage, authenticators, options);

        ////////////////
        // hooks

        app.addHook('preHandler', async (request : FastifyRequest<{Body: CsrfBodyType}>, reply : FastifyReply) => {

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
    }    

    //////////////////
    // page endpoints

    addLoginEndpoints() {

        this.app.get(this.prefix+'login', async (request : FastifyRequest<{Querystring : LoginParamsType}>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'GET', url: this.prefix+'login', ip: request.ip}));
            if (request.user) return reply.redirect(request.query.next||this.loginRedirect); // already logged in

            let data : {next? : any, csrfToken: string|undefined} = {csrfToken: request.csrfToken};
            if (request.query.next) {
                data["next"] = request.query.next;
            }
            return reply.view(this.loginPage, data);
        });

        this.app.post(this.prefix+'login', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'login', ip: request.ip}));
            let next = request.body.next || this.loginRedirect;
            try {
                CrossauthLogger.logger.debug(j({msg: "Next page " + next}));

                return await this.login(request, reply, 
                (reply, user) => {
                    if (!user.factor2 || user.factor2.length == 0) {
                        CrossauthLogger.logger.debug(j({msg: "Successful login - sending redirect"}));
                        return reply.redirect(next);
                    } else {
                        let data : {next? : any, persist? : any, csrfToken: string|undefined} = {
                            csrfToken: request.csrfToken,
                            next: request.body.next||this.loginRedirect,
                            persist: request.body.persist ? "on" : "",
                        };
                        return reply.view(this.loginFactor2Page, data);
                    }
                });
            } catch (e) {
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, reply, (reply, error) => {
                    return reply.view(this.loginPage, {
                        error: error.message,
                        errors: error.messages, 
                        errorCode: error.code, 
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

    addLoginFactor2Endpoints() {
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
                return this.handleError(e, reply, (reply, error) => {
                    return reply.view(this.loginFactor2Page, {
                        error: error.message,
                        errors: error.messages, 
                        errorCode: error.code, 
                        errorCodeName: ErrorCode[error.code], 
                        next: request.body.next, 
                        persist: request.body.persist ? "on" : "",
                        csrfToken: request.csrfToken
                    });                      
                });
            }
        });
    }

    addSignupEndpoints() {
        this.app.get(this.prefix+'signup', async (request : FastifyRequest<{Querystring : LoginParamsType}>, reply : FastifyReply)  => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'GET', url: this.prefix+'signup', ip: request.ip}));
            if (this.signupPage)  { // if is redundant but VC Code complains without it
                let data : {next? : any, csrfToken: string|undefined, allowedFactor2: AuthenticatorDetails[]} = {csrfToken: request.csrfToken, allowedFactor2: this.allowedFactor2FriendlyNames()};
                if (request.query.next) {
                    data["next"] = request.query.next;
                }
                return reply.view(this.signupPage, data);
            }
        });

        this.app.post(this.prefix+'signup', async (request : FastifyRequest<{ Body: SignupBodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'signup', ip: request.ip, user: request.body.username}));
            let next = request.body.next || this.loginRedirect;
            try {
                CrossauthLogger.logger.debug(j({msg: "Next page " + next}));

                return await this.signup(request, reply, 
                (reply, data, _user) => {
                    if (data.userData?.factor2) {
                        console.log(data)
                        return reply.view(this.signupFactor2Page, {csrfToken: data.csrfToken, ...data.userData});
                    } else if (this.enableEmailVerification) {
                        return reply.view(this.signupPage, {
                            next: next, 
                            csrfToken: this.csrfToken(request, reply),
                            message: "Please check your email to finish signing up.",
                            allowedFactor2: this.allowedFactor2FriendlyNames(),
                            ...data.userData,
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
                        errorCode: error.code, 
                        errorCodeName: ErrorCode[error.code], 
                        next: next, 
                        persist: request.body.persist,
                        username: request.body.username,
                        csrfToken: this.csrfToken(request, reply),
                        factor2: request.body.factor2,
                        allowedFactor2: this.allowedFactor2FriendlyNames(),
                        ...extraFields
                        });
                    
                });
            }
        });
    }
    
    addSignupFactor2Endpoints() {
        this.app.post(this.prefix+'signupfactor2', async (request : FastifyRequest<{ Body: SignupFactor2BodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'signupfactor2', ip: request.ip}));
            let next = request.body.next || this.loginRedirect;
            try {
                CrossauthLogger.logger.debug(j({msg: "Next page " + next}));

                return await this.signupFactor2(request, reply, 
                (reply, _user) => {
                    if (this.enableEmailVerification) {
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
                CrossauthLogger.logger.debug(j({err: e}));
                try {
                    const sessionValue = this.getSessionIdFromCookie(request);
                    if (!sessionValue) {
                        CrossauthLogger.logger.error(j({msg: "Signup second factor failure", errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                        CrossauthLogger.logger.error(j({msg: "Session not defined during two factor process"}));
                        return reply.status(500).view(this.errorPage, {status: 500, error: "An unknown error occurred", errorCode: ErrorCode.UnknownError, errorCodeName: "UnknownError"});
                    }
                    let data = await this.sessionManager.dataForSessionKey(sessionValue);
                    let username = data?.username;
                    let factor2 = data?.factor2;
                    if (!username || !factor2) {
                        CrossauthLogger.logger.error(j({msg: "Signup two factor failure - cannot get user data from first factor", }));
                        return reply.status(500).view(this.errorPage, {status: 500, error: "An unknown error occurred", errorCode: ErrorCode.UnknownError, errorCodeName: "UnknownError"});
                    }
                    CrossauthLogger.logger.error(j({msg: "Signup two factor failure", user: username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                    const { userData } = await this.sessionManager.repeatTwoFactorSignup(username, sessionValue, factor2);
                    return this.handleError(e, reply, (reply, error) => {
                            return reply.view(this.signupFactor2Page, {
                            error: error.message,
                            errors: error.messages, 
                            errorCode: error.code, 
                            errorCodeName: ErrorCode[error.code], 
                            next: next, 
                            ...userData,
                            csrfToken: this.csrfToken(request, reply),
                        });
                        
                    });
                } catch (e2) {
                    CrossauthLogger.logger.error(j({err: e2}));
                    return reply.status(500).view(this.errorPage, {status: 500, error: "An unknown error occurred", errorCode: ErrorCode.UnknownError, errorCodeName: "UnknownError"});

                }
            }
        });
    }

    addChangePasswordEndpoints() {
        this.app.get(this.prefix+'changepassword', async (request : FastifyRequest<{Querystring : LoginParamsType}>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'GET', url: this.prefix+'changepassword', ip: request.ip, user: request.user?.username}));
            if (!request.user) return this.sendPageError(reply, 401);
            if (this.changePasswordPage)  { // if is redundant but VC Code complains without it
                let data : {csrfToken: string|undefined} = {csrfToken: request.csrfToken};
                return reply.view(this.changePasswordPage, data);
            }
        });

        this.app.post(this.prefix+'changepassword', async (request : FastifyRequest<{ Body: ChangePasswordBodyType }>, reply : FastifyReply) => {
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
                        errorCode: error.code, 
                        errorCodeName: ErrorCode[error.code], 
                        csrfToken: request.csrfToken,
                    });
                });
            }
        });
    }

    addUpdateUserEndpoints() {
        this.app.get(this.prefix+'updateuser', async (request : FastifyRequest<{Querystring : LoginParamsType}>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'GET', url: this.prefix+'updateuser', ip: request.ip, user: request.user?.username}));
            if (!request.user) return this.sendPageError(reply, 401);
            if (this.updateUserPage)  { // if is redundant but VC Code complains without it
                let data : {csrfToken: string|undefined, user: User} = {csrfToken: request.csrfToken, user: request.user};
                return reply.view(this.updateUserPage, data);
            }
        });

        this.app.post(this.prefix+'updateuser', async (request : FastifyRequest<{ Body: UpdateUserBodyType }>, reply : FastifyReply) => {
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
                        errorCode: error.code, 
                        errorCodeName: ErrorCode[error.code], 
                        csrfToken: request.csrfToken,
                    });
                });
            }
        });
    }

    addRequestPasswordResetENdpoints() {
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
                        errorCode: error.code, 
                        errorCodeName: ErrorCode[error.code], 
                        email: request.body.email,
                        csrfToken: request.csrfToken
                    });
                });
            }
        });
    }

    addResetPasswordEndpoints() {
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
                return reply.view(this.errorPage, {error: error, errorCode: code, errorCodeName: ErrorCode[code]});
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
                        errorCode: error.code, 
                        errorCodeName: ErrorCode[error.code], 
                        csrfToken: request.csrfToken,
                    });
                });
            }
        });
    }

    addVerifyEmailEndpoints() {
        this.app.get(this.prefix+'verifyemail/:token', async (request : FastifyRequest<{Params: VerifyTokenParamType}>, reply : FastifyReply) => {
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
                        errorCode: error.code, 
                        errorCodeName: ErrorCode[error.code], 
                        error: error.message,
                        errors: error.messages,
                    });
                });
            }
        });
    }

    addLogoutEndpoints() {
        this.app.post(this.prefix+'logout', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'logout', ip: request.ip, user: request.user?.username}));
            try {
                return await this.logout(request, reply, 
                (reply) => {return reply.redirect(this.logoutRedirect)});
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: "Logout failure", user: request.user?.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, reply, (reply, error) => {
                    return reply.view(this.errorPage, {error: error.message, errors: error.messages, errorCode: error.code, errorCodeName: ErrorCode[error.code]});
                    
                });
            }
        });
    }

    ////////////////////
    // API endpoints

    addApiLoginEndpoints() {

        this.app.post(this.prefix+'api/login', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/login', ip: request.ip}));
            if (request.user) return reply.header('Content-Type', JSONHDR).send({ok: false, user : request.user}); // already logged in
            try {
                return await this.login(request, reply, 
                (reply, user) => {
                    if (user.twoFactorRequired) {
                        return reply.header('Content-Type', JSONHDR).send({ok: true, twoFactorRequired: true});
                    } else {
                        return reply.header('Content-Type', JSONHDR).send({ok: true, user : user});
                    }
                });
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: "Login failure", user: request.body.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, reply, (reply, error) => {
                    reply.status(this.errorStatus(e)).header('Content-Type', JSONHDR).send({ok: false, error: error.message, errors: error.messages, errorCode: error.code, errorCodeName: ErrorCode[error.code]});                    
                });
            }
        });
    }

    addApiLoginFactor2Endpoints() {
        this.app.post(this.prefix+'api/loginfactor2', async (request : FastifyRequest<{ Body: LoginFactor2BodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/loginfactor2', ip: request.ip}));
            if (request.user) return reply.header('Content-Type', JSONHDR).send({ok: false, user : request.user}); // already logged in
            try {
                return await this.loginFactor2(request, reply, 
                (reply, user) => {
                    return reply.header('Content-Type', JSONHDR).send({ok: true, user : user});
                });
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: "Login failure", hashOfSessionCookie: this.getHashOfSessionCookie(request), errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.handleError(e, reply, (reply, error) => {
                    reply.status(this.errorStatus(e)).header('Content-Type', JSONHDR).send({ok: false, error: error.message, errors: error.messages, errorCode: error.code, errorCodeName: ErrorCode[error.code]});                    
                });
            }
        });
    }

    addApiLogoutEndpoints() {
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
                    reply.status(this.errorStatus(e)).header('Content-Type', JSONHDR).send({ok: false, error: error.message, errors: error.messages, errorCode: ErrorCode[error.code]});                    
                });
            }
        });
    }

    addApiSignupEndpoints() {
        this.app.post(this.prefix+'api/signup', async (request : FastifyRequest<{ Body: SignupBodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/signup', ip: request.ip, user: request.body.username}));
            try {
                return await this.signup(request, reply, 
                (reply, data, user) => {
                    return reply.header('Content-Type', JSONHDR).send({
                    ok: true,
                    user : user,
                    emailVerificationNeeded: this.enableEmailVerification||false,
                    ...data.userData,
                })});
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: "Signup failure", user: request.user?.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                this.handleError(e, reply, (reply, error) => {
                    reply.status(this.errorStatus(e)).header('Content-Type', JSONHDR).send({ok: false, error: error.message, errors: error.messages, errorCode: ErrorCode[error.code]});                    
                });
            }
        });
    }

    addApiSignupFactor2Endpoints() {
        this.app.post(this.prefix+'api/signupfactor2', async (request : FastifyRequest<{ Body: SignupFactor2BodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/signup', ip: request.ip, hashOfSessionCookie: this.getHashOfSessionCookie(request)}));
            try {
                return await this.signupFactor2(request, reply, 
                (reply, user) => {
                    return reply.header('Content-Type', JSONHDR).send({
                    ok: true,
                    user : user,
                    emailVerificationNeeded: this.enableEmailVerification,
                })});
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: "Signup 2FA configuration failure", user: request.user?.username, errorCodeName: e instanceof CrossauthError ? e.codeName : "UnknownError"}));
                CrossauthLogger.logger.debug(j({err: e}));
                this.handleError(e, reply, (reply, error) => {
                    reply.status(this.errorStatus(e)).header('Content-Type', JSONHDR).send({ok: false, error: error.message, errors: error.messages, errorCode: ErrorCode[error.code]});                    
                });
            }
        });
    }

    addApiChangePasswordEndpoints() {
        this.app.post(this.prefix+'api/changepassword', async (request : FastifyRequest<{ Body: ChangePasswordBodyType }>, reply : FastifyReply) => {
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
                    return reply.status(this.errorStatus(e)).header('Content-Type', JSONHDR).send({ok: false, error: error.message, errors: error.messages, errorCode: error.code, errorCodeName: ErrorCode[error.code]});                    
                }, true);
            }
        });
    }

    addApiUpdateUserEndpoints() {
        this.app.post(this.prefix+'api/updateuser', async (request : FastifyRequest<{ Body: UpdateUserBodyType }>, reply : FastifyReply) => {
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
                    reply.status(this.errorStatus(e)).header('Content-Type', JSONHDR).send({ok:false, error: error.message, errors: error.messages, errorCode: error.code, errorCodeName: ErrorCode[error.code]});                    
                }, true);
            }
        });
    }

    addApiResetPasswordEndpoints() {
        this.app.post(this.prefix+'api/resetpassword', async (request : FastifyRequest<{ Body: ResetPasswordBodyType }>, reply : FastifyReply) => {
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
                    reply.status(this.errorStatus(e)).header('Content-Type', JSONHDR).send({ok: false, error: error.message, errors: error.messages, errorCode: error.code, errorCodeName: ErrorCode[error.code]});                    
                }, true);
            }
        });
    }

    addApiRequestPasswordResetEndpoints() {
        this.app.post(this.prefix+'api/requestpasswordreset', async (request : FastifyRequest<{ Body: RequestPasswordResetBodyType }>, reply : FastifyReply) => {
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
                    reply.status(this.errorStatus(e)).header('Content-Type', JSONHDR).send({ok: false, error: error.message, errors: error.messages, errorCode: error.code, errorCodeName: ErrorCode[error.code]});                    
                }, true);
            }
        });
    }

    addApiVerifyEmailEndpoints() {
        this.app.get(this.prefix+'api/verifyemail/:token', async (request : FastifyRequest<{Params: VerifyTokenParamType}>, reply : FastifyReply) => {
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
                    reply.status(this.errorStatus(e)).header('Content-Type', JSONHDR).send({ok: false, error: error.message, errors: error.messages, errorCode: error.code, errorCodeName: ErrorCode[error.code]});                    
                });
            }
        });
    }

    addApiUserForSessionKeyEndpoints() {
        this.app.post(this.prefix+'api/userforsessionkey', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({msg: "API visit", method: 'POST', url: this.prefix+'api/userforsessionkey', ip: request.ip, user: request.user?.username, hashedSessionCookie: this.getHashOfSessionCookie(request)}));
            if (!request.user) return this.sendJsonError(reply, 401);
            await this.validateCsrfToken(request)
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
                return reply.status(this.errorStatus(e)).header('Content-Type', JSONHDR).send({ok: false, errorCode: code, errorCodeName: ErrorCode[code], error : error});

            }
        });
    }

    addApiGetCsrfTokenEndpoints() {
        this.app.get(this.prefix+'api/getcsrftoken', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) => {
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
                return reply.status(this.errorStatus(e)).header('Content-Type', JSONHDR).send({ok: false, errorCode: code, errorCodeName: ErrorCode[code], error : error});

            }
        });
    }

    /////////////////
    // Shared between page and API endpoints

    private async login(request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, user: User) => void) {
        if (request.user) return successFn(reply, request.user); // already logged in
        const username = request.body.username;
        const persist = request.body.persist;
        await this.validateCsrfToken(request);

        const oldSessionId = this.getSessionIdFromCookie(request);

        let extraFields = this.addToSession ? this.addToSession(request) : {}
        let { sessionCookie, csrfCookie, user } = await this.sessionManager.login(username, request.body, extraFields, persist);
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
        return successFn(reply, user);
    }

    private async loginFactor2(request : FastifyRequest<{ Body: LoginFactor2BodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, user: User) => void) {
        if (request.user) return successFn(reply, request.user); // already logged in
        const oldSessionCookieValue = this.getSessionIdFromCookie(request);
        if (!oldSessionCookieValue) throw new CrossauthError(ErrorCode.Unauthorized);
        const persist = request.body.persist;
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

    private async loginWithUser(user: User, request : FastifyRequest, reply : FastifyReply, 
        successFn : (res : FastifyReply, user: User) => void) {
        const oldSessionId = this.getSessionIdFromCookie(request);

        let extraFields = this.addToSession ? this.addToSession(request) : {}
        let { sessionCookie, csrfCookie } = await this.sessionManager.login("", {}, extraFields, undefined, user);
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
            
        await this.validateCsrfToken(request);
        const username = request.body.username;
        const next = request.body.next;
        if (!request.body.factor2) {
            request.body.factor2 = this.allowedFactor2[0]; 
        }
        if (request.body.factor2 && !(this.allowedFactor2.includes(request.body.factor2))) {
            throw new CrossauthError(ErrorCode.Forbidden, "Illegal second factor " + request.body.factor2 + " requested");
        }
        if (request.body.factor2 == "none") request.body.factor2 = undefined;
        let user = this.createUserFn(request, this.userStorage.userEditableFields);
        let passwordErrors = this.authenticators[user.factor1].validateSecrets(request.body);
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
        user.state = "active";
        if (request.body.factor2 && request.body.factor2!="none") {
           user. state = "awaitingtwofactor";
        } else if (this.enableEmailVerification) {
            user.state = "awaitingemailverification";
        }
    
        let userErrors = this.validateUserFn(user);
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
        
        if (((!request.body.factor2) || request.body.factor2=="none") && !twoFactorInitiated) {
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
                const sessionValue = this.getSessionIdFromCookie(request);
                if (!sessionValue) throw new CrossauthError(ErrorCode.Unauthorized);
                const secrets = await this.sessionManager.dataForSessionKey(sessionValue);
                const username = secrets.username;
                const factor2 = secrets.factor2;
                const resp = await this.sessionManager.repeatTwoFactorSignup(username, sessionValue, factor2);
                userData = resp.userData;
            } else {
                // account not created - create one with state awaiting 2FA setup
                const sessionValue = await this.createAnonymousSession(request, reply);
                const resp = await this.sessionManager.initiateTwoFactorSignup(user, request.body, sessionValue, repeatSecrets);
                userData = resp.userData;
            }

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
                CrossauthLogger.logger.error(j({err: e}));
                try {
                    this.sessionManager.deleteUserByUsername(username);
                } catch (e) {
                    CrossauthLogger.logger.error(j({err: e}));
                }

            }
        }
    }

    private async signupFactor2(request : FastifyRequest<{ Body: SignupFactor2BodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, user? : User) => void) {
        const sessionId = this.getSessionIdFromCookie(request);
        await this.validateCsrfToken(request);
        let user;
        try {
            if (!sessionId) throw new CrossauthError(ErrorCode.Unauthorized, "No session active while enabling 2FA.  Please enable cookies");
            user = await this.sessionManager.completeTwoFactorSignup(request.body, sessionId);
        } catch (e) {
            CrossauthLogger.logger.error(j({msg: "signupfactor2 failed", hashedSessionCookie: this.getHashOfSessionCookie(request) }));
            CrossauthLogger.logger.debug(j({err: e}));
            throw e;
        }
        if (!this.enableEmailVerification) {
            return this.loginWithUser(user, request, reply, (request, user) => {
                return successFn(request, user)});
        }
        return successFn(reply, user);
    }

    private async changePassword(request : FastifyRequest<{ Body: ChangePasswordBodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, user? : User) => void) {

        if (!request.user) throw new CrossauthError(ErrorCode.Unauthorized);
        await this.validateCsrfToken(request)
        const authenticator = this.authenticators[request.user.factor1];
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

        let errors = authenticator.validateSecrets(newSecrets);
        if (errors.length > 0) {
            throw new CrossauthError(ErrorCode.PasswordFormat);
        }
        await this.sessionManager.changeSecrets(request.user.username, 1, oldSecrets, newSecrets, repeatSecrets);
        return successFn(reply, undefined);
    }

    private async updateUser(request : FastifyRequest<{ Body: UpdateUserBodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, user : User, emailVerificationRequired : boolean) => void) {

        if (!request.user) throw new CrossauthError(ErrorCode.Unauthorized);
        await this.validateCsrfToken(request);
        let user : User = {
            id: request.user.id,
            username: request.user.username,
            state: "active",
        };
        user = this.updateUserFn(user, request, this.userStorage.userEditableFields);
        let errors = this.validateUserFn(user);
        if (errors.length > 0) {
            throw new CrossauthError(ErrorCode.FormEntry, errors);
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
            await this.validateCsrfToken(request);
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
        if (this.anonymousSessions) await this.validateCsrfToken(request);
        //const user = await this.sessionManager.userForPasswordResetToken(request.body.token);
        const token = request.body.token;
        const user = await this.sessionManager.userForPasswordResetToken(token);
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

        let errors = authenticator.validateSecrets(newSecrets);
        if (errors.length > 0) {
            throw new CrossauthError(ErrorCode.PasswordFormat);
        }
        const user1 = await this.sessionManager.resetSecret(token, 1, newSecrets, repeatSecrets);
        return this.loginWithUser(user1, request, reply, successFn);
    }

    private async logout(request : FastifyRequest, reply : FastifyReply, 
        successFn : (reply : FastifyReply) => void) {
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

    //////////////
    // Helpers

    getSessionIdFromCookie(request : FastifyRequest) : string|undefined{
        if (request.cookies && this.sessionManager.sessionCookieName in request.cookies) {       
            return request.cookies[this.sessionManager.sessionCookieName]
        }
        return undefined;
    }

    getCsrfTokenFromCookie(request : FastifyRequest) : string|undefined{
        if (request.cookies && this.sessionManager.csrfCookieName in request.cookies) {       
            return request.cookies[this.sessionManager.csrfCookieName]
        }
        return undefined;
    }

    getHashOfSessionCookie(request : FastifyRequest) : string {
        const cookieValue = this.getSessionIdFromCookie(request);
        if (!cookieValue) return "";
        try {
            return Hasher.hash(cookieValue);
        } catch (e) {}
        return "";
    }

    getHashOfCsrfCookie(request : FastifyRequest) : string {
        const cookieValue = this.getCsrfTokenFromCookie(request);
        if (!cookieValue) return "";
        try {
            return Hasher.hash(cookieValue);
        } catch (e) {}
        return "";
    }

    async validateCsrfToken(request : FastifyRequest<{ Body: CsrfBodyType }>) {
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
        CrossauthLogger.logger.warn(j({msg: error, errorCode: code, errorCodeName: codeName, httpStatus: status}));
        if (this.errorPage) {
            return reply.status(status).view(this.errorPage, {status: status, error: error, errorCode: code, errorCodeName: codeName});
        } else {
            return reply.status(status).send(status==401 ? ERROR_401 : ERROR_500);
        }
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
        return reply.header('Content-Type', JSONHDR).status(status).send({ok: false, status: status, error: error, errorCode: code, errorCodeName: codeName});
    }

    errorStatus(e : any) {
        if (typeof e == "object" && "httpStatus" in e) return e.httpStatus||500;
        return 500;
    }

    private allowedFactor2FriendlyNames() : AuthenticatorDetails[] {
        let ret : {name: string, friendlyName: string}[] = [];
        this.allowedFactor2.forEach((authenticatorName) => {
            if (authenticatorName in this.authenticators) {
                ret.push({name: authenticatorName, friendlyName: this.authenticators[authenticatorName].friendlyName});
            } else if (authenticatorName == "none") {
                ret.push({name: "none", friendlyName: "None"});

            }
        });
        console.log(ret)
        return ret;
    }
}
