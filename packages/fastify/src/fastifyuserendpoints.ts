import {
    type FastifyRequest,
    type FastifyReply } from 'fastify';
import {
    CrossauthError,
    ErrorCode,
    CrossauthLogger,
    j,
} from '@crossauth/common';
import { UserState } from '@crossauth/common';
import type { User } from '@crossauth/common';
import { FastifyServer } from './fastifyserver';
import { FastifySessionServer,
    type FastifySessionServerOptions,
    type CsrfBodyType} from './fastifysession';
import {
    setParameter,
    ParamType,
    Crypto, } from '@crossauth/backend';
import type {
    AuthenticationParameters } from '@crossauth/backend';
import type {
    DeleteUserQueryType,
} from './fastifyadminendpoints.ts';
    
/////////////////////////////////////////////////////////////////////
// Fastify data types

/**
 * Type for Fastify request body when making an updateuser request.
 * Allows any key value since developers can add fields to the User object.
 */
export interface UpdateUserBodyType extends CsrfBodyType {
    [key: string] : string|undefined,
}

/**
 * Query parameters for the changefactor2 GET endpoint
 */
export interface ChangeFactor2QueryType {
    next? : string,
    required? : boolean,
}
    
/**
 * Body parameters for the changefactor2 POST endpoint
 */
export interface ChangeFactor2BodyType extends CsrfBodyType {
    factor2: string,
    next? : string,
    required?: boolean
}

/**
 * Query parameters for the changepassword GET endpoint
 */
export interface ChangePasswordQueryType {
    next? : string;
    required?: boolean
}

/**
 * Body parameters for the changepassword POST endpoint
 */
export interface ChangePasswordBodyType extends CsrfBodyType {
    oldPassword: string,
    newPassword: string,
    repeatPassword?: string,
    next? : string,
    required?: boolean
}

/**
 * Query parameters for the configurefactor2 GET endpoingt
 */
export interface ConfigureFactor2QueryType {
    next? : string,
}

/**
 * Body parameters for the configurefactor2 POST endpoint
 */
export interface ConfigureFactor2BodyType extends CsrfBodyType {
    next? : string,
    otp? : string,
    token? : string,
    [key:string] : any,
}

/**
 * Query parameters for the requestpasswordreset GET endpoint
 */
export interface RequestPasswordResetQueryType {
    next? : string,
    required? : boolean,
}

/**
 * Body parameters for the requestpasswordreset POST endpoint
 */
export interface RequestPasswordResetBodyType extends CsrfBodyType {
    email: string,
    next? : string,
    required? : boolean,
}

/**
 * Body parameters for the resetpassword POST endpoint
 */
export interface ResetPasswordBodyType extends CsrfBodyType {
    token: string,
    newPassword: string,
    repeatPassword?: string,
}

/**
 * URL parameter for the verifytoken endpoint
 */
export interface VerifyTokenParamType {
    token : string,
}


const JSONHDR : [string,string] = 
    ['Content-Type', 'application/json; charset=utf-8'];

///////////////////////////////////////////////////////////////////////
// Class

/**
 * This class provides user endpoints for the Fastify server.
 * 
 * Endpoints include changeing password, editing the User record, etc.
 * 
 * This class is not intended to be created directly.  It is created
 * by {@link FastifySessionServer}.  For a description of the endpoints,
 * and how to create templates for them, see that class.
 */
export class FastifyUserEndpoints {
    private sessionServer : FastifySessionServer;
    private enableEmailVerification : boolean = true;
    private enablePasswordReset : boolean = true;

    /**
     * The app prefix that was set during construction,
     */
    readonly prefix : string = "/";

    // pages
    private updateUserPage : string = "updateuser.njk";
    private changeFactor2Page : string = "changefactor2.njk";
    private configureFactor2Page : string = "configurefactor2.njk";
    private changePasswordPage : string = "changepassword.njk";
    private resetPasswordPage: string = "resetpassword.njk";
    private requestPasswordResetPage: string = "requestpasswordreset.njk";
    private emailVerifiedPage : string = "emailverified.njk";
    private signupPage : string = "signup.njk";
    private deleteUserPage = "deleteuser.njk";

    /**
     * Constructor.
     * 
     * @param sessionServer the instance of the Fastify session server this
     *        object belongs to
     * @param options See {@link FastifySessionServerOptions}
     */
    constructor(sessionServer : FastifySessionServer,
        options: FastifySessionServerOptions = {}) {

        this.sessionServer = sessionServer;
        setParameter("prefix", ParamType.String, this, options, "PREFIX");
        setParameter("enableEmailVerification", ParamType.Boolean, this, options, "ENABLE_EMAIL_VERIFICATION");
        setParameter("enablePasswordReset", ParamType.Boolean, this, options, "ENABLE_PASSWORD_RESET");
        setParameter("updateUserPage", ParamType.String, this, options, "UPDATE_USER_PAGE");
        setParameter("changeFactor2Page", ParamType.String, this, options, "CHANGE_FACTOR2_PAGE");
        setParameter("configureFactor2Page", ParamType.String, this, options, "SIGNUP_FACTOR2_PAGE");
        setParameter("changePasswordPage", ParamType.String, this, options, "CHANGE_PASSWORD_PAGE");
        setParameter("resetPasswordPage", ParamType.String, this, options, "RESET_PASSWORD_PAGE");
        setParameter("requestPasswordResetPage", ParamType.String, this, options, "REQUEST_PASSWORD_RESET_PAGE");
        setParameter("emailVerifiedPage", ParamType.String, this, options, "EMAIL_VERIFIED_PAGE");
        setParameter("signupPage", ParamType.String, this, options, "SIGNUP_PAGE");
        setParameter("deleteUserPage", ParamType.String, this, options, "DELETE_USER_PAGE");
    }

    //////////////////////////////////////////////////////////////////
    // Endpoints

    /**
     * Adds the `updateuser` GET and POST endpoints.
     */
    addUpdateUserEndpoints() {
        this.sessionServer.app.get(this.prefix+'updateuser', 
            async (request: FastifyRequest,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'GET',
                    url: this.prefix + 'updateuser',
                    ip: request.ip,
                    user: request.user?.username
                }));
            if (!request.user || !this.sessionServer.canEditUser(request)) {
                return FastifyServer.sendPageError(reply,
                    401,
                    this.sessionServer.errorPage);
            }
            if (this.updateUserPage)  { // if is redundant but VC Code complains without it
                let data : {urlPrefix: string, csrfToken: string|undefined, user: User, allowedFactor2: {[key:string]: any}} = {
                    urlPrefix: this.prefix, 
                    csrfToken: request.csrfToken, 
                    user: request.user,
                    allowedFactor2: this.sessionServer.allowedFactor2Details(),
                };
                return reply.view(this.updateUserPage, data);
            }
        });

        this.sessionServer.app.post(this.prefix+'updateuser', 
            async (request: FastifyRequest<{ Body: UpdateUserBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.prefix + 'updateuser',
                    ip: request.ip,
                    user: request.user?.username
                }));
                if (!this.sessionServer.canEditUser(request)) return FastifyServer.sendPageError(reply,
                    401,
                    this.sessionServer.errorPage);
                let extraFields : {[key:string] : string|number|boolean|Date|undefined} = {};
                for (let field in request.body) {
                    if (field.startsWith("user_")) extraFields[field] = request.body[field];
                }

                try {
                    return await this.updateUser(request, reply, 
                    (reply, _user, emailVerificationRequired) => {
                        const message = emailVerificationRequired 
                            ? "Please click on the link in your email to verify your email address."
                            : "Your details have been updated";
                        return reply.view(this.updateUserPage, {
                            csrfToken: request.csrfToken,
                            message: message,
                            urlPrefix: this.prefix, 
                            allowedFactor2: this.sessionServer.allowedFactor2Details(),
                        });
                    });
                } catch (e) {
                    const ce = CrossauthError.asCrossauthError(e);
                    CrossauthLogger.logger.error(j({msg: "Update user failure", user: request.body.username, errorCodeName: ce.codeName, errorCode: ce.code}));
                    CrossauthLogger.logger.debug(j({err: e}));
                    let extraFields : { [key : string] : any }= {};
                    for (let field in request.body) {
                        if (field.startsWith("user_")) extraFields[field] = 
                            request.body[field];
                    }
                    return this.sessionServer.handleError(e, request, reply, (reply, error) => {
                        return reply.view(this.updateUserPage, {
                            user: request.user,
                            errorMessage: error.message,
                            errorMessages: error.messages, 
                            errorCode: error.code, 
                            errorCodeName: ErrorCode[error.code], 
                            csrfToken: request.csrfToken,
                            urlPrefix: this.prefix, 
                            allowedFactor2: this.sessionServer.allowedFactor2Details(),
                            ...extraFields,
                        });
                    });
                }
        });
    }

    /**
     * Adds the `api/updateuser` POST endpoint.
     */
    addApiUpdateUserEndpoints() {
        this.sessionServer.app.post(this.prefix+'api/updateuser', 
            async (request: FastifyRequest<{ Body: UpdateUserBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.prefix + 'api/updateuser',
                    ip: request.ip,
                    user: request.user?.username
                }));
            if (!this.sessionServer.canEditUser(request)) {
                return this.sessionServer.sendJsonError(reply, 401);
            }
            try {
                return await this.updateUser(request, reply, 
                (reply, _user, emailVerificationRequired) => 
                    {return reply.header(...JSONHDR).send({
                    ok: true,
                    emailVerificationRequired: emailVerificationRequired,
                })});
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e); 
                CrossauthLogger.logger.error(j({
                    msg: "Update user failure",
                    user: request.user?.username,
                    errorCodeName: ce.codeName,
                    errorCode: ce.code
                }));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.sessionServer.handleError(e, request, reply, (reply, error) => {
                    reply.status(this.sessionServer.errorStatus(e)).header(...JSONHDR)
                        .send({
                            ok: false,
                            errorMessage: error.message,
                            errorMessages: error.messages,
                            errorCode: error.code,
                            errorCodeName: ErrorCode[error.code]
                    });                    
                }, true);
            }
        });
    }

    /**
     * Adds the `changefactor2` GET and POST endpoints.
     */
    addChangeFactor2Endpoints() {
        this.sessionServer.app.get(this.prefix+'changefactor2', 
            async (request: FastifyRequest<{ Querystring: ChangeFactor2QueryType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'GET',
                    url: this.prefix + 'changefactor2',
                    ip: request.ip,
                    user: request.user?.username
                }));
                if (!this.sessionServer.isSessionUser(request) || !request.user) {
                    // user is not logged on - check if there is an anonymous 
                    // session with passwordchange set (meaning the user state
                    // was set to changepasswordneeded when logging on)
                    const data = await this.sessionServer.getSessionData(request, "factor2change")
                    if (!data?.username) {
                        if (!this.sessionServer.isSessionUser(request)) {
                            // as we create session data, user has to be logged in with cookies
                            return FastifyServer.sendPageError(reply,
                        401,
                        this.sessionServer.errorPage);
                        } 
                    }
                }
                let data = {
                    urlPrefix: this.prefix, 
                    csrfToken: request.csrfToken,
                    next: request.query.next??this.sessionServer.loginRedirect,
                    allowedFactor2: this.sessionServer.allowedFactor2Details(),
                    factor2 : request.user?.factor2??"none",
                    required: request.query.required ?? false,
                };
                return reply.view(this.changeFactor2Page, data);
        });

        this.sessionServer.app.post(this.prefix+'changefactor2', 
            async (request: FastifyRequest<{ Body: ChangeFactor2BodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.prefix + 'changefactor2',
                    ip: request.ip,
                    user: request.user?.username
                }));
                if (!this.sessionServer.isSessionUser(request) || !request.user) {
                    // user is not logged on - check if there is an anonymous 
                    // session with passwordchange set (meaning the user state
                    // was set to changepasswordneeded when logging on)
                    const data = await this.sessionServer.getSessionData(request, "factor2change")
                    if (!data?.username) {
                        if (!this.sessionServer.isSessionUser(request)) {
                            return FastifyServer.sendPageError(reply,
                        401,
                        this.sessionServer.errorPage);
                        } 
                    }
                }
                try {
                    return await this.changeFactor2(request, reply, 
                        (reply, data, _user) => {
                            if (data.factor2) {
                                return reply.view(this.configureFactor2Page, {
                                    csrfToken: data.csrfToken,
                                    next: request.body.next ?? this.sessionServer.loginRedirect,
                                    ...data.userData
                                });
                            } else {
                                return reply.view(this.configureFactor2Page, {
                                    message: "Two factor authentication has been updated",
                                    next: request.body.next ?? this.sessionServer.loginRedirect,
                                    csrfToken: data.csrfToken,
                                });
                            }
                    });
                } catch (e) {
                    const ce = CrossauthError.asCrossauthError(e);
                    CrossauthLogger.logger.error(j({
                        msg: "Change two factor authentication failure",
                        user: request.user?.username,
                        errorCodeName: ce.codeName,
                        errorCode: ce.code
                    }));
                    CrossauthLogger.logger.debug(j({err: e}));
                    return this.sessionServer.handleError(e, request, reply, (reply, error) => {
                        return reply.view(this.changeFactor2Page, {
                            errorMessage: error.message,
                            errorMessages: error.messages, 
                            errorCode: error.code, 
                            errorCodeName: ErrorCode[error.code], 
                            csrfToken: request.csrfToken,
                            urlPrefix: this.prefix, 
                            allowedFactor2: this.sessionServer.allowedFactor2Details(),
                            factor2: request.user?.factor2??"none",
                            next: request.body.next??this.sessionServer.loginRedirect,
                            required: request.body.required,
                        });
                    });
                }
        });
    }

    /**
     * Adds the `api/changefactort2` POST endpoint.
     */
    addApiChangeFactor2Endpoints() {
        this.sessionServer.app.post(this.prefix+'api/changefactor2', 
            async (request: FastifyRequest<{ Body: ChangeFactor2BodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.prefix + 'api/changefactor2',
                    ip: request.ip,
                    user: request.user?.username
                }));
            if (!this.sessionServer.isSessionUser(request)) return this.sessionServer.sendJsonError(reply, 401);
            try {
                return await this.changeFactor2(request, reply, 
                    (reply, data, _user) => {
                        return reply.header(...JSONHDR).send({
                        ok: true,
                        ...data.userData,
                    })});
                } catch (e) {
                const ce = CrossauthError.asCrossauthError(e); 
                CrossauthLogger.logger.error(j({
                    msg: "Change factor2 failure",
                    user: request.user?.username,
                    errorCodeName: ce.codeName,
                    errorCode: ce.code
                }));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.sessionServer.handleError(e, request, reply, (reply, error) => {
                    return reply.status(this.sessionServer.errorStatus(e)).header(...JSONHDR)
                        .send({
                            ok: false,
                            errorMessage: error.message,
                            errorMessages: error.messages,
                            errorCode: error.code,
                            errorCodeName: ErrorCode[error.code]
                        });                    
                }, true);
            }
        });
    }

    /**
     * Adds the `changepassword` GET and POST endpoints.
     */
    addChangePasswordEndpoints() {
        this.sessionServer.app.get(this.prefix+'changepassword', 
            async (request: FastifyRequest<{ Querystring: ChangePasswordQueryType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'GET',
                    url: this.prefix + 'changepassword',
                    ip: request.ip,
                    user: request.user?.username
                }));
                if (!this.sessionServer.isSessionUser(request) || !request.user) {
                    // user is not logged on - check if there is an anonymous 
                    // session with passwordchange set (meaning the user state
                    // was set to UserState.passwordChangeNeeded when logging on)
                    const data = 
                        await this.sessionServer.getSessionData(request, "passwordchange")
                    if (data?.username == undefined) {
                    if (!this.sessionServer.isSessionUser(request)) {
                        return FastifyServer.sendPageError(reply,
                         401,
                            this.sessionServer.errorPage);
                        }
                    }
                }
            
                let data: {
                    urlPrefix: string,
                    csrfToken: string | undefined
                    next: string | undefined,
                    required? : boolean | undefined,
                } = {
                    urlPrefix: this.prefix,
                    csrfToken: request.csrfToken,
                    next : request.query.next,
                    required : request.query.required
                };
                return reply.view(this.changePasswordPage, data);
        });

        this.sessionServer.app.post(this.prefix+'changepassword', 
            async (request: FastifyRequest<{ Body: ChangePasswordBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.prefix + 'changepassword',
                    ip: request.ip,
                    user: request.user?.username
                }));
            try {
                return await this.changePassword(request, reply, 
                (reply, _user) => {
                    if (request.body.next) {
                        return reply.redirect(request.body.next);
                    } 
                    return reply.view(this.changePasswordPage, {
                        csrfToken: request.csrfToken,
                        message: "Your password has been changed.",
                        urlPrefix: this.prefix, 
                        next: request.body.next,
                        required: request.body.required,
                    });
                });
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.error(j({
                    msg: "Change password failure",
                    user: request.user?.username,
                    errorCodeName: ce.codeName,
                    errorCode: ce.code
                }));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.sessionServer.handleError(e, request, reply, (reply, error) => {
                    return reply.view(this.changePasswordPage, {
                        errorMessage: error.message,
                        errorMessages: error.messages, 
                        errorCode: error.code, 
                        errorCodeName: ErrorCode[error.code], 
                        csrfToken: request.csrfToken,
                        urlPrefix: this.prefix, 
                        next : request.body.next,
                        required: request.body.required,
                    });
                });
            }
        });
    }

    /**
     * Adds the `api/changepassword` POST endpoint.
     */
    addApiChangePasswordEndpoints() {
        this.sessionServer.app.post(this.prefix+'api/changepassword', 
            async (request: FastifyRequest<{ Body: ChangePasswordBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.prefix + 'api/changepassword',
                    ip: request.ip,
                    user: request.user?.username
                }));
            if (!this.sessionServer.canEditUser(request)) return this.sessionServer.sendJsonError(reply, 401);
            try {
                return await this.changePassword(request, reply, 
                (reply, _user) => {return reply.header(...JSONHDR).send({
                    ok: true,
                })});
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e); 
                CrossauthLogger.logger.error(j({
                    msg: "Change password failure",
                    user: request.user?.username,
                    errorCodeName: ce.codeName,
                    errorCode: ce.code
                }));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.sessionServer.handleError(e, request, reply, (reply, error) => {
                    return reply.status(this.sessionServer.errorStatus(e)).header(...JSONHDR)
                        .send({
                            ok: false,
                            errorMessage: error.message,
                            errorMessages: error.messages,
                            errorCode: error.code,
                            errorCodeName: ErrorCode[error.code]
                    });                    
                }, true);
            }
        });
    }

    /**
     * Adds the `configurefactor2` GET and POST endpoints.
     */
    addConfigureFactor2Endpoints() {

        this.sessionServer.app.get(this.prefix+'configurefactor2', 
            async (request: FastifyRequest<{ Querystring: ConfigureFactor2QueryType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'GET',
                    url: this.prefix + 'configurefactor2',
                    ip: request.ip
                }));
            try {
                return await this.reconfigureFactor2(request, reply, 
                (reply, data, _user) => {
                    return reply.view(this.configureFactor2Page, { ...data, 
                        next: request.query.next ?? this.sessionServer.loginRedirect});
                });
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.error(j({
                    msg: "Configure factor2 failure",
                    user: request.user?.username,
                    errorCodeName: ce.codeName,
                    errorCode: ce.code              
                }));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.sessionServer.handleError(e, request, reply, (reply, error) => {
                    return reply.view(this.configureFactor2Page, {
                        errorMessage: error.message,
                        errorMessages: error.messages, 
                        errorCode: error.code, 
                        errorCodeName: ErrorCode[error.code], 
                        next: request.query.next??this.sessionServer.loginRedirect, 
                        csrfToken: request.csrfToken,
                        urlPrefix: this.prefix, 
                    });
                    
                });
            }
        });

        this.sessionServer.app.post(this.prefix+'configurefactor2', 
            async (request: FastifyRequest<{ Body: ConfigureFactor2BodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.prefix + 'configurefactor2',
                    ip: request.ip
                }));
                let next = 
                request.body.next && request.body.next.length > 0 ? 
                    request.body.next : this.sessionServer.loginRedirect;
            try {
                CrossauthLogger.logger.debug(j({msg: "Next page " + next}));

                return await this.configureFactor2(request, reply, 
                (reply, user) => {

                    // success

                    const authenticator = user?.factor2 ? 
                        this.sessionServer.authenticators[user.factor2] : undefined;
                    if (!this.sessionServer.isSessionUser(request) && 
                        this.enableEmailVerification &&
                         (authenticator == undefined || 
                            authenticator.skipEmailVerificationOnSignup() != true)) {
                        // email verification has been sent - tell user
                        return reply.view(this.signupPage, {
                            next: next, 
                            csrfToken: request.csrfToken,
                            urlPrefix: this.prefix, 
                            message: "Please check your email to finish signing up."
                        });
                    } else {
                        if (!this.sessionServer.isSessionUser(request)) {
                            // we came here as part of login in - take user to orignally requested page
                            return reply.redirect(request.body.next??this.sessionServer.loginRedirect);
                        } else {
                            // we came here because the user asked to change 2FA - tell them it was successful
                            return reply.view(this.configureFactor2Page, {
                                message: "Two-factor authentication updated",
                                urlPrefix: this.prefix, 
                                next: next, 
                                required: request.body.required,
                                csrfToken: request.csrfToken,
                            });
                        }
                    }
                });
            } catch (e) {

                // error

                CrossauthLogger.logger.debug(j({err: e}));
                try {
                    if (!request.sessionId) {
                        // this shouldn't happen - user's cannot call this URL without having a session,
                        // user or anonymous.  However, just in case...
                        const ce = CrossauthError.asCrossauthError(e);
                        CrossauthLogger.logger.error(j({msg: "Signup second factor failure", errorCodeName: ce.codeName, errorCode: ce.code}));
                        CrossauthLogger.logger.error(j({msg: "Session not defined during two factor process"}));
                        return reply.status(500).view(this.sessionServer.errorPage, {status: 500, errorMessage: "An unknown error occurred", errorCode: ErrorCode.UnknownError, errorCodeName: "UnknownError"});
                    }

                    // normal error - wrong code, etc.  show the page again
                    let data = (await this.sessionServer.sessionManager.dataForSessionId(request.sessionId))["2fa"];
                    const ce = CrossauthError.asCrossauthError(e);
                    CrossauthLogger.logger.error(j({msg: "Signup two factor failure", user: data?.username, errorCodeName: ce.codeName, errorCode: ce.code}));
                    const { userData } = await this.sessionServer.sessionManager.repeatTwoFactorSignup(request.sessionId);
                    return this.sessionServer.handleError(e, request, reply, (reply, error) => {
                            return reply.view(this.configureFactor2Page, {
                            errorMessage: error.message,
                            errorMessages: error.messages, 
                            errorCode: error.code, 
                            errorCodeName: ErrorCode[error.code], 
                            urlPrefix: this.prefix, 
                            next: next, 
                            ...userData,
                            csrfToken: this.sessionServer.csrfToken(request, reply),
                        });
                        
                    });
                } catch (e2) {

                    // this is reached if there is an error processing the error
                    CrossauthLogger.logger.error(j({err: e2}));
                    return reply.status(500).view(this.sessionServer.errorPage, {
                        status: 500,
                        errorMessage: "An unknown error occurred",
                        errorCode: ErrorCode.UnknownError,
                        errorCodeName: "UnknownError"
                    });

                }
            }
        });
    }

    /**
     * Adds the `api/configurefactor2` POST endpoint.
     */
    addApiConfigureFactor2Endpoints(prefix : string) {
        this.sessionServer.app.get(prefix+'api/configurefactor2', 
            async (request : FastifyRequest, reply : FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'GET',
                    url: prefix + 'api/configurefactor2',
                    ip: request.ip,
                    hashOfSessionId: this.sessionServer.getHashOfSessionId(request)
                }));
            try {
                return await this.reconfigureFactor2(request, reply, 
                (reply, data, _user) => {
                    return reply.header(...JSONHDR).send({
                    ok: true,
                    ...data,
                })});
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e); 
                CrossauthLogger.logger.error(j({
                    msg: "Configure 2FA configuration failure",
                    user: request.user?.username,
                    errorCodeName: ce.codeName,
                    errorCode: ce.code
                }));
                CrossauthLogger.logger.debug(j({err: e}));
                this.sessionServer.handleError(e, request, reply, (reply, error) => {
                    reply.status(this.sessionServer.errorStatus(e)).header(...JSONHDR)
                        .send({
                            ok: false,
                            errorMessage: error.message,
                            errorMessages: error.messages,
                            errorCode: ErrorCode[error.code]
                    });                    
                });
            }
        });

        this.sessionServer.app.post(prefix+'api/configurefactor2', 
            async (request: FastifyRequest<{ Body: ConfigureFactor2BodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: prefix + 'api/configurefactor2',
                    ip: request.ip,
                    hashOfSessionId: this.sessionServer.getHashOfSessionId(request)
                }));
            try {
                return await this.configureFactor2(request, reply, 
                (reply, user) => {
                    const resp : {[key:string]: any} = {
                        ok: true,
                        user : user,    
                    };
                    if (!this.sessionServer.isSessionUser(request)) {
                        resp.emailVerificationNeeded = 
                            this.enableEmailVerification;
                    }
                    return reply.header(...JSONHDR).send(resp);
                });
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e); 
                CrossauthLogger.logger.error(j({
                    msg: "Configure 2FA configuration failure",
                    user: request.user?.username,
                    errorCodeName: ce.codeName,
                    errorCode: ce.code
                }));
                CrossauthLogger.logger.debug(j({err: e}));
                this.sessionServer.handleError(e, request, reply, (reply, error) => {
                    reply.status(this.sessionServer.errorStatus(e)).header(...JSONHDR)
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

    /**
     * Adds the `requestpasswordreset` GET and POST endpoints.
     */
    addRequestPasswordResetEndpoints() {
        this.sessionServer.app.get(this.prefix+'requestpasswordreset', 
        async (request : FastifyRequest<{Querystring: RequestPasswordResetQueryType}>, reply : FastifyReply) => {
            CrossauthLogger.logger.info(j({
                msg: "Page visit",
                method: 'GET',
                url: this.prefix + 'requestpasswordreset',
                ip: request.ip
            }));
            let data: {
                csrfToken: string | undefined,
                next?: string,
                required?: boolean
            } = 
                {csrfToken: request.csrfToken,
                next: request.query.next,
                required: request.query.required};
            return reply.view(this.requestPasswordResetPage, data);
        });

        this.sessionServer.app.post(this.prefix+'requestpasswordreset', 
            async (request: FastifyRequest<{ Body: RequestPasswordResetBodyType }>,
                reply: FastifyReply) => {
            const message = "If a user with exists with the email you entered, a message with "
                + " a link to reset your password has been sent."; 
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.prefix + 'requestpasswordreset',
                    ip: request.ip
                }));
                try {
                    return await this.requestPasswordReset(request, reply, 
                    (reply, _user) => {
                        return reply.view(this.requestPasswordResetPage, {
                            csrfToken: request.csrfToken,
                            message: message,
                            urlPrefix: this.prefix, 
                        });
                    });
            } catch (e) {
                    CrossauthLogger.logger.error(j({
                        msg: "Request password reset faiulure user failure",
                        email: request.body.email
                    }));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.sessionServer.handleError(e, request, reply, (reply, error) => {
                    if (error.code == ErrorCode.EmailNotExist) {
                        return reply.view(this.requestPasswordResetPage, {
                            csrfToken: request.csrfToken,                                
                            message: message,
                            urlPrefix: this.prefix, 
                            required: request.body.required,
                            next: request.body.next,
                        });
                    }
                    if (request.body.next) {
                        return reply.redirect(request.body.next);
                    }
                    return reply.view(this.requestPasswordResetPage, {
                        errorMessage: error.message,
                        errorMessages: error.messages, 
                        errorCode: error.code, 
                        errorCodeName: ErrorCode[error.code], 
                        email: request.body.email,
                        csrfToken: request.csrfToken,
                        urlPrefix: this.prefix, 
                    });
                });
            }
        });
    }

    /**
     * Adds the `api/requestpasswordreset`POST endpoint.
     */
    addApiRequestPasswordResetEndpoints() {
        this.sessionServer.app.post(this.prefix+'api/requestpasswordreset', 
            async (request: FastifyRequest<{ Body: RequestPasswordResetBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.prefix + 'api/resetpasswordrequest',
                    ip: request.ip
                }));
            try {
                return await this.requestPasswordReset(request, reply, 
                (reply, _user) => {return reply.header(...JSONHDR).send({
                    ok: true,
                })});
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e); 
                CrossauthLogger.logger.error(j({
                    msg: "Reset password failure failure",
                    email: request.body.email,
                    errorCodeName: ce.codeName,
                    errorCode: ce.code
                }));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.sessionServer.handleError(e, request, reply, (reply, error) => {
                    reply.status(this.sessionServer.errorStatus(e)).header(...JSONHDR)
                        .send({
                            ok: false,
                            errorMessage: error.message,
                            errorMessages: error.messages,
                            errorCode: error.code,
                            errorCodeName: ErrorCode[error.code]
                        });                    
                }, true);
            }
        });
    }

    /**
     * Adds the `resetpassword` GET and POST endpoints.
     */
    addResetPasswordEndpoints() {
        this.sessionServer.app.get(this.prefix+'resetpassword/:token', 
            async (request: FastifyRequest<{ Params: VerifyTokenParamType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'GET',
                    url: this.prefix + 'resetpassword',
                    ip: request.ip
                }));
            try {
                await this.sessionServer.sessionManager.userForPasswordResetToken(request.params.token);
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                return reply.view(this.sessionServer.errorPage, {
                    errorMessage: ce.message,
                    errorCode: ce.code,
                    errorCodeName: ce.codeName
                });
            }
            return reply.view(this.resetPasswordPage, {
                token: request.params.token,
                csrfToken: request.csrfToken
            });
        });

        this.sessionServer.app.post(this.prefix+'resetpassword', 
            async (request: FastifyRequest<{ Body: ResetPasswordBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.prefix + 'resetpassword',
                    ip: request.ip
                }));
            try {
                return await this.resetPassword(request, reply, 
                (reply, _user) => {
                    return reply.view(this.resetPasswordPage, {
                        csrfToken: request.csrfToken,
                        message: "Your password has been changed.",
                        urlPrefix: this.prefix, 
                    });
                });
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e); 
                CrossauthLogger.logger.error(j({
                    msg: "Reset password failure",
                    hashedToken: Crypto.hash(request.body.token),
                    errorCodeName: ce.codeName,
                    errorCode: ce.code
                }));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.sessionServer.handleError(e, request, reply, (reply, error) => {
                    return reply.view(this.resetPasswordPage, {
                        errorMessage: error.message,
                        errorMessages: error.messages, 
                        errorCode: error.code, 
                        errorCodeName: ErrorCode[error.code], 
                        csrfToken: request.csrfToken,
                        urlPrefix: this.prefix, 
                        token: request.body.token,
                    });
                });
            }
        });
    }

    /**
     * Adds the `api/resetpassword` POST endpoint.
     */
    addApiResetPasswordEndpoints() {
        this.sessionServer.app.post(this.prefix+'api/resetpassword', 
            async (request: FastifyRequest<{ Body: ResetPasswordBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.prefix + 'api/resetpassword',
                    ip: request.ip
                }));
            try {
                return await this.resetPassword(request, reply, 
                (reply, _user) => {return reply.header(...JSONHDR).send({
                    ok: true,
                })});
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e); 
                CrossauthLogger.logger.error(j({
                    msg: "Reset password failure",
                    hashedToken: Crypto.hash(request.body.token),
                    errorCodeName: ce.codeName,
                    errorCode: ce.code
                }));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.sessionServer.handleError(e, request, reply, (reply, error) => {
                    reply.status(this.sessionServer.errorStatus(e)).header(...JSONHDR)
                        .send({
                            ok: false,
                            errorMessage: error.message,
                            errorMessages: error.messages,
                            errorCode: error.code,
                            errorCodeName: ErrorCode[error.code]
                        });                    
                }, true);
            }
        });
    }

    /**
     * Adds the `verifyemail` GET and POST endpoints.
     */
    addVerifyEmailEndpoints() {
        this.sessionServer.app.get(this.prefix+'verifyemail/:token', 
            async (request: FastifyRequest<{ Params: VerifyTokenParamType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.prefix + 'verifyemail',
                    ip: request.ip
                }));
            try {
                return await this.verifyEmail(request, reply, 
                (reply, user) => {
                    return reply.view(this.emailVerifiedPage, {
                        urlPrefix: this.prefix,
                        user: user
                    });
                });
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e); 
                CrossauthLogger.logger.error(j({
                    msg: "Verify email failed",
                    hashedToken: Crypto.hash(request.params.token),
                    errorCodeName: ce.codeName,
                    errorCode: ce.code
                }));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.sessionServer.handleError(e, request, reply, (reply, error) => {
                    return reply.view(this.sessionServer.errorPage, {
                        errorCode: error.code, 
                        errorCodeName: ErrorCode[error.code], 
                        errorMessage: error.message,
                        errorMessages: error.messages,
                        urlPrefix: this.prefix, 
                    });
                });
            }
        });
    }

    /**
     * Adds the `api/verifyemail` POST endpoint.
     */
    addApiVerifyEmailEndpoints() {
        this.sessionServer.app.get(this.prefix+'api/verifyemail/:token', 
            async (request: FastifyRequest<{ Params: VerifyTokenParamType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.prefix + 'api/verifyemail',
                    ip: request.ip
                }));
            try {
                return await this.verifyEmail(request, reply, 
                (reply, user) => {return reply.header(...JSONHDR).send({
                    ok: true, 
                    user : user,
                })});
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e); 
                CrossauthLogger.logger.error(j({
                    msg: "Verify email failure",
                    hashedToken: Crypto.hash(request.params.token),
                    errorCodeName: ce.codeName,
                    errorCode: ce.code
                }));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.sessionServer.handleError(e, request, reply, (reply, error) => {
                    reply.status(this.sessionServer.errorStatus(e)).header(...JSONHDR)
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

    /**
     * Adds the `deleteuser` GET and POST endpoints.
     */
    addDeleteUserEndpoints() {

        this.sessionServer.app.get(this.prefix+'deleteuser', 
            async (request: FastifyRequest<{ Querystring: DeleteUserQueryType }>,
                reply: FastifyReply)  => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'GET',
                    url: this.prefix + 'deleteuser',
                    ip: request.ip
                }));
                let user : User;
                if (!request.user) {
                    return reply.redirect(this.sessionServer.loginUrl+"?next=" +
                        this.prefix+"deleteuser");
                }
                try {
                    const resp = await this.sessionServer.userStorage.getUserById(request.user.id);
                    user = resp.user;
                } catch (e) {
                    const ce = CrossauthError.asCrossauthError(e);
                    CrossauthLogger.logger.debug(j({err: e}));
                    return reply.status(ce.httpStatus).view(this.sessionServer.errorPage, {
                        errorMessage: ce.message,
                        errorMessages: ce.messages, 
                        errorCode: ce.code, 
                        errorCodeName: ErrorCode[ce.code], 
                    });
                }
                const next = request.query.next ?? this.prefix;
                let data = {
                    urlPrefix: this.prefix,
                    csrfToken: request.csrfToken,
                    next: next,
                    isAdmin: false,
                    user : user,
                };
            return reply.view(this.deleteUserPage, data);
        });

        this.sessionServer.app.post(this.prefix+'deleteuser', 
            async (request: FastifyRequest<{ Body: DeleteUserQueryType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.prefix + 'deleteuser',
                    ip: request.ip,
                    user: request.user?.username
                }));

                if (!request.user) {
                    return reply.redirect(this.sessionServer.loginUrl+"?next=" +
                        this.prefix+"deleteuser");
                }

                const next = request.body.next ?? this.prefix;
                try {
                    return await this.deleteUser(request, reply, 
                    (reply) => {
                        return reply.view(this.deleteUserPage, {
                            message: "User deleted",
                            csrfToken: request.csrfToken,
                            urlPrefix: this.prefix, 
                            userId : request.user?.id,
                            isAdmin: false,
                            next: next,
                        });
                    });
                } catch (e) {
                    const ce = CrossauthError.asCrossauthError(e);
                    CrossauthLogger.logger.error(j({
                        msg: "Failed deleting user",
                        user: request.user?.username,
                    
                        errorCodeName: ce.codeName,
                        errorCode: ce.code
                    }));
                    CrossauthLogger.logger.debug(j({err: e}));
                    return this.sessionServer.handleError(e, request, reply, (reply, error) => {
                        const ce = CrossauthError.asCrossauthError(e);
                        const statusCode = ce.httpStatus;
                            /*ce.httpStatus >= 400 && ce.httpStatus <= 499 ? 
                                ce.httpStatus : 200;*/
                        return reply.status(statusCode).view(this.deleteUserPage, {
                            errorMessage: error.message,
                            errorMessages: error.messages, 
                            errorCode: error.code, 
                            errorCodeName: ErrorCode[error.code], 
                            csrfToken: request.csrfToken,
                            urlPrefix: this.prefix, 
                            userId : request.user?.id,
                            isAdmin: false,
                            next: next,
                        });
                        
                    });
                }
        });

    }

    /**
     * Adds the `api/deleteuser` POST endpoint.
     */
    addApiDeleteUserEndpoints() {

        this.sessionServer.app.post(this.prefix+'api/deleteuser', 
            async (request: FastifyRequest,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.prefix + 'api/deleteuser',
                    ip: request.ip,
                    user: request.user?.username
                }));
                if (!request.user) {
                    return reply.status(401).header(...JSONHDR).send({ok: false});
                }
                try {
                    return await this.deleteUser(request, reply, 
                        (reply) => {
                        return reply.header(...JSONHDR).send({
                        ok: true,
                        userId : request.user?.id,
                    })});
                } catch (e) {
                    const ce = CrossauthError.asCrossauthError(e); 
                    CrossauthLogger.logger.error(j({
                        msg: "Delete user failure",
                        user: request.user?.username,
                        errorCodeName: ce.codeName,
                        errorCode: ce.code
                    }));
                    CrossauthLogger.logger.debug(j({err: e}));
                    this.sessionServer.handleError(e, request, reply, (reply, error) => {
                        reply.status(this.sessionServer.errorStatus(e)).header(...JSONHDR)
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

    //////////////////////////////////////////////////////////////////
    // Endpoint internal functions

    private async updateUser(request : FastifyRequest<{ Body: UpdateUserBodyType }>, 
        reply : FastifyReply, 
        successFn : (res : FastifyReply, user : User, emailVerificationRequired : boolean)
        => void) {

        // can only call this if logged in and CSRF token is valid
        if (!this.sessionServer.canEditUser(request) || !request.user) {
            throw new CrossauthError(ErrorCode.Unauthorized);
        }
        //await this.validateCsrfToken(request);
        if (this.sessionServer.isSessionUser(request) && !request.csrfToken) throw new CrossauthError(ErrorCode.InvalidCsrf);

        // get new user fields from form, including from the 
        // implementor-provided hook
        let user : User = {
            id: request.user.id,
            username: request.user.username,
            state: "active",
        };
        user = this.sessionServer.updateUserFn(user,
            request,
            this.sessionServer.userStorage.userEditableFields);

        // validate the new user using the implementor-provided function
        let errors = this.sessionServer.validateUserFn(user);
        if (errors.length > 0) {
            throw new CrossauthError(ErrorCode.FormEntry, errors);
        }

        // update the user
        let emailVerificationNeeded = 
            await this.sessionServer.sessionManager.updateUser(request.user, user);

        return successFn(reply, request.user, emailVerificationNeeded);
    }

    private async changeFactor2(request : FastifyRequest<{ Body: ChangeFactor2BodyType }>, 
        reply : FastifyReply, 
        successFn : (res : FastifyReply, data: {[key:string]:any}, user? : User) 
        => void) {
            
        /*// this can only be called for logged in users
        const sessionValue = this.getSessionCookieValue(request);
        if (!sessionValue || !request.user || !this.sessionUser(request)) {
            throw new CrossauthError(ErrorCode.Unauthorized);
        }*/

        // can only call this if logged in, is allowed to edit his or per profile,
        // and CSRF token is valid,
        // or else if login has been initiated but a password change is
        // required
        let user : User
        if (!this.sessionServer.isSessionUser(request) || !request.user) {
            // user is not logged on - check if there is an anonymous 
            // session with passwordchange set (meaning the user state
            // was set to changepasswordneeded when logging on)
            const data = await this.sessionServer.getSessionData(request, "factor2change")
            if (data?.username) {
                const resp = await this.sessionServer.userStorage.getUserByUsername(
                    data?.username, {
                        skipActiveCheck: true,
                        skipEmailVerifiedCheck: true,
                    });
                user = resp.user;
            } else {
                throw new CrossauthError(ErrorCode.Unauthorized);
            }
        } else if (!this.sessionServer.canEditUser(request)) {
            throw new CrossauthError(ErrorCode.InsufficientPriviledges);
        } else {
            user = request.user;
        }
        if (!request.sessionId) {
            throw new CrossauthError(ErrorCode.Unauthorized);
        }

        // validate the CSRF token
        //await this.validateCsrfToken(request);
        if (!request.csrfToken) {
            throw new CrossauthError(ErrorCode.InvalidCsrf);
        }

        // validate the requested factor2
        let newFactor2 : string|undefined = request.body.factor2;
        if (request.body.factor2 && 
            !(this.sessionServer.allowedFactor2.includes(request.body.factor2))) {
            throw new CrossauthError(ErrorCode.Forbidden,
                 "Illegal second factor " + request.body.factor2 + " requested");
        }
        if (request.body.factor2 == "none" || request.body.factor2 == "") {
            newFactor2 = undefined;
        }

        // get data to show user to finish 2FA setup
        const userData = await this.sessionServer.sessionManager
            .initiateTwoFactorSetup(user, newFactor2, request.sessionId);

        // show data to user
        let data: {
            factor2: string | undefined,
            userData: { [key: string]: any }, 
            username: string, 
            next : string, 
            csrfToken: string|undefined} = 
        {
            factor2: newFactor2,
            userData: userData,
            username: userData.username,
            next: request.body.next??this.sessionServer.loginRedirect,
            csrfToken: request.csrfToken,
        };
        return successFn(reply, data)
    }

    private async changePassword(request : FastifyRequest<{ Body: ChangePasswordBodyType }>, 
        reply : FastifyReply, 
        successFn : (res : FastifyReply, user? : User) => void) {

        // can only call this if logged in and CSRF token is valid,
        // or else if login has been initiated but a password change is
        // required
        let user : User;
        let required = false;
        if (!this.sessionServer.isSessionUser(request) || !request.user) {
            // user is not logged on - check if there is an anonymous 
            // session with passwordchange set (meaning the user state
            // was set to changepasswordneeded when logging on)
            const data = await this.sessionServer.getSessionData(request, "passwordchange")
            if (data?.username) {
                const resp = await this.sessionServer.userStorage.getUserByUsername(
                    data?.username, {
                        skipActiveCheck: true,
                        skipEmailVerifiedCheck: true,
                    });
                user = resp.user;
                required = true;
                if (!request.csrfToken) {
                    throw new CrossauthError(ErrorCode.InvalidCsrf);
                }
            } else {
                throw new CrossauthError(ErrorCode.Unauthorized);
            }
        } else if (!this.sessionServer.canEditUser(request)) {
            throw new CrossauthError(ErrorCode.InsufficientPriviledges);
        } else {
            //this.validateCsrfToken(request)
            if (this.sessionServer.isSessionUser(request) && !request.csrfToken) {
                throw new CrossauthError(ErrorCode.InvalidCsrf);
            }
            user = request.user;
        }

        // get the authenticator for factor1 (passwords on factor2 are not supported)
        const authenticator = this.sessionServer.authenticators[user.factor1];

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

        // validate the old secrets, check the new and repeat ones match and 
        // update if valid
        const oldState = user.state;
        try {
            if (required) {
                user.state = "active";
                await this.sessionServer.userStorage.updateUser({id: user.id, state:user.state});
            }
            await this.sessionServer.sessionManager.changeSecrets(user.username,
                1,
                newSecrets,
                repeatSecrets,
                oldSecrets
            );
        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.debug(j({err: e}));
            if (required) {
                try {
                    await this.sessionServer.userStorage.updateUser({id: user.id, state: oldState});
                } catch (e2) {
                    CrossauthLogger.logger.debug(j({err: e2}));
                }
            }
            throw ce;
            
        }
        if (required) {
            // this was a forced change - user is not actually logged on
            return await this.sessionServer.loginWithUser(user, false, request, reply, successFn);
        }
        
        return successFn(reply, undefined);
    }

    private async configureFactor2(request : FastifyRequest<{ Body: ConfigureFactor2BodyType }>, 
        reply : FastifyReply, 
        successFn : (res : FastifyReply, user? : User) => void) {

        // validate the CSRF token
        //await this.validateCsrfToken(request);
        if (this.sessionServer.isSessionUser(request) && !request.csrfToken) {
            throw new CrossauthError(ErrorCode.InvalidCsrf);
        }

        // get the session - it may be a real user or anonymous
        if (!request.sessionId) throw new CrossauthError(ErrorCode.Unauthorized, 
            "No session active while enabling 2FA.  Please enable cookies");
        // finish 2FA setup - validate secrets and update user
        let user = await this.sessionServer.sessionManager.completeTwoFactorSetup(request.body, 
            request.sessionId);
        if (!this.sessionServer.isSessionUser(request) && !this.enableEmailVerification) {
            // we skip the login if the user is already logged in and we are not doing email verification
            return this.sessionServer.loginWithUser(user, true, request, reply, 
                (request, user) => {return successFn(request, user)});
        }
        return successFn(reply, user);
    }

    private async reconfigureFactor2(request : FastifyRequest, reply : FastifyReply, 
        successFn : (res : FastifyReply, data: {[key:string]:any}, user? : User) => void) {
        
        // can only call this if logged in and CSRF token is valid
        if (!request.user || !request.sessionId || !this.sessionServer.isSessionUser(request)) {
            throw new CrossauthError(ErrorCode.Unauthorized);
        }

        // get second factor authenticator
        let factor2 : string = request.user.factor2;
        const authenticator = this.sessionServer.authenticators[factor2];
        if (!authenticator || authenticator.secretNames().length == 0) {
            throw new CrossauthError(ErrorCode.BadRequest, 
                "Selected second factor does not have configuration");
        }
    
        // step one in 2FA setup - create secrets and get data to dispaly to user
        const userData = 
            await this.sessionServer.sessionManager.initiateTwoFactorSetup(request.user,
                factor2,
                request.sessionId);

        // show user result
        let data : {[key:string] : any} = 
        {
            ...userData,
            csrfToken: request.csrfToken,
        };
        return successFn(reply, data)
    }

    private async requestPasswordReset(request : FastifyRequest<{ Body: RequestPasswordResetBodyType }>, 
        reply : FastifyReply, 
        successFn : (res : FastifyReply, user? : User) => void) {

        // this has to be enabled in configuration
        if (!this.enablePasswordReset) {
            throw new CrossauthError(ErrorCode.Configuration,
                 "password reset not enabled");
        }

        // validate the CSRF token
        //await this.validateCsrfToken(request);
        if (!request.csrfToken) { // always require CSRF - user not logged in for this endpoint
            throw new CrossauthError(ErrorCode.InvalidCsrf);
        }

        // get data from request body
        const email = request.body.email;

        // send password reset email
        try {
            await this.sessionServer.sessionManager.requestPasswordReset(email);
        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);
            if (ce.code == ErrorCode.UserNotExist) {
                // fail silently - don't let user know email doesn't exist
                CrossauthLogger.logger.warn(j({
                    msg: "Password reset requested for invalid email",
                    email: request.body.email
                }))
            } else {
                CrossauthLogger.logger.debug(j({
                    err: e,
                    msg: "Couldn't send password reset email"
                }));
            }
        }

        return successFn(reply, undefined);
    }

    private async resetPassword(request : FastifyRequest<{ Body: ResetPasswordBodyType }>, 
        reply : FastifyReply, 
        successFn : (res : FastifyReply, user? : User) => void) {

        // check the CSRF token is valid
        //await this.validateCsrfToken(request);
        if (!request.csrfToken) { // user is not logged on so always require token
            throw new CrossauthError(ErrorCode.InvalidCsrf);
        }

        // get the user based on ther token from the request body
        const token = request.body.token;
        const user = await this.sessionServer.sessionManager.userForPasswordResetToken(token);

        // get secrets from the request body 
        // there should be new_{secret} and repeat_{secret}
        const authenticator = this.sessionServer.authenticators[user.factor1];
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
        const user1 = await this.sessionServer.sessionManager.resetSecret(token, 1, newSecrets, repeatSecrets);
        if (user1.state != UserState.factor2ResetNeeded) {
            // log the user in
            return this.sessionServer.loginWithUser(user1, true, request, reply, successFn);
        }
        return successFn(reply);
    }

    private async verifyEmail(request : FastifyRequest<{ Params: VerifyTokenParamType }>, 
        reply : FastifyReply, 
        successFn : (res : FastifyReply, user? : User) => void) {

        // this has to be enabled in configuration
        if (!this.enableEmailVerification) throw new CrossauthError(ErrorCode.Configuration, 
            "Email verification reset not enabled");

        // get the email verification token
        const token = request.params.token;

        // validate the token and log the user in
        const user = 
            await this.sessionServer.sessionManager.applyEmailVerificationToken(token);
        return await this.sessionServer.loginWithUser(user, true, request, reply, successFn);
    }

    private async deleteUser(request : FastifyRequest, 
        reply : FastifyReply, 
        successFn : (res : FastifyReply) => FastifyReply) {
            
        // throw an error if the CSRF token is invalid
        if (this.sessionServer.isSessionUser(request) && !request.csrfToken) {
            throw new CrossauthError(ErrorCode.InvalidCsrf);
        }

        // throw an error if not logged in
        if (!request.user) {
            throw new CrossauthError(ErrorCode.InsufficientPriviledges);
        }

        await this.sessionServer.userStorage.deleteUserById(request.user.id);
        return successFn(reply);
    }}

