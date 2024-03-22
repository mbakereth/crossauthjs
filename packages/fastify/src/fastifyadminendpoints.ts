import {
    type FastifyRequest,
    type FastifyReply } from 'fastify';
import {
    CrossauthError,
    ErrorCode,
    CrossauthLogger,
    j,
    UserState,
} from '@crossauth/common';
import type { User } from '@crossauth/common';
import { FastifyServer } from './fastifyserver';
import { FastifySessionServer,
    type FastifySessionServerOptions,
    type CsrfBodyType,
    type LoginQueryType,
    type SignupBodyType,
    type AuthenticatorDetails } from './fastifysession';
import {
    setParameter,
    ParamType,
    Hasher } from '@crossauth/backend';
import type {
    AuthenticationParameters } from '@crossauth/backend';
import { STATUS_CODES } from 'http';

/////////////////////////////////////////////////////////////////////
// Fastify data types

interface CreateUserBodyType extends SignupBodyType {
}

const JSONHDR : [string,string] = 
    ['Content-Type', 'application/json; charset=utf-8'];

///////////////////////////////////////////////////////////////////////
// Class

export class FastifyAdminEndpoints {
    private sessionServer : FastifySessionServer;
    private adminPrefix = "/admin/";

    // pages
    private createUserPage = "admin/createuser.njk";

    constructor(sessionServer : FastifySessionServer,
        options: FastifySessionServerOptions = {}) {

        this.sessionServer = sessionServer;
        setParameter("adminPrefix", ParamType.String, this, options, "ADMIN_PREFIX");
        setParameter("createUserPage", ParamType.Boolean, this, options, "ADMIN_CREATE_USER_PAGE");
        if (!this.adminPrefix.endsWith("/")) this.adminPrefix += "/";
        if (!this.adminPrefix.startsWith("/")) "/" + this.adminPrefix;

    }

    addCreateUserEndpoints() {
        this.sessionServer.app.get(this.adminPrefix+'createuser', 
            async (request: FastifyRequest<{ Querystring: LoginQueryType }>,
                reply: FastifyReply)  => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'GET',
                    url: this.adminPrefix + 'createuser',
                    ip: request.ip
                }));
                if (!request?.user || !FastifyServer.isAdmin(request.user)) {
                    return this.accessDeniedPage(request, reply);                    
                }
                let data: {
                    urlprefix: string,
                    next?: any,
                    csrfToken: string | undefined,
                    allowedFactor2: AuthenticatorDetails[]
                } = {
                    urlprefix: this.adminPrefix,
                    csrfToken: request.csrfToken,
                    allowedFactor2: this.sessionServer.allowedFactor2Details()
                };
            if (request.query.next) {
                data["next"] = request.query.next;
            }
            return reply.view(this.createUserPage, data);
        });

        this.sessionServer.app.post(this.adminPrefix+'createuser', 
            async (request: FastifyRequest<{ Body: CreateUserBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.adminPrefix + 'createuser',
                    ip: request.ip,
                    user: request.body.username
                }));
                let next = 
                request.body.next && request.body.next.length > 0 ? 
                    request.body.next : this.adminPrefix;
            try {
                CrossauthLogger.logger.debug(j({msg: "Next page " + next}));

                return await this.createUser(request, reply, 
                (reply, _data, _user) => {
                    return reply.redirect(302, next);
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
                return this.sessionServer.handleError(e, request, reply, (reply, error) => {
                    let extraFields : {[key:string] : string|number|boolean|Date|undefined} = {};
                    for (let field in request.body) {
                        if (field.startsWith("user_")) extraFields[field] = request.body[field];
                    }
                    const ce = CrossauthError.asCrossauthError(e);
                    const statusCode = 
                        ce.httpStatus >= 400 && ce.httpStatus <= 499 ? 
                            ce.httpStatus : 200;
                    return reply.status(statusCode).view(this.createUserPage, {
                        errorMessage: error.message,
                        errorMessages: error.messages, 
                        errorCode: error.code, 
                        errorCodeName: ErrorCode[error.code], 
                        next: next, 
                        persist: request.body.persist,
                        username: request.body.username,
                        csrfToken: request.csrfToken,
                        factor2: request.body.factor2,
                        allowedFactor2: this.sessionServer.allowedFactor2Details(),
                        urlprefix: this.adminPrefix, 
                        ...extraFields,
                        });
                    
                });
            }
        });
    }

    addApiCreateUserEndpoints() {
        this.sessionServer.app.post(this.adminPrefix+'api/createuser', 
            async (request: FastifyRequest<{ Body: SignupBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.adminPrefix + 'api/createuser',
                    ip: request.ip,
                    user: request.body.username
                }));
            try {
                return await this.createUser(request, reply, 
                (reply, data, user) => {
                    return reply.header(...JSONHDR).send({
                    ok: true,
                    user : user,
                    ...data.userData,
                })});
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e); 
                CrossauthLogger.logger.error(j({
                    msg: "Create user failure",
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

    private async createUser(request : FastifyRequest<{ Body: CreateUserBodyType }>, 
        reply : FastifyReply, 
        successFn : (res : FastifyReply, data: {[key:string]:any}, user? : User) 
        => void) {
            
        // throw an error if the CSRF token is invalid
        if (this.sessionServer.isSessionUser(request) && !request.csrfToken) {
            throw new CrossauthError(ErrorCode.InvalidCsrf);
        }

        // throw an error if not an admin user
        if (!request.user || !FastifyServer.isAdmin(request.user)) {
            throw new CrossauthError(ErrorCode.InsufficientPriviledges);
        }
        // get data from the request body
        // make sure the requested second factor is valid
        if (!request.body.factor2) {
            request.body.factor2 = this.sessionServer.allowedFactor2[0]; 
        }
        if (request.body.factor2 && 
            !(this.sessionServer.allowedFactor2.includes(request.body.factor2??"none"))) {
            throw new CrossauthError(ErrorCode.Forbidden, 
                "Illegal second factor " + request.body.factor2 + " requested");
        }
        if (request.body.factor2 == "none" || request.body.factor2 == "") {
            request.body.factor2 = undefined;
        }

        // call implementor-provided function to create the user object (or our default)
        let user = 
            this.sessionServer.createUserFn(request, this.sessionServer.userStorage.userEditableFields);
        if (user.factor2 && user.factor2 != "none") {
            user.state = UserState.factor2ResetNeeded;
            CrossauthLogger.logger.warn(j({msg: `Setting state for user to ${UserState.factor2ResetNeeded}`, 
            username: user.username}));
        } 
        // ask the authenticator to validate the user-provided secret
        let passwordErrors = 
            this.sessionServer.authenticators[user.factor1].validateSecrets(request.body);

        // get the repeat secrets (secret names prefixed with repeat_)
        const secretNames = this.sessionServer.authenticators[user.factor1].secretNames();
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

        // call the implementor-provided hook to validate the user fields
        let userErrors = this.sessionServer.validateUserFn(user);

        // report any errors
        let errors = [...userErrors, ...passwordErrors];
        if (errors.length > 0) {
            throw new CrossauthError(ErrorCode.FormEntry, errors);
        }

        const newUser = await this.sessionServer.sessionManager.createUser(user,
            request.body,
            repeatSecrets, true);
        return successFn(reply, {}, newUser);
    }

    private async accessDeniedPage(request : FastifyRequest, reply : FastifyReply) {
        const ce = new CrossauthError(ErrorCode.InsufficientPriviledges);
        return this.sessionServer.handleError(ce, request, reply, (reply, error) => {
            return reply.status(ce.httpStatus).view(this.sessionServer.errorPage, {
                errorMessage: error.message,
                errorMessages: error.messages, 
                errorCode: error.code, 
                errorCodeName: ErrorCode[error.code], 
                });
            
        });

    } 

}