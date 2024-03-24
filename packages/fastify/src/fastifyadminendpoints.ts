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
import { FastifySessionServer } from './fastifysession';
import type { FastifySessionServerOptions,
    CsrfBodyType,
    LoginQueryType,
    SignupBodyType,
    AuthenticatorDetails } from './fastifysession';
    import {
    setParameter,
    ParamType,
    UserStorage } from '@crossauth/backend';
import type {
    AuthenticationParameters } from '@crossauth/backend';

async function defaultUserSearchFn(searchTerm: string,
    userStorage: UserStorage) : Promise<User[]> {
        let users : User[] = [];
    try {
        const {user} = 
            await userStorage.getUserByUsername(searchTerm);
            users.push(user);
    } catch (e1) {
        const ce1 = CrossauthError.asCrossauthError(e1);
        if (ce1.code != ErrorCode.UserNotExist) {
            CrossauthLogger.logger.debug(j({err: ce1}));
            throw ce1;
        }
        try {
            const {user} = 
                await userStorage.getUserByEmail(searchTerm);
                users.push(user);
        } catch (e2) {
            const ce2 = CrossauthError.asCrossauthError(e2);
            if (ce2.code != ErrorCode.UserNotExist) {
                CrossauthLogger.logger.debug(j({err: ce2}));
                throw ce1;
            }
        }
    }
    return users;

}

/////////////////////////////////////////////////////////////////////
// Fastify data types

interface CreateUserBodyType extends SignupBodyType {
}

interface SelectUserQueryType {
    next? : string,
    search? : string,
    skip? : number,
    take? : number,
    haveNext? : boolean,
    havePrevious? : boolean,
}

interface UserParamType {
    id : string|number,
}

interface EditBodyType extends CsrfBodyType {
    errorMessage?: string,
    errorMessages?: string[], 
    errorCode?: number, 
    errorCodeName?: string, 
}

interface UpdateUserBodyType extends EditBodyType {
    username : string,
    [key:string] : any,
}
const JSONHDR : [string,string] = 
    ['Content-Type', 'application/json; charset=utf-8'];

///////////////////////////////////////////////////////////////////////
// Class

export class FastifyAdminEndpoints {
    private sessionServer : FastifySessionServer;
    private adminPrefix = "/admin/";
    private userSearchFn : 
        (searchTerm : string, userStorage : UserStorage) => Promise<User[]> =
        defaultUserSearchFn;

    // pages
    private adminCreateUserPage = "admin/createuser.njk";
    private adminSelectUserPage = "admin/selectuser.njk";
    private adminUpdateUserPage = "admin/updateuser.njk";

    constructor(sessionServer : FastifySessionServer,
        options: FastifySessionServerOptions = {}) {

        this.sessionServer = sessionServer;
        setParameter("adminPrefix", ParamType.String, this, options, "ADMIN_PREFIX");
        setParameter("adminCreateUserPage", ParamType.Boolean, this, options, "ADMIN_CREATE_USER_PAGE");
        setParameter("adminSelectUserPage", ParamType.Boolean, this, options, "ADMIN_SELECT_USER_PAGE");
        setParameter("adminUpdateUserPage", ParamType.Boolean, this, options, "ADMIN_UPDATE_USER_PAGE");
        if (!this.adminPrefix.endsWith("/")) this.adminPrefix += "/";
        if (!this.adminPrefix.startsWith("/")) "/" + this.adminPrefix;

    }

    ///////////////////////////////////////////////////////////////////
    // Endpoints

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
            return reply.view(this.adminCreateUserPage, data);
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
                    const ce = CrossauthError.asCrossauthError(e);
                    const statusCode = 
                        ce.httpStatus >= 400 && ce.httpStatus <= 499 ? 
                            ce.httpStatus : 200;
                    return reply.status(statusCode).view(this.adminCreateUserPage, {
                        errorMessage: error.message,
                        errorMessages: error.messages, 
                        errorCode: error.code, 
                        errorCodeName: ErrorCode[error.code], 
                        next: next, 
                        persist: request.body.persist,
                        csrfToken: request.csrfToken,
                        factor2: request.body.factor2,
                        allowedFactor2: this.sessionServer.allowedFactor2Details(),
                        urlprefix: this.adminPrefix, 
                        ...request.body,
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

    addSelectUserEndpoints() {
        this.sessionServer.app.get(this.adminPrefix+'selectuser', 
            async (request: FastifyRequest<{ Querystring: SelectUserQueryType }>,
                reply: FastifyReply)  => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'GET',
                    url: this.adminPrefix + 'selectuser',
                    ip: request.ip
                }));
                if (!request?.user || !FastifyServer.isAdmin(request.user)) {
                    return this.accessDeniedPage(request, reply);                    
                }
                try {
                    let users : User[] = [];
                    let skip = Number(request.query.skip);
                    let take = Number(request.query.take);
                    if (!skip) skip = 0;
                    if (!take) take = 10;
                    if (request.query.search) {
                        users = await this.userSearchFn(request.query.search, 
                            this.sessionServer.userStorage)
                    } else {
                        users = 
                            await this.sessionServer.userStorage.getUsers(skip, 
                                take);
                    }
                    let data: {
                        urlprefix: string,
                        next?: any,
                        skip: number,
                        take: number,
                        users: User[],
                        haveNext : boolean,
                        havePrevious : boolean,
                    } = {
                        urlprefix: this.adminPrefix,
                        skip: skip,
                        take: take,
                        users: users,
                        havePrevious: skip > 0,
                        haveNext : take != undefined && users.length == take,
                    };
                if (request.query.next) {
                    data["next"] = request.query.next;
                }
                return reply.view(this.adminSelectUserPage, data);
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.error(j({err: e}));
                return FastifyServer.sendPageError(reply,
                    ce.httpStatus,
                    this.sessionServer.errorPage,
                    ce.message, ce);

            }
        });
    };

    addUpdateUserEndpoints() {
        this.sessionServer.app.get(this.adminPrefix+'updateuser/:id', 
            async (request: FastifyRequest<{ Params: UserParamType }>,
                reply: FastifyReply)  => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'GET',
                    url: this.adminPrefix + 'updateuser',
                    ip: request.ip
                }));
                if (!request?.user || !FastifyServer.isAdmin(request.user)) {
                    return this.accessDeniedPage(request, reply);                    
                }
                try {
                    const {user} = 
                        await this.sessionServer.userStorage.getUserById(request.params.id)
                    let data: {
                        urlprefix: string,
                        csrfToken?: string,
                        user : User,
                    } = {
                        urlprefix: this.adminPrefix,
                        csrfToken: request.csrfToken,
                        user: user,
                    };
                return reply.view(this.adminUpdateUserPage, data);
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.error(j({err: e}));
                return FastifyServer.sendPageError(reply,
                    ce.httpStatus,
                    this.sessionServer.errorPage,
                    ce.message, ce);

            }
        });

        this.sessionServer.app.post(this.adminPrefix+'updateuser/:id', 
            async (request: FastifyRequest<{Params: UserParamType, Body: UpdateUserBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.adminPrefix + 'updateuser',
                    ip: request.ip,
                    user: request.user?.username
                }));
                if (!this.sessionServer.canEditUser(request)) return FastifyServer.sendPageError(reply,
                    401,
                    this.sessionServer.errorPage);
            let user : User|undefined;
            try {
                const {user: user1} = await 
                    this.sessionServer.userStorage.getUserById(request.params.id);
                user = user1;
                return await this.updateUser(user, request, reply, 
                (reply, _user, emailVerificationRequired) => {
                    const message = emailVerificationRequired 
                        ? "Please click on the link in your email to verify your email address."
                        : "User's details have been updated";
                    return reply.view(this.adminUpdateUserPage, {
                        csrfToken: request.csrfToken,
                        message: message,
                        urlprefix: this.adminPrefix, 
                        allowedFactor2: this.sessionServer.allowedFactor2Details(),
                    });
                });
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.error(j({msg: "Update user failure", user: request.body.username, errorCodeName: ce.codeName, errorCode: ce.code}));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.sessionServer.handleError(e, request, reply, (reply, error) => {
                    if (!user) {
                        return FastifyServer.sendPageError(reply,
                            ce.httpStatus,
                            this.sessionServer.errorPage,
                            ce.message, ce);
        
                    }
                    return reply.view(this.adminUpdateUserPage, {
                        user: user,
                        errorMessage: error.message,
                        errorMessages: error.messages, 
                        errorCode: error.code, 
                        errorCodeName: ErrorCode[error.code], 
                        csrfToken: request.csrfToken,
                        urlprefix: this.adminPrefix, 
                        allowedFactor2: this.sessionServer.allowedFactor2Details(),
                        ...request.body,
                    });
                });
            }
        });
    };

    addApiUpdateUserEndpoints() {
        this.sessionServer.app.post(this.adminPrefix+'api/updateuser/:id', 
            async (request: FastifyRequest<{Params: UserParamType, Body: UpdateUserBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.adminPrefix + 'api/updateuser',
                    ip: request.ip,
                    user: request.user?.username
                }));
            if (!this.sessionServer.canEditUser(request)) {
                return this.sessionServer.sendJsonError(reply, 401);
            }
            let user : User|undefined;
            try {
                const {user: user1} = await 
                    this.sessionServer.userStorage.getUserById(request.params.id);
                user = user1;
                return await this.updateUser(user, request, reply, 
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


    ///////////////////////////////////////////////////////////
    // Internal functions

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

    private async updateUser(user : User, request : FastifyRequest<{ Body: UpdateUserBodyType }>, 
        reply : FastifyReply, 
        successFn : (res : FastifyReply, user : User, emailVerificationRequired : boolean)
        => void) {

        // can only call this if logged in and CSRF token is valid
        if (!this.sessionServer.canEditUser(request) || !request.user) {
            throw new CrossauthError(ErrorCode.Unauthorized);
        }
        //await this.validateCsrfToken(request);
        if (this.sessionServer.isSessionUser(request) && !request.csrfToken) throw new CrossauthError(ErrorCode.InvalidCsrf);

        user = this.sessionServer.updateUserFn(user,
            request,
            this.sessionServer.userStorage.userEditableFields);
        if (user.factor2 && user.factor2 != "none") {
            user.state = UserState.factor2ResetNeeded;
            CrossauthLogger.logger.warn(j({msg: `Setting state for user to ${UserState.factor2ResetNeeded}`, 
            username: user.username}));
        } 
    
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
}