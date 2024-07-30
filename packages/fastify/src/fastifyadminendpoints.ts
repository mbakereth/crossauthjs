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

export interface AdminCreateUserBodyType extends SignupBodyType {
}

interface SelectUserQueryType {
    next? : string,
    search? : string,
    skip? : number,
    take? : number,
    haveNext? : boolean,
    havePrevious? : boolean,
}

export interface UserParamType {
    id : string|number,
}

/**
 * Body parameters for the admin update user endpoint
 */
export interface AdminUpdateUserBodyType {
    username : string,
    [key:string] : any,
}

interface ChangePasswordQueryType {
    next? : string;
    required?: boolean
}

/**
 * Body parameters for the admin change password endpoint
 */
export interface AdminChangePasswordBodyType extends CsrfBodyType {
    oldPassword: string,
    newPassword: string,
    repeatPassword?: string,
    next? : string,
    required?: boolean
}

/**
 * URL parameters for the admin delete user endpoint
 */
export interface AdminDeleteUserParamType {
    id : string|number
}

export interface DeleteUserQueryType {
    next? : string
}

const JSONHDR : [string,string] = 
    ['Content-Type', 'application/json; charset=utf-8'];

///////////////////////////////////////////////////////////////////////
// Class

/**
 * This class adds admin endpoints to the Fastidfy session server
 * 
 * This clas is not intended to be created directly.  It is created by
 * {@link FastifySessionServer} if admin endpoints are enabled.
 * 
 * **Endpoints that can be activated**
 * 
 * All page POST methods are passed user, csrfToken, errorCode, errorCodeName, errorMessage, errorMessages, urlPrefix,
 * errorMessages is an array, errorMessage is a single value or concatenation of errorMessages.
 * 
 * All JSON responses have ok, errorMessage, errorMEssages, errorCode, errorCodeName, other than OAuth endpoints.
 * 
 * | METHOD | ENDPOINT                   | PATH PARAMS | GET/BODY PARAMS                                                      | VARIABLES PASSED/RESPONSE JSON                                                                         | FILE                     |
 * | ------ | -------------------------- | ----------- | -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | ------------------------ |
 * | GET    | /admin/createuser          |             | next                                                                 | next, allowedFactor2                                                                                   | adminCreateUserPage      |
 * | POST   | /admin/createuser          |             | next, persist, username, password, repeat_password, factor2, user_*  | message, next, username, factor2, allowedFactor2                                                       | adminCreateUserPage      | 
 * | POST   | /admin/api/createuser      |             | next, persist, username, password, repeat_password, factor2, user_*  | message, next, username, factor2, allowedFactor2                                                       | adminCreateUserPage      | 
 * | GET    | /admin/selectuser          |             | next, search, skip, take, haveNext, havePrevious                     | next, search, skip, take, haveNext, havePrevious                                                       | adminSelectUserPage      |
 * | GET    | /admin/changepassword      | id          | next, required                                                       | next, required, user                                                                                   | adminChangePasswordPage  | 
 * | POST   | /admin//changepassword     | id          | next, required, old_password, new_password, repeat_password          | next, required, user, message                                                                          | adminChangePasswordPage  | 
 * | POST   | /admin//api/changepassword | id          | old_password, new_password, repeat_password                          |                                                                                                        |                          | 
 * | GET    | /admin/updateuser          | id          |                                                                      | user, allowedFactor2, enableOAuthClientManagement                                                      | updatePasswordPage       | 
 * | POST   | /admin/updateuser          | id          | user_*, factor2, status                                              | message, user_*, allowedFactor2, enableOAuthClientManagement                                           | updatePasswordPage       | 
 * | POST   | /admin/api/updateuser      |             | user_*                                                               | emailVerificationRequired                                                                              |                          | 
 * | GET    | /admin/deleteuser          | id          | next                                                                 | next, isAdmin, user                                                                                    | deleteUserPAge           | 
 * | POST   | /admin/deleteuser          | id          | next                                                                 | message, next isAdmin, userId                                                                          | deleteUserPAge           | 
 * | POST   | /admin/api/deleteuser      | id          |                                                                      |                                                                                                        |                          | 
 * | GET    | /selectclient              |             | next, search, skip, take, haveNext, havePrevious, userId             | next, search, skip, take, haveNext, havePrevious, user, clients, isAdmin                               | selectClient             |
 * | GET    | /createclient              |             | next, userId                                                         | next, validFLows, flowNames, user, isAdmin                                                             | createClientPage         |
 * | POST   | /createclient              |             | next, clientName, confidential, redirectUris, (flows), userId        | message, client, next, validFLows, flowNames, user, isAdmin                                            | createClientPage         |
 * | POST   | /api/createclient          |             | clientName, confidential, redirectUris, (flows), userId              | client                                                                                                 |                          |
 * | GET    | /updateclient              | clientId    | next                                                                 | next, validFLows, flowNames, selectedFlows, redirectUris, clientId, clientName, user, isAdmin          | updateClientPage         |
 * | POST   | /updateclient              | clientId    | next, clientName, confidential, redirectUris, (flows), resetSecret   | message, next, validFLows, flowNames, selectedFlows, redirectUris, clientId, clientName, user, isAdmin | updateClientPage         |
 * | POST   | /api/updateclient          | clientId    | clientName, confidential, redirectUris, (flows), resetSecret         | client, newSecret                                                                                      |                          |
 * | GET    | /deleteclient              | clientId    | next, backUrl                                                        | next, backUrl, client                                                                                  | deleteClientPage         | 
 * | POST   | /deleteclient              | clientId    | next                                                                 | message, next, clientId                                                                                | deleteClientPage         | 
 * | POST   | /api/deleteclient          | clientId    |                                                                      |                                                                                                        |                          | 
 *  
*/
export class FastifyAdminEndpoints {
    private sessionServer : FastifySessionServer;
    private adminPrefix = "/admin/";
    private userSearchFn : 
        (searchTerm : string, userStorage : UserStorage) => Promise<User[]> =
        defaultUserSearchFn;
    private enableOAuthClientManagement = false;

    // pages
    private adminCreateUserPage = "admin/createuser.njk";
    private adminSelectUserPage = "admin/selectuser.njk";
    private adminUpdateUserPage = "admin/updateuser.njk";
    private adminChangePasswordPage = "admin/changepassword.njk";
    private deleteUserPage = "deleteuser.njk";

    constructor(sessionServer : FastifySessionServer,
        options: FastifySessionServerOptions = {}) {

        this.sessionServer = sessionServer;
        setParameter("adminPrefix", ParamType.String, this, options, "ADMIN_PREFIX");
        setParameter("adminCreateUserPage", ParamType.String, this, options, "ADMIN_CREATE_USER_PAGE");
        setParameter("adminSelectUserPage", ParamType.String, this, options, "ADMIN_SELECT_USER_PAGE");
        setParameter("adminUpdateUserPage", ParamType.String, this, options, "ADMIN_UPDATE_USER_PAGE");
        setParameter("adminChangePasswordPage", ParamType.String, this, options, "ADMIN_CHANGE_PASSWORD_PAGE");
        setParameter("enableOAuthClientManagement", ParamType.Boolean, this, options, "ENABLE_OAUTH_CLIENT_MANAGEMENT");
        setParameter("deleteUserPage", ParamType.String, this, options, "DELETE_USER_PAGE");
        if (!this.adminPrefix.endsWith("/")) this.adminPrefix += "/";
        if (!this.adminPrefix.startsWith("/")) "/" + this.adminPrefix;
        if (options.userSearchFn) this.userSearchFn = options.userSearchFn

    }

    ///////////////////////////////////////////////////////////////////
    // Endpoints

    /**
     * Adds the `admin/createuser` GET and POST endpoints.
     */
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
                    urlPrefix: string,
                    next?: any,
                    csrfToken: string | undefined,
                    allowedFactor2: AuthenticatorDetails[]
                } = {
                    urlPrefix: this.adminPrefix,
                    csrfToken: request.csrfToken,
                    allowedFactor2: this.sessionServer.allowedFactor2Details()
                };
            if (request.query.next) {
                data["next"] = request.query.next;
            }
            return reply.view(this.adminCreateUserPage, data);
        });

        this.sessionServer.app.post(this.adminPrefix+'createuser', 
            async (request: FastifyRequest<{ Body: AdminCreateUserBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.adminPrefix + 'createuser',
                    ip: request.ip,
                    user: request.user?.username
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
                    const statusCode = ce.httpStatus;
                        /*ce.httpStatus >= 400 && ce.httpStatus <= 499 ? 
                            ce.httpStatus : 200;*/
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
                        urlPrefix: this.adminPrefix, 
                        ...request.body,
                        });
                    
                });
            }
        });
    }

    /**
     * Adds the `admin/api/createuser` POST endpoint.
     */
    addApiCreateUserEndpoints() {
        this.sessionServer.app.post(this.adminPrefix+'api/createuser', 
            async (request: FastifyRequest<{ Body: SignupBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.adminPrefix + 'api/createuser',
                    ip: request.ip,
                    user: request.user?.username
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

    /**
     * Adds the `admin/selectuser` GET and endpoint.
     */
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
                    if (skip < 0) {
                        take = -skip;
                        skip = 0;
                    }
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
                        urlPrefix: string,
                        next?: any,
                        skip: number,
                        take: number,
                        users: User[],
                        haveNext : boolean,
                        havePrevious : boolean,
                    } = {
                        urlPrefix: this.adminPrefix,
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

    /**
     * Adds the `admin/updateuser` GET and POST endpoints.
     */
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
                    let data = {
                        urlPrefix: this.adminPrefix,
                        csrfToken: request.csrfToken,
                        user: user,
                        allowedFactor2: this.sessionServer.allowedFactor2Details(),
                        enableOAuthClientManagement: this.enableOAuthClientManagement,
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
            async (request: FastifyRequest<{Params: UserParamType, Body: AdminUpdateUserBodyType }>,
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
                        urlPrefix: this.adminPrefix, 
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
                        urlPrefix: this.adminPrefix, 
                        allowedFactor2: this.sessionServer.allowedFactor2Details(),
                        ...request.body,
                    });
                });
            }
        });
    };

    /**
     * Adds the `admin/deleteuser` GET and POST endpoints.
     */
    addDeleteUserEndpoints() {

        this.sessionServer.app.get(this.adminPrefix+'deleteuser/:id', 
            async (request: FastifyRequest<{ Params: AdminDeleteUserParamType, Querystring: DeleteUserQueryType }>,
                reply: FastifyReply)  => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'GET',
                    url: this.adminPrefix + 'deleteclient',
                    ip: request.ip
                }));
                let user : User;
                if (!request?.user || !FastifyServer.isAdmin(request.user)) {
                    return this.accessDeniedPage(request, reply);                    
                }
                try {
                    const resp = await this.sessionServer.userStorage.getUserById(request.params.id);
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
                const next = request.query.next ?? this.adminPrefix + "selectuser";
                let data = {
                    urlPrefix: this.adminPrefix,
                    csrfToken: request.csrfToken,
                    next: next,
                    isAdmin: true,
                    user : user,
                };
            return reply.view(this.deleteUserPage, data);
        });

        this.sessionServer.app.post(this.adminPrefix+'deleteuser/:id', 
            async (request: FastifyRequest<{ Params: AdminDeleteUserParamType, Body: DeleteUserQueryType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.adminPrefix + 'deleteuser',
                    ip: request.ip,
                    user: request.user?.username
                }));

                const next = request.body.next ?? this.adminPrefix + "selectuser";
                try {
                    return await this.deleteUser(request, reply, 
                    (reply) => {
                        return reply.view(this.deleteUserPage, {
                            message: "User deleted",
                            csrfToken: request.csrfToken,
                            urlPrefix: this.adminPrefix, 
                            userId : request.params.id,
                            isAdmin: true,
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
                            urlPrefix: this.adminPrefix, 
                            userId : request.params.id,
                            isAdmin: true,
                            next: next,
                        });
                        
                    });
                }
        });

    }

    /**
     * Adds the `admin/api/updateuser` POST endpoint.
     */
    addApiUpdateUserEndpoints() {
        this.sessionServer.app.post(this.adminPrefix+'api/updateuser/:id', 
            async (request: FastifyRequest<{Params: UserParamType, Body: AdminUpdateUserBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.adminPrefix + 'api/updateuser',
                    ip: request.ip,
                    user: request.user?.username
                }));
            if (!request.user || !FastifyServer.isAdmin(request.user)) {
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


    /**
     * Adds the `admin/changepassword` GET and POST endpoints.
     */
    addChangePasswordEndpoints() {
        this.sessionServer.app.get(this.adminPrefix+'changepassword/:id', 
            async (request: FastifyRequest<{Params: UserParamType,  Querystring: ChangePasswordQueryType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'GET',
                    url: this.adminPrefix + 'changepassword',
                    ip: request.ip,
                    user: request.user?.username
                }));

                if (!request?.user || !FastifyServer.isAdmin(request.user)) {
                    return this.accessDeniedPage(request, reply);                    
                }
                try {
                    const {user} = 
                        await this.sessionServer.userStorage.getUserById(request.params.id)
                    let data: {
                        urlPrefix: string,
                        csrfToken?: string,
                        user : User,
                    } = {
                        urlPrefix: this.adminPrefix,
                        csrfToken: request.csrfToken,
                        user: user,
                    };
                return reply.view(this.adminChangePasswordPage, data);
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.error(j({err: e}));
                return FastifyServer.sendPageError(reply,
                    ce.httpStatus,
                    this.sessionServer.errorPage,
                    ce.message, ce);

            }
                
        });

        this.sessionServer.app.post(this.adminPrefix+'changepassword/:id', 
            async (request: FastifyRequest<{Params: UserParamType, Body: AdminChangePasswordBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.adminPrefix + 'changepassword',
                    ip: request.ip,
                    user: request.user?.username
                }));
                let user : User|undefined;
                try {
                    const {user: user1} = await 
                        this.sessionServer.userStorage.getUserById(request.params.id);
                    user = user1;
                    return await this.changePassword(user, request, reply, 
                (reply, _user) => {
                    if (request.body.next) {
                        return reply.redirect(request.body.next);
                    } 
                    return reply.view(this.adminChangePasswordPage, {
                        csrfToken: request.csrfToken,
                        message: "User's password has been changed.",
                        urlPrefix: this.adminPrefix, 
                        next: request.body.next,
                        required: request.body.required,
                        user: user,
                    });
                });
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.error(j({
                    msg: "Change password failure",
                    userId: request.params.id,
                    errorCodeName: ce.codeName,
                    errorCode: ce.code
                }));
                CrossauthLogger.logger.debug(j({err: e}));
                return this.sessionServer.handleError(e, request, reply, (reply, error) => {
                    return reply.view(this.adminChangePasswordPage, {
                        errorMessage: error.message,
                        errorMessages: error.messages, 
                        errorCode: error.code, 
                        errorCodeName: ErrorCode[error.code], 
                        csrfToken: request.csrfToken,
                        urlPrefix: this.adminPrefix, 
                    });
                });
            }
        });
    }

    /**
     * Adds the `admin/api/changepassword` POST endpoint.
     */
    addApiChangePasswordEndpoints() {
        this.sessionServer.app.post(this.adminPrefix+'api/changepassword/:id', 
            async (request: FastifyRequest<{Params: UserParamType, Body: AdminChangePasswordBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.adminPrefix + 'api/changepassword',
                    ip: request.ip,
                    user: request.user?.username
                }));

                if (!request.user || !FastifyServer.isAdmin(request.user)) {
                    return this.sessionServer.sendJsonError(reply, 401);
                }
                let user : User|undefined;
                try {
                    const {user: user1} = await 
                        this.sessionServer.userStorage.getUserById(request.params.id);
                    user = user1;
                    return await this.changePassword(user, request, reply, 
                    (reply, _user) => 
                        {return reply.header(...JSONHDR).send({
                        ok: true,
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
     * Adds the `admin/api/deleteuser` POST endpoint.
     */
    addApiDeleteUserEndpoints() {

        this.sessionServer.app.post(this.adminPrefix+'api/deleteuser/:id', 
            async (request: FastifyRequest<{ Params: AdminDeleteUserParamType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.adminPrefix + 'api/deleteuser',
                    ip: request.ip,
                    user: request.user?.username
                }));
                try {
                    return await this.deleteUser(request, reply, 
                        (reply) => {
                        return reply.header(...JSONHDR).send({
                        ok: true,
                        clientId : request.params.id,
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

    ///////////////////////////////////////////////////////////
    // Internal functions

    private async createUser(request : FastifyRequest<{ Body: AdminCreateUserBodyType }>, 
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

    private async updateUser(user : User, request : FastifyRequest<{ Body: AdminUpdateUserBodyType }>, 
        reply : FastifyReply, 
        successFn : (res : FastifyReply, user : User, emailVerificationRequired : boolean)
        => void) {

        // can only call this if logged in and CSRF token is valid
        if (!request.user || !FastifyServer.isAdmin(request.user)) {
            throw new CrossauthError(ErrorCode.Unauthorized);
        }
        //await this.validateCsrfToken(request);
        if (this.sessionServer.isSessionUser(request) && !request.csrfToken) throw new CrossauthError(ErrorCode.InvalidCsrf);

        const oldFactor2 = user.factor2;
        const oldState = user.state;
        user.state = request.body.state;
        user = this.sessionServer.updateUserFn(user,
            request,
            this.sessionServer.userStorage.userEditableFields);
        const factor2ResetNeeded = user.factor2 && user.factor2 != "none" && user.factor2 != oldFactor2;
        if (factor2ResetNeeded && !(user.state == oldState || user.state == "factor2ResetNeeded")) {
            throw new CrossauthError(ErrorCode.BadRequest, "Cannot change both factor2 and state at the same time");
        }
        if (factor2ResetNeeded) {
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

    private async changePassword(user : User, request : FastifyRequest<{ Body: AdminChangePasswordBodyType }>, 
        reply : FastifyReply, 
        successFn : (res : FastifyReply, user? : User) => void) {

        // can only call this if logged in and CSRF token is valid
        if (!request.user || !FastifyServer.isAdmin(request.user)) {
            throw new CrossauthError(ErrorCode.Unauthorized);
        }
        //await this.validateCsrfToken(request);
        if (this.sessionServer.isSessionUser(request) && !request.csrfToken) throw new CrossauthError(ErrorCode.InvalidCsrf);

        // get the authenticator for factor1 (passwords on factor2 are not supported)
        const authenticator = this.sessionServer.authenticators[user.factor1];

        // the form should contain old_{secret}, new_{secret} and repeat_{secret}
        // extract them, making sure the secret is a valid one
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

        // validate the new secret - this is through an implementor-supplied function
        let errors = authenticator.validateSecrets(newSecrets);
        if (errors.length > 0) {
            throw new CrossauthError(ErrorCode.PasswordFormat);
        }

        user.state = "active";
        await this.sessionServer.userStorage.updateUser({id: user.id, state:user.state});
        await this.sessionServer.sessionManager.changeSecrets(user.username,
            1,
            newSecrets,
            repeatSecrets);
        
        return successFn(reply, undefined);
    }

    private async deleteUser(request : FastifyRequest<{ Params: AdminDeleteUserParamType }>, 
        reply : FastifyReply, 
        successFn : (res : FastifyReply) => FastifyReply) {
            
        // throw an error if the CSRF token is invalid
        if (this.sessionServer.isSessionUser(request) && !request.csrfToken) {
            throw new CrossauthError(ErrorCode.InvalidCsrf);
        }

        // throw an error if not an admin user
        if (!request.user || !FastifyServer.isAdmin(request.user)) {
            throw new CrossauthError(ErrorCode.InsufficientPriviledges);
        }

        await this.sessionServer.userStorage.deleteUserById(request.params.id);
        return successFn(reply);
    }
}