import {
    type FastifyRequest,
    type FastifyReply } from 'fastify';
import {
    CrossauthError,
    ErrorCode,
    CrossauthLogger,
    j,
    OAuthFlows,
} from '@crossauth/common';
import type { OAuthClient, User } from '@crossauth/common';
import { FastifyServer } from './fastifyserver';
import { FastifySessionServer } from './fastifysession';
import { type UserParamType } from './fastifyadminendpoints';

import type { FastifySessionServerOptions,
    CsrfBodyType } from './fastifysession';
import {
    setParameter,
    ParamType,
    OAuthClientManager,
    OAuthClientStorage } from '@crossauth/backend';

export async function defaultClientSearchFn(searchTerm: string,
    clientStorage: OAuthClientStorage, userId? : string|number|null) : Promise<OAuthClient[]> {
        let clients : OAuthClient[] = [];
    try {
        const client = await clientStorage.getClientById(searchTerm)
        clients.push(client);
    } catch (e1) {
        const ce1 = CrossauthError.asCrossauthError(e1);
        if (ce1.code != ErrorCode.UserNotExist) {
            CrossauthLogger.logger.debug(j({err: ce1}));
            throw ce1;
        }
        try {
            clients = 
                await clientStorage.getClientByName(searchTerm, userId);
            } catch (e2) {
            const ce2 = CrossauthError.asCrossauthError(e2);
            if (ce2.code != ErrorCode.UserNotExist) {
                CrossauthLogger.logger.debug(j({err: ce2}));
                throw ce1;
            }
        }
    }
    return clients;

}

/////////////////////////////////////////////////////////////////////
// Fastify data types

interface SelectClientQueryType {
    userId? : string|number,
    next? : string,
    search? : string,
    user? : string|number,
    skip? : number,
    take? : number,
    haveNext? : boolean,
    havePrevious? : boolean,
}

export interface CreateClientQueryType {
    next? : string;
    userId? : string|number,
}

interface CreateClientBodyType extends CsrfBodyType {
    clientName : string,
    confidential? : string,
    userId? : string|number|null,
    redirectUris : string,
    authorizationCode? : string,
    authorizationCodeWithPKCE? : string,
    clientCredentials? : string,
    refreshToken? : string,
    deviceCode? : string,
    password? : string,
    passwordMfa? : string,
    oidcAuthorizationCode? : string,
}

interface DeleteClientParamType {
    clientId : string
}

const JSONHDR : [string,string] = 
    ['Content-Type', 'application/json; charset=utf-8'];

///////////////////////////////////////////////////////////////////////
// Class

export class FastifyAdminClientEndpoints {
    private sessionServer : FastifySessionServer;
    private clientStorage : OAuthClientStorage;
    private clientManager : OAuthClientManager;
    private adminPrefix = "/admin/";
    private clientSearchFn : 
        (searchTerm : string, clientStorage : OAuthClientStorage, userId? : string|number|null) => Promise<OAuthClient[]> =
        defaultClientSearchFn;
    private validFlows : string[] = ["all"];


    // pages
    private adminSelectClientPage = "admin/selectclient.njk";
    private adminCreateClientPage = "admin/createclient.njk";
    private deleteClientPage = "deleteclient.njk";

    constructor(sessionServer : FastifySessionServer,
        options: FastifySessionServerOptions = {}) {


        this.sessionServer = sessionServer;
        if (!options.clientStorage) throw new CrossauthError(ErrorCode.Configuration,
            "Must specify clientStorage if adding OAuth client endpoints");
        this.clientManager = new OAuthClientManager(options);
        this.clientStorage = options.clientStorage;
        setParameter("adminPrefix", ParamType.String, this, options, "ADMIN_PREFIX");
        setParameter("adminCreateClientPage", ParamType.String, this, options, "ADMIN_CREATE_CLIENT_PAGE");
        setParameter("adminSelectClientPage", ParamType.String, this, options, "ADMIN_SELECT_CLIENT_PAGE");
        setParameter("deleteClientPage", ParamType.String, this, options, "DELETE_CLIENT_PAGE");
        setParameter("validFlows", ParamType.StringArray, this, options, "OAUTH_VALID_FLOWS");
        if (this.validFlows.length == 1 &&
            this.validFlows[0] == OAuthFlows.All) {
            this.validFlows = OAuthFlows.allFlows();
        }

        if (options.clientSearchFn) this.clientSearchFn = options.clientSearchFn;
    }

    ///////////////////////////////////////////////////////////////////
    // Endpoints

    addSelectClientEndpoints() {
        this.sessionServer.app.get(this.adminPrefix+'selectclient', 
            async (request: FastifyRequest<{ Querystring: SelectClientQueryType }>,
                reply: FastifyReply)  => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'GET',
                    url: this.adminPrefix + 'selectclient',
                    ip: request.ip
                }));
                if (!request?.user || !FastifyServer.isAdmin(request.user)) {
                    return this.accessDeniedPage(request, reply);                    
                }
                try {
                    let clients : OAuthClient[] = [];
                    let skip = Number(request.query.skip);
                    let take = Number(request.query.take);
                    if (!skip) skip = 0;
                    if (!take) take = 10;
                    let userId : string|number|null = null;
                    let user : User|undefined = undefined;
                    if (request.query.userId) {
                        const resp =
                            await this.sessionServer.userStorage.getUserById(request.query.userId);
                        user = resp.user;
                        userId = user.id;
                    }
                    if (request.query.search) {
                        clients = await this.clientSearchFn(request.query.search, 
                            this.clientStorage, userId)
                    } else {
                        clients = 
                            await this.clientStorage.getClients(skip, 
                                take, userId);
                    }
                    let data: {
                        urlprefix: string,
                        next?: any,
                        user? : User,
                        skip: number,
                        take: number,
                        clients: OAuthClient[],
                        haveNext : boolean,
                        havePrevious : boolean,
                    } = {
                        urlprefix: this.adminPrefix,
                        user : user,
                        skip: skip,
                        take: take,
                        clients: clients,
                        havePrevious: skip > 0,
                        haveNext : take != undefined && clients.length == take,
                    };
                if (request.query.next) {
                    data["next"] = request.query.next;
                }
                return reply.view(this.adminSelectClientPage, data);
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

    addCreateClientEndpoints() {

        this.sessionServer.app.get(this.adminPrefix+'createclient', 
            async (request: FastifyRequest<{ Querystring: CreateClientQueryType }>,
                reply: FastifyReply)  => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'GET',
                    url: this.adminPrefix + 'createclient',
                    ip: request.ip
                }));
                if (!request?.user || !FastifyServer.isAdmin(request.user)) {
                    return this.accessDeniedPage(request, reply);                    
                }
                let user : User|undefined = undefined;
                try {
                    if (request.query.userId) {
                        let resp = await this.sessionServer.userStorage.getUserById(request.query.userId);
                        user = resp.user;
                    }
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
                let data: {
                    urlprefix: string,
                    csrfToken: string | undefined,
                    validFlows: string[],
                    user : User | undefined,
                } = {
                    urlprefix: this.adminPrefix,
                    csrfToken: request.csrfToken,
                    validFlows: this.validFlows,
                    user : user,
                };
            return reply.view(this.adminCreateClientPage, data);
        });

        this.sessionServer.app.post(this.adminPrefix+'createclient', 
            async (request: FastifyRequest<{ Body: CreateClientBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.adminPrefix + 'createclient',
                    ip: request.ip,
                    user: request.user?.username
                }));

                let user : User|undefined = undefined;
                try {
                    if (request.body.userId) {
                        let resp = await this.sessionServer.userStorage.getUserById(request.body.userId);
                        user = resp.user;
                    }
                    return await this.createClient(request, reply, 
                    (reply, client) => {
                        return reply.view(this.adminCreateClientPage, {
                            message: "Created client",
                            client: client,
                            csrfToken: request.csrfToken,
                            urlprefix: this.adminPrefix, 
                            validFlows: this.validFlows,
                            user : user,
                            ...request.body,
                        });
                    }, user);
                } catch (e) {
                    const ce = CrossauthError.asCrossauthError(e);
                    CrossauthLogger.logger.error(j({
                        msg: "Failed creating OAuth client",
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
                        return reply.status(statusCode).view(this.adminCreateClientPage, {
                            errorMessage: error.message,
                            errorMessages: error.messages, 
                            errorCode: error.code, 
                            errorCodeName: ErrorCode[error.code], 
                            csrfToken: request.csrfToken,
                            urlprefix: this.adminPrefix, 
                            ...request.body,
                        });
                        
                    });
                }
        });

    }

    addDeleteClientEndpoints() {

        this.sessionServer.app.get(this.adminPrefix+'deleteclient/:clientId', 
            async (request: FastifyRequest<{ Params: DeleteClientParamType }>,
                reply: FastifyReply)  => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'GET',
                    url: this.adminPrefix + 'deleteclient',
                    ip: request.ip
                }));
                let client : OAuthClient;
                if (!request?.user || !FastifyServer.isAdmin(request.user)) {
                    return this.accessDeniedPage(request, reply);                    
                }
                try {
                    client = await this.clientStorage.getClientById(request.params.clientId);
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
                let data = {
                    urlprefix: this.adminPrefix,
                    csrfToken: request.csrfToken,
                    backUrl: this.adminPrefix + "selectclient",
                    client : client,
                };
            return reply.view(this.deleteClientPage, data);
        });

        this.sessionServer.app.post(this.adminPrefix+'deleteclient/:clientId', 
            async (request: FastifyRequest<{ Params: DeleteClientParamType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.adminPrefix + 'deleteclient',
                    ip: request.ip,
                    user: request.user?.username
                }));

                try {
                    return await this.deleteClient(request, reply, 
                    (reply) => {
                        return reply.view(this.deleteClientPage, {
                            message: "Client deleted",
                            csrfToken: request.csrfToken,
                            urlprefix: this.adminPrefix, 
                            validFlows: this.validFlows,
                            clientId : request.params.clientId,
                            backUrl: this.adminPrefix + "selectclient",
                        });
                    });
                } catch (e) {
                    const ce = CrossauthError.asCrossauthError(e);
                    CrossauthLogger.logger.error(j({
                        msg: "Failed deleting OAuth client",
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
                        return reply.status(statusCode).view(this.deleteClientPage, {
                            errorMessage: error.message,
                            errorMessages: error.messages, 
                            errorCode: error.code, 
                            errorCodeName: ErrorCode[error.code], 
                            csrfToken: request.csrfToken,
                            urlprefix: this.adminPrefix, 
                            clientId : request.params.clientId,
                        });
                        
                    });
                }
        });

    }

    addApiCreateClientEndpoints() {

        this.sessionServer.app.post(this.adminPrefix+'api/createclient', 
            async (request: FastifyRequest<{ Body: CreateClientBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.adminPrefix + 'api/createclient',
                    ip: request.ip,
                    user: request.user?.username
                }));
            let user : User|undefined = undefined;
            try {
                if (request.body.userId) {
                    let resp = await this.sessionServer.userStorage.getUserById(request.body.userId);
                    user = resp.user;
                }
                return await this.createClient(request, reply, 
                (reply, client) => {
                    return reply.header(...JSONHDR).send({
                    ok: true,
                    client : client,
                })}, user);
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e); 
                CrossauthLogger.logger.error(j({
                    msg: "Create client failure",
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

        this.sessionServer.app.post(this.adminPrefix+'api/createclient/:id', 
            async (request: FastifyRequest<{Params: UserParamType, Body: CreateClientBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.adminPrefix + 'api/createclient',
                    ip: request.ip,
                    user: request.user?.username
                }));
            try {
                return await this.createClient(request, reply, 
                (reply, client) => {
                    return reply.header(...JSONHDR).send({
                    ok: true,
                    client : client,
                })});
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e); 
                CrossauthLogger.logger.error(j({
                    msg: "Create client failure",
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

    addApiDeleteClientEndpoints() {

        this.sessionServer.app.post(this.adminPrefix+'api/deleteclient/:clientId', 
            async (request: FastifyRequest<{ Params: DeleteClientParamType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.adminPrefix + 'api/deleteclient',
                    ip: request.ip,
                    user: request.user?.username
                }));
                try {
                    return await this.deleteClient(request, reply, 
                        (reply) => {
                        return reply.header(...JSONHDR).send({
                        ok: true,
                        clientId : request.params.clientId,
                    })});
                } catch (e) {
                    const ce = CrossauthError.asCrossauthError(e); 
                    CrossauthLogger.logger.error(j({
                        msg: "Delete client failure",
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

    ///////////////////////////////////////////////////////////////////
    // Internal functions

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

    private async createClient(request : FastifyRequest<{ Body: CreateClientBodyType }>, 
        reply : FastifyReply, 
        successFn : (res : FastifyReply, client : OAuthClient) => FastifyReply,
        user? : User) {
            
        // throw an error if the CSRF token is invalid
        if (this.sessionServer.isSessionUser(request) && !request.csrfToken) {
            throw new CrossauthError(ErrorCode.InvalidCsrf);
        }

        // throw an error if not an admin user
        if (!request.user || !FastifyServer.isAdmin(request.user)) {
            throw new CrossauthError(ErrorCode.InsufficientPriviledges);
        }

        const confidential = request.body.confidential == "true";
        const clientName = request.body.clientName;
        const redirectUris = request.body.redirectUris.split(/[ \t\n]+/);

        // validate redirect uris
        let redirectUriErrors : string[] = [];
        for (let uri of redirectUris) {
            try {
                OAuthClientManager.validateUri(uri);
            }
            catch (e) {
                CrossauthLogger.logger.error(j({err: e}));
                redirectUriErrors.push("["+uri+"]");
            }
        }
        if (redirectUriErrors.length > 0) {
            throw new CrossauthError(ErrorCode.BadRequest, 
                "The following redirect URIs are invalid: " 
                    + redirectUriErrors.join(" "));
        }

        // get flows from booleans in body
        let validFlows = [];
        if (request.body[OAuthFlows.AuthorizationCode]) validFlows.push(OAuthFlows.AuthorizationCode);
        if (request.body[OAuthFlows.AuthorizationCodeWithPKCE]) validFlows.push(OAuthFlows.AuthorizationCodeWithPKCE);
        if (request.body[OAuthFlows.ClientCredentials]) validFlows.push(OAuthFlows.ClientCredentials);
        if (request.body[OAuthFlows.RefreshToken]) validFlows.push(OAuthFlows.RefreshToken);
        if (request.body[OAuthFlows.DeviceCode]) validFlows.push(OAuthFlows.DeviceCode);
        if (request.body[OAuthFlows.Password]) validFlows.push(OAuthFlows.Password);
        if (request.body[OAuthFlows.PasswordMfa]) validFlows.push(OAuthFlows.PasswordMfa);
        if (request.body[OAuthFlows.OidcAuthorizationCode]) validFlows.push(OAuthFlows.OidcAuthorizationCode);

        const client = 
            await this.clientManager.createClient(clientName,
                redirectUris,
                validFlows,
                confidential,
                user?.id );
        return successFn(reply, client);
    }

    private async deleteClient(request : FastifyRequest<{ Params: DeleteClientParamType }>, 
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

        await this.clientStorage.deleteClient(request.params.clientId);
        return successFn(reply);
    }
}

