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

import type { FastifySessionServerOptions, } from './fastifysession';
import {
    setParameter,
    ParamType,
    OAuthClientManager,
    OAuthClientStorage } from '@crossauth/backend';
import { defaultClientSearchFn } from './fastifyadminclientendpoints'
import type {
    SelectClientQueryType,
    CreateClientQueryType,
    CreateClientBodyType,
    DeleteClientParamType,
    DeleteClientQueryType } from './fastifyadminclientendpoints'

/////////////////////////////////////////////////////////////////////
// Fastify data types

const JSONHDR : [string,string] = 
    ['Content-Type', 'application/json; charset=utf-8'];

///////////////////////////////////////////////////////////////////////
// Class

export class FastifyUserClientEndpoints {
    private sessionServer : FastifySessionServer;
    private clientStorage : OAuthClientStorage;
    private clientManager : OAuthClientManager;
    private prefix = "/";
    private clientSearchFn : 
        (searchTerm : string, clientStorage : OAuthClientStorage, userId? : string|number|null) => Promise<OAuthClient[]> =
        defaultClientSearchFn;
    private validFlows : string[] = ["all"];


    // pages
    private selectClientPage = "selectclient.njk";
    private createClientPage = "createclient.njk";
    private deleteClientPage = "deleteclient.njk";

    constructor(sessionServer : FastifySessionServer,
        options: FastifySessionServerOptions = {}) {


        this.sessionServer = sessionServer;
        if (!options.clientStorage) throw new CrossauthError(ErrorCode.Configuration,
            "Must specify clientStorage if adding OAuth client endpoints");
        this.clientManager = new OAuthClientManager(options);
        this.clientStorage = options.clientStorage;
        setParameter("prefix", ParamType.String, this, options, "PREFIX");
        setParameter("createClientPage", ParamType.String, this, options, "CREATE_CLIENT_PAGE");
        setParameter("selectClientPage", ParamType.String, this, options, "SELECT_CLIENT_PAGE");
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
        this.sessionServer.app.get(this.prefix+'selectclient', 
            async (request: FastifyRequest<{ Querystring: SelectClientQueryType }>,
                reply: FastifyReply)  => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'GET',
                    url: this.prefix + 'selectclient',
                    ip: request.ip
                }));
                if (!request?.user) {
                    return reply.redirect(this.sessionServer.loginUrl + 
                        "?next="+this.prefix+"selectclient");                 
                }
                try {
                    let clients : OAuthClient[] = [];
                    let skip = Number(request.query.skip);
                    let take = Number(request.query.take);
                    if (!skip) skip = 0;
                    if (!take) take = 10;
                    if (request.query.search) {
                        clients = await this.clientSearchFn(request.query.search, 
                            this.clientStorage, request.user.id)
                    } else {
                        clients = 
                            await this.clientStorage.getClients(skip, 
                                take, request.user.id);
                    }
                    const next = request.query.next ?? encodeURIComponent(request.url);
                    let data: {
                        urlprefix: string,
                        next?: string,
                        user? : User,
                        skip: number,
                        take: number,
                        clients: OAuthClient[],
                        haveNext : boolean,
                        havePrevious : boolean,
                        isAdmin : boolean,
                    } = {
                        urlprefix: this.prefix,
                        user : request.user,
                        skip: skip,
                        take: take,
                        clients: clients,
                        havePrevious: skip > 0,
                        haveNext : take != undefined && clients.length == take,
                        isAdmin: false,
                        next: next,
                    };
                if (request.query.next) {
                    data["next"] = request.query.next;
                }
                return reply.view(this.selectClientPage, data);
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

        this.sessionServer.app.get(this.prefix+'createclient', 
            async (request: FastifyRequest<{ Querystring: CreateClientQueryType }>,
                reply: FastifyReply)  => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'GET',
                    url: this.prefix + 'createclient',
                    ip: request.ip
                }));
                if (!request?.user) {
                    return reply.redirect(this.sessionServer.loginUrl + 
                        "?next="+this.prefix+"createclient");                 
                }
                const next = request.query.next ?? "/";
                let data = {
                    urlprefix: this.prefix,
                    csrfToken: request.csrfToken,
                    validFlows: this.validFlows,
                    user : request.user,
                    isAdmin: false,
                    next: next,
                };
            return reply.view(this.createClientPage, data);
        });

        this.sessionServer.app.post(this.prefix+'createclient', 
            async (request: FastifyRequest<{ Body: CreateClientBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.prefix + 'createclient',
                    ip: request.ip,
                    user: request.user?.username
                }));

                if (!request?.user) {
                    return reply.redirect(this.sessionServer.loginUrl + 
                        "?next="+encodeURIComponent(request.url));                 
                }
                const next = request.body.next ?? "/";
                try {
                    return await this.createClient(request, reply, 
                    (reply, client) => {
                        return reply.view(this.createClientPage, {
                            message: "Created client",
                            client: client,
                            csrfToken: request.csrfToken,
                            urlprefix: this.prefix, 
                            validFlows: this.validFlows,
                            user : request.user,
                            isAdmin: true,
                            next: next,
                            ...request.body,
                        });
                    }, request.user);
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
                        return reply.status(statusCode).view(this.createClientPage, {
                            errorMessage: error.message,
                            errorMessages: error.messages, 
                            errorCode: error.code, 
                            errorCodeName: ErrorCode[error.code], 
                            csrfToken: request.csrfToken,
                            urlprefix: this.prefix, 
                            isAdmin: false,
                            next: next,
                            ...request.body,
                        });
                        
                    });
                }
        });

    }

    addApiCreateClientEndpoints() {

        this.sessionServer.app.post(this.prefix+'api/createclient', 
            async (request: FastifyRequest<{ Body: CreateClientBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.prefix + 'api/createclient',
                    ip: request.ip,
                    user: request.user?.username
                }));
            if (!request.user) {
                return reply.status(401).header(...JSONHDR).send({ok: false});
            }
            try {
                return await this.createClient(request, reply, 
                (reply, client) => {
                    return reply.header(...JSONHDR).send({
                    ok: true,
                    client : client,
                })}, request.user);
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

    addDeleteClientEndpoints() {

        this.sessionServer.app.get(this.prefix+'deleteclient/:clientId', 
            async (request: FastifyRequest<{ Params: DeleteClientParamType, Querystring: DeleteClientQueryType }>,
                reply: FastifyReply)  => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'GET',
                    url: this.prefix + 'deleteclient',
                    ip: request.ip
                }));
                let client : OAuthClient;
                if (!request.user) {
                    return reply.redirect(this.sessionServer.loginUrl+"?next=" +
                        this.prefix+"deleteclient/"+request.params.clientId);
                }
                try {
                    client = await this.clientStorage.getClientById(request.params.clientId);
                    if (client.userId != request.user.id) {
                        throw new CrossauthError(ErrorCode.InsufficientPriviledges,
                            "You may not delete this client");
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
                const next = request.query.next ?? "/";
                let data = {
                    urlprefix: this.prefix,
                    csrfToken: request.csrfToken,
                    backUrl: this.prefix + "selectclient",
                    client : client,
                    next: next,
                };
            return reply.view(this.deleteClientPage, data);
        });

        this.sessionServer.app.post(this.prefix+'deleteclient/:clientId', 
            async (request: FastifyRequest<{ Params: DeleteClientParamType, Body: DeleteClientQueryType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.prefix + 'deleteclient',
                    ip: request.ip,
                    user: request.user?.username
                }));

                if (!request.user) {
                    return reply.redirect(this.sessionServer.loginUrl+"?next=" +
                        this.prefix+"deleteclient/"+request.params.clientId);
                }
                const next = this.prefix + "selectclient";
                try {
                    return await this.deleteClient(request, reply, 
                    (reply) => {
                        return reply.view(this.deleteClientPage, {
                            message: "Client deleted",
                            csrfToken: request.csrfToken,
                            urlprefix: this.prefix, 
                            validFlows: this.validFlows,
                            clientId : request.params.clientId,
                            next: next,
                        });
                    }, request.user);
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
                            urlprefix: this.prefix, 
                            clientId : request.params.clientId,
                            next: next,
                        });
                        
                    });
                }
        });

    }

    addApiDeleteClientEndpoints() {

        this.sessionServer.app.post(this.prefix+'api/deleteclient/:clientId', 
            async (request: FastifyRequest<{ Params: DeleteClientParamType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.prefix + 'api/deleteclient',
                    ip: request.ip,
                    user: request.user?.username
                }));
                if (!request.user) {
                    return reply.status(401).header(...JSONHDR).send({ok: false});
                }
                try {
                    return await this.deleteClient(request, reply, 
                        (reply) => {
                        return reply.header(...JSONHDR).send({
                        ok: true,
                        clientId : request.params.clientId,
                    })}, request.user);
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

    private async createClient(request : FastifyRequest<{ Body: CreateClientBodyType }>, 
        reply : FastifyReply, 
        successFn : (res : FastifyReply, client : OAuthClient) => FastifyReply,
        user? : User) {
            
        // throw an error if the CSRF token is invalid
        if (this.sessionServer.isSessionUser(request) && !request.csrfToken) {
            throw new CrossauthError(ErrorCode.InvalidCsrf);
        }

        // throw an error if not an admin user
        if (!request.user) {
            throw new CrossauthError(ErrorCode.InsufficientPriviledges);
        }

        const confidential = request.body.confidential == "true";
        const clientName = request.body.clientName;
        const redirectUris = request.body.redirectUris.split(/,?[ \t\n]+/);

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
        successFn : (res : FastifyReply) => FastifyReply,
        user : User) {
            
        // throw an error if the CSRF token is invalid
        if (this.sessionServer.isSessionUser(request) && !request.csrfToken) {
            throw new CrossauthError(ErrorCode.InvalidCsrf);
        }

        // throw an error if not an admin user
        if (!user) {
            throw new CrossauthError(ErrorCode.InsufficientPriviledges);
        }

        const client = await this.clientStorage.getClientById(request.params.clientId);
        if (client.userId != user.id) {
            throw new CrossauthError(ErrorCode.InsufficientPriviledges,
                "You may not delete this client");
        }
        
        await this.clientStorage.deleteClient(request.params.clientId);
        return successFn(reply);
    }
}
