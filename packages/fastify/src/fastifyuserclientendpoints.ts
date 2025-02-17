// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
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
    UpdateClientParamType,
    UpdateClientBodyType,
    DeleteClientParamType,
    DeleteClientQueryType } from './fastifyadminclientendpoints'

/////////////////////////////////////////////////////////////////////
// Fastify data types

const JSONHDR : [string,string] = 
    ['Content-Type', 'application/json; charset=utf-8'];

///////////////////////////////////////////////////////////////////////
// Class

/**
 * This class provides user endpoints for the Fastify server for manipulating
 * OAuth clients.
 * 
 * Endpoints include changeing password, editing the User record, etc.
 * 
 * This class is not intended to be created directly.  It is created
 * by {@link FastifySessionServer}.  For a description of the endpoints,
 * and how to create templates for them, see that class.
 */
export class FastifyUserClientEndpoints {
    private sessionServer : FastifySessionServer;
    private clientStorage : OAuthClientStorage;
    private clientManager : OAuthClientManager;
    private prefix = "/";
    private clientSearchFn : 
        (searchTerm : string, clientStorage : OAuthClientStorage, userid? : string|number|null) => Promise<OAuthClient[]> =
        defaultClientSearchFn;
    private validFlows : string[] = ["all"];


    // pages
    private selectClientPage = "selectclient.njk";
    private createClientPage = "createclient.njk";
    private updateClientPage = "updateclient.njk";
    private deleteClientPage = "deleteclient.njk";

    /**
     * Constructor
     * @param sessionServer instance of the Fatify session server this is being added to
     * @param options See {@link FastifySessionServerOptions}
     */
    constructor(sessionServer : FastifySessionServer,
        options: FastifySessionServerOptions = {}) {


        this.sessionServer = sessionServer;
        if (!options.clientStorage) throw new CrossauthError(ErrorCode.Configuration,
            "Must specify clientStorage if adding OAuth client endpoints");
        this.clientManager = new OAuthClientManager(options);
        this.clientStorage = options.clientStorage;
        setParameter("prefix", ParamType.String, this, options, "PREFIX");
        setParameter("createClientPage", ParamType.String, this, options, "CREATE_CLIENT_PAGE");
        setParameter("updateClientPage", ParamType.String, this, options, "UPDATE_CLIENT_PAGE");
        setParameter("selectClientPage", ParamType.String, this, options, "SELECT_CLIENT_PAGE");
        setParameter("deleteClientPage", ParamType.String, this, options, "DELETE_CLIENT_PAGE");
        setParameter("validFlows", ParamType.JsonArray, this, options, "OAUTH_validFlows");
        if (this.validFlows.length == 1 &&
            this.validFlows[0] == OAuthFlows.All) {
            this.validFlows = OAuthFlows.allFlows();
        }

        if (options.clientSearchFn) this.clientSearchFn = options.clientSearchFn;
    }

    ///////////////////////////////////////////////////////////////////
    // Endpoints

    /**
     * Adds the `selectclient` GET endpoint.
     */
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
                        urlPrefix: string,
                        next?: string,
                        user? : User,
                        skip: number,
                        take: number,
                        clients: OAuthClient[],
                        haveNext : boolean,
                        havePrevious : boolean,
                        isAdmin : boolean,
                    } = {
                        urlPrefix: this.prefix,
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

    /**
     * Adds the `createclient` GET and POST endpoints.
     */
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
                    urlPrefix: this.prefix,
                    csrfToken: request.csrfToken,
                    validFlows: this.validFlows,
                    flowNames: OAuthFlows.flowNames(this.validFlows),
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
                            urlPrefix: this.prefix, 
                            validFlows: this.validFlows,
                            flowNames: OAuthFlows.flowNames(this.validFlows),
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
                            urlPrefix: this.prefix, 
                            validFlows: this.validFlows,
                            flowNames: OAuthFlows.flowNames(this.validFlows),
                            isAdmin: false,
                            next: next,
                            ...request.body,
                        });
                        
                    });
                }
        });

    }

    /**
     * Adds the `api/createclient` POST endpointss.
     */
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

    /**
     * Adds the `updateclient` GET and POST endpoints.
     */
    addUpdateClientEndpoints() {

        this.sessionServer.app.get(this.prefix+'updateclient/:client_id', 
            async (request: FastifyRequest<{Params: UpdateClientParamType, Querystring: CreateClientQueryType }>,
                reply: FastifyReply)  => {
                if (!this.sessionServer.userStorage) throw new CrossauthError(ErrorCode.Configuration, "Cannot call updateclient unless a user storage is provided ");
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'GET',
                    url: this.prefix + 'updateclient',
                    ip: request.ip
                }));
                if (!request?.user) {
                    return reply.redirect(this.sessionServer.loginUrl + 
                        "?next="+this.prefix+"createclient");                 
                }
                let client : OAuthClient;
                try {
                    client = await this.clientStorage.getClientById(request.params.client_id);
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
                let next = request.query.next;
                if (!next) {
                    if (request.query.userid) next = this.prefix + "selectuser";
                    else next = this.prefix + "selectclient";
                }
                let user : User|undefined = undefined;
                try {
                    if (request.query.userid) {
                        let resp = await this.sessionServer.userStorage.getUserById(request.query.userid);
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
                let selectedFlows : {[key:string]:boolean} = {};
                for (let flow of this.validFlows) {
                    if (client.valid_flow.includes(flow)) {
                        selectedFlows[flow] = true;
                    }
                }
                let data : {[key:string]:any} = {
                    urlPrefix: this.prefix,
                    csrfToken: request.csrfToken,
                    validFlows: this.validFlows,
                    flowNames: OAuthFlows.flowNames(this.validFlows),
                    selectedFlows : selectedFlows,
                    user : user,
                    client_id: client.client_id,
                    client_name: client.client_name,
                    confidential: client.confidential,
                    redirect_uris: client.redirect_uri.join(" "),
                    isAdmin: true,
                    next: next,
                };
            return reply.view(this.updateClientPage, data);
        });

        this.sessionServer.app.post(this.prefix+'updateclient/:client_id', 
            async (request: FastifyRequest<{Params: UpdateClientParamType, Body: UpdateClientBodyType }>,
                reply: FastifyReply) => {
                if (!this.sessionServer.userStorage) throw new CrossauthError(ErrorCode.Configuration, "Cannot call updateclient unless a user storage is provided ");
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.prefix + 'updateclient',
                    ip: request.ip,
                    user: request.user?.username
                }));

                let next = request.body.next;
                if (!next) {
                    next = this.prefix + "selectuser";
                }
                let user : User|undefined = undefined;
                try {
                    if (!this.sessionServer.userStorage) throw new CrossauthError(ErrorCode.Configuration, "Cannot call updateclient unless a user storage is provided ");
                    if (request.body.userid) {
                        let resp = await this.sessionServer.userStorage.getUserById(request.body.userid);
                        user = resp.user;
                    }
                    return await this.updateClient(request, reply, 
                    (reply, client, newSecret) => {
                        return reply.view(this.updateClientPage, {
                            message: "Updated client",
                            client: client,
                            csrfToken: request.csrfToken,
                            urlPrefix: this.prefix, 
                            validFlows: this.validFlows,
                            flowNames: OAuthFlows.flowNames(this.validFlows),
                            user : user,
                            isAdmin: true,
                            next: next,
                            newSecret: newSecret,
                            ...request.body,
                        });
                    });
                } catch (e) {
                    const ce = CrossauthError.asCrossauthError(e);
                    CrossauthLogger.logger.error(j({
                        msg: "Failed updating OAuth client",
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
                        let selectedFlows : {[key:string]:boolean} = {};
                        for (let flow of this.validFlows) {
                            if (flow in request.body) {
                                selectedFlows[flow] = true;
                            }
                        }
                        return reply.status(statusCode).view(this.updateClientPage, {
                            errorMessage: error.message,
                            errorMessages: error.messages, 
                            errorCode: error.code, 
                            errorCodeName: ErrorCode[error.code], 
                            csrfToken: request.csrfToken,
                            urlPrefix: this.prefix, 
                            validFlows : this.validFlows,
                            selectedFlows : selectedFlows,
                            flowNames: OAuthFlows.flowNames(this.validFlows),
                            isAdmin: true,
                            next: next,
                            ...request.body,
                        });
                        
                    });
                }
        });

    }

    /**
     * Adds the `api/updateclient` POST endpoints.
     */
    addApiUpdateClientEndpoints() {

        this.sessionServer.app.post(this.prefix+'api/updateclient/:client_id', 
            async (request: FastifyRequest<{Params: UpdateClientParamType, Body: UpdateClientBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.prefix + 'api/updateclient',
                    ip: request.ip,
                    user: request.user?.username
                }));

                try {
                    if (!this.sessionServer.userStorage) throw new CrossauthError(ErrorCode.Configuration, "Cannot call updateclient unless a user storage is provided ");
                    if (request.body.userid) {
                        await this.sessionServer.userStorage.getUserById(request.body.userid);
                    }
                    return await this.updateClient(request, reply, 
                    (reply, client, newSecret) => {
                        return reply.header(...JSONHDR).send({
                            ok: true,
                            client: client,
                            csrfToken: request.csrfToken,
                            newSecret: newSecret,
                        });
                    });
                } catch (e) {
                    const ce = CrossauthError.asCrossauthError(e);
                    CrossauthLogger.logger.error(j({
                        msg: "Failed updating OAuth client",
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
                            errorCodeName: ErrorCode[error.code], 
                        });
                        
                    });
                }
        });

    }

    /**
     * Adds the `deleteclient` GET and POST endpoints.
     */
    addDeleteClientEndpoints() {

        this.sessionServer.app.get(this.prefix+'deleteclient/:client_id', 
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
                        this.prefix+"deleteclient/"+request.params.client_id);
                }
                try {
                    client = await this.clientStorage.getClientById(request.params.client_id);
                    if (client.userid != request.user.id) {
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
                    urlPrefix: this.prefix,
                    csrfToken: request.csrfToken,
                    backUrl: this.prefix + "selectclient",
                    client : client,
                    next: next,
                };
            return reply.view(this.deleteClientPage, data);
        });

        this.sessionServer.app.post(this.prefix+'deleteclient/:client_id', 
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
                        this.prefix+"deleteclient/"+request.params.client_id);
                }
                const next = this.prefix + "selectclient";
                try {
                    return await this.deleteClient(request, reply, 
                    (reply) => {
                        return reply.view(this.deleteClientPage, {
                            message: "Client deleted",
                            csrfToken: request.csrfToken,
                            urlPrefix: this.prefix, 
                            client_id : request.params.client_id,
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
                            urlPrefix: this.prefix, 
                            client_id : request.params.client_id,
                            validFlows: this.validFlows,
                            next: next,
                        });
                        
                    });
                }
        });

    }

    /**
     * Adds the `api/deleteclient` POST endpoint.
     */
    addApiDeleteClientEndpoints() {

        this.sessionServer.app.post(this.prefix+'api/deleteclient/:client_id', 
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
                        client_id : request.params.client_id,
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

        // throw an error if not logged in
        if (!request.user) {
            throw new CrossauthError(ErrorCode.InsufficientPriviledges);
        }

        const confidential = request.body.confidential == "true";
        const client_name = request.body.client_name;
        const redirect_uris = request.body.redirect_uris.trim().length == 0 ? 
            [] : request.body.redirect_uris.trim().split(/[, ][ \t\n]*/);

        // validate redirect uris
        let redirect_uriErrors : string[] = [];
        for (let uri of redirect_uris) {
            try {
                OAuthClientManager.validateUri(uri);
            }
            catch (e) {
                CrossauthLogger.logger.error(j({err: e}));
                redirect_uriErrors.push("["+uri+"]");
            }
        }
        if (redirect_uriErrors.length > 0) {
            throw new CrossauthError(ErrorCode.BadRequest, 
                "The following redirect URIs are invalid: " 
                    + redirect_uriErrors.join(" "));
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
            await this.clientManager.createClient(client_name,
                redirect_uris,
                validFlows,
                confidential,
                user?.id );
        return successFn(reply, client);
    }

    private async updateClient(request : FastifyRequest<{Params: UpdateClientParamType,  Body: UpdateClientBodyType }>, 
        reply : FastifyReply, 
        successFn : (res : FastifyReply, client : OAuthClient, newSecret: boolean) => FastifyReply) {
            
        // throw an error if the CSRF token is invalid
        if (this.sessionServer.isSessionUser(request) && !request.csrfToken) {
            throw new CrossauthError(ErrorCode.InvalidCsrf);
        }

        // throw an error if not logged in
        if (!request.user) {
            throw new CrossauthError(ErrorCode.InsufficientPriviledges);
        }

        const redirect_uris = request.body.redirect_uris.trim().length == 0 ? 
            [] : request.body.redirect_uris.trim().split(/[, ][ \t\n]*/);

        // validate redirect uris
        let redirect_uriErrors : string[] = [];
        for (let uri of redirect_uris) {
            try {
                OAuthClientManager.validateUri(uri);
            }
            catch (e) {
                CrossauthLogger.logger.error(j({err: e}));
                redirect_uriErrors.push("["+uri+"]");
            }
        }
        if (redirect_uriErrors.length > 0) {
            throw new CrossauthError(ErrorCode.BadRequest, 
                "The following redirect URIs are invalid: " 
                    + redirect_uriErrors.join(" "));
        }

        // get flows from booleans in body
        let validFlows = [];
        for (let flow of this.validFlows) {
            if (flow in request.body) validFlows.push(flow);
        }

        const clientUpdate : Partial<OAuthClient> = {}
        clientUpdate.client_name = request.body.client_name;
        clientUpdate.confidential = request.body.confidential == "true";
        clientUpdate.valid_flow = validFlows;
        clientUpdate.redirect_uri = redirect_uris;
        clientUpdate.userid = request.user.id;
        const resetSecret = request.body.resetSecret == "true";
        
        const {client, newSecret} = 
            await this.clientManager.updateClient(request.params.client_id,
                clientUpdate,
                resetSecret);
        return successFn(reply, client, newSecret);
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

        const client = await this.clientStorage.getClientById(request.params.client_id);
        if (client.userid != user.id) {
            throw new CrossauthError(ErrorCode.InsufficientPriviledges,
                "You may not delete this client");
        }
        
        await this.clientStorage.deleteClient(request.params.client_id);
        return successFn(reply);
    }
}
