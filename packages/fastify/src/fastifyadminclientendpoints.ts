import { FastifyAdminEndpoints } from './fastifyadminendpoints';
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

import type { FastifySessionServerOptions,
    CsrfBodyType } from './fastifysession';
import {
    setParameter,
    ParamType,
    OAuthClientManager,
    OAuthClientStorage } from '@crossauth/backend';

/**
 * The `selectclient` and `admin/selectclient` endpoints have a customisable
 * function for searching for a client.  This is the default 
 * @param searchTerm the search term passed in the query string
 * @param clientStorage the client storage to search
 * @param userid the user id to se3arch for, or null for clients not owned
 *        by a user
 * @returns An array of matching {@link @crossauth/common!OAuthClient} objects,
 */
export async function defaultClientSearchFn(searchTerm: string,
    clientStorage: OAuthClientStorage, userid? : string|number|null) : Promise<OAuthClient[]> {
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
                await clientStorage.getClientByName(searchTerm, userid);
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

/**
 * The query type for Fastify selectclient requests,
 */
export interface SelectClientQueryType {
    userid? : string|number,
    next? : string,
    search? : string,
    user? : string|number,
    skip? : number,
    take? : number,
    haveNext? : boolean,
    havePrevious? : boolean,
}

/**
 * The query type for Fastify createclient requests,
 */
export interface CreateClientQueryType {
    next? : string;
    userid? : string|number,
}

/**
 * The body type for Fastify selectclient requests,
 */
export interface CreateClientBodyType extends CsrfBodyType {
    client_name : string,
    confidential? : string,
    userid? : string|number|null,
    redirect_uris : string,
    authorizationCode? : string,
    authorizationCodeWithPKCE? : string,
    clientCredentials? : string,
    refreshToken? : string,
    deviceCode? : string,
    password? : string,
    passwordMfa? : string,
    oidcAuthorizationCode? : string,
    next? : string,
}

/**
 * The query type for Fastify updateclient requests,
 */
export interface UpdateClientQueryType {
    next? : string;
}

/**
 * The body type for Fastify updateclient requests,
 */
export interface UpdateClientBodyType extends CsrfBodyType {
    client_name : string,
    confidential? : string,
    userid? : string|number|null,
    redirect_uris : string,
    authorizationCode? : string,
    authorizationCodeWithPKCE? : string,
    clientCredentials? : string,
    refreshToken? : string,
    deviceCode? : string,
    password? : string,
    passwordMfa? : string,
    oidcAuthorizationCode? : string,
    next? : string,
    resetSecret? : string,
}

/**
 * The param type for Fastify deleteclient requests,
 */
export interface DeleteClientParamType {
    client_id : string
}

/**
 * The param type for Fastify updateclient requests,
 */
export interface UpdateClientParamType {
    client_id : string
}

/**
 * The query type for Fastify deleteclient requests,
 */
export interface DeleteClientQueryType {
    next? : string
}

const JSONHDR : [string,string] = 
    ['Content-Type', 'application/json; charset=utf-8'];

///////////////////////////////////////////////////////////////////////
// Class

/**
 * This class adds admin endpoints for manipulating OAuth clients.
 * 
 * It is not intended to be instantiated directly.  It is created
 * by {@link FastifySessionServer} if admin endpoints and oauth endpoints
 * are enabled.
 * 
 * For endpoints, see {@link FastifyAdminEndpoints}.
 */
export class FastifyAdminClientEndpoints {
    private sessionServer : FastifySessionServer;
    private clientStorage : OAuthClientStorage;
    private clientManager : OAuthClientManager;
    private adminPrefix = "/admin/";
    private clientSearchFn : 
        (searchTerm : string, clientStorage : OAuthClientStorage, userid? : string|number|null) => Promise<OAuthClient[]> =
        defaultClientSearchFn;
    private validFlows : string[] = ["all"];


    // pages
    private selectClientPage = "selectclient.njk";
    private createClientPage = "createclient.njk";
    private updateClientPage = "updateclient.njk";
    private deleteClientPage = "deleteclient.njk";

    constructor(sessionServer : FastifySessionServer,
        options: FastifySessionServerOptions = {}) {


        this.sessionServer = sessionServer;
        if (!options.clientStorage) throw new CrossauthError(ErrorCode.Configuration,
            "Must specify clientStorage if adding OAuth client endpoints");
        this.clientManager = new OAuthClientManager(options);
        this.clientStorage = options.clientStorage;
        setParameter("adminPrefix", ParamType.String, this, options, "ADMIN_PREFIX");
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
     * Adds the `admin/selectclient` GET endpoint.
     */
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
                const next = request.query.next ?? encodeURIComponent(request.url);
                try {
                    let clients : OAuthClient[] = [];
                    let skip = Number(request.query.skip);
                    let take = Number(request.query.take);
                    if (!skip) skip = 0;
                    if (!take) take = 10;
                    let userid : string|number|null = null;
                    let user : User|undefined = undefined;
                    if (request.query.userid) {
                        if (!this.sessionServer.userStorage) throw new CrossauthError(ErrorCode.Configuration, "Cannot call selectclient with user unless a user storage is provided");
                        const resp =
                            await this.sessionServer.userStorage.getUserById(request.query.userid);
                        user = resp.user;
                        userid = user.id;
                    }
                    if (request.query.search) {
                        clients = await this.clientSearchFn(request.query.search, 
                            this.clientStorage, userid)
                    } else {
                        clients = 
                            await this.clientStorage.getClients(skip, 
                                take, userid);
                    }
                    let data: {
                        urlPrefix: string,
                        user? : User,
                        skip: number,
                        take: number,
                        clients: OAuthClient[],
                        haveNext : boolean,
                        havePrevious : boolean,
                        isAdmin : boolean,
                        next : string,
                    } = {
                        urlPrefix: this.adminPrefix,
                        user : user,
                        skip: skip,
                        take: take,
                        clients: clients,
                        havePrevious: skip > 0,
                        haveNext : take != undefined && clients.length == take,
                        isAdmin: true,
                        next : next,
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
     * Adds the `admin/createclient` GET and POST endpoints.
     */
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
                let next = request.query.next;
                if (!next) {
                    if (request.query.userid) next = this.adminPrefix + "selectuser";
                    else next = this.adminPrefix + "selectclient";
                }
                let user : User|undefined = undefined;
                try {
                    if (request.query.userid) {
                        if (!this.sessionServer.userStorage) throw new CrossauthError(ErrorCode.Configuration, "Cannot call createclient unless a user storage is provided");
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
                let data = {
                    urlPrefix: this.adminPrefix,
                    csrfToken: request.csrfToken,
                    validFlows: this.validFlows,
                    flowNames: OAuthFlows.flowNames(this.validFlows),
                    user : user,
                    isAdmin: true,
                    next: next,
                };
            return reply.view(this.createClientPage, data);
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

                let next = request.body.next;
                if (!next) {
                    if (request.body.userid) next = this.adminPrefix + "selectuser";
                    else next = this.adminPrefix + "selectclient";
                }
                let user : User|undefined = undefined;
                try {
                    if (request.body.userid) {
                        if (!this.sessionServer.userStorage) throw new CrossauthError(ErrorCode.Configuration, "Cannot call createclient unless a user storage is provided");
                        let resp = await this.sessionServer.userStorage.getUserById(request.body.userid);
                        user = resp.user;
                    }
                    return await this.createClient(request, reply, 
                    (reply, client) => {
                        return reply.view(this.createClientPage, {
                            message: "Created client",
                            client: client,
                            csrfToken: request.csrfToken,
                            urlPrefix: this.adminPrefix, 
                            validFlows: this.validFlows,
                            flowNames: OAuthFlows.flowNames(this.validFlows),
                            user : user,
                            isAdmin: true,
                            next: next,
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
                        return reply.status(statusCode).view(this.createClientPage, {
                            errorMessage: error.message,
                            errorMessages: error.messages, 
                            errorCode: error.code, 
                            errorCodeName: ErrorCode[error.code], 
                            csrfToken: request.csrfToken,
                            urlPrefix: this.adminPrefix, 
                            validFlows: this.validFlows,
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
     * Adds the `admin/updateclient` GET and POST endpoints.
     */
    addUpdateClientEndpoints() {

        this.sessionServer.app.get(this.adminPrefix+'updateclient/:client_id', 
            async (request: FastifyRequest<{Params: UpdateClientParamType, Querystring: CreateClientQueryType }>,
                reply: FastifyReply)  => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'GET',
                    url: this.adminPrefix + 'updateclient',
                    ip: request.ip
                }));
                if (!request?.user || !FastifyServer.isAdmin(request.user)) {
                    return this.accessDeniedPage(request, reply);                    
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
                    if (request.query.userid) next = this.adminPrefix + "selectuser";
                    else next = this.adminPrefix + "selectclient";
                }
                let user : User|undefined = undefined;
                try {
                    if (client.userid) {
                        if (!this.sessionServer.userStorage) throw new CrossauthError(ErrorCode.Configuration, "Cannot call updateclient with user unless a user storage is provided");
                        let resp = await this.sessionServer.userStorage.getUserById(client.userid);
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
                    urlPrefix: this.adminPrefix,
                    csrfToken: request.csrfToken,
                    validFlows: this.validFlows,
                    flowNames: OAuthFlows.flowNames(this.validFlows),
                    selectedFlows: selectedFlows,
                    user : user,
                    client_id: client.client_id,
                    client_name: client.client_name,
                    confidential: client.confidential,
                    redirect_uris: client.redirect_uri.join("\n"),
                    isAdmin: true,
                    next: next,
                };
            return reply.view(this.updateClientPage, data);
        });

        this.sessionServer.app.post(this.adminPrefix+'updateclient/:client_id', 
            async (request: FastifyRequest<{Params: UpdateClientParamType, Body: UpdateClientBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.adminPrefix + 'updateclient',
                    ip: request.ip,
                    user: request.user?.username
                }));

                let next = request.body.next;
                if (!next) {
                    if (request.body.userid) next = this.adminPrefix + "selectuser";
                    else next = this.adminPrefix + "selectclient";
                }
                let user : User|undefined = undefined;
                try {
                    if (request.body.userid) {
                        if (!this.sessionServer.userStorage) throw new CrossauthError(ErrorCode.Configuration, "Cannot call updateclient with user unless a user storage is provided");
                        let resp = await this.sessionServer.userStorage.getUserById(request.body.userid);
                        user = resp.user;
                    }
                    return await this.updateClient(request, reply, 
                    (reply, client, newSecret) => {
                        return reply.view(this.updateClientPage, {
                            message: "Updated client",
                            client: client,
                            csrfToken: request.csrfToken,
                            urlPrefix: this.adminPrefix, 
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
                            urlPrefix: this.adminPrefix, 
                            isAdmin: true,
                            next: next,
                            validFlows : this.validFlows,
                            selectedFlows : selectedFlows,
                            flowNames: OAuthFlows.flowNames(this.validFlows),
                            ...request.body,
                        });
                        
                    });
                }
        });

    }

    /**
     * Adds the `admin/deleteclient` GET and POST endpoints.
     */
    addDeleteClientEndpoints() {

        this.sessionServer.app.get(this.adminPrefix+'deleteclient/:client_id', 
            async (request: FastifyRequest<{ Params: DeleteClientParamType, Querystring: DeleteClientQueryType }>,
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
                const next = request.query.next ?? this.adminPrefix + "selectclient";
                let data = {
                    urlPrefix: this.adminPrefix,
                    csrfToken: request.csrfToken,
                    next: next,
                    client : client,
                };
            return reply.view(this.deleteClientPage, data);
        });

        this.sessionServer.app.post(this.adminPrefix+'deleteclient/:client_id', 
            async (request: FastifyRequest<{ Params: DeleteClientParamType, Body: DeleteClientQueryType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.adminPrefix + 'deleteclient',
                    ip: request.ip,
                    user: request.user?.username
                }));

                const next = request.body.next ?? this.adminPrefix + "selectclient";
                try {
                    return await this.deleteClient(request, reply, 
                    (reply) => {
                        return reply.view(this.deleteClientPage, {
                            message: "Client deleted",
                            csrfToken: request.csrfToken,
                            urlPrefix: this.adminPrefix, 
                            validFlows: this.validFlows,
                            client_id : request.params.client_id,
                            next: next,
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
                            urlPrefix: this.adminPrefix, 
                            client_id : request.params.client_id,
                            validFlows: this.validFlows,
                            next: next,
                        });
                        
                    });
                }
        });

    }

    /**
     * Adds the `admin/api/createclient` POST endpoint.
     */
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
                if (request.body.userid) {
                    if (!this.sessionServer.userStorage) throw new CrossauthError(ErrorCode.Configuration, "Cannot call createclient with user unless a user storage is provided");
                    let resp = await this.sessionServer.userStorage.getUserById(request.body.userid);
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
    }

    /**
     * Adds the `admin/api/updateclient` POST endpoint.
     */
    addApiUpdateClientEndpoints() {

        this.sessionServer.app.post(this.adminPrefix+'api/updateclient/:client_id', 
            async (request: FastifyRequest<{Params: UpdateClientParamType, Body: UpdateClientBodyType }>,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.adminPrefix + 'api/updateclient',
                    ip: request.ip,
                    user: request.user?.username
                }));

                try {
                    if (request.body.userid) {
                        if (!this.sessionServer.userStorage) throw new CrossauthError(ErrorCode.Configuration, "Cannot call updateclient with user unless a user storage is provided");
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
     * Adds the `admin/api/deleteclient` POST endpoint.
     */
    addApiDeleteClientEndpoints() {

        this.sessionServer.app.post(this.adminPrefix+'api/deleteclient/:client_id', 
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
                        client_id : request.params.client_id,
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
        const client_name = request.body.client_name;
        const redirect_uris = request.body.redirect_uris.trim().length == 0 ? 
            [] : request.body.redirect_uris.trim().split(/,?[ \t\n]+/);

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
        /*let validFlows = [];
        if (request.body[OAuthFlows.AuthorizationCode]) validFlows.push(OAuthFlows.AuthorizationCode);
        if (request.body[OAuthFlows.AuthorizationCodeWithPKCE]) validFlows.push(OAuthFlows.AuthorizationCodeWithPKCE);
        if (request.body[OAuthFlows.ClientCredentials]) validFlows.push(OAuthFlows.ClientCredentials);
        if (request.body[OAuthFlows.RefreshToken]) validFlows.push(OAuthFlows.RefreshToken);
        if (request.body[OAuthFlows.DeviceCode]) validFlows.push(OAuthFlows.DeviceCode);
        if (request.body[OAuthFlows.Password]) validFlows.push(OAuthFlows.Password);
        if (request.body[OAuthFlows.PasswordMfa]) validFlows.push(OAuthFlows.PasswordMfa);
        if (request.body[OAuthFlows.OidcAuthorizationCode]) validFlows.push(OAuthFlows.OidcAuthorizationCode);*/
        // get flows from booleans in body
        let validFlows = [];
        for (let flow of this.validFlows) {
            if (flow in request.body)
                validFlows.push(flow);
            }
        

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

        // throw an error if not an admin user
        if (!request.user || !FastifyServer.isAdmin(request.user)) {
            throw new CrossauthError(ErrorCode.InsufficientPriviledges);
        }

        const redirect_uris = request.body.redirect_uris.trim().length == 0 ? 
            [] : request.body.redirect_uris.trim().split(/,?[ \t\n]+/);

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
        clientUpdate.userid = request.body.userid;
        if (clientUpdate.userid == undefined) clientUpdate.userid = null;
        const resetSecret = request.body.resetSecret == "true";
        
        const {client, newSecret} = 
            await this.clientManager.updateClient(request.params.client_id,
                clientUpdate,
                resetSecret);
        return successFn(reply, client, newSecret);
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

        await this.clientStorage.deleteClient(request.params.client_id);
        return successFn(reply);
    }
}

