// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { type FastifyRequest, type FastifyReply, type FastifyInstance } from 'fastify';
import { Server, IncomingMessage, ServerResponse } from 'http'
import {
    CrossauthError,
    CrossauthLogger,
    j,
    ErrorCode,
    type User } from '@crossauth/common';
import {
    setParameter,
    ParamType,
    OAuthResourceServer,
    UserStorage } from '@crossauth/backend';
import type { OAuthResourceServerOptions } from '@crossauth/backend';
import { OAuthTokenConsumer } from '@crossauth/backend';
import { FastifySessionAdapter } from './fastifysessionadapter';

/**
 * Options for {@link FastifyOAuthResourceServer}
 */
export interface FastifyOAuthResourceServerOptions extends OAuthResourceServerOptions {

    /** If you set this and your access tokens have a user (`sub` claim), 
     * the `user` field in the request will be populated with a valid
     * access token,
     */
    userStorage? : UserStorage;

    /**
     * If you enabled `protectedEndpoints` in 
     * {@link FastifyOAuthResourceServer.constructor}
     * and the access token is invalid, a 401 reply will be sent before
     * your endpoint is hit.  This will be the body,  Default {}.
     */
    errorBody? : {[key:string]:any};

    /**
     * If you define this, matching resource server endpoints will return
     * a status code of 401 Access Denied if the key is invalid or the 
     * given scopes are not present.
     */
    protectedEndpoints? : {[key:string]: {scope? : string[], acceptSessionAuthorization?: boolean, suburls? : boolean}},

    /**
     * Where access tokens may be found (in this order).
     * 
     * If this contains `session`, must also provide the session adapter
     * 
     * Default `header`
     */
    tokenLocations? : ("beader"|"session")[]

    /**
     * If tokenLocations contains `session`, tokens are keyed on this name.
     * 
     * Default `oauth` 
     */
    sessionDataName? : string

    /**
     * If `tokenLocations` contains `session`, must provide a session adapter
     */
    sessionAdapter? : FastifySessionAdapter;
}

/**
 * OAuth resource server. 
 * 
 * You can subclass this, simply instantiate it, or create it through
 * {@link FastifyServer}.  
 * 
 * There are two way of using this class.  If you don't set
 * `protectedEndpoints` in 
 * {@link FastifyOAuthResourceServer.constructor}, then in your
 * protected endpoints, call {@link FastifyOAuthResourceServer.authorized}
 * to check if the access token is valid and get any user credentials.
 * 
 * If you do set `protectedEndpoints` in 
 * {@link FastifyOAuthResourceServer.constructor}
 * then a `preHandler` is created.
 * 
 * **Middleware**
 * 
 * The preHandler
 * hook will set the `accessTokenPayload`, `user` and `scope` fields 
 * on the Fastify request object based on the content
 * of the access token in the `Authorization` header if it is valid.
 * If a user storage is provided,
 * it will be used to look the user up.  Otherwise a minimal user object
 * is created.
 * If it is not valid it will set the `authError` and `authErrorDescription`.
 * If the access token is invalid, or there is an error, a 401 or 500
 * response is sent before executing your endpoint code.  As per
 * OAuth requirements, if the response is a 401, the WWW-Authenticate header
 * is set.  If a scope is required this is included in that header.
 */
export class FastifyOAuthResourceServer extends OAuthResourceServer {

    private userStorage? : UserStorage;
    private protectedEndpoints : {[key:string]: {scope? : string[], acceptSessionAuthorization?: boolean, suburls? : boolean}} = {};
    private protectedEndpointPrefixes : string[] = [];
    private errorBody : {[key:string]:any} = {};

    private sessionDataName : string = "oauth";
    private tokenLocations : ("header"|"session")[] = ["header"];
    private sessionAdapter? : FastifySessionAdapter;

    /**
     * Constructor
     * @param app the Fastify app
     * @param tokenConsumers the token consumers, one per issuer and audience
     * @param options See {@link FastifyOAuthResourceServerOptions}
     */
    constructor(
        app: FastifyInstance<Server, IncomingMessage, ServerResponse>, 
        tokenConsumers: OAuthTokenConsumer[],
        options : FastifyOAuthResourceServerOptions = {}) {
        super(tokenConsumers, options);

        setParameter("errorBody", ParamType.Json, this, options, "OAUTH_RESSERVER_ACCESS_DENIED_BODY");
        setParameter("tokenLocations", ParamType.JsonArray, this, options, "OAUTH_TOKEN_LOCATIONS");
        setParameter("sessionDataName", ParamType.String, this, options, "OAUTH_SESSION_DATA_NAME");
        this.userStorage = options.userStorage;
        this.sessionAdapter = options.sessionAdapter;

        if (options.protectedEndpoints) {
            const regex = /^[!#\$%&'\(\)\*\+,\.\/a-zA-Z\[\]\^_`-]+/;
            for (const [key, value] of Object.entries(options.protectedEndpoints)) {
                if (!key.startsWith("/")) {
                    throw new CrossauthError(ErrorCode.Configuration, "protected endpoints must be absolute paths without the protocol and hostname");
                }
                if (value.scope) {
                    value.scope.forEach((s : string) => {
                        if (!(regex.test(s))) throw new CrossauthError(ErrorCode.Configuration, "Illegal characters in scope " + s);
                    });
                }
            }
            this.protectedEndpoints = {...options.protectedEndpoints};

            for (let name in options.protectedEndpoints) {
                let endpoint = this.protectedEndpoints[name];
                if (endpoint.suburls == true) {
                    if (!name.endsWith("/")) {
                        name += "/";
                        this.protectedEndpoints[name] = endpoint;
                    }
                    this.protectedEndpointPrefixes.push(name);
                }
            }
        }
            
        if (options.protectedEndpoints) {
            // validate access token and put in request, along with any errors
            app.addHook('preHandler', async (request : FastifyRequest, reply : FastifyReply) => {
                
                // don't authenticate if user already logged in with a session
                //if (request.user && request.authType == "cookie") return;

                const urlWithoutQuery = request.url.split("?", 2)[0];
                let matches = false;
                let matchingEndpoint = "";
                if (urlWithoutQuery in this.protectedEndpoints) {
                    matches = true;
                    matchingEndpoint = urlWithoutQuery;
                } else {
                    for (let name of this.protectedEndpointPrefixes) {
                        if (urlWithoutQuery.startsWith(name))
                            matches = true;
                            matchingEndpoint = name;
                    }    
                }
                if (!matches) return;

                const authResponse = await this.authorized(request);

                // If we are also we are not allowing authentication by
                // and the user is valid, session cookie for this endpoint
                if (!(request.user && request.authType == "cookie" 
                    && this.protectedEndpoints[matchingEndpoint].acceptSessionAuthorization!=true )) {
                    if (!authResponse) {
                        request.authError = "access_denied"
                        request.authErrorDescription = "No access token";
                        const authenticateHeader = this.authenticateHeader(request);
                        return reply.header('WWW-Authenticate', authenticateHeader).status(401).send(this.errorBody);
                    }
                    if (!authResponse.authorized) {
                        const authenticateHeader = this.authenticateHeader(request);
                        return reply.header('WWW-Authenticate', authenticateHeader).status(401).send(this.errorBody);
                    }
                }

                if (authResponse) {
                    // we have a valid token - set the user from it
                    request.accessTokenPayload = authResponse.tokenPayload;
                    request.user = authResponse.user;
                    if (authResponse.tokenPayload?.scope) {
                        if (Array.isArray(authResponse.tokenPayload.scope)) {
                            let scope : string[] = [];
                            for (let tokenScope of authResponse.tokenPayload.scope) {
                                if (typeof tokenScope == "string") {
                                    scope.push(tokenScope);
                                }
                            }
                            request.scope = scope;
                        } else if (typeof authResponse.tokenPayload.scope == "string") {
                            request.scope = authResponse.tokenPayload.scope.split(" ");
                        }
                    }
                    if (this.protectedEndpoints[matchingEndpoint].scope) {
                        for (let scope of this.protectedEndpoints[matchingEndpoint].scope??[]) {
                            if (!request.scope || !(request.scope.includes(scope))
                                && this.protectedEndpoints[matchingEndpoint].acceptSessionAuthorization!=true) {
                                CrossauthLogger.logger.warn(j({msg: "Access token does not have sufficient scope",
                                    username: request.user?.username, url: request.url}));
                                request.scope = undefined;
                                request.accessTokenPayload = undefined;
                                request.user = undefined;
                                request.authError = "access_denied"
                                request.authErrorDescription = "Access token does not have sufficient scope";
                                return reply.status(401).send(this.errorBody);;
                            }
                        }
                    }

                    request.authType = "oauth";
                    request.authError = authResponse?.error
                    if (authResponse?.error == "access_denied") {
                        const authenticateHeader = this.authenticateHeader(request);
                        return reply.header('WWW-Authenticate', authenticateHeader).status(401).send(this.errorBody);
                    } else if (authResponse?.error) {
                        return reply.status(500).send(this.errorBody);
                    } 
                    request.authErrorDescription = authResponse?.error_description;
                    CrossauthLogger.logger.debug(j({msg: "Resource server url", url: request.url, authorized: request.accessTokenPayload!= undefined}));
                }
            });
        }
        
    }

    private authenticateHeader(request : FastifyRequest) : string {
        const urlWithoutQuery = request.url.split("?", 2)[0];
        if (urlWithoutQuery in this.protectedEndpoints) {
            let header = "Bearer";
            if (this.protectedEndpoints[urlWithoutQuery].scope) {
                header += ' scope="' + (this.protectedEndpoints[urlWithoutQuery].scope??[]).join(" ");
            }
            return header;
        }
        return "";
    }


    /**
     * If there is no bearer token, returns `undefinerd`.  If there is a
     * bearer token and it is a valid access token, returns the token
     * payload.  If there was an error, returns it in OAuth form.
     * @param request the Fastify request
     * @returns an objuect with the following fiekds
     *   - `authorized` : `true` or `false`
     *   - `tokenPayload` : the token payload if the token is valid
     *   - `error` : if the token is not valid
     *   - `error_description` : if the token is not valid
     */
    async authorized(request : FastifyRequest) : Promise<{
        authorized: boolean, 
        tokenPayload?: {[key:string]: any}, 
        user? : User,
        error? : string, 
        error_description?: string}|undefined> {
        try {
            let payload : {[key:string]: any}|undefined = undefined;
            for (let loc of this.tokenLocations) {
                if (loc == "header") {
                    const resp = await this.tokenFromHeader(request);
                    if (resp) {
                        payload = resp;
                        break;
                    }
                } else {
                    const resp = await this.tokenFromSession(request);
                    if (resp) {
                        payload = resp;
                        break;
                    }
                }
            }
            let user : User|undefined = undefined;
            if (payload) {
                if (payload.sub && this.userStorage) {
                    const userResp =
                        await this.userStorage.getUserByUsername(payload.sub);
                    if (userResp) user = userResp.user;
                    request.user = user;
                } else if (payload.sub) {
                    request.user = {
                        id: payload.userid ?? payload.sub,
                        username: payload.sub,
                        state: payload.state ?? "active"

                    }
                }
                return {authorized: true, tokenPayload: payload, user: user};
            } else {
                return {authorized: false};
            }
            
        } catch (e) {
            const ce = e as CrossauthError;
            CrossauthLogger.logger.debug(j({err: e}));
            CrossauthLogger.logger.error(j({cerr: ce}));
            return {authorized: false, error: "server_error", error_description: ce.message};
        }
        return undefined;
    }

    private async tokenFromHeader(request : FastifyRequest) : Promise<{[key:string]: any}|undefined> {
        const header = request.headers.authorization;
        if (header && header.startsWith("Bearer ")) {
            const parts = header.split(" ");
            if (parts.length == 2) {
                return await this.accessTokenAuthorized(parts[1]);
            }
        }    
        return undefined;
    }

    private async tokenFromSession(request : FastifyRequest) : Promise<{[key:string]: any}|undefined> {
        if (!this.sessionAdapter) throw new CrossauthError(ErrorCode.Configuration, 
            "Cannot get session data if sessions not enabled");
        const oauthData =  await this.sessionAdapter.getSessionData(request, this.sessionDataName);
        if (oauthData?.session_token) {
            if (oauthData.expires_at && oauthData.expires_at < Date.now()) return undefined;
            return await this.accessTokenAuthorized(oauthData.session_token);
        }
        return undefined;
    }
}
