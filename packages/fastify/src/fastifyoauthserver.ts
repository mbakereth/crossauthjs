// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import {
    type FastifyInstance,
    type FastifyRequest,
    type FastifyReply } from 'fastify';
import { Server, IncomingMessage, ServerResponse } from 'http'
import {
    OAuthClientStorage,
    KeyStorage,
    OAuthAuthorizationServer,
    setParameter,
    ParamType,
    Authenticator,
    Crypto, 
    OAuthClientManager,
    DoubleSubmitCsrfToken } from '@crossauth/backend';
import type {
    OAuthAuthorizationServerOptions,
    DoubleSubmitCsrfTokenOptions,
    Cookie } from '@crossauth/backend';
import {
    CrossauthError,
    CrossauthLogger,
    type OpenIdConfiguration,
    j,
    OAuthFlows,
    ErrorCode,
    type MfaAuthenticatorResponse,
    type User } from '@crossauth/common';
import { FastifyServer, ERROR_500, DEFAULT_ERROR } from './fastifyserver';

export interface DevicePageData {
    authorizationNeeded?: {
        user: User,
        client_id : string,
        client_name : string,
        scope?: string,
        scopes?: string[],
        csrfToken?: string,
    },
    completed: boolean,
    retryAllowed: boolean,
    user?: User,
    csrfToken? : string,
    ok: boolean,
    error? : string,
    error_description? : string,
    user_code?: string,
};

const JSONHDR : [string,string] = ['Content-Type', 'application/json; charset=utf-8'];

//////////////////////////////////////////////////////////////////////////////
// OPTIONS

/**
 * Options for {@link FastifyAuthorizationServer}
 */
export interface FastifyAuthorizationServerOptions 
    extends OAuthAuthorizationServerOptions {

    /**
     * Template file to display on error.  It receives the following parameters;
     *   - `httpStatus`,
     *   - `errorCode`,
     *   - `errorCodeName`
     *   - `errorMessage`
     * Default `error.njk`
     */
    errorPage? : string,

    /**
     * Template file for the device endpoint.  It receives the following parameters;
     *   - `httpStatus`,
     *   - `errorCode`,
     *   - `errorCodeName`
     *   - `errorMessage`
     *   - `ok`
     *   - `authorizationNeeded`
     *      - `client_id`
     *      - `client_name`
     *      - `scope`
     *      - `scopes`
     *      - `user`
     *   - `user_code`
     *   - `retryAlllowed`
     *   - `csrfToken`
     * Default `device.njk`
     */
    devicePage? : string,

    /**
     * Template file for page asking user to authorize a client.
     * It receives the following parameters;
     *   - `user`
     *   - `response_type`
     *   - `client_id`
     *   - `client_name`
     *   - `redirect_uri`
     *   - `scope`
     *   - `scopes`
     *   - `state`
     *   - `code_challenge`
     *   - `code_challenge_method`
     *   - `csrfToken`
     * Default `userauthorize.njk`
     */
    oauthAuthorizePage? : string,

    /**
     * Prefix for URLs.  Default `/`
     */
    prefix? : string,

    /**
     * The login URL (provided by {@link FastifySessionServer}). Default `/login`
     */
    loginUrl? : string,

    /**
     * How to send the refresh token.
     *   - `json` sent in the JSON response as per the OAuth specification
     *   - `cookie` sent as a cookie called `refreshTokenCookieName`.
     *   - `both` both of the above
     * Default `json`
     */
    refreshTokenType? : "json" | "cookie" | "both",

    /**
     * If `refreshTokenType` is `cookie` or `both`, this will be the cookie
     * name.  Default `CROSSAUTH_REFRESH_TOKEN`
     */
    refreshTokenCookieName? : string,

    /**
     * Domain to set when sending a refresh token cookie.
     * Only used if `refreshTokenType` is not `json`
     */
    refreshTokenCookieDomain? : string | undefined;

    /**
     * Whether to set `httpOnly` when sending a refresh token cookie.
     * Only used if `refreshTokenType` is not `json`
     */
    refreshTokenCookieHttpOnly? : boolean;

    /**
     * Path to set when sending a refresh token cookie.
     * Only used if `refreshTokenType` is not `json`
     */
    refreshTokenCookiePath? : string;

    /**
     * Whether to set the `secure` flag when sending a refresh token cookie.
     * Only used if `refreshTokenType` is not `json`
     */
    refreshTokenCookieSecure? : boolean;

    /**
     * SameSite value to set when sending a refresh token cookie.
     * Only used if `refreshTokenType` is not `json`
     */
    refreshTokenCookieSameSite? : boolean | "lax" | "strict" | "none" | undefined;

    /** If true, create a `getcsrftoken` endpoint.
     * You will only need to do this is you don't have session management
     * enabled on your server, which provides an identical  `api/getcsrftoken`,
     * and if `refreshTokenType` is not `json`.
     * Default `false`
     */
    createGetCsrfTokenEndpoint? : false,

    /** options for csrf cookie manager */
    doubleSubmitCookieOptions? : DoubleSubmitCsrfTokenOptions,
}

//////////////////////////////////////////////////////////////////////////////
// FASTIFY INTERFACES

/**
 * Query parameters for the `authorize` Fastify request.
 */
export interface AuthorizeQueryType {
    response_type : string,
    client_id : string,
    redirect_uri : string,
    scope? : string,
    state: string,
    code_challenge? : string,
    code_challenge_method : string,
}

/**
 * Body parameters for the `userauthorize` endpoint 
 * Fastify request requesting the user
 * to authorize a client.
 */
export interface UserAuthorizeBodyType {
    csrfToken : string,
    response_type : string,
    client_id : string,
    redirect_uri : string,
    scope? : string,
    state: string,
    code_challenge? : string,
    code_challenge_method : string,
    authorized : string, // true or false 
}

/**
 * The body parameters for the `token` endpoint.  
 */
interface TokenBodyType {
    grant_type : string,
    client_id : string,
    client_secret?: string,
    redirect_uri : string,
    scope? : string,
    state?: string,
    code? : string,
    code_verifier? : string,
    username? : string,
    password? : string,
    mfa_token? : string,
    oob_code? : string,
    binding_code? : string,
    otp? : string,
    refresh_token? : string,
    device_code? : string,
}

/**
 * The body parameters for the `mfa/challenge` endpoint.  
 */
export interface MfaChallengeBodyType {
    client_id : string,
    client_secret?: string,
    challenge_type: string,
    mfa_token : string,
    authenticator_id : string,
}

/**
 * Query parameters for the `device` Fastify request.
 */
export interface DeviceQueryType {
    user_code? : string,
}

/**
 * The body for the `device` Fastify request.
 */
export interface DeviceBodyType {
    authorized : string, // true or false or blank if not a scope authorization response
    user_code : string,
    client_id : string,
    scope? : string,
}

/**
 * The body for the `device_authorization` Fastify request.
 */
export interface DeviceAuthorizationBodyType {
    client_id : string,
    client_secret?: string,
    scope? : string,
}

///////////////////////////////////////////////////////////////////////////////
// CLASS

/**
 * This class implements an OAuth authorization server, serving endpoints
 * with Fastify.
 * 
 * You shouldn't have to instantiate this directly.  It is instantiated
 * by {@link FastifyServer} if you enable the authorization server there.
 * 
 * | METHOD | ENDPOINT                   | GET/BODY PARAMS                                                                   | RESPONSE/TEMPLATE FILE                             |
 * | ------ | -------------------------- | --------------------------------------------------------------------------------- | -------------------------------------------------- |
 * | GET    | `authorize`                | See OAuth spec                                                                    | See OAuth spec                                     |
 * | GET    | `userauthorize`            | See {@link UserAuthorizeBodyType}                                                 | oauthAuthorizePage                                 |
 * | GET    | `csrftoken`                |                                                                                   | ok, csrfToken (and Set-Cookie)                     |
 * | POST   | `token`                    | See OAuth spec                                                                    | See OAuth spec                                     |
 * | GET    | `mfa/authenticators`       | See {@link https://auth0.com/docs/api/authentication#multi-factor-authentication} | See link to the left                               |
 * | POST   | `mfa/authenticators`       | See {@link https://auth0.com/docs/api/authentication#multi-factor-authentication} | See link to the left                               |
 * | POST   | `mfa/challenge`            | See {@link https://auth0.com/docs/api/authentication#multi-factor-authentication} | See link to the left                               |
 * | POST   | `device_authorization`     | See {@link https://datatracker.ietf.org/doc/html/rfc8628}                         | See link to the left                               |
 * | GET    | `device`                   | `user_code` (optional).                                                           | `devicePage`                                       |
 * | POST   | `device`                   | See {@link DeviceBodyType}.                                                       | `devicePage`                                       |
 * 
 */
export class FastifyAuthorizationServer {

    /** The Fastify app passed to the constructor */
    readonly app : FastifyInstance<Server, IncomingMessage, ServerResponse>;
    /** The underlying framework-independent authorization server */
    readonly authServer : OAuthAuthorizationServer;
    private fastifyServer : FastifyServer;
    private prefix : string = "/";
    private loginUrl : string = "/login";
    private oauthAuthorizePage : string = "userauthorize.njk";
    private errorPage : string = "error.njk";
    private devicePage : string = "device.njk";
    private clientStorage : OAuthClientStorage;

    // Refresh token cookie functionality
    private refreshTokenType : "json"|"cookie"|"both" = "json";
    private refreshTokenCookieName : string = "CROSSAUTH_REFRESH_TOKEN";
    private refreshTokenCookieDomain : string | undefined = undefined;
    private refreshTokenCookieHttpOnly : boolean = false;
    private refreshTokenCookiePath : string = "/";
    private refreshTokenCookieSecure : boolean = true;
    private refreshTokenCookieSameSite : boolean | "lax" | "strict" | "none" | undefined = "strict";

    private csrfTokens : DoubleSubmitCsrfToken | undefined;
    private createGetCsrfTokenEndpoint = false;

    /**
     * Constructor
     * @param app the Fastify app
     * @param fastifyServer the Fastify server this belongs to
     * @param clientStorage where OAuth clients are stored
     * @param keyStorage where refresh tokens, authorization cods, etc are temporarily stored
     * @param authenticators The authenticators (factor1 and factor2) to enable 
     *        for the password flow
     * @param options see {@link FastifyAuthorizationServerOptions}
     */
    constructor(
        app: FastifyInstance<Server, IncomingMessage, ServerResponse>,
        fastifyServer : FastifyServer,
        clientStorage : OAuthClientStorage, 
        keyStorage : KeyStorage,
        authenticators? : {[key:string]: Authenticator},
        options : FastifyAuthorizationServerOptions = {}) {

        this.app = app;
        this.fastifyServer = fastifyServer;
        this.clientStorage = clientStorage;

        this.authServer =
            new OAuthAuthorizationServer(this.clientStorage,
                keyStorage,
                authenticators,
                options);

        setParameter("prefix", ParamType.String, this, options, "PREFIX");
        if (!(this.prefix.endsWith("/"))) this.prefix += "/";
        setParameter("errorPage", ParamType.String, this, options, "ERROR_PAGE");
        setParameter("devicePage", ParamType.String, this, options, "OAUTH_DEVICE_PAGE");
        setParameter("loginUrl", ParamType.String, this, options, "LOGIN_URL");
        setParameter("oauthAuthorizePage", ParamType.String, this, options, "OAUTH_AUTHORIZE_PAGE");
        setParameter("refreshTokenType", ParamType.String, this, options, "OAUTH_REFRESH_TOKEN_TYPE");
        setParameter("refreshTokenCookieName", ParamType.String, this, options, "OAUTH_REFRESH_TOKEN_COOKIE_NAME");
        setParameter("refreshTokenCookieDomain", ParamType.String, this, options, "OAUTH_REFRESH_TOKEN_COOKIE_DOMAIN");
        setParameter("refreshTokenCookieHttpOnly", ParamType.Boolean, this, options, "OAUTH_REFRESH_TOKEN_COOKIE_HTTPONLY");
        setParameter("refreshTokenCookiePath", ParamType.String, this, options, "OAUTH_REFRESH_TOKEN_COOKIE_PATH");
        setParameter("refreshTokenCookieSecure", ParamType.Boolean, this, options, "OAUTH_REFRESH_TOKEN_COOKIE_SECURE");
        setParameter("refreshTokenCookieSameSite", ParamType.String, this, options, "OAUTH_REFRESH_TOKEN_COOKIE_SAMESITE");
        setParameter("createGetCsrfTokenEndpoint", ParamType.String, this, options, "OAUTH_CREATE_GET_CSRF_TOKEN_ENDPOINT");

        if (this.refreshTokenType != "json") {
            if (this.createGetCsrfTokenEndpoint) {
                this.csrfTokens = new DoubleSubmitCsrfToken(options.doubleSubmitCookieOptions);
            } else if (this.fastifyServer.sessionServer) {
                this.csrfTokens = this.fastifyServer.sessionServer.sessionManager.csrfTokens;
            }
        }
        if (this.createGetCsrfTokenEndpoint) {
            this.addApiGetCsrfTokenEndpoints();
        }
        app.get(this.prefix+'.well-known/openid-configuration', 
            async (_request : FastifyRequest, reply : FastifyReply) =>  {
            return reply.header(...JSONHDR).status(200).send(
                this.authServer.oidcConfiguration({
                    authorizeEndpoint: this.prefix+"authorize", 
                    tokenEndpoint: this.prefix+"token", 
                    jwksUri: this.prefix+"jwks", 
                    additionalClaims: []}));
        });

        app.get(this.prefix+'jwks', 
            async (_request : FastifyRequest, reply : FastifyReply) =>  {
            return reply.header(...JSONHDR).status(200).send(
                this.authServer.jwks());
        });

        if (this.authServer.validFlows.includes(OAuthFlows.AuthorizationCode) || 
            this.authServer.validFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE) ||
            this.authServer.validFlows.includes(OAuthFlows.OidcAuthorizationCode)) {

            app.get(this.prefix+'authorize', async (request : FastifyRequest<{ Querystring: AuthorizeQueryType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "Page visit", method: 'GET', url: this.prefix+'authorize', ip: request.ip, user: request.user?.username}));
                return await this.authorizeEndpoint(request, reply, request.query);
            });

            app.post(this.prefix+'authorize', async (request : FastifyRequest<{ Body: AuthorizeQueryType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'authorize', ip: request.ip, user: request.user?.username}));
                return await this.authorizeEndpoint(request, reply, request.body);
            });


            this.app.post(this.prefix+'userauthorize', 
                async (request: FastifyRequest<{ Body: UserAuthorizeBodyType }>,
                    reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'authorize', ip: request.ip, user: request.user?.username}));

                // this should not be called if a user is not logged in
                    if (!request.user) return FastifyServer.sendPageError(reply,
                        401,
                        this.errorPage);  // not allowed here if not logged in
                let csrfCookie : string|undefined;
                let ce : CrossauthError | undefined;
                try {
                    csrfCookie = await this.fastifyServer.validateCsrfToken(request);
                }
                catch (e) {
                    ce = CrossauthError.asCrossauthError(e);
                    ce.message = "Invalid csrf cookie received";
                    CrossauthLogger.logger.error(j({
                        msg: ce.message,
                        hashedCsrfCookie: csrfCookie ? 
                        Crypto.hash(csrfCookie) : undefined,
                        user: request.user?.username,
                        cerr: ce
                    }));
                }

                if (ce) {
                    if (this.errorPage) {
                        return reply.status(ce.httpStatus).view(this.errorPage, 
                            {
                                status: ce.httpStatus,
                                errorMessage: ce.message,
                                errorCode: ce.code,
                                errorCodeName: ce.codeName
                            });
                    } else {
                        let status : "400" | "401" | "500" = "500";
                        switch (ce.httpStatus) {
                            case 401: status = "401" ; break;
                            case 400: status = "400" ; break;
                        }
                        return reply.status(ce.httpStatus)
                            .send(DEFAULT_ERROR[status]??ERROR_500);
                    }
                }
   
                // Create an authorizatin code
                if (!ce) {
                    const authorized = request.body.authorized == "true";
                    return await this.authorize(request, reply, authorized, {
                        responseType: request.body.response_type,
                        client_id : request.body.client_id,
                        redirect_uri: request.body.redirect_uri,
                        scope: request.body.scope,
                        state: request.body.state,
                        codeChallenge: request.body.code_challenge,
                        codeChallengeMethod: request.body.code_challenge_method,
                    });
                }
            });
        }

        if (this.authServer.validFlows.includes(OAuthFlows.AuthorizationCode) || 
            this.authServer.validFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE) ||
            this.authServer.validFlows.includes(OAuthFlows.OidcAuthorizationCode) ||
            this.authServer.validFlows.includes(OAuthFlows.ClientCredentials) ||
            this.authServer.validFlows.includes(OAuthFlows.RefreshToken) ||
            this.authServer.validFlows.includes(OAuthFlows.Password) ||
            this.authServer.validFlows.includes(OAuthFlows.PasswordMfa) ||
            this.authServer.validFlows.includes(OAuthFlows.DeviceCode)) {

            this.app.post(this.prefix+'token', 
                async (request: FastifyRequest<{ Body: TokenBodyType }>,
                    reply: FastifyReply) => {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + 'token',
                        ip: request.ip,
                        user: request.user?.username
                    }));

                // OAuth spec says we may take client credentials from 
                // authorization header
                let client_id = request.body.client_id;
                let client_secret = request.body.client_secret;
                if (request.headers.authorization) {
                    let client_id1 : string|undefined;
                    let client_secret1 : string|undefined;
                    const parts = request.headers.authorization.split(" ");
                    if (parts.length == 2 &&
                        parts[0].toLocaleLowerCase() == "basic") {
                        const decoded = Crypto.base64Decode(parts[1]);
                        const parts2 = decoded.split(":", 2);
                        if (parts2.length == 2) {
                            client_id1 = parts2[0];
                            client_secret1 = parts2[1];
                        }
                    }
                    if (client_id1 == undefined || client_secret1 == undefined) {
                        CrossauthLogger.logger.warn(j({
                            msg: "Ignoring malform authenization header " + 
                                request.headers.authorization}));
                    } else {
                        client_id = client_id1;
                        client_secret = client_secret1;
                    }
                }

                // if refreshTokenType is not "json", check if there
                // is a refresh token in the cookie.
                // there must also be a valid CSRF token
                let refreshToken = request.body.refresh_token;
                if (((this.refreshTokenType == "cookie" && request.cookies && 
                    this.refreshTokenCookieName in request.cookies) ||
                    (this.refreshTokenType == "both" && request.cookies && 
                    this.refreshTokenCookieName in request.cookies &&
                    refreshToken == undefined)) &&
                    this.csrfTokens /* this part is just for typescript checker */) {  
                    const csrfCookie = request.cookies[this.csrfTokens.cookieName];
                    let csrfHeader = request.headers[this.csrfTokens.headerName.toLowerCase()];
                    if (Array.isArray(csrfHeader)) csrfHeader = csrfHeader[0];
                    if (!csrfCookie || !csrfHeader) {
                        return {
                            error: "access_denied",
                            error_description: "Invalid csrf token",
                        }
                    }
                    try {
                        this.csrfTokens.validateDoubleSubmitCsrfToken(csrfCookie, csrfHeader)
                    } catch (e) {
                        CrossauthLogger.logger.debug(j({err: e}));
                        CrossauthLogger.logger.warn(j({cerr: e, msg: "Invalid csrf token", client_id: request.body.client_id}));
                        return {
                            error: "access_denied",
                            error_description: "Invalid csrf token",
                        }
                    }
                    refreshToken = request.cookies[this.refreshTokenCookieName];
                }
        
                const resp = await this.authServer.tokenEndpoint({
                    grantType: request.body.grant_type,
                    client_id : client_id,
                    client_secret : client_secret,
                    scope: request.body.scope,
                    codeVerifier: request.body.code_verifier,
                    code: request.body.code,
                    username: request.body.username,
                    password: request.body.password,
                    mfaToken: request.body.mfa_token,
                    oobCode: request.body.oob_code,
                    bindingCode: request.body.binding_code,
                    otp: request.body.otp,
                    refreshToken: refreshToken,
                    deviceCode: request.body.device_code,
                });

                // device code flow - still pending - return a JSON instead of error
                if (resp.error == "authorization_pending") {
                    return reply.header(...JSONHDR).status(200).send(resp);
                }

                if (resp.refresh_token && this.refreshTokenType != "json") {
                    this.setRefreshTokenCookie(reply, resp.refresh_token, resp.expires_in);
                }
                if (resp.error || !resp.access_token) {
                    let error = "server_error";
                    let errorDescription = "Neither code nor error received when requesting authorization";
                    if (resp.error) error = resp.error;
                    if (resp.error_description) errorDescription = resp.error_description;
                    const ce = CrossauthError.fromOAuthError(error, errorDescription);
                    CrossauthLogger.logger.error(j({cerr: ce}));
                    return reply.header(...JSONHDR).status(ce.httpStatus).send(resp);
                }
                return reply.header(...JSONHDR).send(resp);
            });
        }

        //// PasswordMfa endpoints

        if (this.authServer.validFlows.includes(OAuthFlows.PasswordMfa)) {

            app.get(this.prefix+'mfa/authenticators', 
                async (request : FastifyRequest, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'GET',
                        url: this.prefix + 'mfa/authenticators',
                        ip: request.ip,
                        user: request.user?.username
                    }));
                return await this.mfaAuthenticatorsEndpoint(request, reply);
            });

            app.post(this.prefix+'mfa/authenticators', 
                async (request : FastifyRequest, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + 'mfa/authenticators',
                        ip: request.ip,
                        user: request.user?.username
                    }));
                return await this.mfaAuthenticatorsEndpoint(request, reply);
            });

            app.post(this.prefix+'mfa/challenge', 
                async (request : FastifyRequest<{ Body: MfaChallengeBodyType }>, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + 'mfa/challenge',
                        ip: request.ip,
                        user: request.user?.username
                    }));
                return await this.mfaChallengeEndpoint(request, reply, request.body);
            });
        }

        ////////
        // Device code flow endpoints

        if (this.authServer.validFlows.includes(OAuthFlows.DeviceCode)) {

            this.app.post(this.prefix+'device_authorization', 
                async (request: FastifyRequest<{ Body: DeviceAuthorizationBodyType }>,
                    reply: FastifyReply) => {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + 'device_authorization',
                        ip: request.ip,
                        user: request.user?.username
                    }));

                // OAuth spec says we may take client credentials from 
                // authorization header
                let client_id = request.body.client_id;
                let client_secret = request.body.client_secret;
                if (request.headers.authorization) {
                    let client_id1 : string|undefined;
                    let client_secret1 : string|undefined;
                    const parts = request.headers.authorization.split(" ");
                    if (parts.length == 2 &&
                        parts[0].toLocaleLowerCase() == "basic") {
                        const decoded = Crypto.base64Decode(parts[1]);
                        const parts2 = decoded.split(":", 2);
                        if (parts2.length == 2) {
                            client_id1 = parts2[0];
                            client_secret1 = parts2[1];
                        }
                    }
                    if (client_id1 == undefined || client_secret1 == undefined) {
                        CrossauthLogger.logger.warn(j({
                            msg: "Ignoring malform authenization header " + 
                                request.headers.authorization}));
                    } else {
                        client_id = client_id1;
                        client_secret = client_secret1;
                    }
                }
        
                const resp = await this.authServer.deviceAuthorizationEndpoint({
                    client_id : client_id,
                    client_secret : client_secret,
                    scope: request.body.scope,
                });

                if (resp.error || !resp.device_code || !resp.user_code) {
                    let error = "server_error";
                    let errorDescription = "Neither code nor error received when requesting authorization";
                    if (resp.error) error = resp.error;
                    if (resp.error_description) errorDescription = resp.error_description;
                    const ce = CrossauthError.fromOAuthError(error, errorDescription);
                    CrossauthLogger.logger.error(j({cerr: ce}));
                    return reply.header(...JSONHDR).status(ce.httpStatus).send(resp);
                }
                
                return reply.header(...JSONHDR).send(resp);
            });

            app.get(this.prefix+'device', 
                async (request : FastifyRequest<{Querystring: DeviceQueryType}>, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'GET',
                        url: this.prefix + 'device',
                        ip: request.ip,
                        user: request.user?.username
                    }));
                    if (!request.user) return reply.redirect(this.loginUrl+"?next="+encodeURIComponent(request.url), 302);

                    return await this.deviceGet(false, request, reply, request.user);
                });

                app.get(this.prefix+'api/device', 
                    async (request : FastifyRequest<{Querystring: DeviceQueryType}>, 
                        reply : FastifyReply) =>  {
                        CrossauthLogger.logger.info(j({
                            msg: "Page visit",
                            method: 'GET',
                            url: this.prefix + 'device',
                            ip: request.ip,
                            user: request.user?.username
                        }));
                        if (!request.user) {
                            const ce = new CrossauthError(ErrorCode.Unauthorized, "Not logged in")
                            return reply.header(...JSONHDR).status(401).send({
                                    errorMessage: ce.message,
                                    errorCode: ce.code,
                                    errorCodeName: ce.codeName
            
                            });
                        }

                        return await this.deviceGet(true, request, reply, request.user);
                    });
    
            this.app.post(this.prefix+'device', 
                async (request: FastifyRequest<{ Body: DeviceBodyType }>,
                    reply: FastifyReply) => {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + 'device',
                        ip: request.ip,
                        user: request.user?.username,
                    }));

                    if (!request.user) return reply.redirect(this.loginUrl+"?next="+encodeURIComponent(request.url), 302);

                    return await this.deviceCodePost(false, request, reply);
            });

            this.app.post(this.prefix+'api/device', 
                async (request: FastifyRequest<{ Body: DeviceBodyType }>,
                    reply: FastifyReply) => {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + 'device',
                        ip: request.ip,
                        user: request.user?.username,
                    }));

                    return await this.deviceCodePost(true, request, reply);
            });

        }

    }

    /**
     * Creates and returns a signed CSRF token based on the session ID
     * @returns a CSRF cookie and value to put in the form or CSRF header
     */
    private async createCsrfToken() : 
        Promise<{csrfCookie : Cookie, csrfFormOrHeaderValue : string}> {
        if (!this.csrfTokens) throw new CrossauthError(ErrorCode.Configuration, "CSRF tokens not enabled");
        this.csrfTokens.makeCsrfCookie(await this.csrfTokens.createCsrfToken());
        const csrfToken = this.csrfTokens.createCsrfToken();
        const csrfFormOrHeaderValue = this.csrfTokens.makeCsrfFormOrHeaderToken(csrfToken);
        const csrfCookie = this.csrfTokens.makeCsrfCookie(csrfToken);
        return {
            csrfCookie,
            csrfFormOrHeaderValue,
        }
    }

    private addApiGetCsrfTokenEndpoints() {
        if (!this.csrfTokens) return ;
        this.app.get(this.prefix+'getcsrftoken', 
            async (request: FastifyRequest,
                reply: FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "API visit",
                    method: 'POST',
                    url: this.prefix + 'getcsrftoken',
                    ip: request.ip,
                    user: request.user?.username
                }));
            if (!this.csrfTokens) return;
            let csrfCookieValue = "";
            try {
                const {csrfCookie,
                    csrfFormOrHeaderValue} = await this.createCsrfToken();
                csrfCookieValue = csrfCookie.value;
                    reply.setCookie(csrfCookie.name, csrfCookie.value, csrfCookie.options);
                return reply.header(...JSONHDR)
                    .send({
                    ok: true,
                    csrfToken: csrfFormOrHeaderValue
                });
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.error(j({
                    msg: "getcsrftoken failure",
                    user: request.user?.username,
                    hashedCsrfCookie: Crypto.hash(csrfCookieValue.split(".")[0]),
                    errorCode: ce.code,
                    errorCodeName: ce.codeName
                }));
                CrossauthLogger.logger.debug(j({err: e}));
                return reply.status(ce.httpStatus).header(...JSONHDR)
                    .send({
                        ok: false,
                        errorCode: ce.code,
                        errorCodeName: ce.codeName,
                        error: ce.message,
                    });

            }
        });
    }

    private async authorizeEndpoint(request: FastifyRequest,
        reply: FastifyReply,
        query: AuthorizeQueryType) {
        if (!request.user) return reply.redirect(this.loginUrl+"?next="+encodeURIComponent(request.url), 302);

        // this just checks they are valid strings and not empty if required, 
        // to avoid XSR vulnerabilities
        CrossauthLogger.logger.debug(j({msg: "validating authorize parameters"}))
        let {error_description} = 
            this.authServer.validateAuthorizeParameters(query);
        let ce : CrossauthError|undefined = undefined;
        if (error_description) {
            ce = new CrossauthError(ErrorCode.BadRequest, error_description);
            CrossauthLogger.logger.error(j({
                msg: "authorize parameter invalid",
                cerr: ce,
                user: request.user?.username
            }));
        }  else {
            CrossauthLogger.logger.error(j({
                msg: "authorize parameter valid",
                user: request.user?.username
            }));

        }

        if (ce) {
            if (this.errorPage) {
                return reply.status(ce.httpStatus).view(this.errorPage, 
                    {
                        status: ce.httpStatus,
                        errorMessage: ce.message,
                        errorCode: ce.code,
                        errorCodeName: ce.codeName
                    });
            } else {
                let status : "401" | "400" | "500" = "500"
                switch (ce.httpStatus) {
                    case 401: status = "401" ; break;
                    case 400: status = "400" ; break;
                }
                return reply.status(ce.httpStatus)
                    .send(DEFAULT_ERROR[status]??ERROR_500);
            }
        }
        let hasAllScopes = false;
        CrossauthLogger.logger.debug(j({
            msg: `Checking scopes have been authorized`,
            scope: query.scope }))
        if (query.scope) {
            hasAllScopes = await this.authServer.hasAllScopes(query.client_id,
                request.user,
                query.scope.split(" "));

        } else {
            hasAllScopes = await this.authServer.hasAllScopes(query.client_id,
                request.user,
                [null]);

        }
        if (hasAllScopes) {
            CrossauthLogger.logger.debug(j({
                msg: `All scopes authorized`,
                scope: query.scope
            }))
            // all scopes have been previously authorized 
            // - create an authorization code
            return this.authorize(request, reply, true, {
                responseType: query.response_type,
                client_id : query.client_id,
                redirect_uri: query.redirect_uri,
                scope: query.scope,
                state: query.state,
                codeChallenge: query.code_challenge,
                codeChallengeMethod: query.code_challenge_method,
            });
           
        } else {
            // requesting new scopes - redirect to page to ask user for it
            CrossauthLogger.logger.debug(j({
                msg: `Not all scopes authorized`,
                scope: query.scope
            }))
            try {
                const client = 
                    await this.clientStorage.getClientById(query.client_id);
                
                return reply.view(this.oauthAuthorizePage, {
                    user: request.user,
                    response_type: query.response_type,
                    client_id : query.client_id,
                    client_name : client.client_name,
                    redirect_uri: query.redirect_uri,
                    scope: query.scope,
                    scopes: query.scope ? query.scope.split(" ") : undefined,
                    state: query.state,
                    code_challenge: query.code_challenge,
                    code_challenge_method: query.code_challenge_method,
                    csrfToken: request.csrfToken,
                });
            } catch (e) {
                const ce = e as CrossauthError;
                CrossauthLogger.logger.debug(j({err: ce}));
                if (this.errorPage) {
                    return reply.status(ce.httpStatus).view(this.errorPage, {
                        status: ce.httpStatus, 
                        errorMessage: "Invalid client given", 
                        client_id: query.client_id, 
                        user: request.user?.username, 
                        httpStatus: ce.httpStatus, 
                        errorCode: ErrorCode.UnauthorizedClient, 
                        errorCodeName: ErrorCode[ErrorCode.UnauthorizedClient]});
                } else {
                    return reply.status(ce.httpStatus).send(DEFAULT_ERROR[401]);
                }

            }
        }

    }

    private async authorize(request: FastifyRequest,
        reply: FastifyReply,
        authorized: boolean, {
            responseType,
            client_id,
            redirect_uri,
            scope,
            state,
            codeChallenge,
            codeChallengeMethod,
        } : {
            responseType : string,
            client_id : string,
            redirect_uri : string,
            scope? : string,
            state : string,
            codeChallenge? : string,
            codeChallengeMethod?: string,
        }) {
        let error : string|undefined;
        let errorDescription : string|undefined;
        let code : string|undefined;

        // Create an authorization code
        if (authorized) {
            const resp = await this.authServer.authorizeGetEndpoint({
                responseType,
                client_id,
                redirect_uri,
                scope,
                state,
                codeChallenge,
                codeChallengeMethod,
                user: request.user,
            });
            code = resp.code;
            error = resp.error;
            errorDescription = resp.error_description;

            // couldn't create an authorization code
            if (error || !code) {
                const ce = CrossauthError.fromOAuthError(error??"server_error", 
                    errorDescription??"Neither code nor error received")
                CrossauthLogger.logger.error(j({cerr: ce}));
                if (this.errorPage) {
                    return reply.status(ce.httpStatus).view(this.errorPage, 
                        {
                            status: ce.httpStatus,
                            errorMessage: ce.message,
                            errorCode: ce.code,
                            errorCodeName: ce.codeName
                        });
                } else {
                    let status : "401" | "400" | "500" = "500"
                    switch (ce.httpStatus) {
                        case 401: status = "401" ; break;
                        case 400: status = "400" ; break;
                    }
                    return reply.status(ce.httpStatus)
                        .send(DEFAULT_ERROR[status]??ERROR_500);
                }
            }

            return reply.redirect(this.authServer.redirect_uri(
                redirect_uri,
                code,
                state
            )); 

        } else {

            // resource owner did not grant access
            const ce = new CrossauthError(ErrorCode.Unauthorized,  
                "You have not granted access");
            CrossauthLogger.logger.error(j({
                msg: errorDescription,
                errorCode: ce.code,
                errorCodeName: ce.codeName
            }));
            try {
                OAuthClientManager.validateUri(redirect_uri);
                return reply.redirect(redirect_uri); 
            } catch (e) {
                CrossauthLogger.logger.error(j({
                    msg: `Couldn't send error message ${ce.codeName} to ${redirect_uri}}`}));
            }
        }
    }

    private async mfaAuthenticatorsEndpoint(request: FastifyRequest,
        reply: FastifyReply) : 
        Promise<MfaAuthenticatorResponse[]|
            {error? : string, error_desciption? : string}> {

        const authHeader = request.headers['authorization']?.split(" ");
        if (!authHeader || authHeader.length != 2) {
            return {
                error: "access_denied",
                error_desciption: "Invalid authorization header"
            };
        }
        const mfa_token = authHeader[1];
        const resp = 
            await this.authServer.mfaAuthenticatorsEndpoint(mfa_token);
        if (resp.authenticators) {
            return reply.header(...JSONHDR).status(200).send(resp.authenticators);
        }
        const ce = CrossauthError.fromOAuthError(resp.error??"server_error");
        return reply.header(...JSONHDR).status(ce.httpStatus).send(resp);

    }

    private async mfaChallengeEndpoint(_request: FastifyRequest,
        reply: FastifyReply,
        query: MfaChallengeBodyType) : 
        Promise<MfaAuthenticatorResponse[]|
            {error? : string, error_desciption? : string}> {

        const resp = 
            await this.authServer.mfaChallengeEndpoint(query.mfa_token,
                query.client_id,
                query.client_secret,
                query.challenge_type,
                query.authenticator_id);
        if (resp.error) {
            const ce = CrossauthError.fromOAuthError(resp.error);
            return reply.header(...JSONHDR).status(ce.httpStatus).send(resp);
        }
        
        return reply.header(...JSONHDR).status(200).send(resp);

    }

    private setRefreshTokenCookie(reply : FastifyReply, token : string, expiresIn : number|undefined) {
        if (!this.refreshTokenCookieName) return;
        let expiresAt = expiresIn ? new Date(Date.now() + expiresIn*1000).toUTCString() : undefined;
        let cookieString = this.refreshTokenCookieName + "=" + token;
        if (expiresAt) cookieString += "; expires=" + new Date(expiresAt).toUTCString();
        if (this.refreshTokenCookieSameSite) cookieString += "; SameSite=" + this.refreshTokenCookieSameSite;
        if (this.refreshTokenCookieDomain) cookieString += "; domain=" + this.refreshTokenCookieDomain;
        if (this.refreshTokenCookiePath) cookieString += "; path=" + this.refreshTokenCookiePath;
        if (this.refreshTokenCookieHttpOnly == true) cookieString += "; httpOnly";
        if (this.refreshTokenCookieSecure == true) cookieString += "; secure";
        reply.setCookie(this.refreshTokenCookieName, cookieString)
    }

    /**
     * Returns this server's OIDC configuration.  Just wraps
     * {@link @crossauth/backend!OAuthAuthorizationServer.oidcConfiguration}
     * @returns An {@link @crossauth/common!OpenIdConfiguration} object
     */
    oidcConfiguration() : OpenIdConfiguration {
        return this.authServer.oidcConfiguration({
                authorizeEndpoint: this.prefix+"authorize", 
                tokenEndpoint: this.prefix+"token", 
                jwksUri: this.prefix+"jwks", 
                additionalClaims: []});
    };


    /////
    // Device code flow
 
    private async applyUserCode(userCode : string, request: FastifyRequest, user: User) : Promise<DevicePageData> {
        // if there is a user code, apply it.  Otherwise we will show the form
        // and it will be processed by the action
        try {
            const ret = await this.authServer.deviceEndpoint({userCode, user});
            if (ret.error) {
                return {
                    ok: false,
                    completed: false,
                    retryAllowed: false,
                    error: ret.error,
                    error_description: ret.error_description,

                }
            }
            if (!ret.client_id) {
                CrossauthLogger.logger.error(j({msg: "No client id found for user code", userCodeHash: Crypto.hash(userCode), ip: request.ip, username: request.user?.username}));
                return {
                    ok: false,
                    completed: false,
                    retryAllowed: false,
                    error: "server_error",
                    error_description: "No client id found for user code",
                }
            }
            if (ret.error == "access_denied") {
                CrossauthLogger.logger.error(j({msg: "Incorrect user code given", userCodeHash: Crypto.hash(userCode), ip: request.ip, username: request.user?.username}));
                if (this.authServer.userCodeThrottle > 0) {
                    let wait = (ms : number) => new Promise(resolve => setTimeout(resolve, ms));
                    await wait(this.authServer.userCodeThrottle);    
                }
                return {
                    ok: false,
                    completed: false,
                    retryAllowed: true,
                    error: ret.error,
                    error_description: ret.error_description,
                }
            } else if (ret.error == "expired_token") {
                CrossauthLogger.logger.error(j({msg: "Expired user code", userCodeHash: Crypto.hash(userCode), ip: request.ip, username: request.user?.username}));
                return {
                    ok: false,
                    completed: false,
                    retryAllowed: false,
                    error: ret.error,
                    error_description: ret.error_description,
                }

            }

            const client = await this.clientStorage.getClientById(ret.client_id);

            // if the user needs to authorize scopes, tell the caller this
            // - user code will have not been set to ok in the above call yet
            if (ret.scopeAuthorizationNeeded) {
                return {
                    ok: true,
                    completed: false,
                    retryAllowed: true,
                    authorizationNeeded: {
                        user,
                        client_id: ret.client_id,
                        client_name: client.client_name,
                        scope: ret.scope,
                        scopes : ret.scope ? ret.scope.split(" ") : [],
                        csrfToken: request.csrfToken
                    },
                    user: request.user,
                    csrfToken: request.csrfToken,
                    user_code: userCode,
                }
            
            } else {
                // all scopes were authorized - this completes the flow
                return {
                    ok: true,
                    completed: true,
                    retryAllowed: false,
                    user: request.user,
                    csrfToken: request.csrfToken,
                }
            }
        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.debug(j({err: ce}));
            CrossauthLogger.logger.error(j({msg: ce.message, cerr: ce}));
            return {
                ok: false,
                completed: false,
                retryAllowed: true,
                error: ce.oauthErrorCode,
                error_description: ce.message,
            }
        }
    }

    private async deviceGet(isApi : boolean, 
        request : FastifyRequest<{Querystring: DeviceQueryType}>, 
        reply : FastifyReply, user: User) {
        if (!request.query.user_code) {

            // no user code given - ask for it$
            const data = {
                ok: false,
                completed: false,
                user_code: request.query.user_code,
                csrfToken: request.csrfToken,
            };
            if (isApi) {
                return reply.header(...JSONHDR).status(200).send(data);
            }
            return reply.status(200).view(this.devicePage, data);
        } else {
            // user code given - process it
            let ret = await this.applyUserCode(request.query.user_code, request, user);
            if (ret.error) {
                const ce = CrossauthError.fromOAuthError(ret.error, ret.error_description);
                CrossauthLogger.logger.debug({err: ce});
                CrossauthLogger.logger.error({cerr: ce});
                const data = {
                    ok: false,
                    completed: false,
                    status: ce.httpStatus,
                    errorMessage: ce.message,
                    errorCode: ce.code,
                    errorCodeName: ce.codeName,
                    retryAllowed: ret.retryAllowed,
                };
                if (isApi) {
                    return reply.header(...JSONHDR).status(ce.httpStatus).send(data);
                }
                return reply.status(ce.httpStatus).view(this.devicePage, {
                    csrfToken: request.csrfToken,
                    ...data});
            } else if (ret.authorizationNeeded) {
                const data = {
                    ok: true,
                    completed: false,
                    retryAllowed: ret.retryAllowed,
                    authorizationNeeded: ret.authorizationNeeded,
                    user_code: ret.user_code,
                };
                if (isApi) {
                    return reply.header(...JSONHDR).status(200).send(data);
                }
                return reply.status(200).view(this.devicePage, {
                    csrfToken: request.csrfToken,
                    ...data});

            }

            const data = {
                ok: true,
                completed: true,
            };
            if (isApi) {
                return reply.header(...JSONHDR).status(401).send(data);
            }
        return reply.status(200).view(this.devicePage, {
            csrfToken: request.csrfToken,
            ...data});
        }
    }

    private async deviceCodePost(isApi: boolean, 
        request: FastifyRequest<{ Body: DeviceBodyType }>,
        reply: FastifyReply) {
        try {
            // this should not be called if a user is not logged in
            if (!request.user) throw new CrossauthError(ErrorCode.Unauthorized, "You are not logged in");

            // this should not be called there is no CSRF token
            if (!request.csrfToken) throw new CrossauthError(ErrorCode.Unauthorized, "CSRF token missing or invalid");

            if (!request.body.authorized || request.body.authorized=="") {

                // this is just a request for the user code, not to authorize scopes
                if (request.body.user_code) {
                    // user code given in body   - ask user to authorize
                    // - process code
                    // - request authorization if needed

                    let ret = await this.applyUserCode(request.body.user_code, request, request.user);
                    if (ret.error) {
                        const ce = CrossauthError.fromOAuthError(ret.error, ret.error_description);
                        CrossauthLogger.logger.debug({err: ce});
                        CrossauthLogger.logger.error({cerr: ce});
                        const data =  {
                            ok: false,
                            completed: false,
                            status: ce.httpStatus,
                            errorMessage: ce.message,
                            errorCode: ce.code,
                            errorCodeName: ce.codeName,
                            retryAllowed: ret.retryAllowed,
                        };
                        if (isApi) {
                            return reply.header(...JSONHDR).status(200).send(data);
                        }
                        return reply.status(ce.httpStatus).view(this.devicePage, {
                            csrfToken: request.csrfToken,
                            ...data});
                    } else if (ret.authorizationNeeded) {
                        const data = {
                            ok: true,
                            completed: false,
                            retryAllowed: ret.retryAllowed,
                            authorizationNeeded: ret.authorizationNeeded,
                            user_code: ret.user_code,
                        };
                        if (isApi) {
                            return reply.header(...JSONHDR).status(200).send(data);
                        }
                        return reply.status(200).view(this.devicePage, {
                            csrfToken: request.csrfToken,
                            ...data});

                    }

                    const data = {
                        ok: true,
                        completed: true,
                        csrfToken: request.csrfToken,
                    };
                    if (isApi) {
                        return reply.header(...JSONHDR).status(200).send(data);
                    }
                    return reply.status(200).view(this.devicePage, data);
                } else {
                    // user code not given - display error
                    const ce = CrossauthError.fromOAuthError("unauthorized", "Please enter the code");
                    const data = {
                        ok: false,
                        completed: false,
                        user_code: request.body.user_code,
                        retryAllowed: true,
                        error: "unauthorized",
                        error_description: "Please enter the code",
                        errorMessage: ce.message,
                        errorCode: ce.code,
                        errorCodeName: ce.codeName,
                        };
                    if (isApi) {
                        return reply.header(...JSONHDR).status(401).send(data);
                    }
                    return reply.status(200).view(this.devicePage, {
                        csrfToken: request.csrfToken,
                        ...data});

                }

            } else if (request.body.authorized == "true") {

                // user is authorizing the client
                let userCode = request.body.user_code;
                let scope : string|undefined = request.body.scope;
                if (scope == "") undefined;
                const client_id = request.body.client_id; 
                if (!userCode) throw new CrossauthError(ErrorCode.BadRequest, "user_code missing");
                if (!client_id) throw new CrossauthError(ErrorCode.BadRequest, "client_id missing");


                // validate the scopes
                let ret = await this.authServer.validateAndPersistScope(client_id, scope, request.user);
                if (ret.error) {
                    throw CrossauthError.fromOAuthError(ret.error, ret.error_description);
                }
                ret = await this.applyUserCode(userCode, request, request.user);

                if (ret.error) {
                    // all errors here are fatal as the user code was already validated
                    throw CrossauthError.fromOAuthError(ret.error, ret.error_description);
                }

                const data = {
                    ok: true,
                    completed: true,
                    csrfToken: request.csrfToken,
                };
                if (isApi) {
                    return reply.header(...JSONHDR).status(401).send(data);
                }
                return reply.status(200).view(this.devicePage, data);


            } else {
                // user denied authorization
                throw new CrossauthError(ErrorCode.Unauthorized, "You did not authorize the client");
            }

        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.debug({err: ce});
            CrossauthLogger.logger.error({cerr: ce});
            const data = {
                ok: false,
                status: ce.httpStatus,
                errorMessage: ce.message,
                errorCode: ce.code,
                errorCodeName: ce.codeName,
            };
            if (isApi) {
                return reply.header(...JSONHDR).status(401).send(data);
            }
            return reply.status(ce.httpStatus).view(this.devicePage, {
                csrfToken: request.csrfToken,
                ...data});

        }

    }

}
