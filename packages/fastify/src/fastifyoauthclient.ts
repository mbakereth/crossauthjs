import { jwtDecode } from "jwt-decode";
import { type FastifyRequest, type FastifyReply } from 'fastify';
import {
    CrossauthError,
    ErrorCode,
    CrossauthLogger,
    OAuthFlows,
    type OAuthTokenResponse,
    j, 
    MfaAuthenticatorResponse} from '@crossauth/common';
import {
    setParameter,
    ParamType,
    Hasher,
    OAuthClient } from '@crossauth/backend';
import type { OAuthClientOptions } from '@crossauth/backend';
import { FastifyServer, type FastifyErrorFn } from './fastifyserver';
import type { CsrfBodyType } from './fastifysession.ts';

const JSONHDR : [string,string] = 
    ['Content-Type', 'application/json; charset=utf-8'];

///////////////////////////////////////////////////////////////////////////////
// OPTIONS

export interface FastifyOAuthClientOptions extends OAuthClientOptions {
    siteUrl ?: string,
    prefix? : string,
    sessionDataName? : string,
    errorPage? : string,
    passwordFlowPage? : string,
    mfaOtpPage? : string,
    mfaOobPage? : string,
    authorizedPage? : string,
    authorizedUrl? : string,
    loginUrl? : string,
    loginProtectedFlows? : string,
    passwordFlowUrl? : string,
    passwordOtpUrl? : string,
    passwordOobUrl? : string,
    receiveTokenFn?: (client: FastifyOAuthClient,
        request: FastifyRequest,
        reply: FastifyReply,
        oauthResponse: OAuthTokenResponse) => Promise<FastifyReply>;
    errorFn? :FastifyErrorFn ;
    tokenResponseType? : 
        "sendJson" | 
        "saveInSessionAndLoad" | 
        "saveInSessionAndRedirect" | 
        "sendInPage" | 
        "custom";
    errorResponseType? : 
        "sendJson" | 
        "errorPage" | 
        "custom",
    bffEndpoints?: {
        url: string,
        methods: ("GET" | "POST" | "PUT" | "DELETE" | "PATCH")[],
        matchSubUrls?: boolean
    }[],
    bffEndpointName? : string,
    bffBaseUrl? : string,
    tokenEndpoints? : ("access_token"|"refresh_token"|"id_token"|
        "have_access_token"|"have_refresh"|"have_id")[],
}


/////////////////////////////////////////////////////////////////////////////
// FASTIFY INTERFACES

interface AuthorizeQueryType {
    scope? : string,
}

interface RedirectUriQueryType {
    code? : string,
    state?: string,
    error? : string,
    error_description? : string,
}

interface PasswordQueryType {
    scope? : string,
}

interface ClientCredentialsBodyType {
    scope? : string,
    csrfToken? : string,
}

interface RefreshTokenBodyType {
    refreshToken: string,
    csrfToken? : string,
}

interface PasswordBodyType {
    username : string,
    password: string,
    scope? : string,
    csrfToken? : string,
}

interface PasswordOtpType {
    scope? : string,
    mfa_token : string,
    otp : string,
    challenge_type? : string,
}

interface PasswordOobType {
    scope? : string,
    mfa_token : string,
    oob_code : string,
    binding_code : string,
    challenge_type? : string,
    name? : string,

}

////////////////////////////////////////////////////////////////////////////
// DEFAULT FUNCTIONS

async function jsonError(_server: FastifyServer,
    _request: FastifyRequest,
    reply: FastifyReply,
    ce: CrossauthError) : Promise<FastifyReply> {
    CrossauthLogger.logger.debug(j({err: ce}));
    return reply.header(...JSONHDR)
        .status(ce.httpStatus).send({
            ok: false,
            status: ce.httpStatus,
            errorMessage: ce.message,
            errorMessages: ce.messages,
            errorCode: ce.code,
            errorCodeName: ce.codeName
        });
}

async function pageError(server: FastifyServer,
    _request: FastifyRequest,
    reply: FastifyReply,
    ce: CrossauthError) : Promise<FastifyReply> {
    CrossauthLogger.logger.debug(j({err: ce}));
    return reply.status(ce.httpStatus)
        .view(server.oAuthClient?.errorPage ?? "error.njk", {
            status: ce.httpStatus,
            errorMessage: ce.message,
            errorMessages: ce.messages,
            errorCodeName: ce.codeName
        });
}

function decodePayload(token : string|undefined) : {[key:string]: any}|undefined {
    let payload : {[key:string]: any}|undefined = undefined;
    if (token) {
        try {
            payload = JSON.parse(Hasher.base64Decode(token.split(".")[1]))
        } catch (e) {
            CrossauthLogger.logger.error(j({msg: "Couldn't decode id token"}));
        }
    }
    return payload;

}
async function sendJson(_client: FastifyOAuthClient,
    _request: FastifyRequest,
    reply: FastifyReply,
    oauthResponse: OAuthTokenResponse) : Promise<FastifyReply> {
    return reply.header(...JSONHDR).status(200)
        .send({ok: true, ...oauthResponse, 
            id_payload: decodePayload(oauthResponse.id_token)});
}

function logTokens(oauthResponse: OAuthTokenResponse) {
    if (oauthResponse.access_token) {
        try {
            if (oauthResponse.access_token) {
                const jti = jwtDecode(oauthResponse.access_token)?.jti;
                const hash = jti ? Hasher.hash(jti) : undefined;
                CrossauthLogger.logger.debug(j({msg: "Got access token", 
                    accessTokenHash: hash}));
            }
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
        }
    }
    if (oauthResponse.id_token) {
        try {
            if (oauthResponse.id_token) {
                const jti = jwtDecode(oauthResponse.id_token)?.jti;
                const hash = jti ? Hasher.hash(jti) : undefined;
                CrossauthLogger.logger.debug(j({msg: "Got id token", 
                    idTokenHash: hash}));
            }
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
        }
    }
    if (oauthResponse.refresh_token) {
        try {
            if (oauthResponse.refresh_token) {
                const jti = jwtDecode(oauthResponse.refresh_token)?.jti;
                const hash = jti ? Hasher.hash(jti) : undefined;
                CrossauthLogger.logger.debug(j({msg: "Got refresh token", 
                    refreshTokenHash: hash}));
            }
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
        }
    }
}

async function sendInPage(client: FastifyOAuthClient,
    _request: FastifyRequest,
    reply: FastifyReply,
    oauthResponse: OAuthTokenResponse) : Promise<FastifyReply> {
    if (oauthResponse.error) {
        const ce = CrossauthError.fromOAuthError(oauthResponse.error, 
            oauthResponse.error_description);
        return reply.status(ce.httpStatus)
            .view(client.errorPage, {
                status: ce.httpStatus,
                errorMessage: ce.message,
                errorCodeName: ce.codeName,
                errorCode: ce.code
            });
    }

    logTokens(oauthResponse);
    try {
        return reply.status(200).view(client.authorizedPage, 
            {...oauthResponse,
                id_payload: decodePayload(oauthResponse.id_token)} );
    } catch (e) {
        const ce = e as CrossauthError;
        return reply.status(ce.httpStatus)
            .view(client.errorPage, {
                status: ce.httpStatus,
                errorMessage: ce.message,
                errorCodeName: ce.codeName
            });
    }
}

async function saveInSessionAndLoad(client: FastifyOAuthClient,
    request: FastifyRequest,
    reply: FastifyReply,
    oauthResponse: OAuthTokenResponse) : Promise<FastifyReply> {
    if (oauthResponse.error) {
        const ce = CrossauthError.fromOAuthError(oauthResponse.error, 
            oauthResponse.error_description);
        return reply.status(ce.httpStatus)
            .view(client.errorPage, {
                status: ce.httpStatus,
                errorMessage: ce.message,
                errorCodeName: ce.codeName,
                errorCode: ce.code
            });
    }

    logTokens(oauthResponse);
    try {
        let sessionCookieValue = client.server.getSessionCookieValue(request);
        if (!sessionCookieValue) {
            sessionCookieValue = 
                await client.server.createAnonymousSession(request,
                    reply,
                    { [client.sessionDataName]: oauthResponse });
        } else {
            const expires_at = Date.now() + (oauthResponse.expires_in??0)*1000;
            await client.server.updateSessionData(request,
                client.sessionDataName,
                { ...oauthResponse, expires_at });
        }
        if (!client.authorizedPage) {
            return reply.status(500)
                .view(client.errorPage, {
                    status: 500,
                    errorMessage: "Authorized url not configured",
                    errorCodeName: ErrorCode[ErrorCode.Configuration],
                    errorCode: ErrorCode.Configuration
                });
        }
        return reply.status(200).view(client.authorizedPage, 
            {...oauthResponse,
                id_payload: decodePayload(oauthResponse.id_token)} );
    } catch (e) {
        const ce = e as CrossauthError;
        return reply.status(ce.httpStatus)
            .view(client.errorPage, {
                status: ce.httpStatus,
                errorMessage: ce.message,
                errorCodeName: ce.codeName
            });
    }
}

async function saveInSessionAndRedirect(client: FastifyOAuthClient,
    request: FastifyRequest,
    reply: FastifyReply,
    oauthResponse: OAuthTokenResponse) : Promise<FastifyReply> {
    if (oauthResponse.error) {
        const ce = CrossauthError.fromOAuthError(oauthResponse.error, 
            oauthResponse.error_description);
        return reply.status(ce.httpStatus)
            .view(client.errorPage, {
                status: ce.httpStatus,
                errorMessage: ce.message,
                errorCodeName: ce.codeName,
                errorCode: ce.code
            });
    }

    logTokens(oauthResponse);
    try {
        let sessionCookieValue = client.server.getSessionCookieValue(request);
        if (!sessionCookieValue) {
            sessionCookieValue = 
                await client.server.createAnonymousSession(request,
                    reply,
                    { [client.sessionDataName]: oauthResponse });
        } else {
            const expires_at = 
                (new Date().getTime() + (oauthResponse.expires_in??0)*1000);
            await client.server.updateSessionData(request,
                client.sessionDataName,
                { ...oauthResponse, expires_at });
        }
        if (!client.authorizedUrl) {
            return reply.status(500)
                .view(client.errorPage, {
                    status: 500,
                    errorMessage: "Authorized url not configured",
                    errorCodeName: ErrorCode[ErrorCode.Configuration],
                    errorCode: ErrorCode.Configuration
                });

        }
        return reply.redirect(client.authorizedUrl);
    } catch (e) {
        const ce = e as CrossauthError;
        return reply.status(ce.httpStatus)
            .view(client.errorPage, {
                status: ce.httpStatus,
                errorMessage: ce.message,
                errorCodeName: ce.codeName
            });
    }
}

///////////////////////////////////////////////////////////////////////////////
// CLASSES

export class FastifyOAuthClient extends OAuthClient {
    server : FastifyServer;
    private siteUrl : string = "/";
    private prefix : string = "/";
    errorPage : string = "error.njk";
    passwordFlowPage : string = "passwordflow.njk"
    mfaOtpPage : string = "mfaotp.njk"
    mfaOobPage : string = "mfaoob.njk"
    authorizedPage : string = "authorized.njk";
    authorizedUrl : string = "authorized";
    sessionDataName : string = "oauth";
    private receiveTokenFn : 
        (client: FastifyOAuthClient,
            request: FastifyRequest,
            reply: FastifyReply,
            oauthResponse: OAuthTokenResponse) 
            => Promise<FastifyReply> = sendJson;
    private errorFn : FastifyErrorFn = jsonError;
    private loginUrl : string = "/login";
    private loginProtectedFlows : string[] = [];
    private tokenResponseType :  
        "sendJson" | 
        "saveInSessionAndLoad" | 
        "saveInSessionAndRedirect" | 
        "sendInPage" | 
        "custom" = "sendJson";
    private errorResponseType :  
        "sendJson" | 
        "pageError" | 
        "custom" = "sendJson";
    private passwordFlowUrl : string = "passwordflow";
    private passwordOtpUrl : string = "passwordotp";
    private passwordOobUrl : string = "passwordoob";
    private bffEndpoints: {
        url: string,
        methods: ("GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS" | "HEAD")[],
        matchSubUrls?: boolean
        }[] = [];
    private bffEndpointName = "bff";
    private bffBaseUrl? : string;
    private tokenEndpoints : ("access_token"|"refresh_token"|"id_token"|
        "have_access_token"|"have_refresh"|"have_id")[] = [];

    constructor(server: FastifyServer,
        authServerBaseUri: string,
        options: FastifyOAuthClientOptions) {
        super(authServerBaseUri, options);
        this.server = server;
        setParameter("sessionDataName", ParamType.String, this, options, "OAUTH_SESSION_DATA_NAME");
        setParameter("siteUrl", ParamType.String, this, options, "SITE_URL", true);
        setParameter("tokenResponseType", ParamType.String, this, options, "OAUTH_TOKEN_RESPONSE_TYPE");
        setParameter("errorResponseType", ParamType.String, this, options, "OAUTH_ERROR_RESPONSE_TYPE");
        setParameter("prefix", ParamType.String, this, options, "PREFIX");
        if (!(this.prefix.endsWith("/"))) this.prefix += "/";
        setParameter("loginUrl", ParamType.String, this, options, "LOGIN_URL");
        setParameter("errorPage", ParamType.String, this, options, "ERROR_PAGE");
        setParameter("authorizedPage", ParamType.String, this, options, "AUTHORIZED_PAGE");
        setParameter("authorizedUrl", ParamType.String, this, options, "AUTHORIZED_URL");
        setParameter("loginProtectedFlows", ParamType.StringArray, this, options, "OAUTH_LOGIN_PROTECTED_FLOWS");
        setParameter("passwordFlowUrl", ParamType.String, this, options, "OAUTH_PASSWORD_FLOW_URL");
        setParameter("passwordOtpUrl", ParamType.String, this, options, "OAUTH_PASSWORD_OTP_URL");
        setParameter("passwordOobUrl", ParamType.String, this, options, "OAUTH_PASSWORD_OOB_URL");
        setParameter("passwordFlowPage", ParamType.String, this, options, "OAUTH_PASSWORD_FLOW_PAGE");
        setParameter("mfaOtpPage", ParamType.String, this, options, "OAUTH_MFA_OTP_PAGE");
        setParameter("mfaOobPage", ParamType.String, this, options, "OAUTH_MFA_OOB_PAGE");
        setParameter("bffEndpointName", ParamType.String, this, options, "OAUTH_BFF_ENDPOINT_NAME");
        setParameter("bffBaseUrl", ParamType.String, this, options, "OAUTH_BFF_BASEURL");
        if (options.tokenEndpoints) this.tokenEndpoints = options.tokenEndpoints;

        if (this.bffEndpointName.endsWith("/")) this.bffEndpointName = this.bffEndpointName.substring(0, this.bffEndpointName.length-1);
        if (options.bffEndpoints) this.bffEndpoints = options.bffEndpoints;

        if (this.loginProtectedFlows.length == 1 && 
            this.loginProtectedFlows[0] == OAuthFlows.All) {
            this.loginProtectedFlows = this.validFlows;
        } else {
            if (!OAuthFlows.areAllValidFlows(this.loginProtectedFlows)) {
                throw new CrossauthError(ErrorCode.Configuration,
                     "Invalid flows specificied in " + this.loginProtectedFlows.join(","));
            }
        }

        if (this.tokenResponseType == "custom" && !options.receiveTokenFn) {
            throw new CrossauthError(ErrorCode.Configuration, 
                "Token response type of custom selected but receiveTokenFn not defined");
        }
        if (this.tokenResponseType == "custom" && options.receiveTokenFn) {
            this.receiveTokenFn = options.receiveTokenFn;
        } else if (this.tokenResponseType == "sendJson") {
            this.receiveTokenFn = sendJson;
        } else if (this.tokenResponseType == "sendInPage") {
            this.receiveTokenFn = sendInPage;
        } else if (this.tokenResponseType == "saveInSessionAndLoad") {
            this.receiveTokenFn = saveInSessionAndLoad;
        } else if (this.tokenResponseType == "saveInSessionAndRedirect") {
            this.receiveTokenFn = saveInSessionAndRedirect;
        }

        if (this.errorResponseType == "custom" && !options.errorFn) {
            throw new CrossauthError(ErrorCode.Configuration, 
                "Error response type of custom selected but errorFn not defined");
        }
        if (this.errorResponseType == "custom" && options.errorFn) {
            this.errorFn = options.errorFn;
        } else if (this.errorResponseType == "sendJson") {
            this.errorFn = jsonError;
        } else if (this.errorResponseType == "pageError") {
            this.errorFn = pageError;
        }

        
        if (this,this.loginProtectedFlows.length > 0 && this.loginUrl == "") {
            throw new CrossauthError(ErrorCode.Configuration, 
                "loginUrl must be set if protecting oauth endpoints");
        }
        
        if (!this.prefix.endsWith("/")) this.prefix += "/";
        this.redirectUri = this.siteUrl + this.prefix + "authzcode";

        if (this.validFlows.includes(OAuthFlows.AuthorizationCode)) {
            this.server.app.get(this.prefix+'authzcodeflow', 
                async (request : FastifyRequest<{ Querystring: AuthorizeQueryType }>, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'GET',
                        url: this.prefix + 'authzcodeflow',
                        ip: request.ip,
                        user: request.user?.username
                    }));
                if (!request.user && 
                    this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCode)) {
                    return reply.redirect(302, 
                        this.loginUrl+"?next="+encodeURIComponent(request.url));
                }          
                const {url, error, error_description} = 
                    await this.startAuthorizationCodeFlow(request.query.scope);
                if (error || !url) {
                    const ce = CrossauthError.fromOAuthError(error??"server_error", 
                        error_description);
                    return await this.errorFn(this.server, request, reply, ce)
                }
                    CrossauthLogger.logger.debug(j({
                        msg: `Authorization code flow: redirecting`,
                        url: url
                    }));
                return reply.redirect(url);
            });
        }

        ///////// Authorization code flow with PKCE

        if (this.validFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE)) {
            this.server.app.get(this.prefix+'authzcodeflowpkce', 
                async (request : FastifyRequest<{ Querystring: AuthorizeQueryType }>, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'GET',
                        url: this.prefix + 'authzcodeflowpkce',
                        ip: request.ip,
                        user: request.user?.username
                    }));
                if (!request.user && 
                    this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE)) {
                    return reply.redirect(302, 
                        this.loginUrl+"?next="+encodeURIComponent(request.url));
                }               
                const {url, error, error_description} = 
                    await this.startAuthorizationCodeFlow(request.query.scope, 
                        true);
                if (error || !url) {
                    const ce = CrossauthError.fromOAuthError(error??"server_error", 
                        error_description);
                    return await this.errorFn(this.server, request, reply, ce);
                }
                return reply.redirect(url);
            });
        }

        ///////// Authorization code flow

        if (this.validFlows.includes(OAuthFlows.AuthorizationCode) || 
            this.validFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE) ||
            this.validFlows.includes(OAuthFlows.OidcAuthorizationCode)) {
                    this.server.app.get(this.prefix+'authzcode', 
                async (request : FastifyRequest<{ Querystring: RedirectUriQueryType }>, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'GET',
                        url: this.prefix + 'authzcode',
                        ip: request.ip,
                        user: request.user?.username
                    }));
                if (!request.user &&
                     (this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE) || 
                        this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCode))) {
                    return reply.redirect(302, 
                        this.loginUrl+"?next="+encodeURIComponent(request.url));
                }               
                const resp = 
                    await this.redirectEndpoint(request.query.code,
                        request.query.state,
                        request.query.error,
                        request.query.error_description);
                try {
                    if (resp.error) {
                        const ce = CrossauthError.fromOAuthError(resp.error, 
                            resp.error_description);
                        return await this.errorFn(this.server,
                            request,
                            reply,
                            ce);
                    }
                    return await this.receiveTokenFn(this, request, reply, resp);
                } catch (e) {
                    const ce = CrossauthError.asCrossauthError(e);
                    CrossauthLogger.logger.error(j({
                        msg: "Error receiving token",
                        cerr: ce,
                        user: request.user?.user
                    }));
                    CrossauthLogger.logger.debug(j({err: e}));
                    return await this.errorFn(this.server, request, reply, ce);
                }
            });
        }

        ///////// Client credentials flow

        if (this.validFlows.includes(OAuthFlows.ClientCredentials)) {
            this.server.app.post(this.prefix+'clientcredflow', 
                async (request : FastifyRequest<{ Body: ClientCredentialsBodyType }>, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + 'clientcredflow',
                        ip: request.ip,
                        user: request.user?.username
                    }));
                if (this.server.sessionServer) {
                    // if sessions are enabled, require a csrf token
                    const {error, reply: reply1} = 
                        await server.errorIfCsrfInvalid(request,
                            reply,
                            this.errorFn);
                    if (error) return reply1;
                }
                if (!request.user && 
                    (this.loginProtectedFlows.includes(OAuthFlows.ClientCredentials))) {
                    return reply.status(401).header(...JSONHDR)
                        .send({ok: false, msg: "Access denied"});                }               
                try {
                    const resp = await this.clientCredentialsFlow(request.body?.scope);
                    if (resp.error) {
                        const ce = CrossauthError.fromOAuthError(resp.error, 
                            resp.error_description);
                        return await this.errorFn(this.server,
                            request,
                            reply,
                            ce);
                    }
                    return await this.receiveTokenFn(this, request, reply, resp);
                } catch (e) {
                    const ce = CrossauthError.asCrossauthError(e);
                    CrossauthLogger.logger.error(j({
                        msg: "Error receiving token",
                        cerr: ce,
                        user: request.user?.user
                    }));
                    CrossauthLogger.logger.debug(j({err: e}));
                    return await this.errorFn(this.server, request, reply, ce);
                }
            });
        }

        ///////// Refresh token flow

        if (this.validFlows.includes(OAuthFlows.RefreshToken)) {
            this.server.app.post(this.prefix+'refreshtokenflow', 
                async (request : FastifyRequest<{ Body: RefreshTokenBodyType }>, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + 'refreshtokenflow',
                        ip: request.ip,
                        user: request.user?.username
                    }));
                if (this.server.sessionServer) {
                    // if sessions are enabled, require a csrf token
                    const {error, reply: reply1} = 
                        await server.errorIfCsrfInvalid(request,
                            reply,
                            this.errorFn);
                    if (error) return reply1;
                }
                if (!request.user && 
                    (this.loginProtectedFlows.includes(OAuthFlows.ClientCredentials))) {
                    return reply.status(401).header(...JSONHDR)
                        .send({ok: false, msg: "Access denied"});                }               
                try {
                    const resp = 
                        await this.refreshTokenFlow(request.body.refreshToken);
                    if (resp.error) {
                        const ce = CrossauthError.fromOAuthError(resp.error, 
                            resp.error_description);
                        return await this.errorFn(this.server,
                            request,
                            reply,
                            ce);
                    }
                    return await this.receiveTokenFn(this, request, reply, resp);
                } catch (e) {
                    const ce = CrossauthError.asCrossauthError(e);
                    CrossauthLogger.logger.error(j({
                        msg: "Error receiving token",
                        cerr: ce,
                        user: request.user?.user
                    }));
                    CrossauthLogger.logger.debug(j({err: e}));
                    return await this.errorFn(this.server, request, reply, ce);
                }
            });
        }

        ///////// Password (and MFA) flow

        if (this.validFlows.includes(OAuthFlows.Password) ||
            this.validFlows.includes(OAuthFlows.PasswordMfa)) {
            this.server.app.get(this.prefix+this.passwordFlowUrl, 
                async (request : FastifyRequest<{ Querystring: PasswordQueryType, 
                                                  Body: PasswordBodyType }>, 
                       reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'GET',
                        url: this.prefix + 'passwordFlowUrl',
                        ip: request.ip,
                        user: request.user?.username
                    }));
                if (!request.user && 
                    this.loginProtectedFlows.includes(OAuthFlows.Password)) {
                    return reply.redirect(302, 
                        this.loginUrl+"?next="+encodeURIComponent(request.url));
                }
                return reply.view(this.passwordFlowPage, {
                    user: request.user,
                    scope: request.query.scope,
                    csrfToken: request.csrfToken
                });            
            });

            this.server.app.post(this.prefix+this.passwordFlowUrl, 
                async (request : FastifyRequest<{ Body: PasswordBodyType }>, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + this.passwordFlowUrl,
                        ip: request.ip,
                        user: request.user?.username
                    }));
                return await this.passwordPost(false, request, reply);
            });

            this.server.app.post(this.prefix+"api/"+this.passwordFlowUrl, 
                async (request : FastifyRequest<{ Body: PasswordBodyType }>, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + "api/" + this.passwordFlowUrl,
                        ip: request.ip,
                        user: request.user?.username
                    }));
                return await this.passwordPost(true, request, reply);
            });

        }

        if (this.validFlows.includes(OAuthFlows.PasswordMfa)) {
            this.server.app.post(this.prefix+this.passwordOtpUrl, 
                async (request : FastifyRequest<{ Body: PasswordOtpType }>, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + this.passwordOtpUrl,
                        ip: request.ip,
                        user: request.user?.username
                    }));
                return await this.passwordOtp(false, request, reply);
            });

            this.server.app.post(this.prefix+this.passwordOobUrl, 
                async (request : FastifyRequest<{ Body: PasswordOobType }>, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + this.passwordOobUrl,
                        ip: request.ip,
                        user: request.user?.username
                    }));
                return await this.passwordOob(false, request, reply);
            });

            if (this.validFlows.includes(OAuthFlows.PasswordMfa)) {
                this.server.app.post(this.prefix+"api/"+this.passwordOtpUrl, 
                    async (request : FastifyRequest<{ Body: PasswordOtpType }>, 
                        reply : FastifyReply) =>  {
                        CrossauthLogger.logger.info(j({
                            msg: "Page visit",
                            method: 'POST',
                            url: this.prefix + "api/" + this.passwordOtpUrl,
                            ip: request.ip,
                            user: request.user?.username
                        }));
                    return await this.passwordOtp(true, request, reply);
                });
    
                this.server.app.post(this.prefix+"api/"+this.passwordOobUrl, 
                    async (request : FastifyRequest<{ Body: PasswordOobType }>, 
                        reply : FastifyReply) =>  {
                        CrossauthLogger.logger.info(j({
                            msg: "Page visit",
                            method: 'POST',
                            url: this.prefix + "api/" + this.passwordOobUrl,
                            ip: request.ip,
                            user: request.user?.username
                        }));
                    return await this.passwordOob(true, request, reply);
                });
            }
        }

        // Token endpoints
        for (let tokenType of this.tokenEndpoints) {
            this.server.app.post(this.prefix+tokenType, 
                async (request : FastifyRequest<{Body: CsrfBodyType}>, reply : FastifyReply) => {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + tokenType,
                        ip: request.ip,
                        user: request.user?.username
                    }));
                if (!request.csrfToken) {
                    return reply.header(...JSONHDR).status(401).send({ok: false, msg: "No csrf token given"});
                }
                let isHave = false;
                let tokenName : string = tokenType;
                if (tokenType.startsWith("have_")) {
                    tokenName = tokenType.replace("have_", "");
                    isHave = true;
                }
                const oauthData = await this.server.getSessionData(request, "oauth");
                if (!oauthData) {
                    if (isHave) return reply.header(...JSONHDR).status(200).send({ok: false});
                    return reply.header(...JSONHDR).status(204).send();
                }
                const payload = decodePayload(oauthData[tokenName]);
                if (!payload) {
                    if (isHave) return reply.header(...JSONHDR).status(200).send({ok: false});
                    return reply.header(...JSONHDR).status(204).send();
                }

                if (isHave) return reply.header(...JSONHDR).status(200).send({ok: true});
                return reply.header(...JSONHDR).status(200).send({...payload});
            });
        }

        // Add BFF endpoints
        if (this.bffEndpoints.length > 0 && !this.bffBaseUrl) {
            throw new CrossauthError(ErrorCode.Configuration, "If enabling BFF endpoints, must also define bffBaseUrl");
        }
        if (this.bffBaseUrl == undefined) this.bffBaseUrl = ""; // to stop vs code errors
        if (this.bffBaseUrl.endsWith("/")) this.bffBaseUrl = this.bffBaseUrl.substring(0, this.bffBaseUrl.length-1);
        for (let i=0; i<this.bffEndpoints.length; ++i) {
            const url = this.bffEndpoints[i].url;
            if (url.includes("?") || url.includes("#")) {
                throw new CrossauthError(ErrorCode.Configuration, "BFF urls may not contain query parameters or page fragments");
            }
            if (!(url.startsWith("/"))) {
                throw new CrossauthError(ErrorCode.Configuration, "BFF urls must be absolute and without the HTTP method, hostname or port");

            }
            const methods = this.bffEndpoints[i].methods;
            const matchSubUrls = this.bffEndpoints[i].matchSubUrls??false;
            let route = url;
            if (matchSubUrls) {
                if (!(route.endsWith("/"))) route += "/";
                route += "*";
            }
            for (let i in methods) {
                this.server.app.route({
                    method: methods[i],
                    url: this.prefix + this.bffEndpointName + url,
                    handler: async (request : FastifyRequest<{Body: CsrfBodyType}>, 
                        reply : FastifyReply) =>  {
                        CrossauthLogger.logger.info(j({
                            msg: "Page visit",
                            method: request.method,
                            url: request.url,
                            ip: request.ip,
                            user: request.user?.username
                        }));
                        const url = request.url.substring(this.prefix.length +
                            this.bffEndpointName.length);
                        CrossauthLogger.logger.debug(j({msg: "Resource server URL " + url}))
                        const csrfRequired = 
                            (methods[i] != "GET" && methods[i] != "HEAD" && methods[i] != "OPTIONS");
                        if (this.server.sessionServer && csrfRequired) {
                            // if sessions are enabled, require a csrf token
                            const {error, reply: reply1} =
                                await server.errorIfCsrfInvalid(request,
                                    reply,
                                    this.errorFn);
                            if (error) return reply1;
                        }
                
                        try {
                            const oauthData = 
                                await this.server.getSessionData(request, 
                                    "oauth");
                            if (!oauthData) {
                                return reply.header(...JSONHDR).status(401)
                                    .send({ok: false});
                            }
                            let access_token = oauthData?.access_token;
                            if (oauthData && oauthData.access_token) {
                                const resp = 
                                    await server.oAuthClient?.refreshIfExpired(request,
                                        reply,
                                        oauthData.refresh_token,
                                        oauthData.expires_at);
                                if (resp?.access_token) {
                                    access_token = resp.access_token;
                                }
                            }
                            let headers : {[key:string]: string} = {
                                    'Accept': 'application/json',
                                    'Content-Type': 'application/json',
                            }
                            if (access_token) headers["Authorization"] 
                                = "Bearer " + access_token;
                            let resp : Response;
                            if (request.body) {
                                resp = await fetch(this.bffBaseUrl + url, {
                                    headers:headers,
                                    method: request.method,
                                    body: JSON.stringify(request.body??"{}"),
                                });    
                            } else {
                                resp = await fetch(this.bffBaseUrl + url, {
                                    headers:headers,
                                    method: request.method,
                                });    
                            }
                            const body = await resp.json();
                            for (const pair of resp.headers.entries()) {
                                reply = reply.header(pair[0], pair[1]);
                            }
                            return reply.header(...JSONHDR).status(resp.status)
                                .send(body);
                        } catch (e) {
                            CrossauthLogger.logger.error(j({err: e}));
                            return reply.header(...JSONHDR).status(500).send({});
        
                        }
                    }
    
                });
            }
        }
    }

    private async passwordPost(isApi: boolean,
        request: FastifyRequest<{ Body: PasswordBodyType }>,
        reply: FastifyReply) {
        if (this.server.sessionServer) {
            // if sessions are enabled, require a csrf token
            const {error, reply: reply1} = 
                await this.server.errorIfCsrfInvalid(request,
                    reply,
                    this.errorFn);
            if (error) return reply1;
        }
        try {
            let resp = 
                await this.passwordFlow(request.body.username,
                    request.body.password,
                    request.body.scope);
            if (resp.error == "mfa_required" && 
                resp.mfa_token &&
                this.validFlows.includes(OAuthFlows.PasswordMfa)) {
                const mfa_token = resp.mfa_token;
                resp = await this.passwordMfa(isApi,
                    mfa_token,
                    request.body.scope,
                    request,
                    reply);
                if (resp.error) {
                    const ce = CrossauthError.fromOAuthError(resp.error, 
                        resp.error_description);
                    if (isApi)  {
                        return await this.errorFn(this.server,
                            request,
                            reply,
                            ce);
                    }
                    return reply.view(this.passwordFlowPage, 
                        {
                            user: request.user,
                            username: request.body.username,
                            password: request.body.password,
                            scope: request.body.scope,
                            errorMessage: ce.message,
                            errorCode: ce.code,
                            errorCodeName: ce.codeName,
                            csrfToken: request.csrfToken
                        });            
                }
                return await this.receiveTokenFn(this, request, reply, resp);
               
            } else if (resp.error) {
                const ce = CrossauthError.fromOAuthError(resp.error, 
                    resp.error_description);
                if (isApi)  {
                    return await this.errorFn(this.server, request,reply, ce);
                }
                return reply.view(this.passwordFlowPage, 
                    {
                        user: request.user,
                        username: request.body.username,
                        password: request.body.password,
                        scope: request.body.scope,
                        errorMessage: ce.message,
                        errorCode: ce.code,
                        errorCodeName: ce.codeName,
                        csrfToken: request.csrfToken
                    });            
            }
            return await this.receiveTokenFn(this, request, reply, resp);
        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.error(j({
                msg: "Error receiving token",
                cerr: ce,
                user: request.user?.user
            }));
            CrossauthLogger.logger.debug(j({err: e}));
            if (isApi) return await this.errorFn(this.server,
                request,
                reply,
                ce);
            return reply.view(this.passwordFlowPage, {
                user: request.user,
                username: request.body.username,
                password: request.body.password,
                scope: request.body.scope,
                errorMessage: ce.message,
                errorCode: ce.code,
                errorCodeName: ce.codeName,
                csrfToken: request.csrfToken
            });
        }
    }

    private async passwordMfa(
        isApi : boolean,
        mfa_token: string,
        scope : string|undefined,
        request: FastifyRequest,
        reply: FastifyReply
    ) : Promise<FastifyReply> {

        const authenticatorsResponse = 
            await this.mfaAuthenticators(mfa_token);
        if (authenticatorsResponse.error || 
            !authenticatorsResponse.authenticators ||
            !Array.isArray(authenticatorsResponse.authenticators) ||
            authenticatorsResponse.authenticators.length == 0 ||
            (authenticatorsResponse.authenticators.length > 1 && 
                !authenticatorsResponse.authenticators[0].active )) {
                    if (authenticatorsResponse.error) {
                        return reply.header(...JSONHDR)
                            .send(authenticatorsResponse);
                    } else {
                        return reply.header(...JSONHDR)
                        .send({
                            error: "access_denied",
                            error_description: "No MFA authenticators available"
                    });
        
                }
        }

        const auth = authenticatorsResponse.authenticators[0] as MfaAuthenticatorResponse;
        if (auth.authenticator_type == "otp") {
            const resp = await this.mfaOtpRequest(mfa_token, auth.id);
            if (resp.error || resp.challenge_type!="otp") {
                const ce = CrossauthError.fromOAuthError(resp.error??"server_error",
                    resp.error_description??"Invalid response from MFA OTP challenge");
                if (isApi)  {
                    return await this.errorFn(this.server, request,reply, ce);
                }
                return reply.view(this.errorPage, {
                    user: request.user,
                    errorMessage: ce.message,
                    errorCode: ce.code,
                    errorCodeName: ce.codeName,
                    csrfToken: request.csrfToken
                });            
            }
            return reply.view(this.mfaOtpPage, {
                scope: scope,
                mfa_token: mfa_token,
            });            
        } else if (auth.authenticator_type == "oob") {
            const resp = await this.mfaOobRequest(mfa_token, auth.id);
            if (resp.error || resp.challenge_type!="oob" || !resp.oob_code || 
                resp.binding_method != "prompt") {
                const ce = CrossauthError.fromOAuthError(resp.error??"server_error",
                    resp.error_description??"Invalid response from MFA OOB challenge");
                if (isApi)  {
                    return await this.errorFn(this.server, request,reply, ce);
                }
                return reply.view(this.errorPage, {
                    user: request.user,
                    errorMessage: ce.message,
                    errorCode: ce.code,
                    errorCodeName: ce.codeName,
                    csrfToken: request.csrfToken
                });            
            
            }

            return reply.view(this.mfaOobPage, {
                scope: scope,
                mfa_token: mfa_token,
                oob_channel: auth.oob_channel,
                challenge_type: resp.challenge_type,
                binding_method: resp.binding_method,
                oob_code: resp.oob_code,
                name: auth.name,
            });
        }

        const ce = new CrossauthError(ErrorCode.UnknownError, 
            "Unsupported MFA type " + auth.authenticator_type + " returned");
        if (isApi)  {
            return await this.errorFn(this.server, request,reply, ce);
        }
        return reply.view(this.errorPage, {
            user: request.user,
            errorMessage: ce.message,
            errorCode: ce.code,
            errorCodeName: ce.codeName,
            csrfToken: request.csrfToken
        });            
    }

    private async passwordOtp(isApi: boolean,
        request: FastifyRequest<{Body : PasswordOtpType}>,
        reply: FastifyReply
    ) : Promise<FastifyReply> {

        const resp = await this.mfaOtpComplete(request.body.mfa_token, 
            request.body.otp);
        if (resp.error) {
            const ce = CrossauthError.fromOAuthError(resp.error,
                resp.error_description??"Error completing MFA");
            CrossauthLogger.logger.warn(j({
                msg: "Error completing MFA",
                cerr: ce,
                user: request.user?.user,
                hashedMfaToken: Hasher.hash(request.body.mfa_token),
            }));
            CrossauthLogger.logger.debug(j({err: ce}));
            if (isApi) return await this.errorFn(this.server,
                request,
                reply,
                ce);
            return reply.view(this.mfaOtpPage, {
                user: request.user,
                scope: request.body.scope,
                mfa_token: request.body.mfa_token,
                challenge_tpye: request.body.challenge_type,
                errorMessage: ce.message,
                errorCode: ce.code,
                errorCodeName: ce.codeName,
                csrfToken: request.csrfToken
            });
        }
        return await this.receiveTokenFn(this, request, reply, resp);
    }

    private async passwordOob(isApi: boolean,
        request: FastifyRequest<{Body : PasswordOobType}>,
        reply: FastifyReply
    ) : Promise<FastifyReply> {

        const resp = await this.mfaOobComplete(request.body.mfa_token, 
            request.body.oob_code,
            request.body.binding_code);
        if (resp.error) {
            const ce = CrossauthError.fromOAuthError(resp.error,
                resp.error_description??"Error completing MFA");
            CrossauthLogger.logger.warn(j({
                msg: "Error completing MFA",
                cerr: ce,
                user: request.user?.user,
                hashedMfaToken: Hasher.hash(request.body.mfa_token),
            }));
            CrossauthLogger.logger.debug(j({err: ce}));
            if (isApi) return await this.errorFn(this.server,
                request,
                reply,
                ce);
            return reply.view(this.mfaOobPage, {
                user: request.user,
                scope: request.body.scope,
                oob_code: request.body.mfa_token,
                name: request.body.name,
                challenge_tpye: request.body.challenge_type,
                mfa_token: request.body.mfa_token,
                errorMessage: ce.message,
                errorCode: ce.code,
                errorCodeName: ce.codeName,
                csrfToken: request.csrfToken
            });
        }
        return await this.receiveTokenFn(this, request, reply, resp);
    }

    async refreshIfExpired(request: FastifyRequest,
        reply: FastifyReply,
        refreshToken?: string,
        expiresAt?: number) 
        : Promise<{
            refresh_token?: string,
            access_token?: string,
            expires_at?: number,
            error?: string,
            error_description?: string
        }|undefined> {
            if (!expiresAt || !refreshToken) return undefined;
            if (expiresAt <= Date.now()) {
            try {
                const resp = await this.refreshTokenFlow(refreshToken);
                if (!resp.error && !resp.access_token) {
                    resp.error = "server_error";
                    resp.error_description = "Unexpectedly did not receive error or access token";
                }
                if (!resp.error) {
                    await this.receiveTokenFn(this, request, reply, resp);
                } 
                return {
                    access_token: resp.access_token,
                    refresh_token: resp.refresh_token,
                    expires_at: resp.expires_at,
                    error: resp.error,
                    error_description: resp.error_description
                };
            } catch(e) {
                CrossauthLogger.logger.debug(j({err: e}));
                CrossauthLogger.logger.error(j({
                    cerr: e,
                    msg: "Failed refreshing access token"
                }));
                return {
                    error: "server_error",
                    error_description: "Failed refreshing access token"
                };
            }
        }
        return undefined;
    }
}