import { OAuthClient, type OAuthClientOptions } from '../oauth/client.ts';
import { FastifyRequest, FastifyReply } from 'fastify';
import { setParameter, ParamType } from '../utils';
import { FastifyServer, FastifyErrorFn } from './fastifyserver';
import { CrossauthLogger, OAuthFlows, type OAuthTokenResponse, j } from '@crossauth/common';
import { CrossauthError, ErrorCode  } from '@crossauth/common';
import { jwtDecode } from "jwt-decode";

const JSONHDR : [string,string] = ['Content-Type', 'application/json; charset=utf-8'];

interface AuthorizeQueryType {
    scope? : string,
}

interface RedirectUriQueryType {
    code? : string,
    state?: string,
    error? : string,
    error_description? : string,
}

interface ClientCredentialsBodyType {
    scope? : string,
    csrfToken? : string,
}

export interface FastifyOAuthClientOptions extends OAuthClientOptions {
    siteUrl ?: string,
    prefix? : string,
    sessionDataName? : string,
    errorPage? : string,
    authorizedPage? : string,
    authorizedUrl? : string,
    loginUrl? : string,
    loginProtectedFlows? : string,
    receiveTokenFn? : (client: FastifyOAuthClient, request : FastifyRequest, reply : FastifyReply, oauthResponse : OAuthTokenResponse) => Promise<FastifyReply>;
    errorFn? :FastifyErrorFn ;
    tokenResponseType? : "sendJson" | "saveInSessionAndLoad" | "saveInSessionAndRedirect" | "sendInPage" | "custom";
    errorResponseType? : "sendJson" | "errorPage" | "custom";
}

async function jsonError(_server : FastifyServer, _request : FastifyRequest, reply : FastifyReply, ce : CrossauthError) : Promise<FastifyReply> {
    CrossauthLogger.logger.error(j({err: ce}));
    return reply.header(...JSONHDR).status(ce.httpStatus).send({ok: false, status: ce.httpStatus, errorMessage: ce.message, errorMessages: ce.messages, errorCode: ce.code, errorCodeName: ce.codeName});
}

async function pageError(server: FastifyServer, _request : FastifyRequest, reply : FastifyReply,  ce : CrossauthError) : Promise<FastifyReply> {
    CrossauthLogger.logger.error(j({err: ce}));
    return reply.status(ce.httpStatus).view(server.errorPage, {status: ce.httpStatus, errorMessage: ce.message, errorMessages: ce.messages, errorCodeName: ce.codeName});
}

async function sendJson(_client: FastifyOAuthClient, _request : FastifyRequest, reply : FastifyReply, oauthResponse : OAuthTokenResponse) : Promise<FastifyReply> {
    return reply.header(...JSONHDR).status(200).send({ok: true, ...oauthResponse});
}

async function sendInPage(client: FastifyOAuthClient, _request : FastifyRequest, reply : FastifyReply, oauthResponse : OAuthTokenResponse) : Promise<FastifyReply> {
    if (oauthResponse.error) {
        const ce = CrossauthError.fromOAuthError(oauthResponse.error, oauthResponse.error_description);
        return reply.status(ce.httpStatus).view(client.errorPage, {status: ce.httpStatus, errorMessage: ce.message, errorCodeName: ce.codeName, errorCode: ce.code});
    } else if (oauthResponse.access_token) {
        CrossauthLogger.logger.debug("Got access token " + JSON.stringify(jwtDecode(oauthResponse.access_token)));
    }
    try {
        return reply.status(200).view(client.authorizedPage, {});
    } catch (e) {
        const ce = e as CrossauthError;
        return reply.status(ce.httpStatus).view(client.errorPage, {status: ce.httpStatus, errorMessage: ce.message, errorCodeName: ce.codeName});
    }
}

async function saveInSessionAndLoad(client: FastifyOAuthClient, request : FastifyRequest, reply : FastifyReply, oauthResponse : OAuthTokenResponse) : Promise<FastifyReply> {
    if (oauthResponse.error) {
        const ce = CrossauthError.fromOAuthError(oauthResponse.error, oauthResponse.error_description);
        return reply.status(ce.httpStatus).view(client.errorPage, {status: ce.httpStatus, errorMessage: ce.message, errorCodeName: ce.codeName, errorCode: ce.code});
    } else if (oauthResponse.access_token) {
        CrossauthLogger.logger.debug("Got access token " + JSON.stringify(jwtDecode(oauthResponse.access_token)));
    }
    try {
        let sessionCookieValue = client.server.getSessionCookieValue(request);
        if (!sessionCookieValue) {
            sessionCookieValue = await client.server.createAnonymousSession(request, reply, {[client.sessionDataName] : oauthResponse});
        } else {
            await client.server.updateSessionData(request, client.sessionDataName, oauthResponse);
        }
        if (!client.authorizedPage) {
            return reply.status(500).view(client.errorPage, {status: 500, errorMessage: "Authorized url not configured", errorCodeName: ErrorCode[ErrorCode.Configuration], errorCode: ErrorCode.Configuration});
        }
        return reply.status(200).view(client.authorizedPage, {});
    } catch (e) {
        const ce = e as CrossauthError;
        return reply.status(ce.httpStatus).view(client.errorPage, {status: ce.httpStatus, errorMessage: ce.message, errorCodeName: ce.codeName});
    }
}

async function saveInSessionAndRedirect(client: FastifyOAuthClient, request : FastifyRequest, reply : FastifyReply, oauthResponse : OAuthTokenResponse) : Promise<FastifyReply> {
    if (oauthResponse.error) {
        const ce = CrossauthError.fromOAuthError(oauthResponse.error, oauthResponse.error_description);
        return reply.status(ce.httpStatus).view(client.errorPage, {status: ce.httpStatus, errorMessage: ce.message, errorCodeName: ce.codeName, errorCode: ce.code});
    } else if (oauthResponse.access_token) {
        CrossauthLogger.logger.debug("Got access token " + JSON.stringify(jwtDecode(oauthResponse.access_token)));
    }
    try {
        let sessionCookieValue = client.server.getSessionCookieValue(request);
        if (!sessionCookieValue) {
            sessionCookieValue = await client.server.createAnonymousSession(request, reply, {[client.sessionDataName] : oauthResponse});
        } else {
            await client.server.updateSessionData(request, client.sessionDataName, oauthResponse);
        }
        if (!client.authorizedUrl) {
            return reply.status(500).view(client.errorPage, {status: 500, errorMessage: "Authorized url not configured", errorCodeName: ErrorCode[ErrorCode.Configuration], errorCode: ErrorCode.Configuration});

        }
        return reply.redirect(client.authorizedUrl);
    } catch (e) {
        const ce = e as CrossauthError;
        return reply.status(ce.httpStatus).view(client.errorPage, {status: ce.httpStatus, errorMessage: ce.message, errorCodeName: ce.codeName});
    }
}

export class FastifyOAuthClient extends OAuthClient {
    server : FastifyServer;
    private siteUrl : string = "/";
    private prefix : string = "/";
    errorPage : string = "error.njk";
    authorizedPage : string = "authorized.njk";
    authorizedUrl : string = "authorized.njk";
    sessionDataName : string = "oauth";
    private receiveTokenFn : (client : FastifyOAuthClient, request : FastifyRequest, reply : FastifyReply, oauthResponse : OAuthTokenResponse) => Promise<FastifyReply> = sendJson;
    private errorFn : FastifyErrorFn = jsonError;
    private loginUrl : string = "";
    private loginProtectedFlows : string[] = [];
    private tokenResponseType :  "sendJson" | "saveInSessionAndLoad" | "saveInSessionAndRedirect" | "sendInPage" | "custom" = "sendJson";
    private errorResponseType :  "sendJson" | "pageError" | "custom" = "sendJson";

    constructor(server : FastifyServer, authServerBaseUri : string, options : FastifyOAuthClientOptions) {
        super(authServerBaseUri, options);
        this.server = server;
        setParameter("sessionDataName", ParamType.String, this, options, "OAUTH_SESSION_DATA_NAME");
        setParameter("siteUrl", ParamType.String, this, options, "SITE_URL", true);
        setParameter("tokenResponseType", ParamType.String, this, options, "OAUTH_TOKEN_RESPONSE_TYPE");
        setParameter("errorResponseType", ParamType.String, this, options, "OAUTH_ERROR_RESPONSE_TYPE");
        setParameter("prefix", ParamType.String, this, options, "PREFIX");
        setParameter("loginUrl", ParamType.String, this, options, "LOGIN_URL");
        setParameter("errorPage", ParamType.String, this, options, "ERROR_PAGE");
        setParameter("authorizedPage", ParamType.String, this, options, "AUTHORIZED_PAGE");
        setParameter("authorizedUrl", ParamType.String, this, options, "AUTHORIZED_URL");
        setParameter("loginProtectedFlows", ParamType.StringArray, this, options, "OAUTH_LOGIN_PROTECTED_FLOWS");
        if (this.loginProtectedFlows.length == 1 && this.loginProtectedFlows[0] == OAuthFlows.All) {
            this.loginProtectedFlows = this.validFlows;
        } else {
            if (!OAuthFlows.areAllValidFlows(this.loginProtectedFlows)) {
                throw new CrossauthError(ErrorCode.Configuration, "Invalid flows specificied in " + this.loginProtectedFlows.join(","));
            }
        }

        if (this.tokenResponseType == "custom" && !options.receiveTokenFn) {
            throw new CrossauthError(ErrorCode.Configuration, "Token response type of custom selected but receiveTokenFn not defined");
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
            throw new CrossauthError(ErrorCode.Configuration, "Error response type of custom selected but errorFn not defined");
        }
        if (this.errorResponseType == "custom" && options.errorFn) {
            this.errorFn = options.errorFn;
        } else if (this.errorResponseType == "sendJson") {
            this.errorFn = jsonError;
        } else if (this.errorResponseType == "pageError") {
            this.errorFn = pageError;
        }

        
        if (this,this.loginProtectedFlows.length > 0 && this.loginUrl == "") {
            throw new CrossauthError(ErrorCode.Configuration, "loginUrl must be set if protecting oauth endpoints");
        }
        
        if (!this.prefix.endsWith("/")) this.prefix += "/";
        this.redirectUri = this.siteUrl + this.prefix + "authzcode";

        if (this.validFlows.includes(OAuthFlows.AuthorizationCode)) {
            this.server.app.get(this.prefix+'authzcodeflow', async (request : FastifyRequest<{ Querystring: AuthorizeQueryType }>, reply : FastifyReply) =>  {
                if (!request.user && this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCode)) {
                    return reply.redirect(302, this.loginUrl+"?next="+encodeURIComponent(request.url));
                }          
                const {url, error, error_description} = await this.startAuthorizationCodeFlow(request.query.scope);
                if (error || !url) {
                    const ce = CrossauthError.fromOAuthError(error||"server_error", error_description);
                    return await this.errorFn(this.server, request, reply, ce)
                }
                CrossauthLogger.logger.debug(j({msg: `Authorization code flow: redirecting to ${url}`}));
                return reply.redirect(url);
            });
        }

        if (this.validFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE)) {
            this.server.app.get(this.prefix+'authzcodeflowpkce', async (request : FastifyRequest<{ Querystring: AuthorizeQueryType }>, reply : FastifyReply) =>  {
                if (!request.user && this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE)) {
                    return reply.redirect(302, this.loginUrl+"?next="+encodeURIComponent(request.url));
                }               
                const {url, error, error_description} = await this.startAuthorizationCodeFlow(request.query.scope, true);
                if (error || !url) {
                    const ce = CrossauthError.fromOAuthError(error||"server_error", error_description);
                    return await this.errorFn(this.server, request, reply, ce)
                }
                return reply.redirect(url);
            });
        }

        if (this.validFlows.includes(OAuthFlows.AuthorizationCode) || this.validFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE)) {
            this.server.app.get(this.prefix+'authzcode', async (request : FastifyRequest<{ Querystring: RedirectUriQueryType }>, reply : FastifyReply) =>  {
                if (!request.user && (this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE) || this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCode))) {
                    return reply.redirect(302, this.loginUrl+"?next="+encodeURIComponent(request.url));
                }               
                const resp = await this.redirectEndpoint(request.query.code, request.query.state, request.query.error, request.query.error_description);
                try {
                    return await this.receiveTokenFn(this, request, reply, resp);
                } catch (e) {
                    let code = ErrorCode.UnknownError
                    let message = e instanceof Error ? e.message : "Unknown error";
                    const ce = (e instanceof CrossauthError) ? e as CrossauthError : new CrossauthError(code, message);
                    CrossauthLogger.logger.error(j({err: e}));
                    return await this.errorFn(this.server, request, reply, ce)
                }
});
        }

        if (this.validFlows.includes(OAuthFlows.ClientCredentials)) {
            this.server.app.post(this.prefix+'clientcredflow', async (request : FastifyRequest<{ Body: ClientCredentialsBodyType }>, reply : FastifyReply) =>  {
                if (this.server.sessionServer) {
                    // if sessions are enabled, require a csrf token
                    const error = await server.errorIfCsrfInvalid(request, reply, this.errorFn);
                    if (error) return error;
                }
                if (!request.user && (this.loginProtectedFlows.includes(OAuthFlows.ClientCredentials))) {
                    return reply.redirect(302, this.loginUrl+"?next="+encodeURIComponent(request.url));
                }               
                try {
                    const resp = await this.clientCredentialsFlow(request.body?.scope);
                    return await this.receiveTokenFn(this, request, reply, resp);
                } catch (e) {
                    let code = ErrorCode.UnknownError
                    let message = e instanceof Error ? e.message : "Unknown error";
                    const ce = (e instanceof CrossauthError) ? e as CrossauthError : new CrossauthError(code, message);
                    CrossauthLogger.logger.error(j({err: e}));
                    return await this.errorFn(this.server, request, reply, ce)
                }
            });
        }
    }
}