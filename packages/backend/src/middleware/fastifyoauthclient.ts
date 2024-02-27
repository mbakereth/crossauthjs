import { OAuthClient, type OAuthClientOptions } from '../oauth/client.ts';
import { FastifyRequest, FastifyReply } from 'fastify';
import { setParameter, ParamType } from '../utils';
import { FastifyServer } from './fastifyserver';
import { CrossauthLogger, OAuthFlows, type OAuthTokenResponse } from '@crossauth/common';
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

export interface FastifyOAuthClientOptions extends OAuthClientOptions {
    siteUrl ?: string,
    prefix? : string,
    errorPage? : string,
    authorizedPage? : string,
    authorizedUrl? : string,
    loginUrl? : string,
    loginProtectedFlows? : string,
    receiveTokenFn? : (client: FastifyOAuthClient, request : FastifyRequest, reply : FastifyReply, oauthResponse : OAuthTokenResponse) => Promise<FastifyReply>;
    tokenResponseType? : "sendJson" | "saveInSessionAndLoad" | "saveInSessionAndRedirect" | "sendInPage" | "custom";
}

async function sendJson(_client: FastifyOAuthClient, _request : FastifyRequest, reply : FastifyReply, oauthResponse : OAuthTokenResponse) : Promise<FastifyReply> {
    return reply.header(...JSONHDR).status(200).send({ok: true, ...oauthResponse});
}

async function sendInPage(_client: FastifyOAuthClient, _request : FastifyRequest, reply : FastifyReply, oauthResponse : OAuthTokenResponse) : Promise<FastifyReply> {
    if (oauthResponse.error) {
        const ce = CrossauthError.fromOAuthError(oauthResponse.error, oauthResponse.error_description);
        return reply.status(ce.httpStatus).view("error.njk", {status: ce.httpStatus, error: ce.message, errorCodeName: ce.codeName, errorCode: ce.code});
    } else if (oauthResponse.access_token) {
        CrossauthLogger.logger.debug("Got access token " + JSON.stringify(jwtDecode(oauthResponse.access_token)));
    }
    try {
        return reply.status(200).view("authorized.njk", {});
    } catch (e) {
        const ce = e as CrossauthError;
        return reply.status(ce.httpStatus).view("error.njk", {status: ce.httpStatus, error: ce.message, errorCodeName: ce.codeName});
    }
}

async function saveInSessionAndLoad(client: FastifyOAuthClient, request : FastifyRequest, reply : FastifyReply, oauthResponse : OAuthTokenResponse) : Promise<FastifyReply> {
    if (oauthResponse.error) {
        const ce = CrossauthError.fromOAuthError(oauthResponse.error, oauthResponse.error_description);
        return reply.status(ce.httpStatus).view("error.njk", {status: ce.httpStatus, error: ce.message, errorCodeName: ce.codeName, errorCode: ce.code});
    } else if (oauthResponse.access_token) {
        CrossauthLogger.logger.debug("Got access token " + JSON.stringify(jwtDecode(oauthResponse.access_token)));
    }
    try {
        await client.server.updateSessionData(request, "oauth", oauthResponse);
        if (!client.authorizedPage) {
            return reply.status(500).view("error.njk", {status: 500, error: "Authorized url not configured", errorCodeName: ErrorCode[ErrorCode.Configuration], errorCode: ErrorCode.Configuration});
        }
        return reply.status(200).view(client.authorizedPage, {});
    } catch (e) {
        const ce = e as CrossauthError;
        return reply.status(ce.httpStatus).view("error.njk", {status: ce.httpStatus, error: ce.message, errorCodeName: ce.codeName});
    }
}

async function saveInSessionAndRedirect(client: FastifyOAuthClient, request : FastifyRequest, reply : FastifyReply, oauthResponse : OAuthTokenResponse) : Promise<FastifyReply> {
    if (oauthResponse.error) {
        const ce = CrossauthError.fromOAuthError(oauthResponse.error, oauthResponse.error_description);
        return reply.status(ce.httpStatus).view("error.njk", {status: ce.httpStatus, error: ce.message, errorCodeName: ce.codeName, errorCode: ce.code});
    } else if (oauthResponse.access_token) {
        CrossauthLogger.logger.debug("Got access token " + JSON.stringify(jwtDecode(oauthResponse.access_token)));
    }
    try {
        await client.server.updateSessionData(request, "oauth", oauthResponse);
        if (!client.authorizedUrl) {
            return reply.status(500).view("error.njk", {status: 500, error: "Authorized url not configured", errorCodeName: ErrorCode[ErrorCode.Configuration], errorCode: ErrorCode.Configuration});

        }
        return reply.redirect(client.authorizedUrl);
    } catch (e) {
        const ce = e as CrossauthError;
        return reply.status(ce.httpStatus).view("error.njk", {status: ce.httpStatus, error: ce.message, errorCodeName: ce.codeName});
    }
}

export class FastifyOAuthClient extends OAuthClient {
    server : FastifyServer;
    private siteUrl : string = "/";
    private prefix : string = "/";
    errorPage : string = "error.njk";
    authorizedPage : string = "authorized.njk";
    authorizedUrl : string = "authorized.njk";
    private receiveTokenFn : (client : FastifyOAuthClient, request : FastifyRequest, reply : FastifyReply, oauthResponse : OAuthTokenResponse) => Promise<FastifyReply> = sendJson;
    private loginUrl : string = "";
    private loginProtectedFlows : string[] = [];
    private tokenResponseType :  "sendJson" | "saveInSessionAndLoad" | "saveInSessionAndRedirect" | "sendInPage" | "custom" = "sendJson";

    constructor(server : FastifyServer, authServerBaseUri : string, options : FastifyOAuthClientOptions) {
        super(authServerBaseUri, options);
        this.server = server;
        setParameter("siteUrl", ParamType.String, this, options, "SITE_URL", true);
        setParameter("tokenResponseType", ParamType.String, this, options, "OAUTH_TOKEN_RESPONSE_TYPE", true);
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
                    return reply.status(ce.httpStatus).view(this.errorPage, {status: ce.httpStatus, error: ce.message, errorCode: ce.code, errorCodeName: ce.codeName});
                }
                CrossauthLogger.logger.debug(`Authorization code flow: redirecting to ${url}`);
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
                    return reply.status(ce.httpStatus).view(this.errorPage, {status: ce.httpStatus, error: ce.message, errorCode: ce.code, errorCodeName: ce.codeName});
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
                return await this.receiveTokenFn(this, request, reply, resp);
            });
        }

    }
}