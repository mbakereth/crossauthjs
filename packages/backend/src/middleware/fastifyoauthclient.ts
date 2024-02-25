import { OAuthClient, type OAuthClientOptions } from '../oauth/client.ts';
import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { Server, IncomingMessage, ServerResponse } from 'http'
import { setParameter, ParamType } from '../utils';
import { CrossauthLogger, OAuthFlows, type OAuthTokenResponse } from '@crossauth/common';
import { CrossauthError, ErrorCode  } from '@crossauth/common';

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
    loginUrl? : string,
    loginProtectedFlows? : string,
    receiveTokenFn? : (request : FastifyRequest, reply : FastifyReply, oauthResponse : OAuthTokenResponse) => Promise<FastifyReply>;
}

async function defaultTokenFn(_request : FastifyRequest, reply : FastifyReply, oauthResponse : OAuthTokenResponse) : Promise<FastifyReply> {
    return reply.header(...JSONHDR).status(200).send({ok: true, ...oauthResponse});
}

export class FastifyOAuthClient extends OAuthClient {
    private siteUrl : string = "/";
    private prefix : string = "/";
    private receiveTokenFn : (request : FastifyRequest, reply : FastifyReply, oauthResponse : OAuthTokenResponse) => Promise<FastifyReply> = defaultTokenFn;
    private loginUrl : string = "";
    private loginProtectedFlows : string[] = [];

    constructor(app: FastifyInstance<Server, IncomingMessage, ServerResponse>, options : FastifyOAuthClientOptions) {
        super(options);
        setParameter("siteUrl", ParamType.String, this, options, "SITE_URL", true);
        setParameter("prefix", ParamType.String, this, options, "PREFIX");
        setParameter("loginUrl", ParamType.String, this, options, "LOGIN_URL");
        setParameter("loginProtectedFlows", ParamType.StringArray, this, options, "OAUTH_LOGIN_PROTECTED_FLOWS");
        if (this.loginProtectedFlows.length == 1 && this.loginProtectedFlows[0] == OAuthFlows.All) {
            this.loginProtectedFlows = this.validFlows;
        } else {
            if (!OAuthFlows.areAllValidFlows(this.loginProtectedFlows)) {
                throw new CrossauthError(ErrorCode.Configuration, "Invalid flows specificied in " + this.loginProtectedFlows.join(","));
            }
        }
        if (options.receiveTokenFn) {
            this.receiveTokenFn = options.receiveTokenFn;
        }
        if (this,this.loginProtectedFlows.length > 0 && this.loginUrl == "") {
            throw new CrossauthError(ErrorCode.Configuration, "loginUrl must be set if protecting oauth endpoints");
        }
        
        if (!this.prefix.endsWith("/")) this.prefix += "/";
        this.redirectUri = this.siteUrl + this.prefix + "authzcode";

        if (this.validFlows.includes(OAuthFlows.AuthorizationCode)) {
            app.get(this.prefix+'authzcodeflow', async (request : FastifyRequest<{ Querystring: AuthorizeQueryType }>, reply : FastifyReply) =>  {
                if (!request.user && this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCode)) {
                    return reply.redirect(302, this.loginUrl+"?next="+encodeURIComponent(request.url));
                }          
                const url = await this.startAuthorizationCodeFlow(request.query.scope);
                CrossauthLogger.logger.debug(`Authorization code flow: redirecting to ${url}`);
                return reply.redirect(url);
            });
        }

        if (this.validFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE)) {
            app.get(this.prefix+'authzcodeflowpkce', async (request : FastifyRequest<{ Querystring: AuthorizeQueryType }>, reply : FastifyReply) =>  {
                if (!request.user && this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE)) {
                    return reply.redirect(302, this.loginUrl+"?next="+encodeURIComponent(request.url));
                }               
                const url = await this.startAuthorizationCodeFlow(request.query.scope, true);
                return reply.redirect(url);
            });
        }

        if (this.validFlows.includes(OAuthFlows.AuthorizationCode) || this.validFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE)) {
            app.get(this.prefix+'authzcode', async (request : FastifyRequest<{ Querystring: RedirectUriQueryType }>, reply : FastifyReply) =>  {
                if (!request.user && (this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE) || this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCode))) {
                    return reply.redirect(302, this.loginUrl+"?next="+encodeURIComponent(request.url));
                }               
                const resp = await this.redirectEndpoint(request.query.code, request.query.state, request.query.error, request.query.error_description);
                return await this.receiveTokenFn(request, reply, resp);
            });
        }

    }
}