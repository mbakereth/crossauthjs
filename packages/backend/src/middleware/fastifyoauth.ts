import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { Server, IncomingMessage, ServerResponse } from 'http'
import { OAuthClientStorage } from '../storage';
import { OAuthAuthorizationServer, OAuthFlows, type OAuthAuthorizationServerOptions } from '../oauth/authserver';
import { setParameter, ParamType } from '../utils';
import { Hasher } from '../hasher';
import { CrossauthLogger, OAuthErrorCode, j } from '@crossauth/common';
import { oauthErrorStatus, errorCodeFromAuthErrorString } from '@crossauth/common';
import { FastifyServer, ERROR_401, ERROR_500, DEFAULT_ERROR } from './fastifyserver';
const JSONHDR : [string,string] = ['Content-Type', 'application/json; charset=utf-8'];

export interface FastifyAuthorizationServerOptions extends OAuthAuthorizationServerOptions {
    errorPage? : string,
    oauthAuthorizePagePage? : string,
}

interface AuthorizeQueryType {
    response_type : string,
    client_id : string,
    redirect_uri : string,
    scope? : string,
    state: string,
    code_challenge? : string,
    code_challenge_method : string,
    unauthorized_uri? : string,
}

interface AuthorizeBodyType {
    csrfToken : string,
    response_type : string,
    client_id : string,
    redirect_uri : string,
    scope? : string,
    state: string,
    code_challenge? : string,
    code_challenge_method : string,
    authorized : string, // true or false 
    unauthorized_uri? : string,
}

interface TokenBodyType {
    grant_type : string,
    client_id : string,
    client_secret: string,
    redirect_uri : string,
    scope? : string,
    state: string,
    code? : string,
    code_verifier? : string,
}

export class FastifyAuthorizationServer {
    private app : FastifyInstance<Server, IncomingMessage, ServerResponse>;
    private prefix : string = "/";
    private authServer : OAuthAuthorizationServer;
    private errorPage? : string;
    private oauthAuthorizePage : string = "authorize.njk";

    constructor(
        app: FastifyInstance<Server, IncomingMessage, ServerResponse>,
        fastifyServer : FastifyServer,
        prefix : string,
        clientStorage : OAuthClientStorage, 
        options : FastifyAuthorizationServerOptions) {

        this.prefix = prefix;
        this.app = app;

        this.authServer = new OAuthAuthorizationServer(clientStorage, options);

        setParameter("errorPage", ParamType.String, this, options, "ERROR_PAGE");
        setParameter("oauthAuthorizePage", ParamType.String, this, options, "OAUTH_AUTHORIZE_PAGE");

        if (this.authServer.validFlows.includes(OAuthFlows.AuthorizationCode) || this.authServer.validFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE)) {

            app.get(this.prefix+'authorize', async (request : FastifyRequest<{ Querystring: AuthorizeQueryType }>, reply : FastifyReply) =>  {
                if (!request.user) return reply.redirect(302, prefix+"login?next="+encodeURI(request.url));
                return reply.view(this.oauthAuthorizePage, {
                    user: request.user,
                    response_type: request.query.response_type,
                    client_id : request.query.client_id,
                    redirect_uri: request.query.redirect_uri,
                    scope: request.query.scope,
                    state: request.query.state,
                    code_challenge: request.query.code_challenge,
                    code_challenge_method: request.query.code_challenge_method,
                    csrfToken: request.csrfToken,
                });
            });

            this.app.post(this.prefix+'authorize', async (request : FastifyRequest<{ Body: AuthorizeBodyType }>, reply : FastifyReply) => {
                CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'changepassword', ip: request.ip, user: request.user?.username}));

                let error : string|undefined;
                let errorDescription : string|undefined;
                let code : string|undefined;

                // this should not be called if a user is not logged in
                if (!request.user) return FastifyServer.sendPageError(reply, 401, this.errorPage);  // not allowed here if not logged in
                let csrfCookie : string|undefined;
                try {
                    csrfCookie = await fastifyServer.validateCsrfToken(request);
                }
                catch (e) {
                    error = "server_error";
                    errorDescription = "Invalid csrf cookie received";
                    CrossauthLogger.logger.error(j({msg: errorDescription, hashedCsrfCookie: csrfCookie?Hasher.hash(csrfCookie) : undefined}));
                }
   
                // Create an authorizatin code
                if (!error) {
                    if (request.body.authorized == "true") {
                        const resp = await this.authServer.authorizeGetEndpoint({
                            responseType: request.body.response_type,
                            clientId : request.body.client_id,
                            redirectUri: request.body.redirect_uri,
                            scope: request.body.scope,
                            state: request.body.state,
                            codeChallenge: request.body.code_challenge,
                            codeChallengeMethod: request.body.code_challenge_method
                        });
                        code = resp.code;
                    }

                    // couldn't create an authorization code
                    if (error || !code) {
                        if (!error) error = "server_error";
                        if (errorDescription) errorDescription = "Neither code nor error received";
                        let status = oauthErrorStatus(error);
                        const errorCode = errorCodeFromAuthErrorString(error);
                        CrossauthLogger.logger.error(j({msg: errorDescription, errorCode: errorCode, errorCodeName: error}));
                        if (this.errorPage) {
                            return reply.status(status).view(this.errorPage, {status: status, error: errorDescription, errorCode: errorCode, errorCodeName: error});
                        } else {
                            return reply.status(status).send(DEFAULT_ERROR[status]||ERROR_500);
                        }
                    }

                    return reply.redirect(this.authServer.redirectUri(
                        request.body.redirect_uri,
                        code,
                        request.body.state
                    )); 

                } else {

                    // resource owner did not grant access
                    const error = OAuthErrorCode[OAuthErrorCode.access_denied];
                    const errorDescription = "You have not granted access";
                    let status = 401;
                    const errorCode = errorCodeFromAuthErrorString(error);
                    CrossauthLogger.logger.error(j({msg: errorDescription, errorCode: errorCode, errorCodeName: error}));
                    if (request.body.unauthorized_uri) {
                        try {
                            OAuthAuthorizationServer.validateUri(request.body.unauthorized_uri);
                            return reply.redirect(request.body.unauthorized_uri); 
                        } catch (e) {
                            CrossauthLogger.logger.error(j({msg: `Invalid unauthorizerdUri ${request.body.unauthorized_uri}`}));
                        }
                    }
                    if (this.errorPage) {
                        return reply.status(status).view(this.errorPage, {status: status, error: errorDescription, errorCode: errorCode, errorCodeName: error});
                    } else {
                        return reply.status(status).send(ERROR_401);
                    }
                }
            });
        }

        if (this.authServer.validFlows.includes(OAuthFlows.AuthorizationCode) || this.authServer.validFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE)) {

            this.app.post(this.prefix+'token', async (request : FastifyRequest<{ Body: TokenBodyType }>, reply : FastifyReply) => {

                const flow = this.authServer.inferFlowFromPost(request.body.grant_type, request.body.code_verifier);
                let username : string|undefined;
                if (flow == OAuthFlows.AuthorizationCode || flow == OAuthFlows.AuthorizationCodeWithPKCE) {
                    if (!request.user) {
                        CrossauthLogger.logger.error(j({msg: "Cannot provide a token - user is not logged in"}));
                        return reply.header(...JSONHDR).status(401).send("Cannot complete authorization flow - user is not logged");
                    }
                    username = request.user.username;
                }

                const resp = await this.authServer.tokenPostEndpoint({
                    grantType: request.body.grant_type,
                    clientId : request.body.client_id,
                    clientSecret : request.body.client_secret,
                    scope: request.body.scope,
                    codeVerifier: request.body.code_verifier,
                    code: request.body.code,
                    username : username,
                });

                if (resp.error || !resp.accessToken) {
                    let error = "server_error";
                    let errorDescription = "Neither code nor error received";
                    if (resp.error) error = resp.error;
                    if (resp.errorDescription) errorDescription = resp.errorDescription;
                    let status = oauthErrorStatus(error);
                    const errorCode = errorCodeFromAuthErrorString(error);
                    CrossauthLogger.logger.error(j({msg: errorDescription, errorCode: errorCode, errorCodeName: error}));
                return reply.header(...JSONHDR).status(status).send(resp);
                }
                return reply.header(...JSONHDR).send(resp);
            });
        }
    }
}