import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { Server, IncomingMessage, ServerResponse } from 'http'
import { OAuthClientStorage, KeyStorage } from '../storage';
import { OAuthAuthorizationServer, type OAuthAuthorizationServerOptions } from '../oauth/authserver';
import { setParameter, ParamType } from '../utils';
import { Hasher } from '../hasher';
import { CrossauthError, CrossauthLogger, OAuthErrorCode, OpenIdConfiguration, j } from '@crossauth/common';
import { OAuthFlows } from '@crossauth/common';
import { oauthErrorStatus, errorCodeFromAuthErrorString, ErrorCode } from '@crossauth/common';
import { FastifyServer, ERROR_500, DEFAULT_ERROR } from './fastifyserver';


const JSONHDR : [string,string] = ['Content-Type', 'application/json; charset=utf-8'];

export interface FastifyAuthorizationServerOptions extends OAuthAuthorizationServerOptions {
    errorPage? : string,
    oauthAuthorizePage? : string,
}

interface AuthorizeQueryType {
    response_type : string,
    client_id : string,
    redirect_uri : string,
    scope? : string,
    state: string,
    code_challenge? : string,
    code_challenge_method : string,
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
    private fastifyServer : FastifyServer;
    private app : FastifyInstance<Server, IncomingMessage, ServerResponse>;
    private prefix : string;
    private loginUrl : string;
    readonly authServer : OAuthAuthorizationServer;
    private oauthAuthorizePage : string = "authorize.njk";
    private errorPage : string = "error.njk";
    private clientStorage : OAuthClientStorage;

    constructor(
        app: FastifyInstance<Server, IncomingMessage, ServerResponse>,
        fastifyServer : FastifyServer,
        prefix : string,
        loginUrl : string,
        clientStorage : OAuthClientStorage, 
        keyStorage : KeyStorage,
        options : FastifyAuthorizationServerOptions) {

        this.prefix = prefix;
        this.loginUrl = loginUrl;
        this.app = app;
        this.fastifyServer = fastifyServer;
        this.clientStorage = clientStorage;

        this.authServer = new OAuthAuthorizationServer(this.clientStorage, keyStorage, options);

        setParameter("errorPage", ParamType.String, this, options, "ERROR_PAGE");
        setParameter("oauthAuthorizePage", ParamType.String, this, options, "OAUTH_AUTHORIZE_PAGE");

        app.get(this.prefix+'.well-known/openid-configuration', async (_request : FastifyRequest, reply : FastifyReply) =>  {
            return reply.header(...JSONHDR).status(200).send(
                this.authServer.oidcConfiguration({
                    authorizeEndpoint: prefix+"authorize", 
                    tokenEndpoint: prefix+"token", 
                    jwksUri: prefix+"jwks", 
                    additionalClaims: []}));
        });

        app.get(this.prefix+'jwks', async (_request : FastifyRequest, reply : FastifyReply) =>  {
            return reply.header(...JSONHDR).status(200).send(
                this.authServer.jwks());
        });

        if (this.authServer.validFlows.includes(OAuthFlows.AuthorizationCode) || this.authServer.validFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE)) {

            app.get(this.prefix+'authorize', async (request : FastifyRequest<{ Querystring: AuthorizeQueryType }>, reply : FastifyReply) =>  {
                CrossauthLogger.logger.info(j({msg: "Page visit", method: 'GET', url: this.prefix+'authorize', ip: request.ip, user: request.user?.username}));
                if (!request.user) return reply.redirect(302, this.loginUrl+"?next="+encodeURIComponent(request.url));
                let error : string|undefined;
                let errorDescription : string|undefined;

                // this just checks they are valid strings and not empty if required, to avoid XSR vulnerabilities
                CrossauthLogger.logger.debug(j({msg: "validating authorize parameters"}))
                let {error_description} = this.authServer.validateAuthorizeParameters(request.query);
                let ce : CrossauthError|undefined = undefined;
                if (error_description) {
                    ce = new CrossauthError(ErrorCode.BadRequest, error_description);
                    CrossauthLogger.logger.debug(j({msg: "authorize parameter invalid " + error_description}));
                }  else {
                    CrossauthLogger.logger.debug(j({msg: "authorize parameter valid"}));

                }

                if (ce) {
                    if (this.errorPage) {
                        return reply.status(ce.httpStatus).view(this.errorPage, {status: ce.httpStatus, error: ce.message, errorCode: ce.code, errorCodeName: ce.codeName});
                    } else {
                        let status : "401" | "400" | "500" = "500"
                        switch (ce.httpStatus) {
                            case 401: status = "401" ; break;
                            case 400: status = "400" ; break;
                        }
                        return reply.status(ce.httpStatus).send(DEFAULT_ERROR[status]||ERROR_500);
                    }
                }
                let hasAllScopes = false;
                if (request.query.scope) {
                    hasAllScopes = await this.authServer.hasAllScopes(request.query.client_id, request.user, request.query.scope.split(" "));

                } else {
                    hasAllScopes = await this.authServer.hasAllScopes(request.query.client_id, request.user, [null]);

                }
                if (hasAllScopes) {
                    // all scopes have been previously authorized - create an authorization code
                    return this.authorize(request, reply, true, {
                        responseType: request.query.response_type,
                        clientId : request.query.client_id,
                        redirectUri: request.query.redirect_uri,
                        scope: request.query.scope,
                        state: request.query.state,
                        codeChallenge: request.query.code_challenge,
                        codeChallengeMethod: request.query.code_challenge_method,
                    });
                   
                } else {
                    // requesting new scopes - redirect to page to ask user for it
                    try {
                        CrossauthLogger.logger.debug(j({msg: "Looking up client " + request.query.client_id}));
                        const client = await this.clientStorage.getClient(request.query.client_id);
                        CrossauthLogger.logger.debug(j({msg: "Client " + JSON.stringify(client)}));
                        
                        return reply.view(this.oauthAuthorizePage, {
                            user: request.user,
                            response_type: request.query.response_type,
                            client_id : request.query.client_id,
                            client_name : client.clientName,
                            redirect_uri: request.query.redirect_uri,
                            scope: request.query.scope,
                            scopes: request.query.scope ? request.query.scope.split(" ") : undefined,
                            state: request.query.state,
                            code_challenge: request.query.code_challenge,
                            code_challenge_method: request.query.code_challenge_method,
                            csrfToken: request.csrfToken,
                        });
                    } catch (e) {
                        const ce = e as CrossauthError;
                        if (this.errorPage) {
                            return reply.status(ce.httpStatus).view(this.errorPage, {status: ce.httpStatus, error: "Invalid client given", errorCode: ErrorCode.UnauthorizedClient, errorCodeName: ErrorCode[ErrorCode.UnauthorizedClient]});
                        } else {
                            return reply.status(ce.httpStatus).send(DEFAULT_ERROR[401]);
                        }
    
                    }
                }
            });

            this.app.post(this.prefix+'authorize', async (request : FastifyRequest<{ Body: AuthorizeBodyType }>, reply : FastifyReply) => {
                CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'authorize', ip: request.ip, user: request.user?.username}));

                // this should not be called if a user is not logged in
                if (!request.user) return FastifyServer.sendPageError(reply, 401, this.errorPage);  // not allowed here if not logged in
                let csrfCookie : string|undefined;
                let ce : CrossauthError|undefined = undefined;
                try {
                    csrfCookie = await this.fastifyServer.validateCsrfToken(request);
                }
                catch (e) {
                    if (e instanceof CrossauthError) {
                        ce = e;
                    } else {
                        ce = new CrossauthError(ErrorCode.UnknownError,  "Invalid csrf cookie received")
                    }

                    CrossauthLogger.logger.error(j({msg: ce.message, hashedCsrfCookie: csrfCookie?Hasher.hash(csrfCookie) : undefined}));
                }

                if (ce) {
                    if (this.errorPage) {
                        return reply.status(ce.httpStatus).view(this.errorPage, {status: ce.httpStatus, error: ce.message, errorCode: ce.code, errorCodeName: ce.codeName});
                    } else {
                        let status : "400" | "401" | "500" = "500";
                        switch (ce.httpStatus) {
                            case 401: status = "401" ; break;
                            case 400: status = "400" ; break;
                        }
                        return reply.status(ce.httpStatus).send(DEFAULT_ERROR[status]||ERROR_500);
                    }
                }
   
                // Create an authorizatin code
                if (!ce) {
                    const authorized = request.body.authorized == "true";
                    return await this.authorize(request, reply, authorized, {
                        responseType: request.body.response_type,
                        clientId : request.body.client_id,
                        redirectUri: request.body.redirect_uri,
                        scope: request.body.scope,
                        state: request.body.state,
                        codeChallenge: request.body.code_challenge,
                        codeChallengeMethod: request.body.code_challenge_method,
                    });
                }
            });
        }

        if (this.authServer.validFlows.includes(OAuthFlows.AuthorizationCode) || this.authServer.validFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE)) {

            this.app.post(this.prefix+'token', async (request : FastifyRequest<{ Body: TokenBodyType }>, reply : FastifyReply) => {
                CrossauthLogger.logger.info(j({msg: "Page visit", method: 'POST', url: this.prefix+'token', ip: request.ip, user: request.user?.username}));

                const resp = await this.authServer.tokenPostEndpoint({
                    grantType: request.body.grant_type,
                    clientId : request.body.client_id,
                    clientSecret : request.body.client_secret,
                    scope: request.body.scope,
                    codeVerifier: request.body.code_verifier,
                    code: request.body.code,
                });

                if (resp.error || !resp.access_token) {
                    let error = "server_error";
                    let errorDescription = "Neither code nor error received";
                    if (resp.error) error = resp.error;
                    if (resp.error_description) errorDescription = resp.error_description;
                    let status = oauthErrorStatus(error);
                    const errorCode = errorCodeFromAuthErrorString(error);
                    CrossauthLogger.logger.error(j({msg: errorDescription, errorCode: errorCode, errorCodeName: error}));
                return reply.header(...JSONHDR).status(status).send(resp);
                }
                return reply.header(...JSONHDR).send(resp);
            });
        }
    }

    private async authorize(request : FastifyRequest, reply : FastifyReply, authorized : boolean, {
        responseType,
        clientId,
        redirectUri,
        scope,
        state,
        codeChallenge,
        codeChallengeMethod,
    } : {
        responseType : string,
        clientId : string,
        redirectUri : string,
        scope? : string,
        state : string,
        codeChallenge? : string,
        codeChallengeMethod?: string,
    }) {
        let error : string|undefined;
        let errorDescription : string|undefined;
        let code : string|undefined;

        // Create an authorizatin code
        if (authorized) {
            const resp = await this.authServer.authorizeGetEndpoint({
                responseType,
                clientId,
                redirectUri,
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
                const ce = CrossauthError.fromOAuthError(error||"server_error", errorDescription||"Neither code nor error received")
                CrossauthLogger.logger.error(j({msg: ce.message, errorCode: ce.code, errorCodeName: ce.codeName}));
                if (this.errorPage) {
                    return reply.status(ce.httpStatus).view(this.errorPage, {status: ce.httpStatus, error: ce.message, errorCode: ce.code, errorCodeName: ce.codeName});
                } else {
                    let status : "401" | "400" | "500" = "500"
                    switch (ce.httpStatus) {
                        case 401: status = "401" ; break;
                        case 400: status = "400" ; break;
                    }
                    return reply.status(ce.httpStatus).send(DEFAULT_ERROR[status]||ERROR_500);
                }
            }

            return reply.redirect(this.authServer.redirectUri(
                redirectUri,
                code,
                state
            )); 

        } else {

            // resource owner did not grant access
            const ce = new CrossauthError(ErrorCode.Unauthorized,  "You have not granted access");
            CrossauthLogger.logger.error(j({msg: errorDescription, errorCode: ce.code, errorCodeName: ce.codeName}));
            try {
                OAuthAuthorizationServer.validateUri(redirectUri);
                return reply.redirect(redirectUri); 
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: `Couldn't send error message ${ce.codeName} to ${redirectUri}}`}));
            }
        }
    }

    oidcConfiguration() : OpenIdConfiguration {
        return this.authServer.oidcConfiguration({
                authorizeEndpoint: this.prefix+"authorize", 
                tokenEndpoint: this.prefix+"token", 
                jwksUri: this.prefix+"jwks", 
                additionalClaims: []});
    };


}