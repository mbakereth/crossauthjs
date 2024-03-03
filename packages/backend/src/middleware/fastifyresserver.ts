import { CrossauthError, CrossauthLogger, j, ErrorCode } from '@crossauth/common';
import {  OAuthResourceServer, type OAuthResourceServerOptions } from '../oauth/resserver';
import {  FastifyAuthorizationServer } from './fastifyoauthserver';
import { FastifyRequest, FastifyReply, FastifyInstance } from 'fastify';
import { UserStorage } from '../storage';
import { Server, IncomingMessage, ServerResponse } from 'http'

export interface FastifyOAuthResourceServerOptions extends OAuthResourceServerOptions {
    userStorage? : UserStorage;
}

export class FastifyOAuthResourceServer extends OAuthResourceServer {
    private authServer?: FastifyAuthorizationServer;
    private protectedEndpoints : {[key:string]: {scope? : string}} = {};

    constructor(
        app: FastifyInstance<Server, IncomingMessage, ServerResponse>, 
        authServer? : FastifyAuthorizationServer,
        protectedEndpoints? : {[key:string]: {scope? : string}},
        options : FastifyOAuthResourceServerOptions = {}) {
        super(options);
        this.authServer = authServer;

        if (protectedEndpoints) {
            const regex = /^[!#\$%&'\(\)\*\+,\\.\/a-zA-Z\[\]\^_`-]+/;
            for (const [key, value] of Object.entries(protectedEndpoints)) {
                if (!key.startsWith("/")) {
                    throw new CrossauthError(ErrorCode.Configuration, "protected endpoints must be absolute paths without the protocol and hostname");
                }
                if (value.scope) {
                    value.scope.split(" ").forEach((s : string) => {
                        if (!(regex.test(s))) throw new CrossauthError(ErrorCode.Configuration, "Illegal charactwers in scope " + s);
                    });
                }
            }
            this.protectedEndpoints = protectedEndpoints;
        }

        // validate access token and put in request, along with any errors
        app.addHook('preHandler', async (request : FastifyRequest, _reply : FastifyReply) => {
            const authResponse = await this.authorized(request);
            request.accessTokenPayload = authResponse?.tokenPayload;
            request.authError = authResponse?.error
            request.authErrorDescription = authResponse?.error_description;
            CrossauthLogger.logger.debug(j({msg: "Resource server url", url: request.url, authorized: request.accessTokenPayload!= undefined}));
        });

        app.addHook('onSend', async (request : FastifyRequest, reply : FastifyReply) => {
            const urlWithoutQuery = request.url.split("?", 2)[0];
            if (!request.accessTokenPayload && urlWithoutQuery in this.protectedEndpoints) {
                let header = "Bearer";
                if ("scope" in this.protectedEndpoints[urlWithoutQuery]) {
                    header += ' scope="' + this.protectedEndpoints[urlWithoutQuery]["scope"];
                }
                reply.header("WWW-Authenticate:", header);
                CrossauthLogger.logger.debug(j({msg: "Adding www-authenticate header to reply"}));
            }
        });
    }

   protected async authorized(request : FastifyRequest) : Promise<{
        authorized: boolean, 
        tokenPayload?: {[key:string]: any}, 
        error? : string, 
        error_description?: string}|undefined> {
        try {
            if ((!this.keys || this.keys.length == 0) && this.authServer) {
                // we will get the keys from the auth server directly rather than let the
                // base class to a fetch
                await this.loadConfig(this.authServer.oidcConfiguration())
                await this.loadJwks(this.authServer.authServer.jwks());
            }
            const header = request.headers.authorization;
            if (header && header.startsWith("Bearer ")) {
                const parts = header.split(" ");
                if (parts.length == 2) {
                    const resp = await this.tokenAuthorized(parts[1]);
                    if (resp) {
                        return {authorized: true, tokenPayload: resp};
                    } else {
                        return {authorized: false};
                    }
                }

            }    
        } catch (e) {
            const ce = e as CrossauthError;
            CrossauthLogger.logger.debug(j({err: e}));
            CrossauthLogger.logger.error(j({cerr: ce}));
            return {authorized: false, error: "server_error", error_description: ce.message};
        }
        return undefined;
    }
}