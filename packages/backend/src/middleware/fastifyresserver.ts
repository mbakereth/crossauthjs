import { CrossauthError, CrossauthLogger, j } from '@crossauth/common';
import {  OAuthResourceServer, type OAuthResourceServerOptions } from '../oauth/resserver';
import {  FastifyAuthorizationServer } from './fastifyoauthserver';
import { FastifyRequest } from 'fastify';
import { UserStorage } from '../storage';

export interface FastifyOAuthResourceServerOptions extends OAuthResourceServerOptions {
    authServer? : FastifyAuthorizationServer,
    userStorage? : UserStorage;
}
export class FastifyOAuthResourceServer extends OAuthResourceServer {
    private authServer?: FastifyAuthorizationServer;

    constructor(options : FastifyOAuthResourceServerOptions = {}) {
        super(options);
        this.authServer = options.authServer;
    }

    async authorized(request : FastifyRequest) : Promise<{authorized: boolean, tokenPayload?: {[key:string]: any}, error? : string, error_description?: string}|undefined> {
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