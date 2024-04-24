import {  CrossauthError, ErrorCode, CrossauthLogger, j } from '@crossauth/common';
import { OAuthTokenConsumer } from './tokenconsumer';
import * as jose from 'jose';

/**
 * Options for {@link OAuthResourceServer}
 */
export interface OAuthResourceServerOptions {
}

/**
 * An OAuth resource server
 * 
 * The purpose of this class is for validating access tokens
 */
export class OAuthResourceServer {
    
    /** The token consumer that validates the access tokens.  Required */
    tokenConsumers : {[key:string] : OAuthTokenConsumer} = {};

    /**
     * Constructor
     * @param options See {@link OAuthResourceServerOptions}
     */
    constructor(tokenConsumers : OAuthTokenConsumer[], _options : OAuthResourceServerOptions = {}) {

        for (let consumer of tokenConsumers) {
            this.tokenConsumers[consumer.jwtIssuer] = consumer;

        }
    }

    /**
     * Returns a token payload if the access token has a valid signature
     * and the `type` claim in the payload is `access`, undefined otherwise.
     * 
     * The `aud` token also has to match the `resourceServerName` value
     * passed to the constructor.
     * 
     * Doesn't throw exceptions.
     * 
     * @param accessToken the access token JWT to validate
     * @returns The JWT payload as an object or undefinedf if the JWT is
     *          invalid
     */
    async accessTokenAuthorized(accessToken: string) 
        : Promise<{[key:string]: any}|undefined> {
            try {
                const payload = jose.decodeJwt(accessToken);
                if (payload.iss && payload.iss in this.tokenConsumers)
                    return await this.tokenConsumers[payload.iss].tokenAuthorized(accessToken, "access");
                throw new CrossauthError(ErrorCode.Unauthorized, "Invalid issuer in access token");
            } catch (e) {
                CrossauthLogger.logger.warn(j({err: e}));
                return undefined;
            }
        }

};
