import {  CrossauthLogger, j } from '@crossauth/common';
import { setParameter, ParamType } from '../utils';
import {
    OAuthTokenConsumerBackend,
    type OAuthTokenConsumerBackendOptions } from './tokenconsumer';

/**
 * Options for {@link OAuthResourceServer}
 */
export interface OAuthResourceServerOptions extends OAuthTokenConsumerBackendOptions {

    /** Name for this resource server.  The `aud` field in the JWT must match this */
    resourceServerName? : string,
}

/**
 * An OAuth resource server
 * 
 * The purpose of this class is for validating access tokens
 */
export class OAuthResourceServer {
    
    protected resourceServerName : string = "";

    /** The token consumer that validates the access tokens.  Required */
    tokenConsumer : OAuthTokenConsumerBackend;

    /**
     * Constructor
     * @param options See {@link OAuthResourceServerOptions}
     */
    constructor(options : OAuthResourceServerOptions = {}) {

        setParameter("resourceServerName", ParamType.String, this, options, "OAUTH_RESOURCE_SERVER", true);

        this.tokenConsumer = new OAuthTokenConsumerBackend(this.resourceServerName, options);
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
                return await this.tokenConsumer.tokenAuthorized(accessToken, "access");
            } catch (e) {
                CrossauthLogger.logger.warn(j({err: e}));
                return undefined;
            }
        }

};
