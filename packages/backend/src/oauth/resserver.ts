import {  CrossauthLogger, j } from '@crossauth/common';
import { setParameter, ParamType } from '../utils';
import {
    OAuthBackendTokenConsumer,
    type OAuthBackendTokenConsumerOptions } from './tokenconsumer';

export interface OAuthResourceServerOptions extends OAuthBackendTokenConsumerOptions {

    /** Name for this resource server.  The `aud` field in the JWT must match this */
    resourceServerName? : string,
}

export class OAuthResourceServer {
    
    protected resourceServerName : string = "";
    tokenConsumer : OAuthBackendTokenConsumer;

    constructor(options : OAuthResourceServerOptions = {}) {

        setParameter("resourceServerName", ParamType.String, this, options, "OAUTH_RESOURCE_SERVER", true);

        this.tokenConsumer = new OAuthBackendTokenConsumer(this.resourceServerName, options);
    }

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
