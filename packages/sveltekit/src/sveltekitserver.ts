import { SvelteKitSessionServer, type SvelteKitSessionServerOptions } from './sveltekitsession';
import { UserStorage, KeyStorage, Authenticator } from '@crossauth/backend';
import { CrossauthError, ErrorCode } from '@crossauth/common';
import type { Handle, RequestEvent, ResolveOptions, MaybePromise, } from '@sveltejs/kit';

export interface SvelteKitServerOptions {

}

export type Resolver = (event: RequestEvent, opts?: ResolveOptions) => MaybePromise<Response>;

export class SvelteKitServer {
    userStorage : UserStorage;
    sessionServer? : SvelteKitSessionServer;
    //private secret : String = "";
    hooks : (Handle);
    
    constructor(userStorage: UserStorage, {
        authenticators,
        session
    } : {
        authenticators?: {[key:string]: Authenticator}, 
        session? : {
            keyStorage: KeyStorage, 
            options?: SvelteKitSessionServerOptions,
}
    }, options : SvelteKitServerOptions = {}) {

        //setParameter("secret", ParamType.String, this, options, "SECRET", true);

        this.userStorage = userStorage;
        if (session) {
            if (!authenticators) {
                throw new CrossauthError(ErrorCode.Configuration,
                    "I fusing session management, must supply authenticators")
            }
            this.sessionServer = new SvelteKitSessionServer(userStorage, session.keyStorage, authenticators, {...session.options, ...options});
        }

        this.hooks = async ({event, resolve}) => {
            let response = await resolve(event);
            if (this.sessionServer) {
                response = await(this.sessionServer.sessionHook({event}, response));
                response = await(this.sessionServer.twoFAHook({event}, response));
            }
            return response;
        }
    }

}
