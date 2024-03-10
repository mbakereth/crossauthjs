import { SvelteKitSessionServer, type SvelteKitSessionServerOptions } from './sveltekitsession';
import { UserStorage, KeyStorage, Authenticator } from '@crossauth/backend';
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
        session
    } : {
        session? : {
            keyStorage: KeyStorage, 
            authenticators: {[key:string]: Authenticator}, 
            options?: SvelteKitSessionServerOptions,
}
    }, options : SvelteKitServerOptions = {}) {

        //setParameter("secret", ParamType.String, this, options, "SECRET", true);

        this.userStorage = userStorage;
        if (session) {
            this.sessionServer = new SvelteKitSessionServer(userStorage, session.keyStorage, session.authenticators, {...session.options, ...options});
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
