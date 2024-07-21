import { SvelteKitSessionServer, type SvelteKitSessionServerOptions } from './sveltekitsession';
import { UserStorage, KeyStorage, Authenticator, setParameter, ParamType } from '@crossauth/backend';
import { CrossauthError, ErrorCode, httpStatus } from '@crossauth/common';
import { type Handle, type RequestEvent, type ResolveOptions, type MaybePromise } from '@sveltejs/kit';

export interface SvelteKitServerOptions extends SvelteKitSessionServerOptions {
}

export type Resolver = (event: RequestEvent, opts?: ResolveOptions) => MaybePromise<Response>;

export class SvelteKitServer {
    userStorage : UserStorage;
    sessionServer? : SvelteKitSessionServer;
    //private secret : String = "";
    hooks : (Handle);
    private loginUrl = "/";

    constructor(userStorage: UserStorage, {
        authenticators,
        session,
    } : {
        authenticators?: {[key:string]: Authenticator}, 
        session? : {
            keyStorage: KeyStorage, 
            options?: SvelteKitSessionServerOptions,
}
    }, options : SvelteKitServerOptions = {}) {

        setParameter("loginUrl", ParamType.String, this, options, "LOGIN_URL", false);

        this.userStorage = userStorage;
        if (session) {
            if (!authenticators) {
                throw new CrossauthError(ErrorCode.Configuration,
                    "I fusing session management, must supply authenticators")
            }
            this.sessionServer = new SvelteKitSessionServer(userStorage, session.keyStorage, authenticators, {...session.options, ...options});
        }

        this.hooks = async ({event, resolve}) => {
            if (this.sessionServer) {
                const resp = await(this.sessionServer.sessionHook({event}));
                let response = await resolve(event);;
                this.sessionServer.setHeaders(resp.headers, response)
                const ret = await(this.sessionServer.twoFAHook({event}, response));
                response = ret.response;
                if (!ret.twofa && !event.locals.user) {
                    if (this.sessionServer.isLoginPageProtected(event)) return new Response('', {status: 302, statusText: httpStatus(302), headers: { Location: this.loginUrl}});
                    if (this.sessionServer.isLoginApiProtected(event)) return new Response('', {status: 401, statusText: httpStatus(401)});    
                }
                return response;
            }
            return await resolve(event);

        }
    }

}
