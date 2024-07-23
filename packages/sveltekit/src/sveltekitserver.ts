import { SvelteKitSessionServer, type SvelteKitSessionServerOptions } from './sveltekitsession';
import { UserStorage, KeyStorage, Authenticator, setParameter, ParamType } from '@crossauth/backend';
import { CrossauthError, ErrorCode, httpStatus, type User } from '@crossauth/common';
import { type Handle, type RequestEvent, type ResolveOptions, type MaybePromise } from '@sveltejs/kit';

export interface SvelteKitServerOptions extends SvelteKitSessionServerOptions {
    /** User can set this to check if the user is an administrator.
     * By default, the admin booloean field in the user object is checked
     */
    isAdminFn?: (user : User) => boolean;

}

export type Resolver = (event: RequestEvent, opts?: ResolveOptions) => MaybePromise<Response>;

/**
 * The function to determine if a user has admin rights can be set
 * externally.  This is the default function if none other is set.
 * It returns true iff the `admin` field in the passed user is set to true.
 * 
 * @param user the user to test
 * @returns true or false
 */
function defaultIsAdminFn(user : User) : boolean {
    return user.admin == true;
}

export class SvelteKitServer {
    userStorage : UserStorage;
    sessionServer? : SvelteKitSessionServer;
    //private secret : String = "";
    hooks : (Handle);
    private loginUrl = "/";
    static isAdminFn: (user : User) => boolean = defaultIsAdminFn;

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
        if (options.isAdminFn) SvelteKitServer.isAdminFn = options.isAdminFn;

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
                    if (this.sessionServer.isLoginPageProtected(event)) 
                        return new Response('', {status: 302, statusText: httpStatus(302), headers: { Location: this.loginUrl}});
                    if (this.sessionServer.isLoginApiProtected(event)) 
                        return new Response('', {status: 401, statusText: httpStatus(401)});    
                }
                if (!ret.twofa && this.sessionServer.isAdminEndpoint(event) &&
                    (!event.locals.user || SvelteKitServer.isAdminFn(event.locals.user))) 
                    return new Response('', {status: 401, statusText: httpStatus(401)});    
                return response;
            }
            return await resolve(event);

        }
    }

}
