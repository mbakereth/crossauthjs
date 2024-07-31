import { SvelteKitSessionServer, type SvelteKitSessionServerOptions } from './sveltekitsession';
import { UserStorage, KeyStorage, Authenticator, setParameter, ParamType } from '@crossauth/backend';
import { CrossauthError, ErrorCode, type User } from '@crossauth/common';
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
                    "If using session management, must supply authenticators")
            }
            this.sessionServer = new SvelteKitSessionServer(userStorage, session.keyStorage, authenticators, {...session.options, ...options});
        }

        this.hooks = async ({event, resolve}) => {
            if (this.sessionServer) {
                /*const resp =*/ await this.sessionServer.sessionHook({event});
                //let response = await resolve(event);
                //this.sessionServer.setHeaders(resp.headers, response);
                const ret = await this.sessionServer.twoFAHook({event});
                if (!ret.twofa && !event.locals.user) {
                    if (this.sessionServer.isLoginPageProtected(event))  {
                        if (this.loginUrl) {
                            return new Response(null, {status: 302, headers: {location: this.loginUrl}});
                        }
                        return this.sessionServer.error(401, "Unauthorized");

                    }
                    if (this.sessionServer.isLoginApiProtected(event)) 
                        return this.sessionServer.error(401, "Unauthorized");
                        /*return new Response('{"error": "unauthorized"}', {
                            status: 401,
                            statusText: "Unauthorized",
                            headers: {"content-type": "application/json"}
                        });*/
                }
                if (!ret.twofa && this.sessionServer.isAdminPageEndpoint(event) &&
                    (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user))
                ) {
                        if (this.sessionServer.unauthorizedUrl) {
                            return new Response(null, {status: 302, headers: {location: this.sessionServer.unauthorizedUrl}});
                        }
                        /*return new Response('Unauthorized', {
                            status: 401,
                            statusText: "Unauthorized",
                            //headers: {"content-type": "application/json"}
                        });*/
                        return this.sessionServer.error(401, "Unauthorized");
                }
                if (!ret.twofa && this.sessionServer.isAdminApiEndpoint(event) &&
                    (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user))) {
                        /*return new Response('{"error": "unauthorized"}', {
                            status: 401,
                            statusText: "Unauthorized",
                            headers: {"content-type": "application/json"}
                        });*/
                        return this.sessionServer.error(401, "Unauthorized");
                }
                if (ret.response) return ret.response;
            }
            return await resolve(event);

        }
    }

    dummyLoad : (event : RequestEvent) => Promise<{[key:string]:any}> = async (_event) => {return {}};
    dummyActions : {[key:string]: (event : RequestEvent) => Promise<{[key:string]:any}>} = {};
}
