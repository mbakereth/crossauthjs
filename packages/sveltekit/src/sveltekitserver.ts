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

/**
 * This is the main class for adding Crossauth to Svelekit applications.
 * 
 * To use it, create a file in your `src/lib` directory, eg
 * `src/lib/crossauthsessiion.ts`, something like this:
 * 
 * ```
 * export const prisma = new PrismaClient();
 * const userStorage = new PrismaUserStorage({prismaClient : prisma, userEditableFields: ["email"]});
 * const keyStorage = new PrismaKeyStorage({prismaClient : prisma});
 * const passwordAuthenticator = new LocalPasswordAuthenticator(userStorage);
 * export const crossauth = new SvelteKitServer(userStorage, {
 *     authenticators: {
 *         localpassword: passwordAuthenticator,
 *     },
 *     session: {
 *         keyStorage: keyStorage,
 *     }}, {
 *         loginProtectedPageEndpoints: ["/account"],
 *         redirect,
 *         error
 *     }); 
 * ```
 * 
 * Note that we pass Sveltekit's `action` and `error` methods because, as
 * a module compiled without your Sveltekit application, this class has
 * no access to them otherwise, and they are use internally for things like
 * redirecting to your login page.
 * 
 * This class provides hooks which you can add to by putting the following
 * in your `hooks.server.ts`:
 * 
 * ```
 * import { type Handle } from '@sveltejs/kit';
 * import { crossauth } from '$lib/server/crossauthsession';
 * import { CrossauthLogger } from '@crossauth/common';
 * export const handle: Handle = crossauth.hooks; 
 * ```
 * 
 * This will set the following in `event.locals`:
 * 
 *  - `user`: the logged in {@link @crossauth/common!User} or undefined,
 *  - `csrfToken` a CSRF token if the request is a `GET`, `HEAD` or `OPTIONS`,
 *  - `authType` authentication type, currently only `cookie`,
 *  - `apiKey` the valid API key if one was used (not currently supported),
 *  - `accessTokenPayload` payload for the OAuth access token (not currently supported),
 *  - `authError` string error during authentication process (not currently used)
 *  - `authErrorDescription` error during authentication (not currently used),
 *  - `sessionId` session ID of logged in user, session ID for anonymous user, or undefined,
 *  - `scope` oAuth scope, not currently used,
 *   
 * 
 * For instructions about how to use this class in your endpoints, see
 * {@link SvelktekitUserEndpoints} and {@link SveltekitAdminEndpoints}.
 */
export class SvelteKitServer {

    /** The User storage that was passed during construction */
    readonly userStorage : UserStorage;

    /** The session server if one was requested during construction */
    readonly sessionServer? : SvelteKitSessionServer;
    //private secret : String = "";

    /** For adding in your `hooks.server.ts.  See class documentation
     * for details
     */
    readonly hooks : (Handle);
    private loginUrl = "/";

    /**
     * User-defined function for determining whether a user is an admin.
     * 
     * The default is to look at the `admin` member of the
     * {@link @crossauth/common!User} object.
     */
    static isAdminFn: (user : User) => boolean = defaultIsAdminFn;

    /**
     * Constructor.
     * 
     * @param userStorage where users are stored
     * 
     * @param config an object with configuration:
     *   - `authenticators` an object of authenticator objects that are
     *     used either for factor 1 or factor 2 authentication, keyed on the
     *     name you refer to them with in the user's `factor1` and `factor2`
     *     fields.  See the example in the class documentation.
     *   - `session` if you want a session (session cookie-based
     *     authentication), include this.  See the class documentation for
     *     details.  Note that the options in the third parameter of this
     *     constructor are concatinated with the options defined in
     *     `session.options`, so that you can have global as well as
     *     session server-specific configuration.
     * 
     * @param options Configuration that applies to the whole application,
     *   not just the session server.
     */
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
                await this.sessionServer.sessionHook({event});
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
                }
                if (!ret.twofa && this.sessionServer.isAdminPageEndpoint(event) &&
                    (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user))
                ) {
                        if (this.sessionServer.unauthorizedUrl) {
                            return new Response(null, {status: 302, headers: {location: this.sessionServer.unauthorizedUrl}});
                        }
                        return this.sessionServer.error(401, "Unauthorized");
                }
                if (!ret.twofa && this.sessionServer.isAdminApiEndpoint(event) &&
                    (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user))) {
                        return this.sessionServer.error(401, "Unauthorized");
                }
                if (ret.response) return ret.response;
            }
            return await resolve(event);

        }
    }

    /**
     * See class documentation for {@link SvelteKitUserEndpoints}.
     * 
     * This is an empty `load` which serves no purpose other than to stop
     * Typescript complaining that `load` may be undefined.
     * @param _event Sveltekit event object
     * @returns an empty object
     */
    dummyLoad : (event : RequestEvent) => Promise<{[key:string]:any}> = async (_event) => {return {}};

    /**
     * See class documentation for {@link SvelteKitUserEndpoints}.
     * 
     * This is an empty `load` which serves no purpose other than to stop
     * Typescript complaining that `actions` may be undefined.
     * @returns an empty object
     */
    dummyActions : {[key:string]: (event : RequestEvent) => Promise<{[key:string]:any}>} = {};

    /**
     * It is not possible to get any meaninfgul info about an exception class
     * with `typeof` or `instanceof`.  This method heuristically determines
     * if an exception is a Sveltekit redirect.  It is used internally
     * @param e an exception
     * @returns true or false
     */
    static isSvelteKitRedirect(e : any) {
        return (typeof e == "object" && e != null && "status" in e && "location" in e);
    }

    /**
     * It is not possible to get any meaninfgul info about an exception class
     * with `typeof` or `instanceof`.  This method heuristically determines
     * if an exception is a Sveltekit error.  It is used internally
     * @param e an exception
     * @returns true or false
     */
    static isSvelteKitError(e : any, status : number) {
        return (typeof e == "object" && e != null && "status" in e && "text" in e && "message" in e && e.status == status);
    }
}
