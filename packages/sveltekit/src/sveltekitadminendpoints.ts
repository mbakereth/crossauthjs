import { SvelteKitSessionServer } from './sveltekitsession';
import type { SvelteKitSessionServerOptions, SveltekitEndpoint } from './sveltekitsession';
import { toCookieSerializeOptions } from '@crossauth/backend';
import type { AuthenticationParameters, UserStorage } from '@crossauth/backend';
import type { User, UserInputFields } from '@crossauth/common';
import { CrossauthError, CrossauthLogger, j, ErrorCode } from '@crossauth/common';
import type { RequestEvent } from '@sveltejs/kit';
import { JsonOrFormData } from './utils';

export type SearchUsersReturn = {
    success : boolean,
    users?: User[],
    skip : number,
    take : number,
    search? : string,
    error? : string,
    exception?: CrossauthError,
    hasPrevious : boolean,
    hasNext : boolean,
};

async function defaultUserSearchFn(searchTerm: string,
    userStorage: UserStorage, skip = 0, _take = 10) : Promise<User[]> {
        let users : User[] = [];
    if (skip > 0) return [];
    try {
        const {user} = 
            await userStorage.getUserByUsername(searchTerm);
            users.push(user);
    } catch (e1) {
        const ce1 = CrossauthError.asCrossauthError(e1);
        if (ce1.code != ErrorCode.UserNotExist) {
            CrossauthLogger.logger.debug(j({err: ce1}));
            throw ce1;
        }
        try {
            const {user} = 
                await userStorage.getUserByEmail(searchTerm);
                users.push(user);
        } catch (e2) {
            const ce2 = CrossauthError.asCrossauthError(e2);
            if (ce2.code != ErrorCode.UserNotExist) {
                CrossauthLogger.logger.debug(j({err: ce2}));
                throw ce1;
            }
        }
    }
    return users;

}

/**
 * Provides endpoints for users to login, logout and maintain their 
 * own account.
 * 
 * This class is not intended to be used outside of Crossauth.  For 
 * documentation about functiuons it provides, see
 * {@link SvelteKitSessionServer}.
 */
export class SvelteKitAdminEndpoints {
    private sessionServer : SvelteKitSessionServer;
    private userSearchFn : 
        (searchTerm : string, userStorage : UserStorage, skip? : number, take? : number) => Promise<User[]> =
        defaultUserSearchFn;

    constructor(sessionServer : SvelteKitSessionServer,
        options : SvelteKitSessionServerOptions
    ) {
        this.sessionServer = sessionServer;
        if (options.userSearchFn) this.userSearchFn = options.userSearchFn
    }

    /**
     * Returns either a list of all users or users matching a search term.
     * 
     * The returned list is pagenaed using the `skip` and `take` parameters.
     * 
     * The searching is done with `userSearchFn` that was passed in the
     * options (see {@link SvelteKitSessionServerOptions }).  THe default
     * is an exact username match.
     * 
     * By default, the searh and pagination parameters are taken from 
     * the query parameters in the request but can be overridden.
     * 
     * Does no permission checking - make sure you only call this from
     * endpoints that are protected.
     * 
     * @param event the Sveltekit request event.  The following query parameters
     *        are read:
     *   - `search` the search term which is ignored if it is undefined, null
     *      or the empty string.
     *   - `skip` the number to start returning from.  0 if not defined
     *   - `take` the maximum number to return.  10 if not defined.
     * @param search overrides the search term from the query.
     * @param skip overrides the skip term from the query
     * @param take overrides the take term from the query
     * 
     * @return an object with the following members:
     *   - `success` true or false depending on whether there was an error
     *   - `users` the matching array of users
     *   - `error` error message if `success` is false
     *   - `exception` a {@link @crossauth/common!CrossauthError} if there was
     *      an error.
     *   - `search` the search term that was used
     *   - `skip` the skip term that was used
     *   - `take` the take term that was used
     *   - `hasNext` whether there are still more results after the ones that
     *      were returned
     *   - `hasPrevious` whether there are more results before the ones that
     *      were returned.
     */
    async searchUsers(event : RequestEvent, searchTerm? : string, skip? : number, take? : number)
        : Promise<SearchUsersReturn> {
        try {
            let users : User[] = [];
            let prevUsers : User[] = [];
            let nextUsers : User[] = [];
            if (!skip) {
                try {
                    const str = event.url.searchParams.get("skip");
                    if (str) skip = parseInt(str);
                } catch (e) {
                    CrossauthLogger.logger.warn(j({cerr: e, msg: "skip parameter is not an integer"}))
                }
    
            }
            if (!skip) skip = 0;
            if (!take) {
                try {
                    const str = event.url.searchParams.get("take");
                    if (str) take = parseInt(str);
                } catch (e) {
                    CrossauthLogger.logger.warn(j({cerr: e, msg: "take parameter is not an integer"}))
                }
            }
            if (!take) take = 10;
        
            const searchFromUrl = event.url.searchParams.get("search");
            if (!searchTerm && searchFromUrl != null && searchFromUrl != "") 
                searchTerm = searchFromUrl;
            if (!searchTerm) searchTerm = "";
            if (searchTerm.length == 0) searchTerm = undefined;
            
            if (searchTerm) {
                users = await this.userSearchFn(searchTerm, 
                    this.sessionServer.userStorage, skip, take);
                if (skip > 0) {
                    prevUsers = await this.userSearchFn(searchTerm, 
                        this.sessionServer.userStorage, skip-1, 1);

                }
                } else {
                    users = 
                        await this.sessionServer.userStorage.getUsers(skip, 
                            take);
                    if (users.length == take) {
                        nextUsers = 
                            await this.sessionServer.userStorage.getUsers(skip+take, 
                                1);

                    }
                }

            return {
                success: true,
                users,
                skip,
                take,
                hasPrevious: prevUsers.length > 0,
                hasNext: nextUsers.length > 0,
                search: searchTerm
            }

        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);
            return {
                success: false,
                error: ce.message,
                exception: ce,
                hasPrevious: false,
                hasNext : false,
                skip: skip ?? 0, 
                take: take ?? 10,
                search: searchTerm,
            }
        }

    }

    readonly searchUsersEndpoint  : SveltekitEndpoint = {
        load: async ( event ) => {
            const resp = await this.searchUsers(event);
            delete resp?.exception;
            return resp;
        },
    };
}

