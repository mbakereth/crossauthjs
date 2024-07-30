import { SvelteKitSessionServer } from './sveltekitsession';
import type { SvelteKitSessionServerOptions } from './sveltekitsession';
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
}

