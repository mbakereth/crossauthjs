import { SvelteKitServer, type SveltekitEndpoint } from './sveltekitserver';
import { SvelteKitSessionServer } from './sveltekitsession';
import type { SvelteKitSessionServerOptions } from './sveltekitsession';
import { 
    toCookieSerializeOptions,     
    setParameter,
    ParamType,
 } from '@crossauth/backend';
import type { AuthenticationParameters, OAuthClientStorage } from '@crossauth/backend';
import type { User, UserInputFields, OAuthClient } from '@crossauth/common';
import { CrossauthError, CrossauthLogger, j, ErrorCode, UserState } from '@crossauth/common';
import type { RequestEvent } from '@sveltejs/kit';
import { JsonOrFormData } from './utils';
import type { SearchClientsReturn } from './sveltekitsharedclientendpoints';
import { SvelteKitSharedClientEndpoints, defaultClientSearchFn } from './sveltekitsharedclientendpoints';

//////////////////////////////////////////////////////////////////////
// Class

export class SvelteKitAdminClientEndpoints extends SvelteKitSharedClientEndpoints {

    constructor(sessionServer : SvelteKitSessionServer,
        options : SvelteKitSessionServerOptions
    ) {
        super(sessionServer, options);
        this.sessionServer = sessionServer;
        setParameter("loginUrl", ParamType.JsonArray, this, options, "LOGIN_URL");
        if (options.clientSearchFn) this.clientSearchFn = options.clientSearchFn;
        this.redirect = options.redirect;
        this.error = options.error;
    }

    ///////////////////////////////////////////////////////////////////
    // Functions callable from apps

    /**
     * Returns either a list of all clients for the user matching a search term.
     * 
     * The returned list is pagenaed using the `skip` and `take` parameters.
     * 
     * The searching is done with `clientSearchFn` that was passed in the
     * options (see {@link SvelteKitSessionServerOptions }).  THe default
     * is an exact username match.
     * 
     * By default, the searh and pagination parameters are taken from 
     * the query parameters in the request but can be overridden.
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
     * @param userId if given, only clients for this user will be returned.
     *        otherwise all clients will be returned
     * 
     * @return an object with the following members:
     *   - `success` true or false depending on whether there was an error
     *   - `clients` the matching array of clients
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
    async searchClients(event : RequestEvent, searchTerm? : string, skip? : number, take? : number, userId? : number|string)
        : Promise<SearchClientsReturn> {

        if (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user)) 
            throw this.error(401, "Unauthorized");
        
        return this.searchClients_internal(event, searchTerm, skip, take, userId)

    }

    /////////////////////////////////////////////////////////////////
    // Endpoints
};
