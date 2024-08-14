import { SvelteKitServer } from './sveltekitserver';
import { SvelteKitSessionServer } from './sveltekitsession';
import type { SvelteKitSessionServerOptions } from './sveltekitsession';
import { 
    setParameter,
    ParamType,
} from '@crossauth/backend';
import { CrossauthLogger, j} from '@crossauth/common'
import type { RequestEvent } from '@sveltejs/kit';
import { SvelteKitSharedClientEndpoints } from './sveltekitsharedclientendpoints';
import type {
    SearchClientsPageData,
    UpdateClientPageData,
    UpdateClientFormData,
    DeleteClientPageData,
    DeleteClientFormData,
} from './sveltekitsharedclientendpoints';

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
        : Promise<SearchClientsPageData> {

        if (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user)) 
            throw this.error(401, "Unauthorized");
        
        return this.searchClients_internal(event, searchTerm, skip, take, userId)

    }

    async loadClient(event : RequestEvent)
        : Promise<UpdateClientPageData> {

        if (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user)) 
            throw this.error(401, "Unauthorized");
        return this.loadClient_internal(event)

    }

    async updateClient(event : RequestEvent)
        : Promise<UpdateClientFormData> {

        if (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user)) 
            throw this.error(401, "Unauthorized");
        return this.updateClient_internal(event, true)

    }

    async emptyClient(event : RequestEvent)
    : Promise<UpdateClientPageData> {

        if (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user)) 
            throw this.error(401, "Unauthorized");
        return this.emptyClient_internal(event, true)

    }

    async createClient(event : RequestEvent)
        : Promise<UpdateClientFormData> {

        if (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user)) 
            throw this.error(401, "Unauthorized");
        return this.createClient_internal(event, true)

    }

    async loadDeleteClient(event : RequestEvent)
        : Promise<DeleteClientPageData> {

        if (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user)) 
            throw this.error(401, "Unauthorized");
        return this.loadDeleteClient_internal(event)

    }

    async deleteClient(event : RequestEvent)
        : Promise<DeleteClientFormData> {

        if (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user)) 
            throw this.error(401, "Unauthorized");
        return this.deleteClient_internal(event, true)

    }

    /////////////////////////////////////////////////////////////////
    // Endpoints

    readonly searchClientsEndpoint = {
        load: async ( event: RequestEvent ) => {
            let userId : number|undefined = undefined;
                try {
                    userId = event.url.searchParams.get("userid") ? Number(event.url.searchParams.get("userid")) : undefined;
                } catch (e) {
                    CrossauthLogger.logger.warn(j({msg: "Invalid userId " + event.url.searchParams.get("userid")}));
                }
            const resp = await this.searchClients(event, undefined, undefined, undefined, userId);
            delete resp?.exception;
            return {
                ...this.baseEndpoint(event),
                ...resp,
            };
        },
    };

    readonly updateClientEndpoint = {
        load: async ( event: RequestEvent ) => {
            const resp = await this.loadClient(event);
            delete resp?.exception;
            return {
                ...this.baseEndpoint(event),
                ...resp,
            };
        },
        actions: {
            default: async (event : RequestEvent) => {
                let resp = await this.updateClient(event);
                delete resp.exception;
                return resp;
            }
        }
    };

    readonly createClientEndpoint = {
        load: async ( event: RequestEvent ) => {
            const resp = await this.emptyClient(event);
            delete resp?.exception;
            return {
                ...this.baseEndpoint(event),
                ...resp,
            };
        },
        actions: {
            default: async (event : RequestEvent) => {
                let resp = await this.createClient(event);
                delete resp.exception;
                return resp;
            }
        }
    };

    readonly deleteClientEndpoint = {
        load: async ( event: RequestEvent ) => {
            const resp = await this.loadDeleteClient(event);
            delete resp?.exception;
            return {
                ...this.baseEndpoint(event),
                ...resp,
            };
        },
        actions: {
            default: async (event : RequestEvent) => {
                let resp = await this.deleteClient(event);
                delete resp.exception;
                return resp;
            }
        }
    };
};
