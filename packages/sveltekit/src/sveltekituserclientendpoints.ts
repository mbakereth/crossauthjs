import { SvelteKitServer } from './sveltekitserver';
import { SvelteKitSessionServer } from './sveltekitsession';
import type { SvelteKitSessionServerOptions } from './sveltekitsession';
import { 
    setParameter,
    ParamType,
 } from '@crossauth/backend';
import type { RequestEvent } from '@sveltejs/kit';
import type {
    SearchClientsPageData,
    UpdateClientPageData,
    UpdateClientFormData 
} from './sveltekitsharedclientendpoints';
import { SvelteKitSharedClientEndpoints } from './sveltekitsharedclientendpoints';
import { CrossauthError, j, CrossauthLogger, ErrorCode } from '@crossauth/common';


//////////////////////////////////////////////////////////////////////
// Class

export class SvelteKitUserClientEndpoints extends SvelteKitSharedClientEndpoints {

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
    async searchClients(event : RequestEvent, searchTerm? : string, skip? : number, take? : number)
        : Promise<SearchClientsPageData> {

        if (!event.locals.user) 
            throw this.redirect(302, this.loginUrl + "?next="+encodeURIComponent(event.request.url));
        return this.searchClients_internal(event, searchTerm, skip, take, event.locals.user?.id)

    }

    async loadClient(event : RequestEvent)
        : Promise<UpdateClientPageData> {

        if (!event.locals.user) 
            throw this.redirect(302, this.loginUrl + "?next="+encodeURIComponent(event.request.url));

        // check user owns client
        try {
            const clientId = event.params.clientId;
            if (!clientId) throw new CrossauthError(ErrorCode.BadRequest, "No client ID given");
            const client = await this.clientStorage?.getClientById(clientId);
            if (client?.userId != event.locals.user.id) return this.error(401, "Access denied");
        } catch (e) {
            if (SvelteKitServer.isSvelteKitRedirect(e) || SvelteKitServer.isSvelteKitError(e)) throw e;
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.debug(j({err: e}));
            CrossauthLogger.logger.error(j({cerr: e}));
            return {
                success: false,
                error: ce.message,
                exception: ce,
                validFlows: this.validFlows,
                validFlowNames: this.validFlowNames,
            }
        }

        return this.loadClient_internal(event)

    }

    async updateClient(event : RequestEvent)
        : Promise<UpdateClientFormData> {

        if (!event.locals.user) 
            throw this.redirect(302, this.loginUrl + "?next="+encodeURIComponent(event.request.url));
 
        // check user owns client
        try {
            const clientId = event.params.clientId;
            if (!clientId) throw new CrossauthError(ErrorCode.BadRequest, "No client ID given");
            const client = await this.clientStorage?.getClientById(clientId);
            if (client?.userId != event.locals.user.id) return this.error(401, "Access denied");
        } catch (e) {
            if (SvelteKitServer.isSvelteKitRedirect(e) || SvelteKitServer.isSvelteKitError(e)) throw e;
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.debug(j({err: e}));
            CrossauthLogger.logger.error(j({cerr: e}));
            return {
                success: false,
                error: ce.message,
                exception: ce,
            }
        }
 
        return this.updateClient_internal(event, false)

    }

    async emptyClient(event : RequestEvent)
        : Promise<UpdateClientPageData> {

        if (!event.locals.user) 
            throw this.redirect(302, this.loginUrl + "?next="+encodeURIComponent(event.request.url));


        return this.emptyClient_internal(event, false)

    }

    async createClient(event : RequestEvent)
        : Promise<UpdateClientFormData> {

        if (!event.locals.user) 
            throw this.redirect(302, this.loginUrl + "?next="+encodeURIComponent(event.request.url));


        return this.createClient_internal(event, false)

    }


    /////////////////////////////////////////////////////////////////
    // Endpoints

    readonly searchClientsEndpoint = {
        load: async ( event: RequestEvent ) => {
            const resp = await this.searchClients(event);
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
                delete resp?.exception;
                return resp;
            }
        }
    };

    readonly createClientEndpoint = {
        load: async ( event: RequestEvent ) => {
            console.log("user createClientEndpoint.load")
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
                delete resp?.exception;
                return resp;
            }
        }
    };

};
