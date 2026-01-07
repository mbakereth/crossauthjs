// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
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

/**
 * Endpoints for manipulating the OAuth client table, for use by admins.
 * 
 * You do not instantiate this directly - it is created when you create
 * a {@link SvelteKitServer}.
 * 
 * **Endpoints**
 * 
 * These endpoints can only be called if an admin user is logged in, as defined
 * by the {@link SvelteKitServer.isAdminFn}.  If the user does not
 * have this permission, a 401 error is raised.
 * 
 * | Name                       | Description                                                 | PageData (returned by load)                                                      | ActionData (return by actions)                                   | Form fields expected by actions                                  | URL param |
 * | -------------------------- | ----------------------------------------------------------- | -------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------- | --------- |
 * | baseEndpoint               | This PageData is returned by all endpoints' load function.  | - `user` logged in {@link @crossauth/common!User}                                | *Not provided*                                                   |                                                                  |           |
 * |                            |                                                             | - `csrfToken` CSRF token if enabled                                              |                                                                  |                                                                  |           |                                                                                  | loginPage                | 
 * | -------------------------- | ----------------------------------------------------------- | -------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------- | --------- |
 * | searchClientsEndpoint      | Returns a paginated set of clients or those matching search | See {@link SearchClientsPageData}                                                | *Not provided*                                                   |                                                                  |           |
 * | -------------------------- | ----------------------------------------------------------- | -------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------- | --------- |
 * | updateClientEndpoint       | Updates a client                                            | See {@link UpdateClientPageData}                                                | `default`:                                                       |                                                                  |           |
 * |                            |                                                             |                                                                                  | See {@link UpdateClientFormData}                                | See {@link SvelteKitSharedClientEndpoints.updateClient_internal} | client_id  |
 * | -------------------------- | ----------------------------------------------------------- | -------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------- | --------- |
 * | createClientEndpoint       | Creates a new client                                        | See {@link CreateClientPageData}                                                | `default`:                                                       |                                                                  |           |
 * |                            |                                                             |                                                                                  | See {@link CreateClientFormData}                                | See {@link SvelteKitSharedClientEndpoints.createClient_internal} | client_id  |
 * | -------------------------- | ----------------------------------------------------------- | -------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------- | --------- |
 * | deleteClientEndpoint       | Deletes a client                                            | See {@link DeleteClientPageData}                                                | `default`:                                                       |                                                                  |           |
 * |                            |                                                             |                                                                                  | See {@link DeleteClientFormData}                                | See {@link SvelteKitSharedClientEndpoints.deleteClient_internal} | client_id  |
 * | -------------------------- | ----------------------------------------------------------- | -------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------- | --------- |
 */
export class SvelteKitAdminClientEndpoints extends SvelteKitSharedClientEndpoints {

    /**
     * Constructor
     * @param sessionServer the session server which will have these endpoints
     * @param options See {@link SvelteKitSessionServerOptions}.
     */
    constructor(sessionServer : SvelteKitSessionServer,
        options : SvelteKitSessionServerOptions
    ) {
        super(sessionServer, options);
        this.sessionServer = sessionServer;
        setParameter("loginUrl", ParamType.String, this, options, "LOGIN_URL");
        if (options.clientSearchFn) this.clientSearchFn = options.clientSearchFn;
        this.redirect = options.redirect;
        this.error = options.error;
    }

    ///////////////////////////////////////////////////////////////////
    // Functions callable from apps

    /**
     * See {@link SvelteKitSharedClientEndpoints.searchClients_internal}
     */
    async searchClients(event : RequestEvent, searchTerm? : string, skip? : number, take? : number, userid? : number|string)
        : Promise<SearchClientsPageData> {

        if (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user)) 
            throw this.error(401, "Unauthorized");
        
        return this.searchClients_internal(event, searchTerm, skip, take, userid)

    }

    /**
     * See {@link SvelteKitSharedClientEndpoints.loadClient_internal}
     */
    async loadClient(event : RequestEvent)
        : Promise<UpdateClientPageData> {

        if (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user)) 
            throw this.error(401, "Unauthorized");
        return this.loadClient_internal(event)

    }

    /**
     * See {@link SvelteKitSharedClientEndpoints.updateClient_internal}
     */
    async updateClient(event : RequestEvent)
        : Promise<UpdateClientFormData> {

        if (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user)) 
            throw this.error(401, "Unauthorized");
        return this.updateClient_internal(event, true)

    }

    /**
     * See {@link SvelteKitSharedClientEndpoints.emptyClient_internal}
     */
    async emptyClient(event : RequestEvent)
    : Promise<UpdateClientPageData> {

        if (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user)) 
            throw this.error(401, "Unauthorized");
        return this.emptyClient_internal(event, true)

    }

    /**
     * See {@link SvelteKitSharedClientEndpoints.createClient_internal}
     */
    async createClient(event : RequestEvent)
        : Promise<UpdateClientFormData> {

        if (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user)) 
            throw this.error(401, "Unauthorized");
        return this.createClient_internal(event, true)

    }

    /**
     * See {@link SvelteKitSharedClientEndpoints.loadDeleteClient_internal}
     */
    async loadDeleteClient(event : RequestEvent)
        : Promise<DeleteClientPageData> {

        if (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user)) 
            throw this.error(401, "Unauthorized");
        return this.loadDeleteClient_internal(event)

    }

    /**
     * See {@link SvelteKitSharedClientEndpoints.deleteClient_internal}
     */
    async deleteClient(event : RequestEvent)
        : Promise<DeleteClientFormData> {

        if (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user)) 
            throw this.error(401, "Unauthorized");
        return this.deleteClient_internal(event, true)

    }

    /////////////////////////////////////////////////////////////////
    // Endpoints

    /**
     * See class documentation.
     */
    readonly searchClientsEndpoint = {
        load: async ( event: RequestEvent ) => {
            let userid : number|undefined = undefined;
                try {
                    userid = event.url.searchParams.get("userid") ? Number(event.url.searchParams.get("userid")) : undefined;
                } catch (e) {
                    CrossauthLogger.logger.warn(j({msg: "Invalid userid " + event.url.searchParams.get("userid")}));
                }
            const resp = await this.searchClients(event, undefined, undefined, undefined, userid);
            return {
                ...this.baseEndpoint(event),
                ...resp,
            };
        },
    };

    /**
     * See class documentation.
     */
    readonly updateClientEndpoint = {
        load: async ( event: RequestEvent ) => {
            const resp = await this.loadClient(event);
            return {
                ...this.baseEndpoint(event),
                ...resp,
            };
        },
        actions: {
            default: async (event : RequestEvent) => {
                let resp = await this.updateClient(event);
                return resp;
            }
        }
    };

    /**
     * See class documentation.
     */
    readonly createClientEndpoint = {
        load: async ( event: RequestEvent ) => {
            const resp = await this.emptyClient(event);
            return {
                ...this.baseEndpoint(event),
                ...resp,
            };
        },
        actions: {
            default: async (event : RequestEvent) => {
                let resp = await this.createClient(event);
                return resp;
            }
        }
    };

    /**
     * See class documentation.
     */
    readonly deleteClientEndpoint = {
        load: async ( event: RequestEvent ) => {
            const resp = await this.loadDeleteClient(event);
            return {
                ...this.baseEndpoint(event),
                ...resp,
            };
        },
        actions: {
            default: async (event : RequestEvent) => {
                let resp = await this.deleteClient(event);
                return resp;
            }
        }
    };
};
