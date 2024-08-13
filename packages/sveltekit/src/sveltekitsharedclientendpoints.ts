import { SvelteKitServer } from './sveltekitserver';
import { SvelteKitSessionServer } from './sveltekitsession';
import type { SvelteKitSessionServerOptions } from './sveltekitsession';
import { 
    setParameter,
    ParamType,
    OAuthClientManager,
 } from '@crossauth/backend';
import type {  OAuthClientStorage } from '@crossauth/backend';
import type {  OAuthClient } from '@crossauth/common';
import { CrossauthError, CrossauthLogger, j, ErrorCode, OAuthFlows } from '@crossauth/common';
import type { RequestEvent } from '@sveltejs/kit';
import { JsonOrFormData } from './utils';

//////////////////////////////////////////////////////////////////////
// Return types

/**
 * Return type for {@link SvelteKitUserClientEndpoints.searchClients}
 *  {@link SvelteKitAdminClientEndpoints.searchClients} load.
 * 
 * See class documentation for {@link SvelteKitUserEndpoints} for more details.
 */
export type SearchClientsPageData = {
    success : boolean,
    clients?: OAuthClient[],
    skip : number,
    take : number,
    search? : string,
    error? : string,
    exception?: CrossauthError,
    hasPrevious : boolean,
    hasNext : boolean,
};

/**
 * Return type for {@link SvelteKitUserClientEndpoints.updateClient}
 *  {@link SvelteKitAdminClientEndpoints.updateClient} load.
 * 
 * See class documentation for {@link SvelteKitUserEndpoints} for more details.
 */
export type UpdateClientPageData = {
    success: boolean,
    client?: OAuthClient,
    clientId?: string;
    clientUsername? : string,
    error? : string,
    exception?: CrossauthError,
    validFlows: string[],
    validFlowNames: {[key:string]:string},
};

/**
 * Return type for {@link SvelteKitUserClientEndpoints.updateClient}
 *  {@link SvelteKitAdminClientEndpoints.updateClient} actions.
 * 
 * See class documentation for {@link SvelteKitUserEndpoints} for more details.
 */
export type UpdateClientFormData = {
    success : boolean,
    client?: OAuthClient,
    error? : string,
    exception?: CrossauthError,
    formData?: {[key:string]:string},
    plaintextSecret? : string,
};

/**
 * Return type for {@link SvelteKitUserClientEndpoints.updateClient}
 *  {@link SvelteKitAdminClientEndpoints.updateClient} load.
 * 
 * See class documentation for {@link SvelteKitUserEndpoints} for more details.
 */
export type CreateClientPageData = {
    success: boolean,
    clientUserId? : string|number,
    clientUsername? : string,
    error? : string,
    exception?: CrossauthError,
    validFlows: string[],
    validFlowNames: {[key:string]:string},
};

/**
 * Return type for {@link SvelteKitUserClientEndpoints.updateClient}
 *  {@link SvelteKitAdminClientEndpoints.updateClient} actions.
 * 
 * See class documentation for {@link SvelteKitUserEndpoints} for more details.
 */
export type CreateClientFormData = {
    success : boolean,
    client?: OAuthClient,
    error? : string,
    exception?: CrossauthError,
    formData?: {[key:string]:string},
};

//////////////////////////////////////////////////////////////////////
// Default functions

/**
 * The `selectclient` and `admin/selectclient` endpoints have a customisable
 * function for searching for a client.  This is the default 
 * @param searchTerm the search term passed in the query string
 * @param clientStorage the client storage to search
 * @param userId the user id to se3arch for, or null for clients not owned
 *        by a user
 * @returns An array of matching {@link @crossauth/common!OAuthClient} objects,
 */
export async function defaultClientSearchFn(searchTerm: string,
    clientStorage: OAuthClientStorage, skip: number, _take: number, userId? : string|number|null) : Promise<OAuthClient[]> {
        let clients : OAuthClient[] = [];
    if (skip > 0) return [];
    try {
        const client = await clientStorage.getClientById(searchTerm)
        clients.push(client);
    } catch (e1) {
        const ce1 = CrossauthError.asCrossauthError(e1);
        if (ce1.code != ErrorCode.UserNotExist) {
            CrossauthLogger.logger.debug(j({err: ce1}));
            throw ce1;
        }
        try {
            clients = 
                await clientStorage.getClientByName(searchTerm, userId);
            } catch (e2) {
            const ce2 = CrossauthError.asCrossauthError(e2);
            if (ce2.code != ErrorCode.UserNotExist) {
                CrossauthLogger.logger.debug(j({err: ce2}));
                throw ce1;
            }
        }
    }
    return clients;

}

//////////////////////////////////////////////////////////////////////
// Class

export class SvelteKitSharedClientEndpoints {
    protected sessionServer : SvelteKitSessionServer;
    protected loginUrl = "/login";
    protected clientSearchFn : 
        (searchTerm : string, clientStorage : OAuthClientStorage, skip: number, take: number, userId? : string|number|null) => Promise<OAuthClient[]> =
        defaultClientSearchFn;
    protected redirect : any;
    protected error: any;
    protected validFlows : string[] = ["all"];
    protected validFlowNames : {[key:string]:string};
    protected clientManager : OAuthClientManager;
    protected clientStorage? : OAuthClientStorage;

    constructor(sessionServer : SvelteKitSessionServer,
        options : SvelteKitSessionServerOptions
    ) {
        this.sessionServer = sessionServer;
        setParameter("loginUrl", ParamType.JsonArray, this, options, "LOGIN_URL");
        if (options.clientSearchFn) this.clientSearchFn = options.clientSearchFn;
        this.redirect = options.redirect;
        this.error = options.error;

        setParameter("validFlows", ParamType.JsonArray, this, options, "OAUTH_VALID_FLOWS");
        if (this.validFlows.length == 1 &&
            this.validFlows[0] == OAuthFlows.All) {
                this.validFlows = OAuthFlows.allFlows();
        }
        this.validFlowNames = OAuthFlows.flowNames(this.validFlows);
        this.clientManager = new OAuthClientManager(options);
        this.clientStorage = options.clientStorage;

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
    async searchClients_internal(event : RequestEvent, searchTerm? : string, skip? : number, take? : number, userId?: string|number)
        : Promise<SearchClientsPageData> {

        try {

            if (!this.sessionServer.userStorage) throw new CrossauthError(ErrorCode.Configuration, "Must provide user storage to use this function");
            if (!this.sessionServer.clientStorage) throw new CrossauthError(ErrorCode.Configuration, "Must provide client storage to use this function");

            // can only call this if logged in 
            if (!event.locals.user) 
                throw this.redirect(302, this.loginUrl + "?next="+encodeURIComponent(event.request.url));
            
            let clients : OAuthClient[] = [];
            let prevClients : OAuthClient[] = [];
            let nextClients : OAuthClient[] = [];
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
                clients = await this.clientSearchFn(searchTerm, 
                    this.sessionServer.clientStorage, skip, take);
                if (skip > 0) {
                    prevClients = await this.clientSearchFn(searchTerm, 
                        this.sessionServer.clientStorage, skip-1, 1, userId);

                }
            } else {
                clients = 
                    await this.sessionServer.clientStorage.getClients(skip, 
                        take, userId);
                if (clients.length == take) {
                    nextClients = 
                        await this.sessionServer.clientStorage.getClients(skip+take, 
                            1, userId);

                }
            }

            return {
                success: true,
                clients,
                skip,
                take,
                hasPrevious: prevClients.length > 0,
                hasNext: nextClients.length > 0,
                search: searchTerm
            }

        } catch (e) {
            if (SvelteKitServer.isSvelteKitRedirect(e) ||
                 SvelteKitServer.isSvelteKitRedirect(e)) 
                throw e;
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

    protected async loadClient_internal(event : RequestEvent) : Promise<UpdateClientPageData> {
        const clientId = event.params.clientId;
        try {
            if (!clientId) throw new CrossauthError(ErrorCode.BadRequest, "No client ID specified");
            if (!this.clientStorage) throw new CrossauthError(ErrorCode.Configuration, "No client storage specified");
            const client = await this.clientStorage.getClientById(clientId);
            const userResp  = client.userId == undefined ? undefined : await this.sessionServer?.userStorage?.getUserById(client.userId);
            const clientUsername = userResp?.user?.username;
            return {
                success: true,
                client: client,
                validFlows: this.validFlows,
                validFlowNames: this.validFlowNames,
                clientId,
                clientUsername,
            }
        } catch (e) {
            let ce = CrossauthError.asCrossauthError(e, "Couldn't log in");
            return {
                error: ce.message,
                exception: ce,
                success: false,
                validFlows: this.validFlows,
                validFlowNames: this.validFlowNames,
                clientId,
            }
        }
    }

    protected async updateClient_internal(event : RequestEvent, isAdmin: boolean) : Promise<UpdateClientFormData> {
        
        let formData : {[key:string]:string}|undefined = undefined;
        try {
            const clientId = event.params.clientId;
            if (!clientId) throw new CrossauthError(ErrorCode.BadRequest, "No client ID given");

            // get form data
            var data = new JsonOrFormData();
            await data.loadData(event);
            formData = data.toObject();

            // get client
            //const client = await this.clientStorage?.getClientById(clientId);
            //if (!client) throw new CrossauthError(ErrorCode.InvalidClientId, "Client does not exist");

        // throw an error if the CSRF token is invalid
        if (this.sessionServer.enableCsrfProtection && event.locals.authType == "cookie" && !event.locals.csrfToken) {
            throw new CrossauthError(ErrorCode.InvalidCsrf);
        }

        const redirectUris = formData.redirectUris.trim().length == 0 ? 
            [] : formData.redirectUris.trim().split(/,?[ \t\n]+/);

        // validate redirect uris
        let redirectUriErrors : string[] = [];
        for (let uri of redirectUris) {
            try {
                OAuthClientManager.validateUri(uri);
            }
            catch (e) {
                CrossauthLogger.logger.error(j({err: e}));
                redirectUriErrors.push("["+uri+"]");
            }
        }
        if (redirectUriErrors.length > 0) {
            throw new CrossauthError(ErrorCode.BadRequest, 
                "The following redirect URIs are invalid: " 
                    + redirectUriErrors.join(" "));
        }

        // get flows from booleans in body
        let validFlows = [];
        for (let flow of this.validFlows) {
            if (flow in formData)
             validFlows.push(flow);
        }
        
        const clientUpdate : Partial<OAuthClient> = {}
        clientUpdate.clientName = formData.clientName;
        clientUpdate.confidential = data.getAsBoolean("confidential") ?? false;
        clientUpdate.validFlow = validFlows;
        clientUpdate.redirectUri = redirectUris;
        if (isAdmin) {
            let userId : string|number|undefined = formData.userId ?? undefined;
            if (userId && this.sessionServer?.userStorage) {
                const {user} = await this.sessionServer?.userStorage.getUserById(userId);
                userId = user.id;
            }
            clientUpdate.userId = formData.userId ? Number(formData.userId) : null;

        }
        const resetSecret = formData.resetSecret == "true";
        
        const {client: newClient, newSecret} = 
            await this.clientManager.updateClient(clientId,
                clientUpdate,
                resetSecret);
        return {
            success: true,
            client: newClient,
            formData: formData,
            //plaintextSecret: resetSecret ? formData.clientSecret : undefined,
            plaintextSecret: newSecret && newClient.clientSecret ? newClient.clientSecret : undefined,

        }

        } catch (e) {
            if (SvelteKitServer.isSvelteKitRedirect(e) || SvelteKitServer.isSvelteKitError(e)) throw e;
            let ce = CrossauthError.asCrossauthError(e, "Couldn't log in");
            return {
                error: ce.message,
                exception: ce,
                success: false,
                formData,
            }
        } 
    }

    protected async emptyClient_internal(event : RequestEvent, isAdmin : boolean) : Promise<CreateClientPageData> {
        try {
            // get client user id and username

            var data = new JsonOrFormData();
            await data.loadData(event);

            let clientUserId : string|number|undefined = undefined;
            if (isAdmin) {
                const clientUserIdString = event.url.searchParams.get("userid");
                if (clientUserIdString && this.sessionServer?.userStorage) {
                    const {user} = await this.sessionServer?.userStorage.getUserById(clientUserIdString);
                    clientUserId = user.id;
                }
    
                const formClientUserId = data.get("userId");
                if (formClientUserId  && this.sessionServer?.userStorage) {
                        const {user} = await this.sessionServer?.userStorage.getUserById(formClientUserId);
                        clientUserId = user.id;
                }
                    
            } else {
                if (!event.locals.user) throw new CrossauthError(ErrorCode.Unauthorized)
                clientUserId = event.locals.user.id;
            }

            if (!this.clientStorage) throw new CrossauthError(ErrorCode.Configuration, "No client storage specified");
            const userResp  = clientUserId == undefined ? undefined : await this.sessionServer?.userStorage?.getUserById(clientUserId);
            const clientUsername = userResp?.user?.username;

            return {
                success: true,
                validFlows: this.validFlows,
                validFlowNames: this.validFlowNames,
                clientUserId,
                clientUsername,
            }
        } catch (e) {
            let ce = CrossauthError.asCrossauthError(e, "Couldn't log in");
            return {
                error: ce.message,
                exception: ce,
                success: false,
                validFlows: this.validFlows,
                validFlowNames: this.validFlowNames,
            }
        }
    }

    protected async createClient_internal(event : RequestEvent, isAdmin: boolean) : Promise<CreateClientFormData> {
        
        let formData : {[key:string]:string}|undefined = undefined;
        try {

            // get form data
            var data = new JsonOrFormData();
            await data.loadData(event);
            formData = data.toObject();

            // get client user id 
            let clientUserId : string|number|undefined = undefined;
            if (isAdmin) {
                const clientUserIdString = data.get("userId");
                if (clientUserIdString  && this.sessionServer?.userStorage) {
                    const {user} = await this.sessionServer?.userStorage.getUserById(clientUserIdString);
                    clientUserId = user.id;
                }
            } else {
                if (!event.locals.user) throw new CrossauthError(ErrorCode.Unauthorized)
                    clientUserId = event.locals.user.id;
            }

            if (!this.clientStorage) throw new CrossauthError(ErrorCode.Configuration, "No client storage specified");
            if (clientUserId) await this.sessionServer?.userStorage?.getUserById(clientUserId); // just to make it throw an exception if user doesn't exist

            // throw an error if the CSRF token is invalid
            if (this.sessionServer.enableCsrfProtection && event.locals.authType == "cookie" && !event.locals.csrfToken) {
                throw new CrossauthError(ErrorCode.InvalidCsrf);
            }

            const redirectUris = formData.redirectUris.trim().length == 0 ? 
                [] : formData.redirectUris.trim().split(/,?[ \t\n]+/);

            // validate redirect uris
            let redirectUriErrors : string[] = [];
            for (let uri of redirectUris) {
                try {
                    OAuthClientManager.validateUri(uri);
                }
                catch (e) {
                    CrossauthLogger.logger.error(j({err: e}));
                    redirectUriErrors.push("["+uri+"]");
                }
            }
            if (redirectUriErrors.length > 0) {
                throw new CrossauthError(ErrorCode.BadRequest, 
                    "The following redirect URIs are invalid: " 
                        + redirectUriErrors.join(" "));
            }

            // get flows from booleans in body
            let validFlows = [];
            for (let flow of this.validFlows) {
                if (flow in formData)
                validFlows.push(flow);
            }
            
            const clientUpdate : Partial<OAuthClient> = {}
            clientUpdate.clientName = formData.clientName;
            clientUpdate.confidential = data.getAsBoolean("confidential")
            clientUpdate.validFlow = validFlows;
            clientUpdate.redirectUri = redirectUris;
            if (isAdmin) {
                clientUpdate.userId = formData.userId ? Number(formData.userId) : null;
            }
            
            const newClient = 
                await this.clientManager.createClient(formData.clientName,
                    redirectUris,
                    validFlows,
                    data.getAsBoolean("confidential") ?? false,
                    clientUserId );
            return {
                success: true,
                client: newClient,
                formData: formData,
            }

        } catch (e) {
            if (SvelteKitServer.isSvelteKitRedirect(e) || SvelteKitServer.isSvelteKitError(e)) throw e;
            let ce = CrossauthError.asCrossauthError(e, "Couldn't log in");
            return {
                error: ce.message,
                exception: ce,
                success: false,
                formData,
            }
        } 
    }

    /////////////////////////////////////////////////////////////////
    // Endpoints

    /**
     * Returned by all endpoitns
     * @param event the sveltekit request event
     * @returns object with
     *   - `user` - the logged in user
     *   - `csrfToken` the CSRF token if using
     */
    baseEndpoint(event : RequestEvent) {
        return {
            user : event.locals.user,
            csrfToken: event.locals.csrfToken,
        }
    }
};
