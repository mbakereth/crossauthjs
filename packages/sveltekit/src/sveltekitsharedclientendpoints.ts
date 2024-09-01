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
import { error, redirect } from '@sveltejs/kit';

//////////////////////////////////////////////////////////////////////
// Return types

/**
 * Return type for {@link SvelteKitUserClientEndpoints.searchClient}
 *  {@link SvelteKitAdminClientEndpoints.searchClient} load.
 * 
 * See class documentation for {@link SvelteKitSharedClientEndpoints} for more details.
 */
export type SearchClientsPageData = {
    ok : boolean,
    clients?: OAuthClient[],
    skip : number,
    take : number,
    search? : string,
    error? : string,
    exception?: CrossauthError,
    hasPrevious : boolean,
    hasNext : boolean,
    clientUserId? : string|number,
};

/**
 * Return type for {@link SvelteKitUserClientEndpoints.updateClientEndpoint}
 *  {@link SvelteKitAdminClientEndpoints.updateClientEndpoint} load.
 * 
 * See class documentation for {@link SvelteKitSharedClientEndpoints} for more details.
 */
export type UpdateClientPageData = {
    ok: boolean,
    client?: OAuthClient,
    client_id?: string;
    clientUsername? : string,
    error? : string,
    exception?: CrossauthError,
    validFlows: string[],
    valid_flowNames: {[key:string]:string},
};

/**
 * Return type for {@link SvelteKitUserClientEndpoints.updateClientEndpoint}
 *  {@link SvelteKitAdminClientEndpoints.updateClienEndpoint} actions.
 * 
 * See class documentation for {@link SvelteKitSharedClientEndpoints} for more details.
 */
export type UpdateClientFormData = {
    ok : boolean,
    client?: OAuthClient,
    error? : string,
    exception?: CrossauthError,
    formData?: {[key:string]:string},
    plaintextSecret? : string,
};

/**
 * Return type for {@link SvelteKitUserClientEndpoints.createClientEndpoints}
 *  {@link SvelteKitAdminClientEndpoints.createClient} load.
 * 
 * See class documentation for {@link SvelteKitSharedClientEndpoints} for more details.
 */
export type CreateClientPageData = {
    ok: boolean,
    clientUserId? : string|number,
    clientUsername? : string,
    error? : string,
    exception?: CrossauthError,
    validFlows: string[],
    valid_flowNames: {[key:string]:string},
};

/**
 * Return type for {@link SvelteKitUserClientEndpoints.createClientEndpoint}
 *  {@link SvelteKitAdminClientEndpoints.createClientEndpoint} actions.
 * 
 * See class documentation for {@link SvelteKitSharedClientEndpoints} for more details.
 */
export type CreateClientFormData = {
    ok : boolean,
    client?: OAuthClient,
    error? : string,
    exception?: CrossauthError,
    formData?: {[key:string]:string},
};

/**
 * Return type for {@link SvelteKitUserClientEndpoints.deleteClientEndpoint}
 *  {@link SvelteKitAdminClientEndpoints.deleteClientEndpoint} load.
 * 
 * See class documentation for {@link SvelteKitSharedClientEndpoints} for more details.
 */
export type DeleteClientPageData = {
    ok: boolean,
    client?: OAuthClient,
    client_id?: string;
    clientUsername? : string,
    error? : string,
    exception?: CrossauthError,
};

/**
 * Return type for {@link SvelteKitUserClientEndpoints.deleteClientEndpoint}
 *  {@link SvelteKitAdminClientEndpoints.deleteClientEndpoint} actions.
 * 
 * See class documentation for {@link SvelteKitSharedClientEndpoints} for more details.
 */
export type DeleteClientFormData = {
    ok : boolean,
    error? : string,
    exception?: CrossauthError,
};

//////////////////////////////////////////////////////////////////////
// Default functions

/**
 * The `selectclient` and `admin/selectclient` endpoints have a customisable
 * function for searching for a client.  This is the default 
 * @param searchTerm the search term passed in the query string
 * @param clientStorage the client storage to search
 * @param userid the user id to se3arch for, or null for clients not owned
 *        by a user
 * @returns An array of matching {@link @crossauth/common!OAuthClient} objects,
 */
export async function defaultClientSearchFn(searchTerm: string,
    clientStorage: OAuthClientStorage, skip: number, _take: number, userid? : string|number|null) : Promise<OAuthClient[]> {
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
                await clientStorage.getClientByName(searchTerm, userid);
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

/**
 * Base class for user and admin endpoints that manipulate the OAuth
 * clients table
 */
export class SvelteKitSharedClientEndpoints {

    /**
     * The session server that instantiated this.  
     * 
     * Set in the constructor
     */
    protected sessionServer : SvelteKitSessionServer;

    /**
     * The login URL taken from the {@link SvelteKitSessionServerOptions}
     * in the constructor.
     */
    protected loginUrl = "/login";

    /**
     * Function for searching the client table.  Default is to make
     * an exact match search on `client_name`.
     */
    protected clientSearchFn : 
        (searchTerm : string, clientStorage : OAuthClientStorage, skip: number, take: number, userid? : string|number|null) => Promise<OAuthClient[]> =
        defaultClientSearchFn;
    
    /**
     * The redirect function taken from the {@link SvelteKitSessionServerOptions}
     * in the constructor.
     */
    protected redirect : any;

    /**
     * The error function taken from the {@link SvelteKitSessionServerOptions}
     * in the constructor.
     */
    protected error: any;

    /**
     * Taken from the {@link SvelteKitSessionServerOptions}
     * in the constructor.
     */
    protected validFlows : string[] = ["all"];

    /**
     * Friendly names for `validFlows`
     */
    protected valid_flowNames : {[key:string]:string};

    /**
     * The OAuth client manager instantiated during construction
     */
    protected clientManager : OAuthClientManager;

    /**
     * Taken from the {@link SvelteKitSessionServerOptions}
     * in the constructor.
     */
    protected clientStorage? : OAuthClientStorage;

    /**
     * Constructor
     * 
     * @param sessionServer the session server to add these endpoints to
     * @param options See {@link SvelteKitSessionServerOptions}
     */
    constructor(sessionServer : SvelteKitSessionServer,
        options : SvelteKitSessionServerOptions
    ) {
        this.sessionServer = sessionServer;
        setParameter("loginUrl", ParamType.JsonArray, this, options, "LOGIN_URL");
        if (options.clientSearchFn) this.clientSearchFn = options.clientSearchFn;
        this.redirect = options.redirect ?? redirect;
        this.error = options.error ?? error;

        setParameter("validFlows", ParamType.JsonArray, this, options, "OAUTH_validFlows");
        if (this.validFlows.length == 1 &&
            this.validFlows[0] == OAuthFlows.All) {
                this.validFlows = OAuthFlows.allFlows();
        }
        this.valid_flowNames = OAuthFlows.flowNames(this.validFlows);
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
     *   - `ok` true or false depending on whether there was an error
     *   - `clients` the matching array of clients
     *   - `error` error message if `ok` is false
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
    async searchClients_internal(event : RequestEvent, searchTerm? : string, skip? : number, take? : number, userid?: string|number)
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
                        this.sessionServer.clientStorage, skip-1, 1, userid);

                }
            } else {
                clients = 
                    await this.sessionServer.clientStorage.getClients(skip, 
                        take, userid);
                if (clients.length == take) {
                    nextClients = 
                        await this.sessionServer.clientStorage.getClients(skip+take, 
                            1, userid);

                }
            }

            return {
                ok: true,
                clients,
                skip,
                take,
                hasPrevious: prevClients.length > 0,
                hasNext: nextClients.length > 0,
                search: searchTerm,
                clientUserId : userid,
            }

        } catch (e) {
            if (SvelteKitServer.isSvelteKitRedirect(e) ||
                 SvelteKitServer.isSvelteKitRedirect(e)) 
                throw e;
            const ce = CrossauthError.asCrossauthError(e);
            return {
                ok: false,
                error: ce.message,
                exception: ce,
                hasPrevious: false,
                hasNext : false,
                skip: skip ?? 0, 
                take: take ?? 10,
                search: searchTerm,
                clientUserId : userid,
            }
        }

    }

    /**
     * The base class of the load function for updating an OAuth client.
     * 
     * @param event the Sveltekit request event.  The following are taken:
     *   - `client_id` from the URL path parameters
     * @returns {@see UpdateClientPageData}
     */
    protected async loadClient_internal(event : RequestEvent) : Promise<UpdateClientPageData> {
        const client_id = event.params.client_id;
        try {
            if (!client_id) throw new CrossauthError(ErrorCode.BadRequest, "No client ID specified");
            if (!this.clientStorage) throw new CrossauthError(ErrorCode.Configuration, "No client storage specified");
            const client = await this.clientStorage.getClientById(client_id);
            const userResp  = client.userid == undefined ? undefined : await this.sessionServer?.userStorage?.getUserById(client.userid);
            const clientUsername = userResp?.user?.username;
            return {
                ok: true,
                client: client,
                validFlows: this.validFlows,
                valid_flowNames: this.valid_flowNames,
                client_id,
                clientUsername,
            }
        } catch (e) {
            let ce = CrossauthError.asCrossauthError(e, "Couldn't load client");
            return {
                error: ce.message,
                exception: ce,
                ok: false,
                validFlows: this.validFlows,
                valid_flowNames: this.valid_flowNames,
                client_id,
            }
        }
    }

    /**
     * The base class of the actions function for updating an OAuth client.
     * 
     * @param event the Sveltekit request event.  The following are taken:
     *   - `client_id` from the URL path parameters
     *   - `client_name` from the body form data
     *   - `redirect_uri` from the body form data (space-separated)
     *   - `confidential` from the body form data: 1, `on`, `yes` or `true` are true
     *   _ `resetSecret` if true (1, `on`, `yes` or `true`), create and return a new secret.  Ignored if not confidential
     *   - Flow names from {@link @crossauth/common/OAuthFlows} taken from the body form data.  1, `on`, `yes` or `true` are true 
     * @returns {@see UpdateClientFormData}.  If a new secret was created, it will be placed as plaintext in the client that is returned.
     */
    protected async updateClient_internal(event : RequestEvent, isAdmin: boolean) : Promise<UpdateClientFormData> {
        
        let formData : {[key:string]:string}|undefined = undefined;
        try {
            const client_id = event.params.client_id;
            if (!client_id) throw new CrossauthError(ErrorCode.BadRequest, "No client ID given");

            // get form data
            var data = new JsonOrFormData();
            await data.loadData(event);
            formData = data.toObject();

            // get client
            //const client = await this.clientStorage?.getClientById(client_id);
            //if (!client) throw new CrossauthError(ErrorCode.InvalidClientId, "Client does not exist");

        // throw an error if the CSRF token is invalid
        if (this.sessionServer.enableCsrfProtection && event.locals.authType == "cookie" && !event.locals.csrfToken) {
            throw new CrossauthError(ErrorCode.InvalidCsrf);
        }

        const redirect_uri = !formData.redirect_uri || formData.redirect_uri.trim().length == 0 ? 
            [] : formData.redirect_uri.trim().split(/,?[ \t\n]+/);

        // validate redirect uris
        let redirect_uriErrors : string[] = [];
        for (let uri of redirect_uri) {
            try {
                OAuthClientManager.validateUri(uri);
            }
            catch (e) {
                CrossauthLogger.logger.error(j({err: e}));
                redirect_uriErrors.push("["+uri+"]");
            }
        }
        if (redirect_uriErrors.length > 0) {
            throw new CrossauthError(ErrorCode.BadRequest, 
                "The following redirect URIs are invalid: " 
                    + redirect_uriErrors.join(" "));
        }

        // get flows from booleans in body
        let validFlows = [];
        for (let flow of this.validFlows) {
            if (flow in formData)
             validFlows.push(flow);
        }
        
        const clientUpdate : Partial<OAuthClient> = {}
        clientUpdate.client_name = formData.client_name;
        clientUpdate.confidential = data.getAsBoolean("confidential") ?? false;
        clientUpdate.valid_flow = validFlows;
        clientUpdate.redirect_uri = redirect_uri;
        if (isAdmin) {
            let userid : string|number|undefined = formData.userid ?? undefined;
            if (userid && this.sessionServer?.userStorage) {
                const {user} = await this.sessionServer?.userStorage.getUserById(userid);
                userid = user.id;
            }
            clientUpdate.userid = formData.userid ? Number(formData.userid) : null;

        }
        const resetSecret = data.getAsBoolean("resetSecret");
        
        const {client: newClient, newSecret} = 
            await this.clientManager.updateClient(client_id,
                clientUpdate,
                resetSecret);
        return {
            ok: true,
            client: newClient,
            formData: formData,
            //plaintextSecret: resetSecret ? formData.client_secret : undefined,
            plaintextSecret: newSecret && newClient.client_secret ? newClient.client_secret : undefined,

        }

        } catch (e) {
            if (SvelteKitServer.isSvelteKitRedirect(e) || SvelteKitServer.isSvelteKitError(e)) throw e;
            let ce = CrossauthError.asCrossauthError(e, "Couldn't update client");
            return {
                error: ce.message,
                exception: ce,
                ok: false,
                formData,
            }
        } 
    }

    /**
     * The base class of the load function for creating an OAuth client.
     * 
     * @param event the Sveltekit request event.  The following are taken:
     *   - `userid` from the body parameters parameters.  Ignored if `isAdmin` is false.  Can be undefined
     *   - 
     * @returns {@see CreateClientPageData}.  
     */
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
    
                const formClientUserId = data.get("userid");
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
                ok: true,
                validFlows: this.validFlows,
                valid_flowNames: this.valid_flowNames,
                clientUserId,
                clientUsername,
            }
        } catch (e) {
            let ce = CrossauthError.asCrossauthError(e, "Couldn't initialize new client");
            return {
                error: ce.message,
                exception: ce,
                ok: false,
                validFlows: this.validFlows,
                valid_flowNames: this.valid_flowNames,
            }
        }
    }

    /**
     * The base class of the actions function for creating an OAuth client.
     * 
     * @param event the Sveltekit request event.  The following are taken:
     *   - `userid` from the URL query parameters.  Ignored if `isAdmin` is false.  Can be undefined
     *   - `client_name` from the body form data
     *   - `redirect_uri` from the body form data (space-separated)
     *   - `confidential` from the body form data: 1, `on`, `yes` or `true` are true
     *   - Flow names from {@link @crossauth/common/OAuthFlows} taken from the body form data.  1, `on`, `yes` or `true` are true 
     * @returns {@see UpdateClientFormData}.  If a secret was created, it will be placed as plaintext in the client that is returned.  A random `client_id` is created.
     */
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
                const clientUserIdString = data.get("userid");
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

            const redirect_uri = !formData.redirect_uri || formData.redirect_uri.trim().length == 0 ? 
                [] : formData.redirect_uri.trim().split(/,?[ \t\n]+/);

            // validate redirect uris
            let redirect_uriErrors : string[] = [];
            for (let uri of redirect_uri) {
                try {
                    OAuthClientManager.validateUri(uri);
                }
                catch (e) {
                    CrossauthLogger.logger.error(j({err: e}));
                    redirect_uriErrors.push("["+uri+"]");
                }
            }
            if (redirect_uriErrors.length > 0) {
                throw new CrossauthError(ErrorCode.BadRequest, 
                    "The following redirect URIs are invalid: " 
                        + redirect_uriErrors.join(" "));
            }

            // get flows from booleans in body
            let validFlows = [];
            for (let flow of this.validFlows) {
                if (flow in formData)
                validFlows.push(flow);
            }
            
            const clientUpdate : Partial<OAuthClient> = {}
            clientUpdate.client_name = formData.client_name;
            clientUpdate.confidential = data.getAsBoolean("confidential")
            clientUpdate.valid_flow = validFlows;
            clientUpdate.redirect_uri = redirect_uri;
            if (isAdmin) {
                clientUpdate.userid = formData.userid ? Number(formData.userid) : null;
            }
            
            const newClient = 
                await this.clientManager.createClient(formData.client_name,
                    redirect_uri,
                    validFlows,
                    data.getAsBoolean("confidential") ?? false,
                    clientUserId );
            return {
                ok: true,
                client: newClient,
                formData: formData,
            }

        } catch (e) {
            if (SvelteKitServer.isSvelteKitRedirect(e) || SvelteKitServer.isSvelteKitError(e)) throw e;
            let ce = CrossauthError.asCrossauthError(e, "Couldn't create client");
            return {
                error: ce.message,
                exception: ce,
                ok: false,
                formData,
            }
        } 
    }

    /**
     * The base class of the load function for deleting an OAuth client.
     * 
     * @param event the Sveltekit request event.  The following are taken:
     *   - `client_id` from the URL path parameters
     * @returns {@see DeleteClientPageData}
     */
    protected async loadDeleteClient_internal(event : RequestEvent) : Promise<DeleteClientPageData> {
        const client_id = event.params.client_id;
        try {
            if (!client_id) throw new CrossauthError(ErrorCode.BadRequest, "No client ID specified");
            if (!this.clientStorage) throw new CrossauthError(ErrorCode.Configuration, "No client storage specified");
            const client = await this.clientStorage.getClientById(client_id);
            const userResp  = client.userid == undefined ? undefined : await this.sessionServer?.userStorage?.getUserById(client.userid);
            const clientUsername = userResp?.user?.username;
            return {
                ok: true,
                client: client,
                client_id,
                clientUsername,
            }
        } catch (e) {
            let ce = CrossauthError.asCrossauthError(e, "Couldn't load client");
            return {
                error: ce.message,
                exception: ce,
                ok: false,
                client_id,
            }
        }
    }

    /**
     * The base class of the actions function for deleting an OAuth client.
     * 
     * @param event the Sveltekit request event.  The following are taken:
     *   - `client_id` from the URL path parameters
     * @returns {@see DeleteClientFormData}
     */
    protected async deleteClient_internal(event : RequestEvent, isAdmin: boolean) : Promise<DeleteClientFormData> {
        
        try {
            // throw an error if the CSRF token is invalid
            if (this.sessionServer.enableCsrfProtection && event.locals.authType == "cookie" && !event.locals.csrfToken) {
                throw new CrossauthError(ErrorCode.InvalidCsrf);
            }

            const client_id = event.params.client_id;
            if (!client_id) throw new CrossauthError(ErrorCode.BadRequest, "No client ID given");

            if (!this.clientStorage) throw new CrossauthError(ErrorCode.Configuration, "No client storage specified");
            const client = await this.clientStorage?.getClientById(client_id);

            if (!isAdmin) {
                if (client.userid != event.locals.user?.id) throw this.error(401, "Unauthorized");
            }
        
        await this.clientStorage.deleteClient(client_id);
        return {
            ok: true,
        }

        } catch (e) {
            if (SvelteKitServer.isSvelteKitRedirect(e) || SvelteKitServer.isSvelteKitError(e)) throw e;
            let ce = CrossauthError.asCrossauthError(e, "Couldn't delete client");
            return {
                error: ce.message,
                exception: ce,
                ok: false,
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
