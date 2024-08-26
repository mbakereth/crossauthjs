import { jwtDecode } from "jwt-decode";
import QRCode from 'qrcode';
import {
    CrossauthError,
    ErrorCode,
    CrossauthLogger,
    OAuthFlows,
    j,} from '@crossauth/common';
import type {
    OAuthTokenResponse,
    MfaAuthenticatorResponse,
    OAuthDeviceAuthorizationResponse} from '@crossauth/common';
import {
    setParameter,
    ParamType,
    Crypto,
    OAuthClientBackend } from '@crossauth/backend';
import type { OAuthClientOptions } from '@crossauth/backend';
import { SvelteKitServer } from './sveltekitserver';
import { json } from '@sveltejs/kit';
import type { RequestEvent } from '@sveltejs/kit';
import { JsonOrFormData } from './utils';

export type SvelteKitErrorFn = (server: SvelteKitServer,
    event: RequestEvent,
    ce: CrossauthError) => Promise<Response>;

///////////////////////////////////////////////////////////////////////////////
// OPTIONS

/**
 * Options for {@link SvelteKitOAuthClient}.
 */
export interface SvelteKitOAuthClientOptions extends OAuthClientOptions {

    /** 
     * You will have to create a route for the redirect Uri, using
     * the `redirectUriEndpoint` load function.  But the URL for it
     * here.  It should be an absolute URL.
     * 
     * It should be a fully qualified URL as it is called from
     * the browser in a redriect.
     * 
     * The default is "oauth/authzcode".
     */
    redirectUri ?: string,

    /**
     * When using the BFF (backend-for-frontend) pattern, tokens are saved
     * in the `data` field of the session ID.  They are saved in the JSON
     * object with this field name.  Default `oauth`.
     */
    sessionDataName? : string,

    /**
     * If the {@link SvelteKitOAuthClientOptions.tokenResponseType} is
     * `saveInSessionAndRedirect`, this is the relative URL that the usder
     * will be redirected to after authorization is complete.
     */
    authorizedUrl? : string,

    /**
     * Relative URL to redirect user to if login is required.
     */
    loginUrl? : string,

    /**
     * All flows listed here will require the user to login (here at the client).
     * If if a flow is not listed here, there does not need to be a user
     * logged in here at the client.
     * 
     * In most cases you can ignore this and use 
     * {@link SvelteKitSessionServerOptions.loginProtectedPageEndpoints}
     * to protect the endpoints that begin the flows.
     * 
     * See {@link @crossauth/common!OAuthFlows}.
     */
    loginProtectedFlows? : string[],

    /**
     * This function is called after successful authorization to pass the
     * new tokens to.
     * @param oauthResponse the response from the OAuth `token` endpoint.
     * @param client the OAuth client
     * @param event the SvelteKit request event
     * @param silent if true, don't return a Response, only JSON or undefined.
     * @returns a Response, JSON or undefined
     */
    receiveTokenFn?: (oauthResponse: OAuthTokenResponse,
        client: SvelteKitOAuthClient,
        event: RequestEvent, silent: boolean) => Promise<Response|TokenReturn|undefined>;

    /**
     * The function to call when there is an OAuth error and
     * {@link SvelteKitOAuthClientOptions.errorResponseType}
     * is `custom`.
     * See {@link SvelteKitErrorFn}.
     */
    errorFn? :SvelteKitErrorFn;

    /**
     * This function called when the token endpoint in the device code flow
     * reports that authorization is pending
     * @param oauthResponse the response from the OAuth `token` endpoint.
     * @param client the OAuth client
     * @param event the SvelteKit request event
     * @returns a Response, JSON or undefined
     */
    deviceCodePendingFn?: (oauthResponse: OAuthTokenResponse,
        client: SvelteKitOAuthClient,
        event: RequestEvent) => Promise<Response|TokenReturn|undefined>;

    /**
     * What to do when receiving tokens.
     * See {@link SvelteKitOAuthClient} class documentation for full description.
     */
    tokenResponseType? : 
        "sendJson" | 
        "saveInSessionAndLoad" | 
        "saveInSessionAndRedirect" | 
        "saveInSessionAndReturn" | 
        "sendInPage" | 
        "custom";

    /**
     * What do do on receiving an OAuth error.
     * See lass documentation for full description.
     */
    errorResponseType? : 
        "sendJson" | 
        "svelteKitError" | 
        "custom",

    /** 
     * Array of resource server endppints to serve through the
     * BFF (backend-for-frontend) mechanism.
     * See {@link SvelteKitOAuthClient} class documentation for full description.
     */
    bffEndpoints?: {
        url: string,
        methods: ("GET" | "POST" | "PUT" | "DELETE" | "PATCH")[],
        matchSubUrls?: boolean
    }[],

    /**
     * Prefix for BFF endpoints.  Default "bff".
     * See {@link SvelteKitOAuthClient} class documentation for full description.
     */
    bffEndpointName? : string,

    /**
     * Base URL for resource server endpoints called through the BFF
     * mechanism.
     * See {@link SvelteKitOAuthClient} class documentation for full description.
     */
    bffBaseUrl? : string,

    /**
     * Now many times to attempt to make a BFF request before failing
     * with an unauthorized reponse.  This is useful when you have
     * enable auto refresh.  If you make a resource request just as the
     * token is renewing, you might get an error.
     * 
     * Default 1
     */
    bffMaxTries? : number,

    /**
     * How many milliseconds to sleep between BFF tries.
     * 
     * See {@link SvelteKitOAuthClientOptions.bffMaxTries}
     * 
     * Default 500
     */
    bffSleepMilliseconds? : number,

    /**
     * Endpoints to provide to acces tokens through the BFF mechanism,
     * See {@link FastifyOAuthClient} class documentation for full description.
     */
    tokenEndpoints? : ("access_token"|"refresh_token"|"id_token"|
        "have_access_token"|"have_refresh_token"|"have_id_token")[],

    /** Pass the Sveltekit redirect function */
    redirect? : any,

    /** Pass the Sveltekit error function */
    error? : any,

    /**
     * Set of flows to enable (see {@link @crossauth/common!OAuthFlows}).
     * 
     * Defaults to all flows, as they must be created manually in
     * your `routes`.  However, be aware that the Password and Password MFA
     * flows are on the same endpoint, so if you want to support one and
     * not the other, set this variable.
     */
    validFlows? : string[],
}

////////////////////////////////////////////////////////////////////////////
// Interfaces

/**
 * Returned by the authorize endpoint
 */
export interface AuthorizationCodeFlowReturn {
    ok: boolean,
    error? : string,
    error_description? : string
}

/**
 * Returned by the token endpoint
 */
export interface TokenReturn extends OAuthTokenResponse {
    ok: boolean,
    id_payload?: {[key:string]:any},
}

/**
 * Returned by the redirect URI endpoint
 */
export interface RedirectUriReturn extends OAuthTokenResponse {
    ok: boolean,
}

////////////////////////////////////////////////////////////////////////////
// DEFAULT FUNCTIONS

async function jsonError(_server: SvelteKitServer,
    _event: RequestEvent,
    ce: CrossauthError) : Promise<Response> {
    CrossauthLogger.logger.debug(j({err: ce}));
    return json({
            ok: false,
            status: ce.httpStatus,
            errorMessage: ce.message,
            errorMessages: ce.messages,
            errorCode: ce.code,
            errorCodeName: ce.codeName
    }, {status: ce.httpStatus});
}

async function svelteKitError(server: SvelteKitServer,
    _event: RequestEvent,
    ce: CrossauthError) : Promise<Response> {
        throw server.oAuthClient?.error(ce.httpStatus, ce.message);
} 

function decodePayload(token : string|undefined) : {[key:string]: any}|undefined {
    let payload : {[key:string]: any}|undefined = undefined;
    if (token) {
        try {
            payload = JSON.parse(Crypto.base64Decode(token.split(".")[1]))
        } catch (e) {
            CrossauthLogger.logger.error(j({msg: "Couldn't decode id token"}));
        }
    }
    return payload;

}

async function sendJson(oauthResponse: OAuthTokenResponse,
    _client: SvelteKitOAuthClient,
    _event: RequestEvent,
    _silent?: boolean) : Promise<Response|undefined> {
        return json({ok: true, ...oauthResponse, 
            id_payload: decodePayload(oauthResponse.id_token)})
}

function logTokens(oauthResponse: OAuthTokenResponse) {
    if (oauthResponse.access_token) {
        try {
            if (oauthResponse.access_token) {
                const jti = jwtDecode(oauthResponse.access_token)?.jti;
                const hash = jti ? Crypto.hash(jti) : undefined;
                CrossauthLogger.logger.debug(j({msg: "Got access token", 
                    accessTokenHash: hash}));
            }
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
        }
    }
    if (oauthResponse.id_token) {
        try {
            if (oauthResponse.id_token) {
                const jti = jwtDecode(oauthResponse.id_token)?.jti;
                const hash = jti ? Crypto.hash(jti) : undefined;
                CrossauthLogger.logger.debug(j({msg: "Got id token", 
                    idTokenHash: hash}));
            }
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
        }
    }
    if (oauthResponse.refresh_token) {
        try {
            if (oauthResponse.refresh_token) {
                const jti = jwtDecode(oauthResponse.refresh_token)?.jti;
                const hash = jti ? Crypto.hash(jti) : undefined;
                CrossauthLogger.logger.debug(j({msg: "Got refresh token", 
                    refreshTokenHash: hash}));
            }
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
        }
    }
}

async function updateSessionData(oauthResponse: OAuthTokenResponse,
    client: SvelteKitOAuthClient,
    event: RequestEvent,
    ) {
        let sessionCookieValue = client.server.sessionServer?.getSessionCookieValue(event);
        let expires_in = oauthResponse.expires_in;
        if (!expires_in && oauthResponse.access_token) {
            const payload = jwtDecode(oauthResponse.access_token);
            if (payload.exp) expires_in = payload.exp;
        }
        if (!expires_in) {
            throw new CrossauthError(ErrorCode.BadRequest, 
                "OAuth server did not return an expiry for the access token");
        }
        const expires_at = Date.now() + (expires_in)*1000;
        if (!sessionCookieValue) {
            sessionCookieValue = 
                await client.server.sessionServer?.createAnonymousSession(event,
                    { [client.sessionDataName]: {...oauthResponse, expires_at} });
        } else {
            const existingData = 
                await client.server.sessionServer?.getSessionData(event, client.sessionDataName);
            await client.server.sessionServer?.updateSessionData(event,
                client.sessionDataName,
                { ...existingData??{},  ...oauthResponse, expires_at });
        }

}

async function saveInSessionAndRedirect(oauthResponse: OAuthTokenResponse,
    client: SvelteKitOAuthClient,
    event: RequestEvent,
    silent: boolean
    ) : Promise<Response|undefined> {
    if (oauthResponse.error) {
        const ce = CrossauthError.fromOAuthError(oauthResponse.error, 
            oauthResponse.error_description);
        return client.errorFn(client.server, event, ce);
    }

    logTokens(oauthResponse);

    try {
        if (oauthResponse.access_token || oauthResponse.id_token || oauthResponse.refresh_token) {
            await updateSessionData(oauthResponse, client, event);
        }

        if (!silent) return client.redirect(302, client.authorizedUrl);
    } catch (e) {
        if (SvelteKitServer.isSvelteKitError(e) || SvelteKitServer.isSvelteKitRedirect(e)) throw e;
        const ce = CrossauthError.asCrossauthError(e);
        CrossauthLogger.logger.debug(j({err: ce}));
        CrossauthLogger.logger.debug(j({cerr: ce, msg: "Error receiving tokens"}));
        return client.errorFn(client.server, event, ce);
    }
}

async function saveInSessionAndReturn(oauthResponse: OAuthTokenResponse,
    client: SvelteKitOAuthClient,
    event: RequestEvent,
    silent: boolean
    ) : Promise<Response|undefined> {
    if (oauthResponse.error) {
        const ce = CrossauthError.fromOAuthError(oauthResponse.error, 
            oauthResponse.error_description);
        return client.errorFn(client.server, event, ce);
    }

    logTokens(oauthResponse);

    try {
        if (oauthResponse.access_token || oauthResponse.id_token || oauthResponse.refresh_token) {
            await updateSessionData(oauthResponse, client, event);
        }

        return json({ok: true, ...oauthResponse});
        if (!silent) return client.redirect(302, client.authorizedUrl);
    } catch (e) {
        if (SvelteKitServer.isSvelteKitError(e) || SvelteKitServer.isSvelteKitRedirect(e)) throw e;
        const ce =CrossauthError.asCrossauthError(e);
        CrossauthLogger.logger.debug(j({err: ce}));
        CrossauthLogger.logger.debug(j({cerr: ce, msg: "Error receiving tokens"}));
        return client.errorFn(client.server, event, ce);
    }
}

async function saveInSessionAndLoad(oauthResponse: OAuthTokenResponse,
    client: SvelteKitOAuthClient,
    event: RequestEvent,
    _silent : boolean
    ) : Promise<TokenReturn|undefined> {
    if (oauthResponse.error) {
        return {
            ok: false,
            error: oauthResponse.error,
            error_description: oauthResponse.error_description
        }
    }

    logTokens(oauthResponse);

    try {
        if (oauthResponse.access_token || oauthResponse.id_token || oauthResponse.refresh_token) {
            await updateSessionData(oauthResponse, client, event);
        }

    return {
        ok: true,
        ...oauthResponse,
        id_payload: decodePayload(oauthResponse.id_token)}
    } catch (e) {
        if (SvelteKitServer.isSvelteKitError(e) || SvelteKitServer.isSvelteKitRedirect(e)) throw e;
        const ce =CrossauthError.asCrossauthError(e);
        CrossauthLogger.logger.debug(j({err: ce}));
        CrossauthLogger.logger.debug(j({cerr: ce, msg: "Error receiving tokens"}));
        return {
            ok: false,
            error: ce.oauthErrorCode,
            error_description: ce.message,
        }
    }
}

async function sendInPage(oauthResponse: OAuthTokenResponse,
    _client: SvelteKitOAuthClient,
    _event: RequestEvent,
    _silent: boolean,
    ) : Promise<TokenReturn|undefined> {
    if (oauthResponse.error) {
        return {
            ok: false, 
            error: oauthResponse.error,
            error_description: oauthResponse.error_description
        }
    }

    logTokens(oauthResponse);

    try {

        return {
            ok: true,
            ...oauthResponse,
            id_payload: decodePayload(oauthResponse.id_token)}
        } catch (e) {
            if (SvelteKitServer.isSvelteKitError(e) || SvelteKitServer.isSvelteKitRedirect(e)) throw e;
            const ce =CrossauthError.asCrossauthError(e);
        CrossauthLogger.logger.debug(j({err: ce}));
        CrossauthLogger.logger.debug(j({cerr: ce, msg: "Error receiving tokens"}));
        return {
            ok: false,
            error: ce.oauthErrorCode,
            error_description: ce.message,
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// CLASSES

/**
 * The SvelteKit version of the OAuth client.
 * 
 * Makes requests to an authorization server, using a configurable set
 * of flows, which sends back errors or tokens,
 * 
 * When constructing this class, you define what happens with tokens that
 * are returned, or errors that are returned.  You do this with the
 * configuration options {@link SvelteKitOAuthClientOptions.tokenResponseType}
 * and {@link SvelteKitOAuthClientOptions.errorResponseType}.
 * 
 * **{@link SvelteKitOAuthClientOptions.tokenResponseType}**
 * 
 *   - `sendJson` the token response is sent as-is as a JSON Response.  
 *      In addition to the `token` endpoint response fields,
 *      `ok: true` and `id_payload` with the decoded 
 *      payload of the ID token are retruned.  
 *      This method should be used
 *      with `get`/ `post` endpoints, not `load`/`actions`.
 *   - `saveInSessionAndLoad` the response fields are saved in the `data`
 *      field of the session ID in key storage.  In addition, `expires_at` is 
 *      set to the number of seconds since Epoch that the access token expires
 *      at.  When using this method, you should define a SvelteKit page
 *      in your routes and put the the `load` (GET methods) or `actions` 
 *      (POST methods) function for each endpoint
 *      in the route's `+page.server.ts`.
 *      A consequence is the query parameters passed to the 
 *      redirect Uri are displayed in the address bar, as the response
 *      is to the redirect to the redirect Uri.
 *    - saveInSessionAndRedirect` same as `saveInSessionAndLoad` except that 
 *      a redirect is done to the `authorizedUrl`.  As an alternative to using `load`
 *      or `actions` method in a `+page.server.ts`, you can use the `get` 
 *      or `post` method in a `+server.ts`.
 *    - saveInSessionAndReturn` same as `saveInSessionAndLoad` except that 
 *      a JSON response is returned`.  Instead of using the `load`
 *      or `actions` method in a `+page.server.ts`, you should use the `get` 
 *      or `post` method in a `+server.ts`.
 *    - `sendInPage` same as `saveinSessionAndLoad` except the tokens are
 *      not saved in the session.  Use the `load`/`actions` function in your
 *      `+page.server.ts`.
 *    - `custom` the function in 
 *       {@link SvelteKitOAuthClientOptions.receiveTokenFn} is called.  If
 *       using `get` or `post` methods, your functiin should return
 *       a Response.  If using `load` and `actions` ir shouls ewruen
 *       an object for passing in `data` or `form` exports.
 *      
 * **{@link SvelteKitOAuthClientOptions.errorResponseType}**
 * 
 *    - `sendJson` a JSON response is sent with fields
 *       `status`, `errorMessage`,
 *      `errorMessages` and `errorCodeName`.
 *    - `svelteKitError` calls the SvelteKit `error` function (the one
 *      provided in the options to {@link SvelteKitServe}).
 *    - `custom` {@link SvelteKitOAuthClientOptions.errorFn} is called.
 * 
 *    Note that this parameter is only used when you are using the `get`/`post`
 *    endpoints, not the `load`/ `actions` ones.  The latter return the error in 
 *    the PageData from the load.
 * 
 * **Backend-for-Frontend (BFF)**
 * 
 * This class supports the backend-for-frontend (BFF) model.  
 * This pattern avoids you having to store the access token in the frontend.

 * For this to work
 * you should set @link SvelteKitOAuthClientOptions.tokenResponseType} to
 * `saveInSessionAndLoad` or `saveInSessionAndRedirect`.  Then to call
 * your resource server functions, you call then on a URL on this client
 * rather than the resource server directly.  The client backend will 
 * attach the access token, and also refresh the token automatically if
 * expired.
 * 
 * You need to provide the following options:
 *   - `bffBaseUrl` - the resource server URL, eg `http://resserver.com`
 *   - `bffEndpointName` - the prefix for BFF endpoints on this server.
 *     Eg if your BFF URL on this server is in `routes/bff` then 
 *     set `bffEndpointName` to `/bff`.
 * 
 * You may optionally also se `bffEndpoints`.
 * 
 * To sue BFF, first set `tokenResponseType` to 
 * `saveInSessionAndLoad` or `saveInSessionAndRedirect` and set `bffBaseUrl`
 * and `bffEndpointName`.  THen create a route in your `routes` called
 * *bffEndpointName*`/`*someMethod* with a `+server.ts`.  In that `+server.ts`,
 * create a `GET` and/or `POST` endpoint with
 * `bffEndpoint.get` or `bffEndpoint.post`.  The request will be forwarded
 * to *bffBaseUrl*`/`*someMethod* with the the body and query parameters
 * taken from your query and with the access token attached as the
 * `Authorization` header.  The resulting JSON and HTTP status will be returned.
 * 
 * If you have a lot of endpoints, you may instead prefer to create a single
 * one, eg as `routes/[...method]` and use `allBffEndpoint.get` or `.post` .
 * Put all valid BFF endpoints in the `bffEndpoints` option.  If, for one
 * of these endpoints, eg `method`, you set `matchSubUrls` to true, then
 * `method/XXX`, `method/YYY` will match as well as `method`.
 * 
 * **Endpoints provided by this class**
 * 
 * | Name                                  | Description                                                  | PageData (returned by load) or JSON returned by get/post                     | ActionData (return by actions)                                   | Form fields expected by actions or post/get input data          | 
 * | ------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | authorizationCodeFlowEndpoint         | Starts the authorization code flow.                          | None - redirects to `redirectUri`                                            | *Not provided*                                                   | - `scope`                                                       |  
 * | ------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | authorizationCodeFlowWithPKCEEndpoint | Starts the authorization code flow with PKCE.                | None - redirects to `redirectUri`                                            | *Not provided*                                                   | - `scope`                                                       |  
 * | ------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | redirectUriEndpoint                   | Redirect Uri for authorization code flows                    | See {@link OAuthTokenResponse}                                               | *Not provided*                                                   | As per OAuth Authorization Code Flow spec                       |  
 * | ------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | clientCredentialsFlowEndpoint         | Executes the client credentials flow                         | *Not provided*                                                               | See {@link OAuthTokenResponse}                                   | As per OAuth Client Credentials Flow spec                       |  
 * | ------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | refreshTokenFlowEndpoint              | Executes the refresh token flow                              | *Not provided*                                                               | See {@link OAuthTokenResponse}                                   | As per OAuth Refresh Token Flow spec                            |  
 * | ------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | refreshTokensIfExpiredEndpoint        | Executes the refresh token flow only if access token expired | *Not provided*                                                               | See {@link OAuthTokenResponse}                                   | As per OAuth Refresh Token Flow spec or nothing                 |  
 * | ------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | autoRefreshTokensIfExpiredEndpoint    | Same as refreshTokensIfExpiredEndpoint but only returns an object, no redirect | *Not provided*                                             | See {@link OAuthTokenResponse}                                   | As per OAuth Refresh Token Flow spec or nothing                 |  
 * | ------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | refreshTokensIfExpiredEndpoint        | Same as refreshTokenFlowEndpoint but only returns an object, no redirect | *Not provided*                                                   | See {@link OAuthTokenResponse}                                   | As per OAuth Refresh Token Flow spec or nothing                 |  
 * | ------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | passwordFlowEndpoint                  |                                                              | *Not provided*                                                               | `password`                                                       |                                                                 |  
 * |                                       | Executes the password flow only with out without MFA         |                                                                              |   -  See {@link OAuthTokenResponse}.  Returns password flow response if no MFA, MFA challenge response if user has 2FA | See OAuth password flow or Auth0 Password with MFA password flow specs |  
 * |                                       |                                                              |                                                                              | `passwordOtp`                                                                                                          |                                                                        |  
 * |                                       |  Pass OTP for Password MFA flow                              |                                                                              |   -  See {@link OAuthTokenResponse}.  Returns Password MFA challenge response if user has 2FA                          | See Auth0 Password with MFA password flow specs                        |  
 * |                                       |                                                              |                                                                              | `passwordOob`                                                                                                          |                                                                        |  
 * |                                       |  Pass OOB for Password MFA flow                              |                                                                              |   -  See {@link OAuthTokenResponse}.  Returns Password MFA challenge response if user has 2FA                          | See Auth0 Password with MFA password flow specs                        |  
 * | ------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | 
 * | passwordOtp Endpoint                  | `post` is same as `passwordOtp` action above                 | *Not provided*                                                               | See {@link OAuthTokenResponse}.  Returns MFA challenge response if user has 2FA                                        | See OAuth password flow or Auth0 Password with MFA password flow specs |  
 * | ------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | 
 * | passwordOob Endpoint                  | `post` is same as `passwordOob` action above                 | *Not provided*                                                               | See {@link OAuthTokenResponse}.  Returns MFA challenge response if user has 2FA                                        | See OAuth password flow or Auth0 Password with MFA password flow specs |  
 * | ------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | 
 * | bffEndpoint                           | BFF resource server request.  See class documentation        | As per the corresponding resource server endpoint                            | As per the correspoinding resource server endpoint               | As per the corresponding resource server endpoint               |  
 * | ------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | allBffEndpoint                        | BFF resource server request.  See class documentation        | As per the corresponding resource server endpoint                            | As per the correspoinding resource server endpoint               | As per the corresponding resource server endpoint               |  
 * | ------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | accessTokenEndpoint                   | For BFF only, return the access token payload or error       | JSON of the access token payload                                             | *Not provided*                                                   |                                                                 |  
 * | ------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | refreshTokenEndpoint                  | For BFF only, return the refresh token payload or error      | JSON of the refresh token payload                                            | *Not provided*                                                   |                                                                 |  
 * | ------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | idTokenEndpoint                       | For BFF only, return the id token payload or error           | POST: JSON of the id token payload                                                 | *Not provided*                                                   |                                                                 |  
 * | ------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | havAeccessTokenEndpoint               | For BFF only, return whether access token present            | POST: `ok` of false or true                                                        | *Not provided*                                                   |                                                                 |  
 * | ------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | haveRefreshTokenEndpoint              | For BFF only, return whether refresh token present           | POST: `ok` of false or true                                                        | *Not provided*                                                   |                                                                 |  
 * | ------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | haveIdTokenEndpoint                   | For BFF only, return whether id token present                | POST: `ok` of false or true                                                        | *Not provided*                                                   |                                                                 |  
 * | ------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | tokensEndpoint                        | For BFF only, a JSON object of all of the above              | POST: All of the above, keyed on `access_token`, `have_access_token`, etc.         | *Not provided*                                                   |                                                                 |  
 * | ------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 */
export class SvelteKitOAuthClient extends OAuthClientBackend {
    server : SvelteKitServer;
    sessionDataName : string = "oauth";
    private receiveTokenFn : 
        ( oauthResponse: OAuthTokenResponse,
            client: SvelteKitOAuthClient,
            event : RequestEvent,
            silet: boolean) 
            => Promise<Response|TokenReturn|undefined> = sendJson;
    readonly errorFn : SvelteKitErrorFn = jsonError;
    private loginUrl : string = "/login";
    private validFlows : string[] = [OAuthFlows.All];
    authorizedUrl : string = "";
    private autoRefreshActive : {[key:string]: boolean} = {};

    readonly redirect : any;
    readonly error : any;

    /** 
     * See {@link FastifyOAuthClientOptions}
     */
    loginProtectedFlows : string[] = [];
    private tokenResponseType :  
        "sendJson" | 
        "saveInSessionAndLoad" | 
        "saveInSessionAndRedirect" | 
        "saveInSessionAndLoad" | 
        "saveInSessionAndReturn" | 
        "sendInPage" | 
        "custom" = "sendJson";
    private errorResponseType :  
        "sendJson" | 
        "svelteKitError" | 
        "custom" = "sendJson";
    private bffEndpoints: {
        url: string,
        methods: ("GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS" | "HEAD")[],
        methodsString: string[],
        matchSubUrls?: boolean
        }[] = [];
    private bffEndpointName = "bff";
    private bffBaseUrl? : string;
    private tokenEndpoints : string[] = [];
    private bffMaxTries : number = 1;
    private bffSleepMilliseconds : number = 500;
    
    /**
     * Constructor
     * @param server the {@link FastifyServer} instance
     * @param authServerBaseUrl the `iss` claim in the access token must match this value
     * @param options See {@link FastifyOAuthClientOptions}
     */
    constructor(server: SvelteKitServer,
        authServerBaseUrl: string,
        options: SvelteKitOAuthClientOptions) {
        super(authServerBaseUrl, options);
        this.server = server;
        setParameter("sessionDataName", ParamType.String, this, options, "OAUTH_SESSION_DATA_NAME");
        setParameter("tokenResponseType", ParamType.String, this, options, "OAUTH_TOKEN_RESPONSE_TYPE");
        setParameter("errorResponseType", ParamType.String, this, options, "OAUTH_ERROR_RESPONSE_TYPE");
        setParameter("loginUrl", ParamType.String, this, options, "LOGIN_URL");
        setParameter("bffEndpointName", ParamType.String, this, options, "OAUTH_BFF_ENDPOINT_NAME");
        setParameter("bffBaseUrl", ParamType.String, this, options, "OAUTH_BFF_BASEURL");
        setParameter("redirectUri", ParamType.String, this, options, "OAUTH_REDIRECTURI", true);
        setParameter("authorizedUrl", ParamType.String, this, options, "AUTHORIZED_URL", false);
        setParameter("validFlows", ParamType.JsonArray, this, options, "OAUTH_VALID_FLOWS");
        setParameter("bffMaxTries", ParamType.Number, this, options, "OAUTH_BFF_MAX_RETRIES");
        setParameter("bffSleepMilliseconds", ParamType.Number, this, options, "OAUTH_BFF_SLEEP_MILLISECONDS");

        if (this.bffEndpointName && !this.bffEndpointName.startsWith("/")) this.bffEndpointName = "/" + this.bffEndpointName;
        if (this.bffEndpointName && this.bffEndpointName.endsWith("/")) this.bffEndpointName = this.bffEndpointName.substring(0, this.bffEndpointName.length-1);
        if (this.bffBaseUrl && this.bffBaseUrl.endsWith("/")) this.bffBaseUrl = this.bffBaseUrl.substring(0, this.bffBaseUrl.length-1);

        if (options.redirect) this.redirect = options.redirect;
        if (options.error) this.error = options.error;        

        if (this.validFlows.length == 1 && this.validFlows[0] == OAuthFlows.All) {
            this.validFlows = OAuthFlows.allFlows();
        } else {
            if (!OAuthFlows.areAllValidFlows(this.validFlows)) {
                throw new CrossauthError(ErrorCode.Configuration, "Invalid flows specificied in " + this.validFlows.join(","));
            }
        }

        try {
            new URL(this.redirectUri ?? "");
        } catch (e) {
            throw new CrossauthError(ErrorCode.Configuration, "Invalid redirect Uri " + this.redirectUri);
        }

        if (options.tokenEndpoints) this.tokenEndpoints = options.tokenEndpoints;

        if (this.bffEndpointName.endsWith("/")) this.bffEndpointName = this.bffEndpointName.substring(0, this.bffEndpointName.length-1);
        if (options.bffEndpoints) this.bffEndpoints = options.bffEndpoints.map((ep) => {
            return {...ep, methodsString: ep.methods.map((m) => m)};
        });
        if (this.bffEndpoints) {
            for (let endpoint of this.bffEndpoints) {
                if (!endpoint.url.startsWith("/")) endpoint.url = "/" + endpoint.url;
            }
        }

        if (this.loginProtectedFlows.length == 1 && 
            this.loginProtectedFlows[0] == OAuthFlows.All) {
            this.loginProtectedFlows = this.validFlows;
        } else {
            if (!OAuthFlows.areAllValidFlows(this.loginProtectedFlows)) {
                throw new CrossauthError(ErrorCode.Configuration,
                        "Invalid flows specificied in " + this.loginProtectedFlows.join(","));
            }
        }

        // receive token fn
        if (this.tokenResponseType == "custom" && !options.receiveTokenFn) {
            throw new CrossauthError(ErrorCode.Configuration, 
                "Token response type of custom selected but receiveTokenFn not defined");
        }
        if (this.tokenResponseType == "custom" && options.receiveTokenFn) {
            this.receiveTokenFn = options.receiveTokenFn;
        } else if (this.tokenResponseType == "sendJson") {
            this.receiveTokenFn = sendJson;
        } else if (this.tokenResponseType == "sendInPage") {
            this.receiveTokenFn = sendInPage;
        } else if (this.tokenResponseType == "saveInSessionAndLoad") {
            this.receiveTokenFn = sendJson; saveInSessionAndLoad;
        } else if (this.tokenResponseType == "saveInSessionAndRedirect") {
            this.receiveTokenFn = saveInSessionAndRedirect;
        } else if (this.tokenResponseType == "saveInSessionAndReturn") {
            this.receiveTokenFn = saveInSessionAndReturn;
        }
        if ((this.tokenResponseType == "saveInSessionAndLoad" || this.tokenResponseType == "saveInSessionAndRedirect") &&
            this.authorizedUrl == "") {
            throw new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is" + this.tokenResponseType + ", must provide authorizedUrl");
        }
        if ((this.tokenResponseType == "saveInSessionAndLoad" || this.tokenResponseType == "saveInSessionAndRedirect") &&
            this.server.sessionServer == undefined) {
            throw new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is" + this.tokenResponseType + ", must activate the session server");
        }
        
        // errorFn
        if (this.errorResponseType == "custom" && !options.errorFn) {
            throw new CrossauthError(ErrorCode.Configuration, 
                "Error response type of custom selected but errorFn not defined");
        }
        if (this.errorResponseType == "custom" && options.errorFn) {
            this.errorFn = options.errorFn;
        } else if (this.errorResponseType == "sendJson") {
            this.errorFn = jsonError;
        } else if (this.errorResponseType == "svelteKitError") {
            this.errorFn = svelteKitError;
        }

        if (!options.redirect) throw new CrossauthError(ErrorCode.Configuration, "Must provide the SvelteKit redirect function");
        if (!options.error && this.errorResponseType == "svelteKitError") throw new CrossauthError(ErrorCode.Configuration, "Must provide the SvelteKit error function");

        if (this,this.loginProtectedFlows.length > 0 && this.loginUrl == "") {
            throw new CrossauthError(ErrorCode.Configuration, 
                "loginUrl must be set if protecting oauth endpoints");
        }
    }       

    private async passwordPost(event : RequestEvent, formData: {[key:string]:string}) : Promise<OAuthTokenResponse> {

        try {
            let resp = 
                await this.passwordFlow(formData.username,
                    formData.password,
                    formData.scope);
                if (resp.error == "mfa_required" && 
                resp.mfa_token &&
                this.validFlows.includes(OAuthFlows.PasswordMfa)) {
                const mfa_token = resp.mfa_token;
                let scope : string|undefined = formData.scope;
                if (scope == "") scope = undefined;
                resp = await this.passwordMfa(mfa_token,
                    scope,
                    event);
                if (resp.error) {
                    const ce = CrossauthError.fromOAuthError(resp.error, 
                        resp.error_description);
                        throw ce;
                    }
                //return await this.receiveTokenFn(resp, this, event);
                return resp;
               
            } else if (resp.error) {
                const ce = CrossauthError.fromOAuthError(resp.error, 
                    resp.error_description);
                    throw ce;
            }
            //return await this.receiveTokenFn(resp, this, event);
            return resp;
        } catch (e) {
            if (SvelteKitServer.isSvelteKitError(e) || SvelteKitServer.isSvelteKitRedirect(e)) throw e;
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.error(j({
                msg: "Error receiving token",
                cerr: ce,
                user: event.locals.user?.user
            }));
            CrossauthLogger.logger.debug(j({err: e}));
            return {
                error: ce.oauthErrorCode,
                error_description: ce.message,
            };            
        }
    }

    private async passwordMfa(
        mfa_token: string,
        scope : string|undefined,
        _event: RequestEvent,
    ) : Promise<OAuthTokenResponse> {

        const authenticatorsResponse = 
            await this.mfaAuthenticators(mfa_token);
            if (authenticatorsResponse.error || 
            !authenticatorsResponse.authenticators ||
            !Array.isArray(authenticatorsResponse.authenticators) ||
            authenticatorsResponse.authenticators.length == 0 ||
            (authenticatorsResponse.authenticators.length > 1 && 
                !authenticatorsResponse.authenticators[0].active )) {
                    return {
                        error: authenticatorsResponse.error ?? "server_error",
                        error_description: authenticatorsResponse.error_description ?? "Unexpected error getting MFA authenticators",
                    };                    
                }

        const auth = authenticatorsResponse.authenticators[0] as MfaAuthenticatorResponse;
        if (auth.authenticator_type == "otp") {
            const resp = await this.mfaOtpRequest(mfa_token, auth.id);
            if (resp.error || resp.challenge_type!="otp") {
                const ce = CrossauthError.fromOAuthError(resp.error??"server_error",
                    resp.error_description??"Invalid response from MFA OTP challenge");
                CrossauthLogger.logger.debug({err: ce});
                CrossauthLogger.logger.error({cerr: ce});
                return {
                    error: ce.oauthErrorCode,
                    error_description: ce.message,
                }
            }
            return {
                scope: scope,
                mfa_token: mfa_token,
                challenge_type: resp.challenge_type,
            };            
        } else if (auth.authenticator_type == "oob") {
            const resp = await this.mfaOobRequest(mfa_token, auth.id);
            if (resp.error || resp.challenge_type!="oob" || !resp.oob_code || 
                resp.binding_method != "prompt") {
                const ce = CrossauthError.fromOAuthError(resp.error??"server_error",
                    resp.error_description??"Invalid response from MFA OOB challenge");
                    CrossauthLogger.logger.debug({err: ce});
                    CrossauthLogger.logger.error({cerr: ce});
                    return {
                        error: ce.oauthErrorCode,
                        error_description: ce.message,
                    }
                
            }

            return {
                scope: scope,
                mfa_token: mfa_token,
                oob_channel: auth.oob_channel,
                challenge_type: resp.challenge_type,
                binding_method: resp.binding_method,
                oob_code: resp.oob_code,
                name: auth.name,
            };
        }

        const ce = new CrossauthError(ErrorCode.UnknownError, 
            "Unsupported MFA type " + auth.authenticator_type + " returned");
            return {
                error: ce.oauthErrorCode,
                error_description: ce.message,
        };                    
    }

    private async passwordOtp(
        _event: RequestEvent,
        formData: {[key:string]:string}
    ) : Promise<OAuthTokenResponse> {

        let scope : string|undefined = formData.scope;
        if (scope == "") scope = undefined;
        const resp = await this.mfaOtpComplete(formData.mfa_token, 
            formData.otp, scope);
        if (resp.error) {
            const ce = CrossauthError.fromOAuthError(resp.error,
                resp.error_description??"Error completing MFA");
            return {
                error: ce.oauthErrorCode,
                error_description: ce.message,
            };                    
        }
        //return await this.receiveTokenFn(resp, this, event);
        return resp;
    }

    private async passwordOob(
        event: RequestEvent,
        formData: {[key:string]:string}
    ) : Promise<OAuthTokenResponse> {

        let scope : string|undefined = formData.scope;
        if (scope == "") scope = undefined;
        const resp = await this.mfaOobComplete(formData.mfa_token, 
            formData.oob_code,
            formData.binding_code,
            scope);
        if (resp.error) {
            CrossauthLogger.logger.warn(j({
                msg: "Error completing MFA",
                user: event.locals.user?.user,
                hashedMfaToken: formData.mfa_token ? Crypto.hash(formData.mfa_token) : undefined,
            }));
            return {
                error: resp.error,
                error_description: resp.error_description,
            };                    
        }
        //return await this.receiveTokenFn(resp, this, event);
        return resp;
    }

    private async refresh(mode: "silent"|"post"|"page", event: RequestEvent,
        onlyIfExpired : boolean,
        refreshToken?: string,
        expiresAt?: number) 
        : Promise<Response|{
            refresh_token?: string,
            access_token?: string,
            expires_in?: number,
            expires_at?: number,
            error?: string,
            error_description?: string
            }|undefined> {
        
        if (!expiresAt || !refreshToken) {
            if (mode != "silent") {
                return await this.receiveTokenFn({},
                    this,
                    event, 
                    true);
            } 
            return undefined;
        }

        if (!onlyIfExpired || expiresAt <= Date.now()) {
            if (event.locals.sessionId && this.autoRefreshActive[event.locals.sessionId]) return undefined;

            try {
                if (event.locals.sessionId) this.autoRefreshActive[event.locals.sessionId] = true;
                const resp = await this.refreshTokenFlow(refreshToken);
                if (!resp.error && !resp.access_token) {
                    resp.error = "server_error";
                    resp.error_description = "Unexpectedly did not receive error or access token";
                }
                if (!resp.error) {
                    const resp1 = await this.receiveTokenFn(resp,
                        this,
                        event,
                        mode == "silent");
                    if (mode != "silent") return resp1;
                } 
                if (mode != "silent") {
                    const ce = CrossauthError.fromOAuthError(resp.error??"server_error", 
                        resp.error_description);
                        if (mode == "page") return this.errorFn(this.server, event, ce);
                        return {
                            error: ce.oauthErrorCode,
                            error_description: ce.message,
                        };                    
                    }
                let expires_in = resp.expires_in;
                if (!expires_in && resp.access_token) {
                    const payload = jwtDecode(resp.access_token);
                    if (payload.exp) expires_in = payload.exp;
                }
                if (!expires_in) {
                    throw new CrossauthError(ErrorCode.BadRequest, 
                        "OAuth server did not return an expiry for the access token");
                }
                const expires_at = 
                    (new Date().getTime() + (expires_in*1000));
                return {
                    access_token: resp.access_token,
                    refresh_token: resp.refresh_token,
                    expires_in: resp.expires_in,
                    expires_at: expires_at,
                    error: resp.error,
                    error_description: resp.error_description
                };
            } catch(e) {
                if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                if (SvelteKitServer.isSvelteKitError(e)) throw e;
                CrossauthLogger.logger.debug(j({err: e}));
                CrossauthLogger.logger.error(j({
                    cerr: e,
                    msg: "Failed refreshing access token"
                }));
                if (mode != "silent") {
                    const ce = CrossauthError.asCrossauthError(e);
                    if (mode == "page") return this.errorFn(this.server, event, ce);
                    return {
                        error: ce.oauthErrorCode,
                        error_description: ce.message,
                    };                    
                }

                return {
                    error:  "server_error",
                    error_description: "Failed refreshing access token",
                };                    

            } finally {
                if (event.locals.sessionId && event.locals.sessionId in this.autoRefreshActive) delete this.autoRefreshActive[event.locals.sessionId];
            }
        }
        return undefined;
    }

    private async refreshTokens(event : RequestEvent,
        mode: "silent" | "post" | "page",
        onlyIfExpired : boolean) : Promise<(TokenReturn&{expires_at?: number})|Response|undefined> {

        try {
            if (!this.server.sessionServer) {
                return {
                    ok: false,
                    error: "server_error",
                    error_description: "Refresh tokens if expired or silent refresh only available if sessions are enabled",
                };
            }
            if (this.server.sessionServer.enableCsrfProtection && !event.locals.csrfToken) {
                return {
                    ok: false,
                    error: "access_denied",
                    error_description: "No CSRF token found"
                }; 
            }
            const oauthData = await this.server.sessionServer.getSessionData(event, this.sessionDataName);
            if (!oauthData?.refresh_token) {
                if (mode == "silent") {
                    return new Response(null, {status: 204});
                } else {
                    const ce = new CrossauthError(ErrorCode.InvalidSession,
                        "No tokens found in session");
                    throw ce;
                }
            }
    
            const resp = 
                await this.refresh(mode, event,
                    onlyIfExpired,
                    oauthData.refresh_token,
                    oauthData.expires_at
                );
            if (mode == "silent") {
                if (resp instanceof Response) {
                    throw new CrossauthError(ErrorCode.Configuration, "Unexpected error: refresh: mode is silent but didn't receive an object")
                }
                return {ok: true, expires_at: resp?.expires_at};
            } else if (mode == "post") {
                if (resp == undefined) return this.receiveTokenFn({}, this, event, false);
                if (resp != undefined) {
                    if (resp instanceof Response) return resp;
                    throw new CrossauthError(ErrorCode.Configuration, "refreshTokenFn for post should return Response not object");
                }
            }
    
        } catch (e) {
            if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
            if (SvelteKitServer.isSvelteKitError(e)) throw e;
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.debug({err: ce});
            CrossauthLogger.logger.error({cerr: ce});
            if (mode == "page") return this.errorFn(this.server, event, ce);
            else return {
                ok: false,
                error: ce.oauthErrorCode,
                error_description: ce.message,
            };
        }

    };

    private async passwordFlow_post(event : RequestEvent, passwordFn : (event : RequestEvent, formData: {[key:string]:string}) => Promise<OAuthTokenResponse>) {
        if (this.tokenResponseType == "saveInSessionAndLoad" || this.tokenResponseType == "sendInPage") {
            const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use actions not post");
            return this.errorFn(this.server, event, ce);
        }
        let formData : {[key:string]:string}|undefined = undefined;
        try {

            if (!(this.validFlows.includes(OAuthFlows.Password) ||
                this.validFlows.includes(OAuthFlows.PasswordMfa))) {
                const ce = new CrossauthError(ErrorCode.Unauthorized, "Password flow is not supported");
                return this.errorFn(this.server, event, ce);
            }
            var data = new JsonOrFormData();
            await data.loadData(event);
            formData = data.toObject();

            if (!event.locals.user && 
                (this.loginProtectedFlows.includes(OAuthFlows.Password) ||
                this.loginProtectedFlows.includes(OAuthFlows.PasswordMfa))) {
                const ce = new CrossauthError(ErrorCode.Unauthorized, "Must log in to use password flow");

                return this.errorFn(this.server, event, ce);
            }    

            // if the session server and CSRF protection enabled, require a valid CSRF token
            if (this.server.sessionServer && this.server.sessionServer.enableCsrfProtection) {
                try {
                    const cookieValue = this.server.sessionServer.getCsrfCookieValue(event);
                    if (cookieValue) this.server.sessionServer.sessionManager.validateCsrfCookie(cookieValue);
               }
               catch (e) {
                if (SvelteKitServer.isSvelteKitError(e) || SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                const ce = new CrossauthError(ErrorCode.Unauthorized, "CSRF token not present");
                return this.errorFn(this.server, event, ce);
               }

            }

            const resp = 
                await passwordFn(event, formData);
            if (!resp) throw new CrossauthError(ErrorCode.UnknownError, "Password flow returned no data");
            if (resp.error) return {
                ok: false,
                ...resp,
            }
            const resp2 = await this.receiveTokenFn(resp, this, event, false) ;
            if (resp && resp2 instanceof Response) return resp2;
            throw new CrossauthError(ErrorCode.UnknownError, "Receive token function did not return a Response");

        } catch (e) {
            if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
            if (SvelteKitServer.isSvelteKitError(e)) throw e;
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.debug({err: e});
            CrossauthLogger.logger.error({cerr: e});
            //throw this.error(ce.httpStatus, ce.message);
            return this.errorFn(this.server, event, ce);

        }
    }

    private async passwordFlow_action( event : RequestEvent, passwordFn : (event : RequestEvent, formData: {[key:string]:string}) => Promise<OAuthTokenResponse> ) {
        if (/*this.tokenResponseType == "saveInSessionAndRedirect" ||*/ this.tokenResponseType == "sendJson" || this.tokenResponseType == "saveInSessionAndLoad") {
            const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use post not load");
            throw ce;
        }

        let formData : {[key:string]:string}|undefined = undefined;
        try {

            if (!(this.validFlows.includes(OAuthFlows.Password) ||
                 this.validFlows.includes(OAuthFlows.PasswordMfa))) {
                const ce = new CrossauthError(ErrorCode.Unauthorized, "Password and Password MFA flows are not supported");
                return this.errorFn(this.server, event, ce);
            }
            var data = new JsonOrFormData();
            await data.loadData(event);
            formData = data.toObject();

            if (!event.locals.user && 
                (this.loginProtectedFlows.includes(OAuthFlows.Password) ||
                this.loginProtectedFlows.includes(OAuthFlows.PasswordMfa))) {
                const ce = new CrossauthError(ErrorCode.Unauthorized, "Must log in to use refresh token");
                throw ce;
            }    
            
            // if the session server and CSRF protection enabled, require a valid CSRF token
            if (this.server.sessionServer && this.server.sessionServer.enableCsrfProtection) {
                try {
                    const cookieValue = this.server.sessionServer.getCsrfCookieValue(event);
                    if (cookieValue) this.server.sessionServer.sessionManager.validateCsrfCookie(cookieValue);
                }
                catch (e) {
                    if (SvelteKitServer.isSvelteKitError(e) || SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "CSRF token not present");
                    throw ce;
                }

            }

            const resp = 
                await passwordFn(event, formData);
            if (!resp) throw new CrossauthError(ErrorCode.UnknownError, "Password flow returned no data");
            if (resp.error) {
                return {
                    ok: false,
                    ...resp,
                }
            }
            if (resp.challenge_type) {
                if (!(this.validFlows.includes(OAuthFlows.PasswordMfa))) {
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "Password MFA flow is not supported");
                    return this.errorFn(this.server, event, ce);
                }
                return resp;
            }
            const resp2 = await this.receiveTokenFn(resp, this, event, false) ?? {};
            if (resp2 instanceof Response) throw new CrossauthError(ErrorCode.Configuration, "Refresh token flow should return an object not Response");
            return resp2;
            
        } catch (e) {
            if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
            if (SvelteKitServer.isSvelteKitError(e)) throw e;
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.debug({err: e});
            CrossauthLogger.logger.error({cerr: e});
            //throw this.error(ce.httpStatus, ce.message);
            return { 
                ok: false,
                error: ce.oauthErrorCode, 
                error_description: ce.message
            };

        }

    }

    /**
     * Call a resource on the resource server, passing in the access token 
     * along with the body from the event and, unless overridden, the URL.
     * 
     * It is probably easier to use `bffEndpoint` instead of this method.
     * However you can use this if you need to pass custom headers or want
     * to specify the URL manually.
     * 
     * @param event the Sveltekit request event
     * @param opts additional data to put in resource server request.  You can also override the URL here
     * @returns resource server response
     */
    async bff(event : RequestEvent, opts: {method?: "GET"|"POST"|"PUT"|"HEAD"|"OPTIONS"|"PATCH"|"DELETE", headers? : Headers, url? : string} = {}) : Promise<Response> {
        try {
            if (!this.server.sessionServer) throw new CrossauthError(ErrorCode.Configuration, "Session server must be instantiated to use bff()");
            if (!this.server.oAuthClient) throw new CrossauthError(ErrorCode.Configuration, "OAuth Client not found"); // pathological but prevents TS errors
            if (!this.bffBaseUrl) throw new CrossauthError(ErrorCode.Configuration, "Must set bffBaseUrl to use bff()");
            if (!this.bffEndpointName) throw new CrossauthError(ErrorCode.Configuration, "Must set bffEndpointName to use bff()");
    
            let url : URL | string | undefined = opts.url;
            if (!url) {
                if (!event.url.pathname.startsWith(this.bffEndpointName)) throw new CrossauthError(ErrorCode.Unauthorized, "Attempt to call BFF url with the wrong prefix");
                const path = event.url.pathname.substring(this.bffEndpointName.length);
                let query = event.url.searchParams?.toString() ?? undefined;
                if (query && query != "") query = "?" + query;
                url = new URL(this.bffBaseUrl + path + query);
            }
            if (!opts.headers) {
                opts.headers = new Headers();
            }
            for (let i = 0; i < this.bffMaxTries; ++i) {

                if (i > 0) await new Promise(r => setTimeout(r, this.bffSleepMilliseconds));


                const oauthData = 
                    await this.server.sessionServer.getSessionData(event, 
                        this.sessionDataName);
                        if (!oauthData) {
                    if (i == this.bffMaxTries) {
                        throw new CrossauthError(ErrorCode.Unauthorized, "No access token found");
                    } else {
                        continue;
                    }
                }
                let access_token = oauthData.access_token;
                if (oauthData && oauthData.access_token) {
                    const resp = 
                    await this.refresh("silent",
                            event,
                            true,
                            oauthData.refresh_token,
                            oauthData.expires_at);
                            // following shouldn't happen but TS doesn't know that
                    if (resp instanceof Response) throw new CrossauthError(ErrorCode.Configuration, "Expected object when refreshing tokens, not Response");
                    if (resp?.access_token) {
                        access_token = resp.access_token;
                    } else if (resp?.error) {
                        continue; // try again
                    }
                }

                opts.headers.set("accept", "application/json");
                opts.headers.set("content-type", "application/json");
                if (access_token) opts.headers.set("authorization", "Bearer " + access_token);

                let resp : Response;
                let body : {[key:string]:any} | undefined = undefined;
                if (event.request.body) {
                    var data = new JsonOrFormData();
                    await data.loadData(event);
                    body = data.toObject();
                }
                CrossauthLogger.logger.debug(j({msg: "Calling BFF URL", url: url, method: event.request.method}));
                if (body) {
                    resp = await fetch(url, {
                        headers:opts.headers,
                        method: opts.method ?? event.request.method,
                        body: JSON.stringify(body??"{}"),
                    });    
                } else {
                    resp = await fetch(url, {
                        headers:opts.headers,
                        method: opts.method ?? event.request.method,
                    });    
                }
                if (resp.status == 401) {
                    if (i < this.bffMaxTries - 1) {
                        continue;
                    } else {
                        return resp;
                    }
                } else {
                    return resp;
                }
            }
            return new Response(null, {status: 401}); // not reached but to ensure TS return type is correct

        } catch (e) {
            if (SvelteKitServer.isSvelteKitError(e) || SvelteKitServer.isSvelteKitRedirect(e)) throw e;
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.debug({err: ce});
            CrossauthLogger.logger.error({cerr: ce});
            return json({
                error: ce.oauthErrorCode,
                error_description: ce.message,
            }, {status: ce.httpStatus});
        }

    }

    async unpack(resp : Response) : Promise<{status: number, body: {[key:string]:any}, error? : string, error_description? : string}> {
        if (resp.status == 204)  {
            return {status: 204, body: {}};
        } else {
            try {
                return {status: resp.status, body: await resp.json()};
            } catch (e) {
                if (SvelteKitServer.isSvelteKitError(e) || SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug({err: ce});
                CrossauthLogger.logger.error({cerr: ce});
                return {status: resp.status, body: {}, error: ce.oauthErrorCode, error_description: ce.message}
            }
        }
    }

    pack(ret : {[key:string]:any}|undefined|Response) {
        if (ret instanceof Response) return ret;
        let status = 200;
        if (ret?.error == "access_denied") status = 401;
        else if (ret?.error) status = 500;
        else if (!ret) status = 204;
        return json(ret ?? null, {status});
    }

    /**
     * Ordinarily you would not call this directly but use `allBffEndpoint`.
     * 
     * However you can use this if you need to pass custom headers.
     * @param event the Sveltekit request event
     * @param opts additional data to put in resource server request
     * @returns resource server response
     */
    async allBff(event : RequestEvent, opts: {method?: "GET"|"POST"|"PUT"|"HEAD"|"OPTIONS"|"PATCH"|"DELETE", headers? : Headers} = {}) : Promise<Response> {
        try {
            CrossauthLogger.logger.debug(j({msg: "Called allBff", url: event.url.toString()}));
            if (!this.server.sessionServer) throw new CrossauthError(ErrorCode.Configuration, "Session server must be instantiated to use bff()");
            if (!this.server.oAuthClient) throw new CrossauthError(ErrorCode.Configuration, "OAuth Client not found"); // pathological but prevents TS errors
            if (!this.bffBaseUrl) throw new CrossauthError(ErrorCode.Configuration, "Must set bffBaseUrl to use bff()");
            if (!this.bffEndpointName) throw new CrossauthError(ErrorCode.Configuration, "Must set bffEndpointName to use bff()");
    
            if (!this.bffEndpoints || this.bffEndpoints.length == 0) throw new CrossauthError(ErrorCode.Unauthorized, "Invalid BFF endpoint");
            if (!event.url.pathname.startsWith(this.bffEndpointName)) throw new CrossauthError(ErrorCode.Unauthorized, "Attempt to call BFF url with the wrong prefix");
            const path = event.url.pathname.substring(this.bffEndpointName.length);

            let idx = undefined;
            for (let i=0; i < this.bffEndpoints.length; ++i) {
                let endpoint = this.bffEndpoints[i];
                if (endpoint.matchSubUrls) {
                    let url = endpoint.url;
                    let urlWithSlash = endpoint.url;
                    if (!urlWithSlash.endsWith("/")) urlWithSlash += "/";
                    if (endpoint.methodsString.includes(event.request.method) && (path.startsWith(urlWithSlash) || path == url))  {
                        idx = i;
                        break;
                    }
                } else {
                    let url = endpoint.url;
                    if (endpoint.methodsString.includes(event.request.method) && (path == url))  {
                        idx = i;
                        break;
                    }
                }
            }

            if (idx != undefined) return await this.bff(event, opts);
            else {
                throw new CrossauthError(ErrorCode.Unauthorized, "Illegal BFF URL called " + event.url.toString());
            }

        } catch (e) {
            if (SvelteKitServer.isSvelteKitError(e) || SvelteKitServer.isSvelteKitRedirect(e)) throw e;
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.debug({err: ce});
            CrossauthLogger.logger.error({cerr: ce});
            return json({
                error: ce.oauthErrorCode,
                error_description: ce.message,
            }, {status: ce.httpStatus});
        }

    }

    private tokenPayload(token : string, oauthData : {[key:string]:any}) : {[key:string]:any}|undefined {
        let isHave = false;
        if (token.startsWith("have_")) {
            isHave = true;
            token = token.substring(5)
        }
        if (!(token in oauthData)) {
            return isHave ? {ok: false} : undefined;
        }
        const payload = decodePayload(oauthData[token]);
        return isHave ? {ok: true} : payload;
    }

    async tokens(event : RequestEvent, token: string|string[]) : Promise<{status: number, body?: {[key:string]:any}}> {
        try {
            if (!this.server.sessionServer) throw new CrossauthError(ErrorCode.Configuration, "Session server must be instantiated to use bff()");
            if (!this.server.oAuthClient) throw new CrossauthError(ErrorCode.Configuration, "OAuth Client not found"); // pathological but prevents TS errors

            if (!this.tokenEndpoints || this.tokenEndpoints.length == 0)
                throw new CrossauthError(ErrorCode.Unauthorized, "No tokens have been made available");

            let tokens = Array.isArray(token) ? token : [token];

            const oauthData = 
                await this.server.sessionServer.getSessionData(event, 
                    this.sessionDataName);
            if (!oauthData) {
                throw new CrossauthError(ErrorCode.Unauthorized, "No access token found");
            }
            let tokensReturning : {
                access_token?: {[key:string]:any},
                have_access_token?: boolean,
                refresh_token?: {[key:string]:any},
                have_refresh_token?: boolean,
                id_token?: {[key:string]:any},
                have_id_token?: boolean,
            } = {};
            let lastTokenPayload : ({[key:string]:any}|undefined) = undefined;
            let isHave = false;
            for (let t of tokens) {
                if (!this.tokenEndpoints.includes(t)) throw new CrossauthError(ErrorCode.Unauthorized, "Token type " + t + " may not be returned");
                isHave = false;
                let tokenName : string = t;
                if (t.startsWith("have_")) {
                    tokenName = t.replace("have_", "");
                    isHave = true;
                }
                let payload = this.tokenPayload(tokenName, oauthData);
                if (payload) {
                    // @ts-ignore because t is a string
                    tokensReturning[t] = isHave ? true : payload;
                } else if (isHave) {
                    // @ts-ignore because t is a string
                    tokensReturning[t] = false;
                }
                lastTokenPayload = payload;
            }
            if (!Array.isArray(token)) {
                if (!lastTokenPayload) {
                    if (token.startsWith("have_")) return {status: 200, body: {ok: false}};
                    else return {status: 204};
                }
                if (isHave) return  {status: 200, body: {ok: true}};
                return {status: 200, body: lastTokenPayload};
            } else {
                return {status: 200, body: tokensReturning};
            }

        } catch (e) {
            if (SvelteKitServer.isSvelteKitError(e) || SvelteKitServer.isSvelteKitRedirect(e)) throw e;
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.debug({err: ce});
            CrossauthLogger.logger.error({cerr: ce});
            return {status: ce.httpStatus, body: {
                error: ce.oauthErrorCode,
                error_description: ce.message,
            }};
        }

    }

    async tokensResponse(event : RequestEvent, token: string|string[]) : Promise<Response> {
        const resp = await this.tokens(event, token);
        if (resp.body) return json(resp.body, {status: resp.status});
        return json(null, {status: resp.status});
    }

    private async startDeviceCodeFlow_internal(event : RequestEvent) : Promise<OAuthDeviceAuthorizationResponse&{verification_uri_qrdata? : string}> {
        let formData : {[key:string]:string}|undefined = undefined;
        try {

            if (!(this.validFlows.includes(OAuthFlows.DeviceCode))) {
                const ce = new CrossauthError(ErrorCode.Unauthorized, "Device code flow is not supported");
                throw ce;
            }
            var data = new JsonOrFormData();
            await data.loadData(event);
            formData = data.toObject();
                
            // if the session server and CSRF protection enabled, require a valid CSRF token
            if (this.server.sessionServer && this.server.sessionServer.enableCsrfProtection) {
                try {
                    const cookieValue = this.server.sessionServer.getCsrfCookieValue(event);
                    if (cookieValue) this.server.sessionServer.sessionManager.validateCsrfCookie(cookieValue);
                }
                catch (e) {
                    if (SvelteKitServer.isSvelteKitError(e) || SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "CSRF token not present");
                    throw ce;
                }

            }

            // get scopes from body
            let scope : string|undefined = formData.scope;
            if (scope == "") scope = undefined;

            let url = this.authServerBaseUrl;
            if (!(url.endsWith("/"))) url += "/";
            url += this.deviceAuthorizationUrl;
            const resp =  await this.startDeviceCodeFlow(url, scope);

            let qrUrl : string|undefined = undefined;
            if (resp.verification_uri_complete) {
                await QRCode.toDataURL(resp.verification_uri_complete)
                    .then((url) => {
                            qrUrl = url;
                    })
                    .catch((err) => {
                        CrossauthLogger.logger.debug(j({err: err}));
                        CrossauthLogger.logger.warn(j({msg: "Couldn't generate verification URL QR Code"}))
                    });
        
            }
            if (qrUrl) return {verification_uri_qrdata: qrUrl, ...resp};
            return resp;
        } catch (e) {
            if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
            if (SvelteKitServer.isSvelteKitError(e)) throw e;
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.debug({err: e});
            CrossauthLogger.logger.error({cerr: e});
            //throw this.error(ce.httpStatus, ce.message);
            return { 
                error: ce.oauthErrorCode, 
                error_description: ce.message
            };
        }
    }

    private async pollDeviceCodeFlow_internal(event : RequestEvent) : Promise<TokenReturn|Response|undefined> {
        let formData : {[key:string]:string}|undefined = undefined;
        try {

            if (!(this.validFlows.includes(OAuthFlows.DeviceCode))) {
                const ce = new CrossauthError(ErrorCode.Unauthorized, "Device code flow is not supported");
                throw ce;
            }
            var data = new JsonOrFormData();
            await data.loadData(event);
            formData = data.toObject();
                
            // if the session server and CSRF protection enabled, require a valid CSRF token
            if (this.server.sessionServer && this.server.sessionServer.enableCsrfProtection) {
                try {
                    const cookieValue = this.server.sessionServer.getCsrfCookieValue(event);
                    if (cookieValue) this.server.sessionServer.sessionManager.validateCsrfCookie(cookieValue);
                }
                catch (e) {
                    if (SvelteKitServer.isSvelteKitError(e) || SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "CSRF token not present");
                    throw ce;
                }

            }

            // get device code from body
            let deviceCode = formData.device_code;
            if (!deviceCode) throw new CrossauthError(ErrorCode.BadRequest, "No device code given when polling for user authorization")

            const resp =  await this.pollDeviceCodeFlow(deviceCode);
            if (resp.access_token && !resp.error) {
                const resp2 = await this.receiveTokenFn(resp, this, event, false);
                return resp2;    
            } else {
                if (resp.error == "authorization_pending") return {ok: true, ...resp};
                let error = resp.error ?? "server_error";
                let error_description = resp.error_description ?? "Didn't receive an access token";
                const ce = CrossauthError.fromOAuthError(error, error_description);
                return this.errorFn(this.server, event, ce);
            }


        } catch (e) {
            if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
            if (SvelteKitServer.isSvelteKitError(e)) throw e;
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.debug({err: e});
            CrossauthLogger.logger.error({cerr: e});
            //throw this.error(ce.httpStatus, ce.message);
            return this.errorFn(this.server, event, ce);
        }
    }


    ////////////////////////////////////////////////////////////////
    // Endpoints

    /////
    // Authorization code flows

    readonly authorizationCodeFlowEndpoint = {

        get: async (event : RequestEvent) => {
            if (this.tokenResponseType == "saveInSessionAndLoad" || this.tokenResponseType == "sendInPage") {
                const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use load not get");
                return this.errorFn(this.server, event, ce);
            }
            try {

                if (!(this.validFlows.includes(OAuthFlows.AuthorizationCode))) {
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "Authorization flow is not supported");
                    return this.errorFn(this.server, event, ce);
                }

                if (!event.locals.user && 
                    this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCode)) {
                    throw this.redirect(302, 
                        this.loginUrl+"?next="+encodeURIComponent(event.request.url));
                }          
                let scope = event.url.searchParams.get("scope") ?? undefined;
                if (scope == "") scope = undefined;
                const {url, error, error_description} = 
                    await this.startAuthorizationCodeFlow(scope);
                if (error || !url) {
                    const ce = CrossauthError.fromOAuthError(error??"server_error", 
                        error_description);
                    return await this.errorFn(this.server, event, ce)
                }
                    CrossauthLogger.logger.debug(j({
                        msg: `Authorization code flow: redirecting`,
                        url: url
                    }));
                throw this.redirect(302, url);

            } catch (e) {
                if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                if (SvelteKitServer.isSvelteKitError(e)) throw e;
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug({err: e});
                CrossauthLogger.logger.error({cerr: e});
                //throw this.error(ce.httpStatus, ce.message);
                return this.errorFn(this.server, event, ce);

            }
        },

        load: async (event : RequestEvent) : Promise<AuthorizationCodeFlowReturn> => {
            if (/*this.tokenResponseType == "saveInSessionAndRedirect" ||*/ this.tokenResponseType == "sendJson" || this.tokenResponseType == "saveInSessionAndLoad") {
                const ce = new CrossauthError(ErrorCode.Unauthorized, "Authorization flow is not supported");
                return {
                    ok: false,
                    error: ce.oauthErrorCode,
                    error_description: ce.message,
                }
            }
            try {
                if (!(this.validFlows.includes(OAuthFlows.AuthorizationCode))) {
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "Authorization flow is not supported");
                    return {
                        ok: false,
                        error: ce.oauthErrorCode,
                        error_description: ce.message,
                    }
                }

                if (!event.locals.user && 
                    this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCode)) {
                    throw this.redirect(302, 
                        this.loginUrl+"?next="+encodeURIComponent(event.request.url));
                }          
                let scope = event.url.searchParams.get("scope") ?? undefined;
                if (scope == "") scope = undefined;
                const {url, error, error_description} = 
                    await this.startAuthorizationCodeFlow(scope);
                if (error || !url) {
                    const ce = CrossauthError.fromOAuthError(error??"server_error", 
                        error_description);
                    return {
                        ok: false,
                        error: ce.oauthErrorCode,
                        error_description: ce.message,
                    }
                }
                CrossauthLogger.logger.debug(j({
                    msg: `Authorization code flow: redirecting`,
                    url: url
                }));
                throw this.redirect(302, url);

            } catch (e) {
                if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                if (SvelteKitServer.isSvelteKitError(e)) throw e;
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug({err: e});
                CrossauthLogger.logger.error({cerr: e});
                //throw this.error(ce.httpStatus, ce.message);
                return {
                    ok: false,
                    error: ce.oauthErrorCode,
                    error_description: ce.message,
                }

            }
        },

    };

    readonly authorizationCodeFlowWithPKCEEndpoint = {

        get: async (event : RequestEvent) => {
            if (this.tokenResponseType == "saveInSessionAndLoad" || this.tokenResponseType == "sendInPage") {
                const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use load not get");
                return this.errorFn(this.server, event, ce);
            }
            try {

                if (!(this.validFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE))) {
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "Authorization flow is not supported");
                    return this.errorFn(this.server, event, ce);
                }

                if (!event.locals.user && 
                    this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE)) {
                    throw this.redirect(302, 
                        this.loginUrl+"?next="+encodeURIComponent(event.request.url));
                }          
                let scope = event.url.searchParams.get("scope") ?? undefined;
                if (scope == "") scope = undefined;
                const {url, error, error_description} = 
                    await this.startAuthorizationCodeFlow(scope, true);
                if (error || !url) {
                    const ce = CrossauthError.fromOAuthError(error??"server_error", 
                        error_description);
                    return await this.errorFn(this.server, event, ce)
                }
                    CrossauthLogger.logger.debug(j({
                        msg: `Authorization code flow: redirecting`,
                        url: url
                    }));
                throw this.redirect(302, url);

            } catch (e) {
                if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                if (SvelteKitServer.isSvelteKitError(e)) throw e;
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug({err: e});
                CrossauthLogger.logger.error({cerr: e});
                //throw this.error(ce.httpStatus, ce.message);
                return json({ 
                    error: ce.oauthErrorCode, 
                    error_description: ce.message
                }, {status: ce.httpStatus});

            }
        },

        load: async (event : RequestEvent) : Promise<AuthorizationCodeFlowReturn> => {
            if (/*this.tokenResponseType == "saveInSessionAndRedirect" ||*/ this.tokenResponseType == "sendJson" || this.tokenResponseType == "saveInSessionAndLoad") {
                const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use get not load");
                return {
                    ok: false,
                    error: ce.oauthErrorCode,
                    error_description: ce.message,
                }
            }
            try {

                if (!(this.validFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE))) {
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "Authorization flow is not supported");
                    return {
                        ok: false,
                        error: ce.oauthErrorCode,
                        error_description: ce.message,
                    }
                    }

                if (!event.locals.user && 
                    this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE)) {
                    throw this.redirect(302, 
                        this.loginUrl+"?next="+encodeURIComponent(event.request.url));
                }          
                let scope = event.url.searchParams.get("scope") ?? undefined;
                if (scope == "") scope = undefined;
                const {url, error, error_description} = 
                    await this.startAuthorizationCodeFlow(scope, true);
                if (error || !url) {
                    const ce = CrossauthError.fromOAuthError(error??"server_error", 
                        error_description);
                        return {
                            ok: false,
                            error: ce.oauthErrorCode,
                            error_description: ce.message,
                        }
                        }
                    CrossauthLogger.logger.debug(j({
                        msg: `Authorization code flow: redirecting`,
                        url: url
                    }));
                throw this.redirect(302, url);

            } catch (e) {
                if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                if (SvelteKitServer.isSvelteKitError(e)) throw e;
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug({err: e});
                CrossauthLogger.logger.error({cerr: e});
                //throw this.error(ce.httpStatus, ce.message);
                return {
                    ok: false,
                    error: ce.oauthErrorCode,
                    error_description: ce.message,
                }

            }
        },
    };

    readonly redirectUriEndpoint = {

        get: async (event : RequestEvent) => {
            if (this.tokenResponseType == "saveInSessionAndLoad" || this.tokenResponseType == "sendInPage") {
                const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use load not get");
                return this.errorFn(this.server, event, ce);
            }
            try {

                if (!(this.validFlows.includes(OAuthFlows.AuthorizationCode) || 
                    this.validFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE) ||
                    this.validFlows.includes(OAuthFlows.OidcAuthorizationCode))) {
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "Authorization flows are not supported");
                    return this.errorFn(this.server, event, ce);
                }

                if (!event.locals.user && 
                    (this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE) || 
                    this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCode))) {
                    throw this.redirect(302, 
                        this.loginUrl+"?next="+encodeURIComponent(event.request.url));
                }    

                const code = event.url.searchParams.get("code") ?? "";
                const state = event.url.searchParams.get("state") ?? undefined;
                const error = event.url.searchParams.get("error") ?? undefined;
                const error_description = event.url.searchParams.get("error") ?? undefined;
                const resp =  await this.redirectEndpoint(code,
                    state,
                    error,
                    error_description);
                    if (resp.error) return this.errorFn(this.server, event, CrossauthError.fromOAuthError(resp.error, resp.error_description));

                    if (resp.error) {
                        const ce = CrossauthError.fromOAuthError(resp.error, 
                        resp.error_description);
                        return await this.errorFn(this.server,
                        event,
                        ce);
                }
                return await this.receiveTokenFn(resp, this, event, false);

            } catch (e) {
                if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                if (SvelteKitServer.isSvelteKitError(e)) throw e;
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug({err: e});
                CrossauthLogger.logger.error({cerr: e});
                //throw this.error(ce.httpStatus, ce.message);
                return this.errorFn(this.server, event, ce);

            }
        },

        load: async (event : RequestEvent) : Promise<RedirectUriReturn> => {
            if (/*this.tokenResponseType == "saveInSessionAndRedirect" ||*/ this.tokenResponseType == "sendJson" || this.tokenResponseType == "saveInSessionAndLoad") {
                const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use get not load");
                return {
                    ok: false,
                    error: ce.oauthErrorCode,
                    error_description: ce.message,
                }
            }
            try {

                if (!(this.validFlows.includes(OAuthFlows.AuthorizationCode) || 
                    this.validFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE) ||
                    this.validFlows.includes(OAuthFlows.OidcAuthorizationCode))) {
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "Authorization flows are not supported");
                    return {
                        ok: false,
                        error: ce.oauthErrorCode,
                        error_description: ce.message,
                    }
                }

                if (!event.locals.user && 
                    (this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE) || 
                    this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCode))) {
                    throw this.redirect(302, 
                        this.loginUrl+"?next="+encodeURIComponent(event.request.url));
                }    
                
                const code = event.url.searchParams.get("code") ?? "";
                const state = event.url.searchParams.get("state") ?? undefined;
                const error = event.url.searchParams.get("error") ?? undefined;
                const error_description = event.url.searchParams.get("error") ?? undefined;
                const resp =  await this.redirectEndpoint(code,
                    state,
                    error,
                    error_description);
                if (resp.error) return {
                    ok: false,
                    error: resp.error,
                    error_description: resp.error_description,
                }


                if (resp.error) {
                    const ce = CrossauthError.fromOAuthError(resp.error, 
                        resp.error_description);
                    return {
                        ok: false,
                        error: ce.oauthErrorCode,
                        error_description: ce.message,
                    }
                }
                const receiveTokenResp = await this.receiveTokenFn(resp, this, event, false);
                if (receiveTokenResp instanceof Response) return {
                    ok: false,
                    error: "server_error",
                    error_description: "When using load, receiveTokenFn should return an object not a Response",

                };
                if (receiveTokenResp == undefined) return {
                    ok: false,
                    error: "server_error",
                    error_description: "No response received from receiveTokenFn",

                };
                if (receiveTokenResp.error) return {
                    ok: false,
                    error: receiveTokenResp.error,
                    error_description: receiveTokenResp.error_description,

                }
                return {
                    ...receiveTokenResp,
                }

            } catch (e) {
                if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                if (SvelteKitServer.isSvelteKitError(e)) throw e;
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug({err: e});
                CrossauthLogger.logger.error({cerr: e});
                //throw this.error(ce.httpStatus, ce.message);
                return {
                    ok: false,
                    error: ce.oauthErrorCode,
                    error_description: ce.message,
                }

            }
        },
    };

    /////
    // Client credentials flow

    readonly clientCredentialsFlowEndpoint = {

        post: async (event : RequestEvent) => {
            if (this.tokenResponseType == "saveInSessionAndLoad" || this.tokenResponseType == "sendInPage") {
                const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use actions not post");
                return this.errorFn(this.server, event, ce);
            }
            let formData : {[key:string]:string}|undefined = undefined;
            try {

                if (!(this.validFlows.includes(OAuthFlows.ClientCredentials))) {
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "Client credentials flow is not supported");
                    return this.errorFn(this.server, event, ce);
                }
                var data = new JsonOrFormData();
                await data.loadData(event);
                formData = data.toObject();

                if (!event.locals.user && 
                    (this.loginProtectedFlows.includes(OAuthFlows.ClientCredentials))) {
                    return this.error(401, "Must log in to use client credentials");
                }    
                
                const resp = await this.clientCredentialsFlow(formData?.scope);
                if (resp.error) {
                    const ce = CrossauthError.fromOAuthError(resp.error, 
                        resp.error_description);
                    return await this.errorFn(this.server,
                        event,
                        ce);
                }
                return await this.receiveTokenFn(resp, this, event, false);

            } catch (e) {
                if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                if (SvelteKitServer.isSvelteKitError(e)) throw e;
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug({err: e});
                CrossauthLogger.logger.error({cerr: e});
                //throw this.error(ce.httpStatus, ce.message);
                return this.errorFn(this.server, event, ce);

            }
        },

        actions: {
            default: async ( event : RequestEvent ) => {
                if (/*this.tokenResponseType == "saveInSessionAndRedirect" ||*/ this.tokenResponseType == "sendJson" || this.tokenResponseType == "saveInSessionAndLoad") {
                    const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use post not load");
                    throw ce;
                }

                let formData : {[key:string]:string}|undefined = undefined;
                try {
    
                    if (!(this.validFlows.includes(OAuthFlows.ClientCredentials))) {
                        const ce = new CrossauthError(ErrorCode.Unauthorized, "Client credentials flow is not supported");
                        throw ce;
                    }
                    var data = new JsonOrFormData();
                    await data.loadData(event);
                    formData = data.toObject();
    
                    if (!event.locals.user && 
                        (this.loginProtectedFlows.includes(OAuthFlows.ClientCredentials))) {
                            return {
                                ok: false,
                                error: "access_denied",
                                error_description: "Must log in to use client credentials flow" ,
                            }
                        }    
                    
                    const resp = await this.clientCredentialsFlow(formData?.scope);
                    if (resp.error) {
                        const ce = CrossauthError.fromOAuthError(resp.error, 
                            resp.error_description);
                        throw ce;
                    }
                    return await this.receiveTokenFn(resp, this, event, false) ?? {};
    
                } catch (e) {
                    if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                    if (SvelteKitServer.isSvelteKitError(e)) throw e;
                    const ce = CrossauthError.asCrossauthError(e);
                    CrossauthLogger.logger.debug({err: e});
                    CrossauthLogger.logger.error({cerr: e});
                    //throw this.error(ce.httpStatus, ce.message);
                    return { 
                        ok: false,
                        error: ce.oauthErrorCode, 
                        error_description: ce.message
                    };
    
                }
    
            }        
        }
    };

    /////
    // Refresh token flows

    readonly refreshTokenFlowEndpoint = {

        post: async (event : RequestEvent) => {
            if (this.tokenResponseType == "saveInSessionAndLoad" || this.tokenResponseType == "sendInPage") {
                const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use actions not post");
                return this.errorFn(this.server, event, ce);
            }
            let formData : {[key:string]:string}|undefined = undefined;
            try {

                if (!(this.validFlows.includes(OAuthFlows.RefreshToken))) {
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "Refresh token flow is not supported");
                    return this.errorFn(this.server, event, ce);
                }
                var data = new JsonOrFormData();
                await data.loadData(event);
                formData = data.toObject();

                if (!event.locals.user && 
                    (this.loginProtectedFlows.includes(OAuthFlows.RefreshToken))) {
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "Must log in to use refresh token flow");

                    return this.errorFn(this.server, event, ce);
                }    

                // if the session server and CSRF protection enabled, require a valid CSRF token
                if (this.server.sessionServer && this.server.sessionServer.enableCsrfProtection) {
                    try {
                        const cookieValue = this.server.sessionServer.getCsrfCookieValue(event);
                        if (cookieValue) this.server.sessionServer.sessionManager.validateCsrfCookie(cookieValue);
                   }
                   catch (e) {
                    if (SvelteKitServer.isSvelteKitError(e) || SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "CSRF token not present");
                        return this.errorFn(this.server, event, ce);
                   }
    
                }

                // get refresh token from body if present, otherwise
                // try to find in session
                let refreshToken : string | undefined = formData.refresh_token;
                if (!refreshToken && this.server.sessionServer) {
                    const oauthData = await this.server.sessionServer.getSessionData(event, this.sessionDataName);
                    if (!oauthData?.refresh_token) {
                        const ce = new CrossauthError(ErrorCode.BadRequest,
                            "No refresh token in session or in parameters");
                        return this.errorFn(this.server, event, ce);
                    }
                    refreshToken = oauthData.refresh_token;
                } 
                if (!refreshToken) {
                    // TODO: refresh token cookie - call with no refresh token?
                    const ce = new CrossauthError(ErrorCode.BadRequest,
                        "No refresh token supplied");
                    return this.errorFn(this.server, event, ce);
                }

                const resp = 
                    await this.refreshTokenFlow(refreshToken);
            
                const resp2 = await this.receiveTokenFn(resp, this, event, false) ;
                if (resp && resp2 instanceof Response) return resp2;
                throw new CrossauthError(ErrorCode.UnknownError, "Receive token function did not return a Response");

            } catch (e) {
                if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                if (SvelteKitServer.isSvelteKitError(e)) throw e;
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug({err: e});
                CrossauthLogger.logger.error({cerr: e});
                //throw this.error(ce.httpStatus, ce.message);
                return this.errorFn(this.server, event, ce);

            }
        },

        actions: {
            default: async ( event : RequestEvent ) => {
                if (/*this.tokenResponseType == "saveInSessionAndRedirect" ||*/ this.tokenResponseType == "sendJson" || this.tokenResponseType == "saveInSessionAndLoad") {
                    const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use post not load");
                    throw ce;
                }

                let formData : {[key:string]:string}|undefined = undefined;
                try {
    
                    if (!(this.validFlows.includes(OAuthFlows.RefreshToken))) {
                        const ce = new CrossauthError(ErrorCode.Unauthorized, "Refresh token flow is not supported");
                        return this.errorFn(this.server, event, ce);
                    }
                    var data = new JsonOrFormData();
                    await data.loadData(event);
                    formData = data.toObject();
    
                    if (!event.locals.user && 
                        (this.loginProtectedFlows.includes(OAuthFlows.RefreshToken))) {
                        const ce = new CrossauthError(ErrorCode.Unauthorized, "Must log in to use refresh token");
                        throw ce;
                    }    
                    
                    // if the session server and CSRF protection enabled, require a valid CSRF token
                    if (this.server.sessionServer && this.server.sessionServer.enableCsrfProtection) {
                        try {
                            const cookieValue = this.server.sessionServer.getCsrfCookieValue(event);
                            if (cookieValue) this.server.sessionServer.sessionManager.validateCsrfCookie(cookieValue);
                    }
                    catch (e) {
                        if (SvelteKitServer.isSvelteKitError(e) || SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                        const ce = new CrossauthError(ErrorCode.Unauthorized, "CSRF token not present");
                        throw ce;
                    }
        
                    }

                    // get refresh token from body if present, otherwise
                    // try to find in session
                    let refreshToken : string | undefined = formData.refresh_token;
                    if (!refreshToken && this.server.sessionServer) {
                        const oauthData = await this.server.sessionServer.getSessionData(event, this.sessionDataName);
                        if (!oauthData?.refresh_token) {
                            const ce = new CrossauthError(ErrorCode.BadRequest,
                                "No refresh token in session or in parameters");
                            throw ce;
                        }
                        refreshToken = oauthData.refresh_token;
                    } 
                    if (!refreshToken) {
                        // TODO: refresh token cookie - call with no refresh token?
                        const ce = new CrossauthError(ErrorCode.BadRequest,
                            "No refresh token supplied");
                        throw ce;
                    }

                    const resp = 
                        await this.refreshTokenFlow(refreshToken);

                    const resp2 = await this.receiveTokenFn(resp, this, event, false) ?? {};
                    if (resp2 instanceof Response) throw new CrossauthError(ErrorCode.Configuration, "Refresh token flow should return an object not Response");
                    return resp2;

                } catch (e) {
                    if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                    if (SvelteKitServer.isSvelteKitError(e)) throw e;
                    const ce = CrossauthError.asCrossauthError(e);
                    CrossauthLogger.logger.debug({err: e});
                    CrossauthLogger.logger.error({cerr: e});
                    //throw this.error(ce.httpStatus, ce.message);
                    return { 
                        ok: false,
                        error: ce.oauthErrorCode, 
                        error_description: ce.message
                    };
    
                }
    
            }        
        }
    
    };

    readonly refreshTokensIfExpiredEndpoint = {

        post: async (event : RequestEvent) => {
            if (this.tokenResponseType == "saveInSessionAndLoad" || this.tokenResponseType == "sendInPage") {
                const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use actions not post");
                return this.errorFn(this.server, event, ce);
            }
            return this.pack(await this.refreshTokens(event, "post", true));
        },

        actions: {
            default: async ( event : RequestEvent ) => {
                if (/*this.tokenResponseType == "saveInSessionAndRedirect" ||*/ this.tokenResponseType == "sendJson" || this.tokenResponseType == "saveInSessionAndLoad") {
                    const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use post not load");
                    throw ce;
                }
                return this.refreshTokens(event, "page", true);

            }
        },
    
    };

    readonly autoRefreshTokensIfExpiredEndpoint = {

        post: async (event : RequestEvent) => {
            if (this.tokenResponseType == "saveInSessionAndLoad" || this.tokenResponseType == "sendInPage") {
                const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use actions not post");
                return this.errorFn(this.server, event, ce);
            }
            return this.pack(await this.refreshTokens(event, "silent", true));
        },
    };

    readonly autoRefreshTokensEndpoint = {

        post: async (event : RequestEvent) => {
            if (this.tokenResponseType == "saveInSessionAndLoad" || this.tokenResponseType == "sendInPage") {
                const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use actions not post");
                return this.errorFn(this.server, event, ce);
            }
            return this.pack(await this.refreshTokens(event, "silent", false));
        },
    };

    /////
    // Device code flow

    readonly startDeviceCodeFlowEndpoint = {
        actions: {
            default: async ( event : RequestEvent ) => {
                return await this.startDeviceCodeFlow_internal(event);
            },
        },
        post: async (event : RequestEvent) => {
            const resp = await this.startDeviceCodeFlow_internal(event);
            if (resp.error) {
                const ce = CrossauthError.fromOAuthError(resp.error, resp.error_description)
                return json(resp, {status: ce.httpStatus});
            }
            return json(resp);
        }
    }

    readonly pollDeviceCodeFlowEndpoint = {
        actions: {
            default: async ( event : RequestEvent ) => {
                /*if (this.tokenResponseType == "sendJson" || this.tokenResponseType == "saveInSessionAndLoad") {
                    const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use post not load");
                    throw ce;
                }*/

                const resp = await this.pollDeviceCodeFlow_internal(event);
                if (resp instanceof (Response)) return this.unpack(resp);
                if (resp == undefined) return {};
                return resp;
            },
        },
        post: async (event : RequestEvent) => {
            /*if (this.tokenResponseType == "saveInSessionAndLoad" || this.tokenResponseType == "sendInPage") {
                const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use actions not post");
                return this.errorFn(this.server, event, ce);
            }*/
            const resp = await this.pollDeviceCodeFlow_internal(event);
            if (resp instanceof Response) return resp;
            if (resp == undefined) return new Response(null, {status: 204});
            if (resp.error) {
                const ce = CrossauthError.fromOAuthError(resp.error, resp.error_description)
                return json(resp, {status: ce.httpStatus});
            }
            return json(resp);
        }
    }


    /////
    // Password and Password MFA flows

    readonly passwordFlowEndpoint = {

        post: async (event : RequestEvent) => 
            await this.passwordFlow_post(event, (e: RequestEvent, formData: {[key:string]:string}) => this.passwordPost(e, formData)),
        

        actions: {
            password: async ( event : RequestEvent ) => 
                await this.passwordFlow_action(event, (e: RequestEvent, formData: {[key:string]:string}) => this.passwordPost(e, formData)),
            
            passwordOtp: async ( event : RequestEvent ) => 
                await this.passwordFlow_action(event, (e: RequestEvent, formData: {[key:string]:string}) => this.passwordOtp(e, formData)),

            passwordOob: async ( event : RequestEvent ) => 
                await this.passwordFlow_action(event, (e: RequestEvent, formData: {[key:string]:string}) => this.passwordOob(e, formData)),

        }
    };

    readonly passwordOtpEndpoint = {

        post: async (event : RequestEvent) => 
            await this.passwordFlow_post(event, (e: RequestEvent, formData: {[key:string]:string}) => this.passwordOtp(e, formData)),
        
        actions: {
            default: async ( event : RequestEvent ) => 
                await this.passwordFlow_action(event, (e: RequestEvent, formData: {[key:string]:string}) => this.passwordOtp(e, formData)),
        }
    };

    readonly passwordOobEndpoint = {

        post: async (event : RequestEvent) => 
            await this.passwordFlow_post(event, (e: RequestEvent, formData: {[key:string]:string}) => this.passwordOob(e, formData)),
        
        actions: {
            default: async ( event : RequestEvent ) => 
                await this.passwordFlow_action(event, (e: RequestEvent, formData: {[key:string]:string}) => this.passwordOob(e, formData)),
        }
    };

    /////
    // BFF endpoints

    readonly bffEndpoint = {

        post: async (event : RequestEvent) => await this.bff(event),
        get: async (event : RequestEvent) => await this.bff(event),
        put: async (event : RequestEvent) => await this.bff(event),
        head: async (event : RequestEvent) => await this.bff(event),
        options: async (event : RequestEvent) => await this.bff(event),
        delete: async (event : RequestEvent) => await this.bff(event),
        patch: async (event : RequestEvent) => await this.bff(event),
        
        actions: {
            get: async ( event : RequestEvent ) => 
                await this.unpack(await this.bff(event)),
            post: async ( event : RequestEvent ) => 
                await this.unpack(await this.bff(event)),
        },

    };

    readonly allBffEndpoint = {

        post: async (event : RequestEvent) => await this.allBff(event),
        get: async (event : RequestEvent) => await this.allBff(event),
        put: async (event : RequestEvent) => await this.allBff(event),
        head: async (event : RequestEvent) => await this.allBff(event),
        options: async (event : RequestEvent) => await this.allBff(event),
        delete: async (event : RequestEvent) => await this.allBff(event),
        patch: async (event : RequestEvent) => await this.allBff(event),        

        actions: {
            get: async ( event : RequestEvent ) => 
                await this.unpack(await this.allBff(event, {method: "GET"})),
            gpostet: async ( event : RequestEvent ) => 
                await this.unpack(await this.allBff(event, {method: "POST"})),
            put: async ( event : RequestEvent ) => 
                await this.unpack(await this.allBff(event, {method: "PUT"})),
            options: async ( event : RequestEvent ) => 
                await this.unpack(await this.allBff(event, {method: "OPTIONS"})),
            delete: async ( event : RequestEvent ) => 
                await this.unpack(await this.allBff(event, {method: "DELETE"})),
            patch: async ( event : RequestEvent ) => 
                await this.unpack(await this.allBff(event, {method: "PATCH"})),
        },
    };

    /////
    // Endpoints for getting BFF tokens

    readonly accessTokenEndpoint = {
        post: async (event : RequestEvent) => await this.tokens(event, "access_token"),
        actions: {
            default: async ( event : RequestEvent ) => 
                await this.tokens(event, "access_token"),
        },
    }

    readonly haveAccessTokenEndpoint = {
        post: async (event : RequestEvent) => await this.tokensResponse(event, "have_access_token"),
        actions: {
            default: async ( event : RequestEvent ) => 
                await this.tokens(event, "have_access_token"),
        },
    }

    readonly refreshTokenEndpoint = {
        post: async (event : RequestEvent) => await this.tokensResponse(event, "refresh_token"),
        actions: {
            default: async ( event : RequestEvent ) => 
                await this.tokens(event, "refresh_token"),
        },
    }

    readonly haveRefreshTokenEndpoint = {
        post: async (event : RequestEvent) => await this.tokensResponse(event, "have_refresh_token"),
        actions: {
            default: async ( event : RequestEvent ) => 
                await this.tokens(event, "have_refresh_token"),
        },
    }

    readonly idTokenEndpoint = {
        post: async (event : RequestEvent) => await this.tokensResponse(event, "id_token"),
        actions: {
            default: async ( event : RequestEvent ) => 
                await this.tokens(event, "id_token"),
        },
    }

    readonly haveIdTokenEndpoint = {
        post: async (event : RequestEvent) => await this.tokensResponse(event, "have_id_token"),
        actions: {
            default: async ( event : RequestEvent ) => 
                await this.tokens(event, "have_id_token"),
        },
    }

    readonly tokensEndpoint = {
        post: async (event : RequestEvent) => await this.tokensResponse(event, this.tokenEndpoints),
        actions: {
            default: async ( event : RequestEvent ) => 
                await this.tokens(event,this.tokenEndpoints),
        },
    }
}
