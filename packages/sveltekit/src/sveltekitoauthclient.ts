import { jwtDecode } from "jwt-decode";
import { type FastifyRequest, type FastifyReply } from 'fastify';
import {
    CrossauthError,
    ErrorCode,
    CrossauthLogger,
    OAuthFlows,
    type OAuthTokenResponse,
    j, 
    type MfaAuthenticatorResponse} from '@crossauth/common';
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
 * Options for {@link FastifyOAuthClient}.
 */
export interface SvelteKitOAuthClientOptions extends OAuthClientOptions {

    /** The base URL for endpoints served by this class.
     */
    siteUrl: string,

    /** 
     * You will have to create a route for the redirect Uri, using
     * the `redirectUriEndpoint` load function.  But the URL for it
     * here.  It can be an absolute URL or relative to siteUrl.
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
     * If the {@link FastifyOAuthClientOptions.tokenResponseType} is
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
     * See {@link @crossauth/common!OAuthFlows}.
     */
    loginProtectedFlows? : string[],

    /**
     * This function is called after successful authorization to pass the
     * new tokens to.
     * @param oauthResponse the response from the OAuth `token` endpoint.
     * @param client the fastify OAuth client
     * @param request the Fastify request
     * @param reply the Fastify reply
     * @returns the Fastify reply
     */
    receiveTokenFn?: (oauthResponse: OAuthTokenResponse,
        client: SvelteKitOAuthClient,
        event: RequestEvent) => Promise<Response|undefined>;

    /**
     * The function to call when there is an OAuth error and
     * {@link SvelteKitOAuthClientOptions.errorResponseType}
     * is `custom`.
     * See {@link SvelteKitErrorFn}.
     */
    errorFn? :SvelteKitErrorFn;

    /**
     * What to do when receiving tokens.
     * See {@link FastifyOAuthClient} class documentation for full description.
     */
    tokenResponseType? : 
        "sendJson" | 
        "saveInSessionAndLoad" | 
        "saveInSessionAndRedirect" | 
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
     * Endpoints to provide to acces tokens through the BFF mechanism,
     * See {@link FastifyOAuthClient} class documentation for full description.
     */
    tokenEndpoints? : ("access_token"|"refresh_token"|"id_token"|
        "have_access_token"|"have_refresh"|"have_id")[],

    /** Pass the Sveltekit redirect function */
    redirect? : any,

    /** Pass the Sveltekit error function */
    error? : any,
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
    });
}

async function svelteKitError(server: SvelteKitServer,
    _event: RequestEvent,
    ce: CrossauthError) : Promise<Response> {
        throw server.oauthClient?.error(ce.httpStatus, ce.message);
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
    _event: RequestEvent) : Promise<Response|undefined> {
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

        return client.redirect(302, client.authorizedUrl);
    } catch (e) {
        const ce = e as CrossauthError;
        CrossauthLogger.logger.debug(j({err: ce}));
        CrossauthLogger.logger.debug(j({cerr: ce, msg: "Error receiving tokens"}));
        client.errorFn(client.server, event, ce);
    }
}


///////////////////////////////////////////////////////////////////////////////
// CLASSES
export class SvelteKitOAuthClient extends OAuthClientBackend {
    server : SvelteKitServer;
    private siteUrl : string = "/";
    sessionDataName : string = "oauth";
    private receiveTokenFn : 
        ( oauthResponse: OAuthTokenResponse,
            client: SvelteKitOAuthClient,
            event : RequestEvent) 
            => Promise<Response|undefined> = sendJson;
    readonly errorFn : SvelteKitErrorFn = jsonError;
    private loginUrl : string = "/login";
    authorizedUrl : string = "";

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
        "sendInPage" | 
        "custom" = "sendJson";
    private errorResponseType :  
        "sendJson" | 
        "svelteKitError" | 
        "custom" = "sendJson";
    private bffEndpoints: {
        url: string,
        methods: ("GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS" | "HEAD")[],
        matchSubUrls?: boolean
        }[] = [];
    private bffEndpointName = "bff";
    private bffBaseUrl? : string;
    private tokenEndpoints : ("access_token"|"refresh_token"|"id_token"|
        "have_access_token"|"have_refresh"|"have_id")[] = [];
    
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
        setParameter("siteUrl", ParamType.String, this, options, "SITE_URL", true);
        setParameter("tokenResponseType", ParamType.String, this, options, "OAUTH_TOKEN_RESPONSE_TYPE");
        setParameter("errorResponseType", ParamType.String, this, options, "OAUTH_ERROR_RESPONSE_TYPE");
        setParameter("loginUrl", ParamType.String, this, options, "LOGIN_URL");
        setParameter("loginProtectedFlows", ParamType.JsonArray, this, options, "OAUTH_LOGIN_PROTECTED_FLOWS");
        setParameter("bffEndpointName", ParamType.String, this, options, "OAUTH_BFF_ENDPOINT_NAME");
        setParameter("bffBaseUrl", ParamType.String, this, options, "OAUTH_BFF_BASEURL");
        setParameter("redirectUri", ParamType.String, this, options, "OAUTH_REDIRECTURI", true);
        setParameter("authorizedUrl", ParamType.String, this, options, "AUTHORIZED_URL", false);

        if (options.redirect) this.redirect = options.redirect;
        if (options.error) this.error = options.error;        

        let redirectUri = this.redirectUri ?? "";
        try {
            new URL(redirectUri);
        } catch (e1) {
            redirectUri = this.siteUrl;
            if (!redirectUri.endsWith("/") && !this.redirectUri?.startsWith("/")) {
                redirectUri += "/";
            }
            redirectUri += this.redirectUri;
            try {
                new URL(redirectUri);
            } catch (e2) {
                throw new CrossauthError(ErrorCode.Configuration, "Invalid redirect Uri " + this.redirectUri);
            }
        }

        if (options.tokenEndpoints) this.tokenEndpoints = options.tokenEndpoints;

        if (this.bffEndpointName.endsWith("/")) this.bffEndpointName = this.bffEndpointName.substring(0, this.bffEndpointName.length-1);
        if (options.bffEndpoints) this.bffEndpoints = options.bffEndpoints;

        if (this.loginProtectedFlows.length == 1 && 
            this.loginProtectedFlows[0] == OAuthFlows.All) {
            this.loginProtectedFlows = this.validFlows;
        } else {
            if (!OAuthFlows.areAllValidFlows(this.loginProtectedFlows)) {
                throw new CrossauthError(ErrorCode.Configuration,
                        "Invalid flows specificied in " + this.loginProtectedFlows.join(","));
            }
        }

        if (this.tokenResponseType == "custom" && !options.receiveTokenFn) {
            throw new CrossauthError(ErrorCode.Configuration, 
                "Token response type of custom selected but receiveTokenFn not defined");
        }
        if (this.tokenResponseType == "custom" && options.receiveTokenFn) {
            this.receiveTokenFn = options.receiveTokenFn;
        } else if (this.tokenResponseType == "sendJson") {
            this.receiveTokenFn = sendJson;
        } else if (this.tokenResponseType == "sendInPage") {
            this.receiveTokenFn = sendJson; //TODO: correct sendInPage;
        } else if (this.tokenResponseType == "saveInSessionAndLoad") {
            this.receiveTokenFn = sendJson; // TODO: correct saveInSessionAndLoad;
        } else if (this.tokenResponseType == "saveInSessionAndRedirect") {
            this.receiveTokenFn = sendJson; // TODO: correct saveInSessionAndRedirect;
        }
        if ((this.tokenResponseType == "saveInSessionAndLoad" || this.tokenResponseType == "saveInSessionAndRedirect") &&
            this.authorizedUrl == "") {
            throw new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is" + this.tokenResponseType + ", must provide authorizedUrl");
        }
        if ((this.tokenResponseType == "saveInSessionAndLoad" || this.tokenResponseType == "saveInSessionAndRedirect") &&
            this.server.sessionServer == undefined) {
            throw new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is" + this.tokenResponseType + ", must activate the session server");
        }
        if (this.errorResponseType == "custom" && !options.errorFn) {
            throw new CrossauthError(ErrorCode.Configuration, 
                "Error response type of custom selected but errorFn not defined");
        }
        if (this.errorResponseType == "custom" && options.errorFn) {
            this.errorFn = options.errorFn;
        } else if (this.errorResponseType == "sendJson") {
            this.errorFn = jsonError;
        } else if (this.errorResponseType == "svelteKitError") {
            this.errorFn = jsonError; // TODO: correct pageError;
        }

        if (!options.redirect) throw new CrossauthError(ErrorCode.Configuration, "Must provide the SvelteKit redirect function");
        if (!options.error && this.errorResponseType == "svelteKitError") throw new CrossauthError(ErrorCode.Configuration, "Must provide the SvelteKit error function");

        if (this,this.loginProtectedFlows.length > 0 && this.loginUrl == "") {
            throw new CrossauthError(ErrorCode.Configuration, 
                "loginUrl must be set if protecting oauth endpoints");
        }
    }       
    
    ////////////////////////////////////////////////////////////////
    // Endpoints

    readonly authorizationCodeFlowEndpoint = {

        get: async (event : RequestEvent) => {
            if (this.tokenResponseType == "saveInSessionAndLoad") {
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
                const scope = event.url.searchParams.get("scope") ?? undefined;
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
                return json({ 
                    error: ce.oauthErrorCode, 
                    error_description: ce.message
                });

            }
        },
    };

    readonly authorizationCodeFlowWithPKCEEndpoint = {

        get: async (event : RequestEvent) => {
            if (this.tokenResponseType == "saveInSessionAndLoad") {
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
                const scope = event.url.searchParams.get("scope") ?? undefined;
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
                });

            }
        },
    };

    readonly redirectUriEndpoint = {

        get: async (event : RequestEvent) => {
            if (this.tokenResponseType == "saveInSessionAndLoad") {
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
                if (resp.error) throw new CrossauthError()

                if (resp.error) {
                    const ce = CrossauthError.fromOAuthError(resp.error, 
                        resp.error_description);
                    return await this.errorFn(this.server,
                        event,
                        ce);
                }
                return await this.receiveTokenFn(resp, this, event);

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
                });

            }
        },
    };
}
