import { CrossauthError, CrossauthLogger, j } from "@crossauth/common";
import { OAuthTokenProvider } from './tokenprovider.ts';

const TOLERANCE_SECONDS = 30;
const AUTOREFRESH_RETRIES = 2;
const AUTOREFRESH_RETRY_INTERVAL_SECS = 30;

/**
 * Used by {@link OAuthClient} and {@link OAuthBsffClient} to automatically
 * refresh access and ID tokens
 */
export class OAuthAutoRefresher {
    private autoRefreshUrl : string = "/autorefresh";
    protected csrfHeader : string = "X-CROSSAUTH-CSRF";
    protected headers : {[key:string]:string} = {};
    private autoRefreshActive = false;
    protected mode :  "no-cors" | "cors" | "same-origin" = "cors";
    protected credentials : "include" | "omit" | "same-origin" = "same-origin";
    protected tokenProvider : OAuthTokenProvider;

    /**
     * Constructor
     * 
     * @param options
     *   - `autoRefreshUrl` the URL to call to perform the refresh  Default is `/autorefresh`
     *   - `csrfHeader` the header to put CSRF tokens into 
     *        (default `X-CROSSAUTH-CSRF`))
     *   - `mode` overrides the default `mode` in fetch calls
     *   - `credentials` - overrides the default `credentials` for fetch calls
     *   - `headers` - adds headers to fetfh calls
     *   - `tokenProvider` - class for fetching tokens and adding them to requests
     */
    constructor(options  : {
            autoRefreshUrl : string,
            csrfHeader? : string,
            credentials? : "include" | "omit" | "same-origin",
            mode? : "no-cors" | "cors" | "same-origin",
            headers? : {[key:string]:any},
            tokenProvider : OAuthTokenProvider,
        
        }) {
        this.tokenProvider = options.tokenProvider;
        this.autoRefreshUrl = options.autoRefreshUrl;
        if (options.csrfHeader) this.csrfHeader = options.csrfHeader;
        if (options.headers) this.headers = options.headers;
        if (options.mode) this.mode = options.mode;
        if (options.credentials) this.credentials = options.credentials;
    }


    async startAutoRefresh(tokensToFetch : ("access"|"id")[] = ["access", "id"], 
        errorFn? : (msg : string, e? : CrossauthError) => void) {
    
        if (!this.autoRefreshActive) {
            this.autoRefreshActive = true;
            CrossauthLogger.logger.debug(j({msg: "Starting auto refresh"}));
            await this.scheduleAutoRefresh(tokensToFetch, errorFn);
        }
    }


    stopAutoRefresh() {
        this.autoRefreshActive = false;
        CrossauthLogger.logger.debug(j({msg: "Stopping auto refresh"}));
    }

    private async scheduleAutoRefresh(tokensToFetch : ("access"|"id")[], 
        errorFn? : (msg : string, e? : CrossauthError) => void) {
            // Get CSRF token
            const csrfTokenPromise = this.tokenProvider.getCsrfToken();
            const csrfToken = csrfTokenPromise ?  await csrfTokenPromise : undefined;

            // Get token expiries
            const expiries = await this.tokenProvider.getTokenExpiries([...tokensToFetch, "refresh"], csrfToken);
            if (expiries.refresh == undefined) {
                CrossauthLogger.logger.debug(j({msg: `No refresh token found`}))
                return;
            }

            const now = Date.now();

            // if neither access nor ID token expires, we have nothing to do
            let tokenExpiry = expiries.id;
            if (!tokenExpiry || (expiries.access && expiries.access < tokenExpiry)) tokenExpiry = expiries.access;
            if (!tokenExpiry) {
                CrossauthLogger.logger.debug(j({msg: `No tokens expire`}))
                return;
            }

            // renew token TOLERANCE_SECONDS before expiry
            const renewTime = tokenExpiry*1000 - now - TOLERANCE_SECONDS;
            if (renewTime < 0) {
                CrossauthLogger.logger.debug(j({msg: `Expiry time has passed`}))
                return;
            }

            // if refresh token is about to expire, don't try to use it
            if (expiries.refresh && expiries.refresh - TOLERANCE_SECONDS < renewTime) {
                CrossauthLogger.logger.debug(j({msg: `Refresh token has expired`}))
                return;
            }

            // schedule auto refresh task
            let wait = (ms : number) => new Promise(resolve => setTimeout(resolve, ms));
            CrossauthLogger.logger.debug(j({msg: `Waiting ${renewTime} before refreshing tokens`}))
            await wait(renewTime);
            await this.autoRefresh(tokensToFetch, csrfToken, errorFn);

    }

    private async autoRefresh(tokensToFetch : ("access"|"id")[], csrfToken? : string, errorFn? : (msg : string, e? : CrossauthError) => void,
        ) {
        if (this.autoRefreshActive) {
            let reply : {[key:string]:any} | undefined = undefined;
            let success = false;
            let tries = 0;
            while (!success && tries <= AUTOREFRESH_RETRIES) {
                try {
                    let headers = {...this.headers};
                    if (csrfToken) {
                        headers[this.csrfHeader] = csrfToken;
                    }
                    CrossauthLogger.logger.debug(j({msg: `Initiating auto refresh`}));
                    const resp = await this.tokenProvider.jsonFetchWithToken(this.autoRefreshUrl,
                    {
                        method: 'POST',
                        headers: {
                            'Accept': 'application/json',
                            'Content-Type': 'application/json',
                            ...headers,
                        },
                        mode: this.mode,
                        credentials: this.credentials,
                        body: {
                            csrfToken
                        }
                    }, "refresh");

                    if (!resp.ok) { 
                        CrossauthLogger.logger.error(j({msg: "Failed auto refreshing tokens", status: resp.status}));
        
                    }
                    reply = await resp.json();

                    if (reply?.ok) { 
                        await this.scheduleAutoRefresh(tokensToFetch, errorFn);
                        success = true;
                        try {
                            await this.tokenProvider.receiveTokens(reply);
                        } catch (e) {
                            const cerr = CrossauthError.asCrossauthError(e);
                            if (errorFn) {
                                errorFn("Couldn't receive tokens", cerr);
                            } else {
                                CrossauthLogger.logger.debug(j({err: e}));
                                CrossauthLogger.logger.error(j({msg: "Error receiving tokens", cerr: cerr}))
                            }
                        }

                    } else {
                        if (tries < AUTOREFRESH_RETRIES) {
                            CrossauthLogger.logger.error(j({msg: `Failed auto refreshing tokens.  Retrying in ${AUTOREFRESH_RETRY_INTERVAL_SECS} seconds`}));
                            let wait = (ms : number) => new Promise(resolve => setTimeout(resolve, ms));
                            await wait(AUTOREFRESH_RETRY_INTERVAL_SECS*1000);
                        } else {
                            CrossauthLogger.logger.error(j({msg: `Failed auto refreshing tokens.  Number of retries exceeded`}));
                            if (errorFn) {
                                errorFn("Failed auto refreshing tokens");
                            }
                        }
                        tries++;
                    }

                } catch (e) {
                    const ce = CrossauthError.asCrossauthError(e);
                    CrossauthLogger.logger.debug(j({err: ce}));
                    if (tries < AUTOREFRESH_RETRIES) {
                        CrossauthLogger.logger.error(j({msg: `Failed auto refreshing tokens.  Retrying in ${AUTOREFRESH_RETRIES} seconds`}));
                        let wait = (ms : number) => new Promise(resolve => setTimeout(resolve, ms));
                        await wait(AUTOREFRESH_RETRY_INTERVAL_SECS);
                    } else {
                        CrossauthLogger.logger.error(j({msg: `Failed auto refreshing tokens.  Number of retries exceeded`}));
                        if (errorFn) {
                            errorFn(ce.message, ce);
                        }
                    }
                    tries++;
                }
            }
        }
    }
}