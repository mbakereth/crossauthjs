import { ApiKeyManager, UserStorage, KeyStorage } from '@crossauth/backend';
import type { ApiKeyManagerOptions } from '@crossauth/backend';
import { CrossauthLogger, j } from '@crossauth/common';
import type { RequestEvent, MaybePromise } from '@sveltejs/kit';

/**
 * Options for {@link SvelteKitApiKeyServer }.
 * 
 * See {@link SveltekitApiKeyServer } constructor for description of parameters
 */
export interface SvelteKitApiKeyServerOptions extends ApiKeyManagerOptions {
    /** Pass the Sveltekit redirect function */
    redirect? : any,

    /** Pass the Sveltekit error function */
    error? : any,

}

/**
 * This class adds API key functionality to the Fatify server.
 * 
 * You shouldn't have to instantiate this directly.  It is created 
 * when instantiating {@link SvelteKitServer} if enabling API key support-
 * 
 * API keys are bearer tokens than have to be manually created for a user.
 * They can be used in place of username/password login and session cookies.
 * 
 * This class adds a `preHandler` hook that sets the `user` field in the
 * Fastify request.  It also sets `scopes` in the request object if there
 * is a `scope` field in the JSON object in the `data` field in in the API
 * record in key storage.
 */
export class SvelteKitApiKeyServer {
    private userStorage : UserStorage;
    private apiKeyManager : ApiKeyManager;

    /**
     * Hook to check if the user is logged in and set data in `locals`
     * accordingly.
     */
    readonly hook : (input: {event: RequestEvent}, 
        //response: Response
    ) => /*MaybePromise<Response>*/ MaybePromise<void>;

    /**
     * Constructor
     * 
     * @param app the Fastify app instance
     * @param userStorage the user storage with user accounts
     * @param keyStorage the storage for finding API keys
     * @param options See {@link FastifyApiKeyServerOptions}
     */
    constructor(
        userStorage: UserStorage, 
        keyStorage: KeyStorage, 
        options: SvelteKitApiKeyServerOptions = {}) {

        this.userStorage = userStorage;
        this.apiKeyManager = new ApiKeyManager(keyStorage, options);
    
        this.hook = async ({ event}/*, response*/) => {
            CrossauthLogger.logger.debug("APIKey hook");

            const authzHeader = event.request.headers.get("authorization");
            if (authzHeader) {
                try {
                    CrossauthLogger.logger.debug(j({
                        msg: "Received authorization header"}));
                    const key = 
                        await this.apiKeyManager.validateToken(
                            authzHeader);
                    CrossauthLogger.logger.debug(j({
                        msg: "Valid API key",
                        hahedApiKey: ApiKeyManager.hashSignedApiKeyValue(key.value)
                    }));
                    const data = KeyStorage.decodeData(key.data);
                    event.locals.apiKey = {...key, ...data};
                    if ("scope" in data && Array.isArray(data.scope)) {
                        let scopes = [];
                        for (let scope of data.scope) {
                            if (typeof scope == "string") scopes.push(scope);
                        }
                        event.locals.scope = scopes;
                    }
                    if (key.userId) {
                        try {
                            const {user} = await this.userStorage.getUserById(key.userId);
                            event.locals.user = user;
                            event.locals.authType = "apiKey";
                            CrossauthLogger.logger.debug(j({msg: "API key is for user", userId: user.id, user: user.username, hahedApiKey: ApiKeyManager.hashSignedApiKeyValue(key.value)}));
                        } catch (e2) {
                            CrossauthLogger.logger.error(j({msg: "API key has invalid user", userId: key.userId,  hashedApiKey: ApiKeyManager.hashSignedApiKeyValue(key.value)}));
                            CrossauthLogger.logger.debug(j({err: e2}));
                        }
                    }
                } catch (e) {
                    CrossauthLogger.logger.error(j({msg: "Invalid authorization header received", header: authzHeader}));
                    CrossauthLogger.logger.debug(j({err: e}));
                }
            };
        }
    }
}
