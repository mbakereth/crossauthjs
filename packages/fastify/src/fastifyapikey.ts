import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { Server, IncomingMessage, ServerResponse } from 'http'
import { ApiKeyManager, UserStorage, KeyStorage } from '@crossauth/backend';
import type { ApiKeyManagerOptions } from '@crossauth/backend';
import { CrossauthLogger, j } from '@crossauth/common';

/**
 * Options for {@link FastifyApiKeyServer }.
 * 
 * See {@link FastifyApiKeyServer } constructor for description of parameters
 */
export interface FastifyApiKeyServerOptions extends ApiKeyManagerOptions {

    /** You can pass your own fastify instance or omit this, in which case 
     *  Crossauth will create one */
    app? : FastifyInstance<Server, IncomingMessage, ServerResponse>,
}

/**
 * This class adds API key functionality to the Fatify server.
 * 
 * You shouldn't have to instantiate this directly.  It is created 
 * when instantiating {@link FastifyServer} if enabling API key support-
 * 
 * API keys are bearer tokens than have to be manually created for a user.
 * They can be used in place of username/password login and session cookies.
 * 
 * This class adds a `preHandler` hook that sets the `user` field in the
 * Fastify request.  It also sets `scopes` in the request object if there
 * is a `scope` field in the JSON object in the `data` field in in the API
 * record in key storage.
 */
export class FastifyApiKeyServer {
    private app : FastifyInstance<Server, IncomingMessage, ServerResponse>;
    private userStorage : UserStorage;
    private apiKeyManager : ApiKeyManager;

    /**
     * Constructor
     * 
     * @param app the Fastify app instance
     * @param userStorage the user storage with user accounts
     * @param keyStorage the storage for finding API keys
     * @param options See {@link FastifyApiKeyServerOptions}
     */
    constructor(
        app: FastifyInstance<Server, IncomingMessage, ServerResponse>,
        userStorage: UserStorage, 
        keyStorage: KeyStorage, 
        options: FastifyApiKeyServerOptions = {}) {

        this.app = app;
        this.userStorage = userStorage;
        this.apiKeyManager = new ApiKeyManager(keyStorage, options);

        ////////////////
        // hooks

        // session management: validate session and CSRF cookies and 
        // populate request.user
        this.app.addHook('preHandler', 
            async (request : FastifyRequest, _reply : FastifyReply) => {
            if (request.headers.authorization) {
                try {
                    CrossauthLogger.logger.debug(j({
                        msg: "Received authorization header"}));
                    const key = 
                        await this.apiKeyManager.validateToken(
                            request.headers.authorization);
                    CrossauthLogger.logger.debug(j({
                        msg: "Valid API key",
                        hahedApiKey: ApiKeyManager.hashSignedApiKeyValue(key.value)
                    }));
                    const data = KeyStorage.decodeData(key.data);
                    request.apiKey = {...key, ...data};
                    if ("scope" in data && Array.isArray(data.scope)) {
                        let scopes = [];
                        for (let scope of data.scope) {
                            if (typeof scope == "string") scopes.push(scope);
                        }
                        request.scope = scopes;
                    }
                    if (key.userId) {
                        try {
                            const {user} = await this.userStorage.getUserById(key.userId);
                            request.user = user;
                            request.authType = "apiKey";
                            CrossauthLogger.logger.debug(j({msg: "API key is for user", userId: user.id, user: user.username, hahedApiKey: ApiKeyManager.hashSignedApiKeyValue(key.value)}));
                        } catch (e2) {
                            CrossauthLogger.logger.error(j({msg: "API key has invalid user", userId: key.userId,  hashedApiKey: ApiKeyManager.hashSignedApiKeyValue(key.value)}));
                            CrossauthLogger.logger.debug(j({err: e2}));
                        }
                    }
                } catch (e) {
                    CrossauthLogger.logger.error(j({msg: "Invalid authorization header received", header: request.headers.authorization}));
                    CrossauthLogger.logger.debug(j({err: e}));
                }

            }
        });

    }
};

