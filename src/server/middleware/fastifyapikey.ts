import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { Server, IncomingMessage, ServerResponse } from 'http'
import { ApiKeyManager } from '../apikey';
import type { ApiKeyManagerOptions } from '../apikey';
import { UserStorage, KeyStorage } from '../storage';
import { CrossauthLogger, j } from '../..';

/**
 * Options for {@link FastifyApiKeyServer }.
 * 
 * See {@link FastifyApiKeyServer } constructor for description of parameters
 */
export interface FastifyApiKeyServerOptions extends ApiKeyManagerOptions {

    /** You can pass your own fastify instance or omit this, in which case Crossauth will create one */
    app? : FastifyInstance<Server, IncomingMessage, ServerResponse>,
}

const JSONHDR : [string,string] = ['Content-Type', 'application/json; charset=utf-8'];

export class FastifyApiKeyServer {
    private app : FastifyInstance<Server, IncomingMessage, ServerResponse>;
    private userStorage : UserStorage;
    private apiKeyManager : ApiKeyManager;

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

        // session management: validate session and CSRF cookies and populate request.user
        app.addHook('preHandler', async (request : FastifyRequest, _reply : FastifyReply) => {
            if (request.headers.authorization) {
                try {
                    CrossauthLogger.logger.debug(j({msg: "Received authorization header"}));
                    const key = await this.apiKeyManager.getKeyFromHeaderValue(request.headers.authorization);
                    CrossauthLogger.logger.debug(j({msg: "Valid API key", hahedApiKey: ApiKeyManager.hashSignedApiKeyValue(key.value)}));
                    request.apiKey = {...key, ...KeyStorage.decodeData(key.data)};
                    if (key.userId) {
                        try {
                            const {user} = await this.userStorage.getUserById(key.userId);
                            request.user = user;
                            CrossauthLogger.logger.debug(j({msg: "API key is for user", userId: user.id, hahedApiKey: ApiKeyManager.hashSignedApiKeyValue(key.value)}));
                        } catch (e2) {
                            CrossauthLogger.logger.error(j({msg: "API key has invalid user", userId: key.userId,  hashedApiKey: ApiKeyManager.hashApiKeyValue(request.headers.authorization)}));
                            CrossauthLogger.logger.debug(j({err: e2}));
                        }
                    }
                } catch (e) {
                    CrossauthLogger.logger.error(j({msg: "Invalid api key received", hashedApiKey: ApiKeyManager.hashApiKeyValue(request.headers.authorization)}));
                    CrossauthLogger.logger.debug(j({err: e}));
                }

            }
        });

    }
};

