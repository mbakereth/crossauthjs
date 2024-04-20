import {
    OAuthClientStorage
} from '../storage';
import { setParameter, ParamType } from '../utils';
import { Crypto } from '../crypto';
import { OAuthFlows } from '@crossauth/common';
import type {
    OAuthClient,
} from '@crossauth/common';
import {
    CrossauthError,
    ErrorCode,
    CrossauthLogger,
    j } from '@crossauth/common';

const CLIENT_ID_LENGTH = 16;
const CLIENT_SECRET_LENGTH = 32;

/**
 * Options for {@link OAuthClientManager}
 */
export interface OAuthClientManagerOptions {
    /** PBKDF2 HMAC for hashing client secret */
    oauthPbkdf2Digest? : string;

    /** PBKDF2 iterations for hashing client secret */
    oauthPbkdf2Iterations? : number;

    /** PBKDF2 key length for hashing client secret */
    oauthPbkdf2KeyLength? : number;

    clientStorage? : OAuthClientStorage;
}

/**
 * Functionality for creating and updating clients, and validating 
 * redirect URIs.
 */
export class OAuthClientManager {
    private oauthPbkdf2Digest = "sha256";
    private oauthPbkdf2Iterations = 40000;
    private oauthPbkdf2KeyLength = 32;
    private clientStorage : OAuthClientStorage;

    /**
     * Constructor
     * @param options See  {@link OAuthClientManagerOptions}
     */
    constructor(options: OAuthClientManagerOptions = {}) {
        if (!options.clientStorage) throw new CrossauthError(ErrorCode.Configuration,
            "Must specify clientStorage when adding a client manager");
        this.clientStorage = options.clientStorage;

        setParameter("oauthPbkdf2Digest", ParamType.String, this, options, "OAUTH_PBKDF2_DIGEST");
        setParameter("oauthPbkdf2KeyLength", ParamType.String, this, options, "OAUTH_PBKDF2_KEYLENGTH");
        setParameter("requireRedirectUriRegistration", ParamType.Boolean, this, options, "OAUTH_REQUIRE_REDIRECT_URI_REGISTRATION");
    }

    /**
     * Creates a client and puts it in the storage
     * @param clientName friendly name for the client
     * @param redirectUri set of valid redirect URIs (may be empty)
     * @param validFlow set of OAuth flows this client is allowed to initiate
     *        (may be empty)
     * @param confidential if true, client can keep secrets confidential
     *        and a clientSecret will be created
     * @param userId user id who owns the client, or undefined for no user
     * @returns the new client.  `clientId` and `clientSecret` (plaintext)
     *          will be populated.
     */
    async createClient(clientName: string,
        redirectUri: string[],
        validFlow?: string[],
        confidential = true,
        userId? : string|number) : Promise<OAuthClient> {
        const clientId = OAuthClientManager.randomClientId();
        let clientSecret : string|undefined = undefined;
        if (confidential) {
            const plaintext = OAuthClientManager.randomClientSecret();
            clientSecret = await Crypto.passwordHash(plaintext, {
                encode: true,
                iterations: this.oauthPbkdf2Iterations,
                keyLen: this.oauthPbkdf2KeyLength,
                digest: this.oauthPbkdf2Digest,
            });
        }
        redirectUri.forEach((uri) => {
            OAuthClientManager.validateUri(uri);
        });
        if (!validFlow) {
            validFlow = OAuthFlows.allFlows();
        }
        const client = {
            clientId: clientId,
            clientSecret: clientSecret,
            clientName : clientName,
            redirectUri : redirectUri,
            confidential: confidential,
            validFlow: validFlow,
            userId: userId,
        }
        return await this.clientStorage.createClient(client);
    }

    /**
     * Updates a client
     * @param clientId the clientId to update.
     * @param client the fields to update.  Anything not in here (or undefined)
     *        will remain unchanged
     * @param resetSecret if true, generate a new client secret
     * @returns the updated client.  If it has a secret. it will be in
     *          `clientSecret` as plaintext.
     */
    async updateClient(clientId: string,
        client: Partial<OAuthClient>,
        resetSecret : boolean = false) : Promise<{client: OAuthClient, newSecret: boolean}> {
        const oldClient = await this.clientStorage.getClientById(clientId);
        let newSecret = false;
        let plaintext : string|undefined = undefined;
        if ((client.confidential === true && !oldClient.confidential) ||
            (client.confidential === true && resetSecret)) {
            plaintext = OAuthClientManager.randomClientSecret();
            client.clientSecret = await Crypto.passwordHash(plaintext, {
                encode: true,
                iterations: this.oauthPbkdf2Iterations,
                keyLen: this.oauthPbkdf2KeyLength,
                digest: this.oauthPbkdf2Digest,
            });
            newSecret = true;
        }
        else if (client.confidential === false) {
            client.clientSecret = null;
        }
        if (client.redirectUri) {
            client.redirectUri.forEach((uri) => {
                OAuthClientManager.validateUri(uri);
            });
        }
        client.clientId = clientId;
        await this.clientStorage.updateClient(client);
        const newClient = await this.clientStorage.getClientById(clientId);
        if (plaintext) newClient.clientSecret = plaintext;
        return {client: newClient, newSecret: newSecret};
    }

    /**
     * Create a random OAuth client id
     */
    static randomClientId() : string {
        return Crypto.randomValue(CLIENT_ID_LENGTH)
    }

     /**
     * Create a random OAuth client secret
     */
    static randomClientSecret() : string {
        return Crypto.randomValue(CLIENT_SECRET_LENGTH)
    }

    /** If the passed redirect URI is not in the set of valid ones,
     * throw {@link @crossauth/common!CrossauthError} with
     *  {@link @crossauth/common!CrossauthError} `BadRequest`.
     * @param uri the redirect URI to validate
     * @throws {@link @crossauth/common!CrossauthError} with
     *  {@link @crossauth/common!CrossauthError} `BadRequest`.
     */
    static validateUri(uri : string) {
        let valid = false;
        try {
            const validUri = new URL(uri);
            valid = validUri.hash.length == 0;
        } catch (e) {
            // test if its a valid relative url
            try {
                const validUri = new URL(uri);
                valid = validUri.hash.length == 0;
            } catch (e2) {
                CrossauthLogger.logger.debug(j({err: e}));
            }
        }
        if (!valid) {
            throw CrossauthError.fromOAuthError("invalid_request", 
            `Invalid redirect Uri ${uri}`);
        }
    }
}
