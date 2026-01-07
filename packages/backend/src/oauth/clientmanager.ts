// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
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
     * @param client_name friendly name for the client
     * @param redirect_uri set of valid redirect URIs (may be empty)
     * @param valid_flow set of OAuth flows this client is allowed to initiate
     *        (may be empty)
     * @param confidential if true, client can keep secrets confidential
     *        and a client_secret will be created
     * @param userid user id who owns the client, or undefined for no user
     * @returns the new client.  `client_id` and `client_secret` (plaintext)
     *          will be populated.
     */
    async createClient(client_name: string,
        redirect_uri: string[],
        valid_flow?: string[],
        confidential = true,
        userid? : string|number) : Promise<OAuthClient> {
        const client_id = OAuthClientManager.randomClientId();
        let client_secret : string|undefined = undefined;
        let plaintext : string|undefined = undefined;
        if (confidential) {
            plaintext = OAuthClientManager.randomClientSecret();
            client_secret = await Crypto.passwordHash(plaintext, {
                encode: true,
                iterations: this.oauthPbkdf2Iterations,
                keyLen: this.oauthPbkdf2KeyLength,
                digest: this.oauthPbkdf2Digest,
            });
        }
        redirect_uri.forEach((uri) => {
            OAuthClientManager.validateUri(uri);
        });
        if (!valid_flow) {
            valid_flow = OAuthFlows.allFlows();
        }
        const client = {
            client_id: client_id,
            client_secret: client_secret,
            client_name : client_name,
            redirect_uri : redirect_uri,
            confidential: confidential,
            valid_flow: valid_flow,
            userid: userid,
        }
        let newClient : OAuthClient | undefined = undefined;
        for (let tryNum=0; tryNum<5; ++tryNum) {
            try {
                newClient = await this.clientStorage.createClient(client);
                break;
            } catch (e) {
                if (tryNum == 4) {
                    const ce = CrossauthError.asCrossauthError(e);
                    if (ce.code != ErrorCode.ClientExists) throw e;                        
                } else {
                    client.client_id = OAuthClientManager.randomClientId();
                }
            }           
        }
        if (!newClient) throw new CrossauthError(ErrorCode.ClientExists);
        if (newClient.client_secret && plaintext) newClient.client_secret = plaintext;
        return newClient;
    }

    /**
     * Updates a client
     * @param client_id the client_id to update.
     * @param client the fields to update.  Anything not in here (or undefined)
     *        will remain unchanged
     * @param resetSecret if true, generate a new client secret
     * @returns the updated client.  If it has a secret. it will be in
     *          `client_secret` as plaintext.
     */
    async updateClient(client_id: string,
        client: Partial<OAuthClient>,
        resetSecret : boolean = false) : Promise<{client: OAuthClient, newSecret: boolean}> {
        const oldClient = await this.clientStorage.getClientById(client_id);
        let newSecret = false;
        let plaintext : string|undefined = undefined;
        if ((client.confidential === true && !oldClient.confidential) ||
            (client.confidential === true && resetSecret)) {
            plaintext = OAuthClientManager.randomClientSecret();
            client.client_secret = await Crypto.passwordHash(plaintext, {
                encode: true,
                iterations: this.oauthPbkdf2Iterations,
                keyLen: this.oauthPbkdf2KeyLength,
                digest: this.oauthPbkdf2Digest,
            });
            newSecret = true;
        }
        else if (client.confidential === false) {
            client.client_secret = null;
        }
        if (client.redirect_uri) {
            client.redirect_uri.forEach((uri) => {
                OAuthClientManager.validateUri(uri);
            });
        }
        client.client_id = client_id;
        await this.clientStorage.updateClient(client);
        const newClient = await this.clientStorage.getClientById(client_id);
        if (plaintext) newClient.client_secret = plaintext;
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
