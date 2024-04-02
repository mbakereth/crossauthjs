import {
    OAuthClientStorage
} from '../storage';
import { setParameter, ParamType } from '../utils';
import { Hasher } from '../hasher';
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

export interface OAuthClientManagerOptions {
    /** PBKDF2 HMAC for hashing client secret */
    oauthPbkdf2Digest? : string;

    /** PBKDF2 iterations for hashing client secret */
    oauthPbkdf2Iterations? : number;

    /** PBKDF2 key length for hashing client secret */
    oauthPbkdf2KeyLength? : number;

    clientStorage? : OAuthClientStorage;
}

export class OAuthClientManager {
    private oauthPbkdf2Digest = "sha256";
    private oauthPbkdf2Iterations = 40000;
    private oauthPbkdf2KeyLength = 32;
    private clientStorage : OAuthClientStorage;

    constructor(options: OAuthClientManagerOptions = {}) {
        if (!options.clientStorage) throw new CrossauthError(ErrorCode.Configuration,
            "Must specify clientStorage when adding a client manager");
        this.clientStorage = options.clientStorage;

        setParameter("oauthPbkdf2Digest", ParamType.String, this, options, "OAUTH_PBKDF2_DIGEST");
        setParameter("oauthPbkdf2KeyLength", ParamType.String, this, options, "OAUTH_PBKDF2_KEYLENGTH");
        setParameter("requireRedirectUriRegistration", ParamType.Boolean, this, options, "OAUTH_REQUIRE_REDIRECT_URI_REGISTRATION");
    }

    async createClient(clientName: string,
        redirectUri: string[],
        validFlow?: string[],
        confidential = true,
        userId? : string|number) : Promise<OAuthClient> {
        const clientId = OAuthClientManager.randomClientId();
        let clientSecret : string|undefined = undefined;
        if (confidential) {
            const plaintext = OAuthClientManager.randomClientSecret();
            clientSecret = await Hasher.passwordHash(plaintext, {
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
     * Create a random OAuth client id
     */
    static randomClientId() : string {
        return Hasher.randomValue(CLIENT_ID_LENGTH)
    }

     /**
     * Create a random OAuth client secret
     */
    static randomClientSecret() : string {
        return Hasher.randomValue(CLIENT_SECRET_LENGTH)
    }

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
