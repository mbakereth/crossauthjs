// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import type { ApiKey } from '@crossauth/common';
import { KeyPrefix } from '@crossauth/common';
import { KeyStorage } from './storage.ts';
import { setParameter, ParamType } from './utils.ts';
import { Crypto } from './crypto.ts';
import { ErrorCode, CrossauthError } from '@crossauth/common';

/**
 * Options for {@link ApiKeyManager}.
 */
export interface ApiKeyManagerOptions {

    /** Length in bytes of the randomly-created key (before Base64 encoding and signature) */
    keyLength? : number,

    /** Server secret.  Needed for emailing tokens and for csrf tokens */
    secret? : string;

    /** The prefix to add to the hashed key in storage.  Defaults to 
     * {@link @crossauth/common!KeyPrefix}.apiKey
     */
    prefix? : string;

    /** The token type in the Authorization header.  Defaults to "ApiKey" */
    authScheme? : string;
}

/**
 * Manager API keys.
 * 
 * The caller must pass a {@link KeyStorage} object.  This must provide a 
 * string field called `name` in the returned {@link @crossauth/common!Key}
 * objects (in other words, the databsae table behind it must have a `name` field).
 * 
 * Api keys have three forms in their value.  The {@link @crossauth/common!Key} 
 * object's `value` field is a base64-url-encoded random number.
 * When the key is in a header, it is expected to be folled by a dot and a 
 * signature to protect against injection attacks.
 * When stored in the key storage, only the unsigned part is used (before the 
 * dot), it is hashed and preceded by
 * `prefix`.  The signature part is dropped for storage economy.  This does 
 * not compromise security so long as the
 * signature is always validated before comparing with the database.
 */
export class ApiKeyManager {
    private apiKeyStorage : KeyStorage;
    private keyLength : number = 16;
    private secret : string = "";

    /** The prefix to add to the hashed key in storage.  Defaults to 
     * {@link @crossauth/common!KeyPrefix}.apiKey
     */
    prefix = KeyPrefix.apiKey;

    /** The name of the speak in the Authorization header.  Defaults to "ApiKey" */
    authScheme? : string = "ApiKey";

    /**
     * Constructor.
     * 
     * @param apiKeyStorage storage for API keys.  In addition to the fields {@link KeyStorage} needs, the storage also needs a string field called `name`.
     * @param options options.  See {@link ApiKeyManagerOptions}
     */
    constructor(apiKeyStorage: KeyStorage, options : ApiKeyManagerOptions = {}) {
        this.apiKeyStorage = apiKeyStorage;

        setParameter("secret", ParamType.String, this, options, "SECRET", true);
        setParameter("keyLength", ParamType.String, this, options, "APIKEY_LENGTH");
        setParameter("prefix", ParamType.String, this, options, "APIKEY_PREFIX");
        setParameter("authScheme", ParamType.String, this, options, "APIKEY_AUTHSCHEME");
    }

    /**
     * Creates a new random key and returns it, unsigned.  It is also persisted in the key storage as a 
     * hash of the unsigned part prefixed with {@link prefix()}.
     * @param name a name for they key.  This is for the user to refer to it 
     *             (eg, for showing the keys the user has created or deleting 
     *             a key)
     * @param userid id for the user who owns this key, which may be undefined 
     *               for keys not associated with a user
     * @param data any application-specific extra data.
     *              If it contains an array called `scope` and this array 
     *              contains `editUser`, the api key can be used for user
     *              manipulation functions (eg change password)}
     * @param expiry expiry as a number of seconds from now
     * @param extraFields any extra fields to save in key storage, and pass 
     *                    back in the {@link @crossauth/common!Key} object.
     * @returns the new key as a {@link ApiKey} object, plus the token for the 
     *          Authorization header (with the signature appended.)
     */
    async createKey(name: string,
        userid: string | number | undefined,
        data?: { [key: string]: any },
        expiry?: number,
        extraFields?: { [key: string]: any }) : 
            Promise<{key: ApiKey, token: string}> {
        const value = Crypto.randomValue(this.keyLength);
        const created = new Date();
        const expires = expiry ? new Date(created.getTime()+expiry*1000) : undefined;
        const hashedKey = ApiKeyManager.hashApiKeyValue(value);
        const key = {
            name : name,
            value : value,
            userid : userid,
            data : KeyStorage.encodeData(data),
            expires : expires,
            created : created,
            ...extraFields,
        }
        await this.apiKeyStorage.saveKey(
            userid, 
            this.prefix+hashedKey, 
            created, 
            expires, 
            key.data, 
            {name: name, ...extraFields});
        const token = this.signApiKeyValue(value);

        return {key, token};
    }

    private static hashApiKeyValue(unsignedValue : string) {
        return Crypto.hash(unsignedValue);
    }

    /**
     * Returns the hash of the bearer value from the Authorization header.
     * 
     * This has little practical value other than for reporting.  Unhashed
     * tokens are never reported.
     * @param unsignedValue the part of the Authorization header after "Berear ".
     * @returns a hash of the value (without the prefix).
     */
    static hashSignedApiKeyValue(unsignedValue : string) {
        return Crypto.hash(unsignedValue.split(".")[0]);
    }

    private unsignApiKeyValue(signedValue : string) : string {
        return Crypto.unsign(signedValue, this.secret).v;
    }

    private signApiKeyValue(unsignedValue : string) : string {
        return Crypto.sign({v: unsignedValue}, this.secret);

    }

    private async getKey(signedValue : string) : Promise<ApiKey> {
        if (this.authScheme!="" && signedValue.startsWith(this.authScheme+" ")) {
            const regex = new RegExp(`^${this.authScheme} `);
            signedValue = signedValue.replace(regex, "");
        }
        const unsignedValue = this.unsignApiKeyValue(signedValue);
        const hashedValue = ApiKeyManager.hashApiKeyValue(unsignedValue);
        const key = await this.apiKeyStorage.getKey(this.prefix+hashedValue);
        if (!("name" in key)) throw new CrossauthError(ErrorCode.InvalidKey, "Not a valid API key");
        return {...key, name: key.name};
    }

    /**
     * Returns the {@link ApiKey} if the token is valid, throws an exception otherwise.
     * @param headerValue the token from the Authorization header (after the "Bearer ").
     * @returns The {@link ApiKey} object
     * @throws {@link @crossauth/common!CrossauthError} with code `InvalidKey`
     */
    async validateToken(headerValue : string) : Promise<ApiKey> {
        const parts = headerValue.split(" ");
        if (parts.length != 2 || parts[0] != this.authScheme) {
            throw new CrossauthError(ErrorCode.InvalidKey, `Not a ${this.authScheme} token`);
        }
        return await this.getKey(parts[1]);
    }
}
