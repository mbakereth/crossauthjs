import type { ApiKey } from '@crossauth/common';
import { KeyStorage } from './storage.ts';
import { setParameter, ParamType } from './utils.ts';
import { Hasher } from './hasher';
import { ErrorCode, CrossauthError } from '@crossauth/common';

export interface ApiKeyManagerOptions {

    /** Length in bytes of the randomly-created key (before Base64 encoding and signature) */
    keyLength? : number,

    /** Server secret.  Needed for emailing tokens and for csrf tokens */
    secret? : string;
}

export class ApiKeyManager {
    private apiKeyStorage : KeyStorage;
    private keyLength : number = 16;
    private secret : string = "";

    constructor(apiKeyStorage: KeyStorage, options : ApiKeyManagerOptions = {}) {
        this.apiKeyStorage = apiKeyStorage;

        setParameter("secret", ParamType.String, this, options, "SECRET", true);
        setParameter("keyLength", ParamType.String, this, options, "APIKEY_LENGTH");
    }

    async createKey(name : string, userId : string|number|undefined, data? : {[key:string]: any}, expiry? : number,
        extraFields?: {[key:string]: any}) : Promise<ApiKey> {
        const value = Hasher.randomValue(this.keyLength);
        const created = new Date();
        const expires = expiry ? new Date(created.getTime()+expiry*1000) : undefined;
        const hashedKey = ApiKeyManager.hashApiKeyValue(value);
        const key = {
            name : name,
            value : value,
            userId : userId,
            data : KeyStorage.encodeData(data),
            expires : expires,
            created : created,
            ...extraFields,
        }
        await this.apiKeyStorage.saveKey(
            userId, 
            hashedKey, 
            created, 
            expires, 
            key.data, 
            {name: name, ...extraFields});
        return key;
    }

    static hashApiKeyValue(unsignedValue : string) {
        return Hasher.hash(unsignedValue);
    }

    static hashSignedApiKeyValue(unsignedValue : string) {
        return Hasher.hash(unsignedValue.split(".")[0]);
    }

    unsignApiKeyValue(signedValue : string) : string {
        return Hasher.unsign(signedValue, this.secret).v;
    }

    signApiKeyValue(unsignedValue : string) : string {
        return Hasher.sign({v: unsignedValue}, this.secret);

    }

    createHeader(unsignedValue : string) {
        return "Bearer " + this.signApiKeyValue(unsignedValue);
    }

    async getKey(signedValue : string) : Promise<ApiKey> {
        const unsignedValue = this.unsignApiKeyValue(signedValue);
        const hashedValue = ApiKeyManager.hashApiKeyValue(unsignedValue);
        const key = await this.apiKeyStorage.getKey(hashedValue);
        if (!("name" in key)) throw new CrossauthError(ErrorCode.InvalidKey, "Not a valid API key");
        return {...key, name: key.name};
    }

    async getKeyFromHeaderValue(headerValue : string) : Promise<ApiKey> {
        const parts = headerValue.split(" ");
        if (parts.length != 2 || parts[0].toLowerCase() != "bearer") {
            throw new CrossauthError(ErrorCode.InvalidKey, "Not a bearer token");
        }
        return await this.getKey(parts[1]);
    }

}