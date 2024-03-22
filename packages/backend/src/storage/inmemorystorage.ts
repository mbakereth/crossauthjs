import { UserStorage, KeyStorage, type UserStorageGetOptions, type UserStorageOptions, OAuthClientStorage, type OAuthClientStorageOptions, OAuthAuthorizationStorage, type OAuthAuthorizationStorageOptions } from '../storage';
import { type User, type UserSecrets, type Key, type UserInputFields, type UserSecretsInputFields, type OAuthClient } from '@crossauth/common';
import { CrossauthError, ErrorCode } from '@crossauth/common';
import { CrossauthLogger, j, UserState } from '@crossauth/common';

/**
 * Optional parameters for {@link InMemoryUserStorage}.
 * 
 * See {@link InMemoryUserStorage.constructor} for definitions.
 */
export interface InMemoryUserStorageOptions extends UserStorageOptions {
}

interface UserWithNormalization extends User {
    usernameNormalized? : string,
    emailNormalized? : string,
}

/**
 * Implementation of {@link UserStorage} where username and password is stored in memory.  It is really only
 * intended for testing and is not thread safe.
 * 
 * There is no separate ID field - it is set to username.
 *
 * You can optionally check if the state field is set to `awaitingemailverification` when validating users,  
*/
export class InMemoryUserStorage extends UserStorage {
    usersByUsername : { [key : string]: User } = {};
    usersByEmail : { [key : string]: User } = {};
    secretsByUsername : { [key : string]: UserSecretsInputFields } = {};
    secretsByEmail : { [key : string]: UserSecretsInputFields } = {};

    /**
     * Creates a InMemoryUserStorage object, optionally overriding defaults.
     * @param options {@see InMemoryUserStorageOptions}
    */
    constructor(options : InMemoryUserStorageOptions = {}) {
        super(options);
    }

    /**
     * Create a user
     * @param user the user to save
     * @param secrets optionally, secrets to save
     */
    async createUser(user: UserInputFields, secrets? : UserSecretsInputFields)
        : Promise<User> {

            user.usernameNormalized = UserStorage.normalize(user.username);
            if (user.usernameNormalized in this.usersByUsername) {
                throw new CrossauthError(ErrorCode.UserExists);
            }
            if ("email" in user && user.email) {
                user.emailNormalized = UserStorage.normalize(user.email);
                if (user.emailNormalized in this.getUserByEmail) {
                    throw new CrossauthError(ErrorCode.UserExists);
                }
    
            }

            const userToStore = {id: user.username, ...user}
            this.usersByUsername[user.usernameNormalized] = userToStore;
            this.secretsByUsername[user.usernameNormalized] = secrets??{};
            if ("email" in user && user.email) this.usersByEmail[user.emailNormalized] = userToStore;
            if ("email" in user && user.email) this.secretsByEmail[user.emailNormalized] = secrets??{};

        return {id: user.username, ...user};
    }

    /**
     * Returns a {@link User }and {@link UserSecrets } instance matching the given username, or throws an Exception.
     * 
     * @param username the username to look up
     * @returns a {@link User } and {@link UserSecrets }instance
     * @throws {@link @crossauth/common!CrossauthError } with {@link ErrorCode } set to either `UserNotExist`.
     */
    async getUserByUsername(
        username : string, 
        options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}> {
        const usernameNormalized = UserStorage.normalize(username);
        if (usernameNormalized in this.usersByUsername) {

            const user = this.usersByUsername[usernameNormalized];
            if (!user) throw new CrossauthError(ErrorCode.UserNotExist);
            if (options?.skipActiveCheck!=true && user["state"]==UserState.passwordChangeNeeded) {
                CrossauthLogger.logger.debug(j({msg: "Password change required"}));
                throw new CrossauthError(ErrorCode.PasswordChangeNeeded);
            }
            if (options?.skipActiveCheck!=true && user["state"]==UserState.passwordResetNeeded) {
                CrossauthLogger.logger.debug(j({msg: "Password reset required"}));
                throw new CrossauthError(ErrorCode.PasswordResetNeeded);
            }
            if (options?.skipActiveCheck!=true && user["state"]==UserState.factor2ResetNeeded) {
                CrossauthLogger.logger.debug(j({msg: "2FA reset required"}));
                throw new CrossauthError(ErrorCode.Factor2ResetNeeded);
            }
            if (options?.skipActiveCheck!=true && user["state"]==UserState.awaitingTwoFactorSetup) {
                CrossauthLogger.logger.debug(j({msg: "2FA setup is not complete"}));
                throw new CrossauthError(ErrorCode.TwoFactorIncomplete);
            }
            if (options?.skipEmailVerifiedCheck!=true && user['state'] == UserState.awaitingEmailVerification) {
                CrossauthLogger.logger.debug(j({msg: "User email not verified"}));
                throw new CrossauthError(ErrorCode.EmailNotVerified);
            }
            if (options?.skipActiveCheck!=true && user['state'] == UserState.disabled) {
                CrossauthLogger.logger.debug(j({msg: "User is deactivated"}));
                throw new CrossauthError(ErrorCode.UserNotActive);
            }
            const secrets = this.secretsByUsername[usernameNormalized];
            return {user: {...user}, secrets: {userId: user.id, ...secrets}};
        }

        CrossauthLogger.logger.debug(j({msg: "User does not exist"}));
        throw new CrossauthError(ErrorCode.UserNotExist);
    }

    /**
     * Returns a {@link User } and {@link UserSecrets } instance matching the given email address, or throws an Exception.
     * 
     * @param email the emaila ddress to look up
     * @returns a {@link User } and {@link UserSecrets } instance, ie including the password hash.
     * @throws {@link @crossauth/common!CrossauthError } with {@link ErrorCode } set to either `UserNotExist`.
     */
    async getUserByEmail(email : string, 
        options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}> {
        const emailNormalized = UserStorage.normalize(email);
        if (emailNormalized in this.usersByEmail) {

            const user = this.usersByEmail[emailNormalized];
            if (!user) throw new CrossauthError(ErrorCode.UserNotExist);
            if (options?.skipEmailVerifiedCheck!=true && user['state'] == "awaitingemailverification") {
                CrossauthLogger.logger.debug(j({msg: "User email not verified"}));
                throw new CrossauthError(ErrorCode.EmailNotVerified);
            }
            if (user['state'] != "active") {
                CrossauthLogger.logger.debug(j({msg: "User is deactivated"}));
                throw new CrossauthError(ErrorCode.UserNotActive);
            }
            const secrets = this.secretsByEmail[emailNormalized];
            return {user: {...user}, secrets: {userId: user.id, ...secrets}};
        }

        CrossauthLogger.logger.debug(j({msg: "User does not exist"}));
        throw new CrossauthError(ErrorCode.UserNotExist);
    }

    /**
     * Same as {@link getUserByUsername } - userId is the username in this model,
     * @param id the user ID to match 
     * @returns a {@link UserWithPassword } instance, ie including the password hash.
     * @throws {@link @crossauth/common!CrossauthError } with {@link ErrorCode } set to either `UserNotExist` or `Connection`.
     */
    async getUserById(id : string, 
        options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}> {
        return /*await*/ this.getUserByUsername(id, options);
    }

    /**
     * If the given session key exist in the database, update it with the passed values.  If it doesn't
     * exist, throw a CreossauthError with InvalidKey.
     * @param user the user to update.  The id to update is taken from this obkect, which must be present.  All other attributes are optional. 
     */
    async updateUser(user : Partial<User>, secrets?: Partial<UserSecrets>) : Promise<void> {
        let newUser : Partial<UserWithNormalization> = {...user};
        if ("username" in newUser && newUser.username) {
            newUser.usernameNormalized = UserStorage.normalize(newUser.username);
        } else if ("id" in newUser && newUser.id) {
            newUser.usernameNormalized = UserStorage.normalize(String(newUser.id));
        }
        if ("email" in newUser && newUser.email) {
            newUser.emailNormalized = UserStorage.normalize(newUser.email);

        }
        if (newUser.usernameNormalized && newUser.usernameNormalized in this.usersByUsername) {
            for (let field in newUser) {
                this.usersByUsername[newUser.usernameNormalized][field] = newUser[field];
            }
            if (secrets) {
                this.secretsByUsername[newUser.usernameNormalized] = {
                    ...this.secretsByUsername[newUser.usernameNormalized],
                    ...secrets,
                }
            }
        }
    }

    /**
     * Deletes the given user
     * @param username username of user to delete
     */
    async deleteUserByUsername(username: string): Promise<void> {
        const normalizedUser = UserStorage.normalize(String(username));
        if (normalizedUser in this.usersByUsername) {
            const user = this.usersByUsername[normalizedUser];
            delete this.usersByUsername[normalizedUser];
            delete this.secretsByUsername[normalizedUser];
            const emailNormalized = UserStorage.normalize(String(user.email));
            if (emailNormalized in this.usersByEmail) {
                delete this.usersByEmail[emailNormalized];
                delete this.secretsByEmail[emailNormalized];
            }
        }
    }
}

/**
 * Implementation of {@link KeyStorage } where keys stored in memory.  Intended for testing.
 */
export class InMemoryKeyStorage extends KeyStorage {
    private keys : { [key : string]: Key } = {};
    private keysByUserId : { [key : string]: Key[] } = {};
    private nonUserKeys : Key[] = [];

    /**
     * Constructor
     */
    constructor() {
        super();
    }

    /**
     * Returns the matching key recortd, with additional, or throws an exception.
     * @param key the key to look up in the key storage.
     * @returns the matching Key record
     * @throws a {@link @crossauth/common!CrossauthError } instance with {@link ErrorCode} of `InvalidKey`, `UserNotExist` or `Connection`
     */
    async getKey(key : string) : Promise<Key> {
        if (this.keys && key in this.keys) {
            return this.keys[key];
        }
        CrossauthLogger.logger.debug(j({msg: "Key does not exist in key storage"}));
        let err = new CrossauthError(ErrorCode.InvalidKey); 
        CrossauthLogger.logger.debug(j({err: err}));
        throw err;
    }

    /**
     * Saves a session key in the session table.
     * 
     * @param userId user ID to store with the session key.  See {@link InMemoryUserStorage} for how this may differ from `username`.
     * @param key the session key to store.
     * @param dateCreated the date/time the key was created.
     * @param expires the date/time the key expires.
     * @param extraFields these will also be stored in the key table row
     */
    async saveKey(userId : string | number | undefined, 
                      keyValue : string, dateCreated : Date, 
                      expires : Date | undefined, 
                      data? : string,
                      extraFields? : {[key : string]: any}) : Promise<void> {
        const key : Key = {
            value : keyValue,
            userId : userId,
            created: dateCreated,
            expires: expires,
            data: data,
            ...extraFields
        };
        this.keys[keyValue] = key;
        if (userId) {
            if (!(userId in this.keysByUserId)) {
                this.keysByUserId[userId] = [key]
            } else {
                this.keysByUserId[userId].push(key);
            }
        } else {
            this.nonUserKeys.push(key);

        }
    }

    /**
     * 
     * @param key the key to delete
     */
    async deleteKey(keyValue : string) : Promise<void> {
        if (keyValue in this.keys) {
            const key = this.keys[keyValue];
            if (key.userId) {
                delete this.keysByUserId[key.userId];
            } else {
                this.nonUserKeys = this.nonUserKeys.filter((v) => v.value != keyValue);
            }
            delete this.keys[keyValue];
        }
    }

    /**
     * Deletes all keys from storage for the given user ID
     * 
     * @param userId : user ID to delete keys for
     */
    async deleteAllForUser(userId : string | number | undefined | null, prefix: string, except : string|undefined = undefined) : Promise<void> {
        for (const key in this.keys) {
            if (this.keys[key].userId == userId && (!except || key != except) && key.startsWith(prefix)) {
                delete  this.keys[key];
            } 
        }
        if (userId) {
            if (userId in this.keysByUserId) delete this.keysByUserId[userId];
        } else {
            this.nonUserKeys = [];
        }
    }

    async getAllForUser(userId : string|number|undefined) : Promise<Key[]> {
        if (!userId) return this.nonUserKeys;
        if (userId in this.keysByUserId) return this.keysByUserId[userId];
        return [];
    }

    async deleteMatching(key : Partial<Key>) : Promise<void> {
        for (let keyValue in this.keys) {
            let matches = true;
            const thisKey = this.keys[keyValue];
            for (let entry in key) {
                if (entry in thisKey && thisKey[entry] != key[entry]) {
                    matches = false;
                    break;
                }
            }
            if (matches) {
                delete this.keys[keyValue];
            }
        }

        for (let userId in this.keysByUserId) {
            const thisKeys = this.keysByUserId[userId];
            for (let i=0; i<thisKeys.length; ++i) {
                let matches = true;
                let idx = 0;
                const thisKey = thisKeys[i];
                for (let entry in key) {
                    if (entry in thisKey && thisKey[entry] != key[entry]) {
                        matches = false;
                        idx = i;
                        break;
                    }
                }
                if (matches) {
                    this.keysByUserId[userId] = this.keysByUserId[userId].splice(idx, 1);
                }
            }
        }

        for (let i=0; i<this.nonUserKeys.length; ++i) {
            let matches = true;
            let idx = 0;
            const thisKey = this.nonUserKeys[i];
            for (let entry in key) {
                if (entry in thisKey && thisKey[entry] != key[entry]) {
                    matches = false;
                    idx = i;
                    break;
                }
            }
            if (matches) {
                this.nonUserKeys = this.nonUserKeys.splice(idx, 1);
            }
        }
    }


    /**
     * If the given session key exist in the database, update it with the passed values.  If it doesn't
     * exist, throw a CreossauthError with InvalidKey.
     * @param key 
     */
    async updateKey(key : Partial<Key>) : Promise<void> {
        if (key.value && key.value in this.keys) {
            let value : string = key.value??"";
            for (let field in key) {
                this.keys[value][field] = key[field];
            }
        }
    }

    /**
     * See {@link KeyStorage}.
     */
    async updateData(keyName : string, dataName: string, value: any|undefined) : Promise<void> {
        const key = await this.getKey(keyName);
        let data : {[key:string] : any};
        if (!key.data || key.data == "") {
            data = {}
        } else {
            try {
                data = JSON.parse(key.data);
            } catch (e) {
                CrossauthLogger.logger.debug(j({err: e}));
                throw new CrossauthError(ErrorCode.DataFormat);
            }
        }
        data[dataName] = value;
        key.data = JSON.stringify(data);
    }

}

/**
 * Implementation of {@link KeyStorage } where keys stored in memory.  Intended for testing.
 */
export class InMemoryOAuthClientStorage extends OAuthClientStorage {
    private clients : { [clientId : string]: OAuthClient } = {};

    /**
     * Constructor
     */
    constructor(_options : OAuthClientStorageOptions = {}) {
        super();
    }

    /**
     * Returns the matching key recortd, with additional, or throws an exception.
     * @param key the key to look up in the key storage.
     * @returns the matching Key record
     * @throws a {@link @crossauth/common!CrossauthError } instance with {@link ErrorCode} of `InvalidKey`, `UserNotExist` or `Connection`
     */
    async getClient(clientId : string) : Promise<OAuthClient> {
        if (this.clients && clientId in this.clients) {
            return this.clients[clientId];
        }
        CrossauthLogger.logger.debug(j({msg: "Client does not exist in client storage"}));
        let err = new CrossauthError(ErrorCode.InvalidClientId); 
        CrossauthLogger.logger.debug(j({err: err}));
        throw err;
    }

    /**
     * Saves a client in the client table.
     * 
     * @param client the client to save.
     */
    async createClient(client : OAuthClient) : Promise<OAuthClient> {
        return this.clients[client.clientId] = client;
    }

    /**
     * 
     * @param clinetId the client to delete
     */
    async deleteClient(clientId : string) : Promise<void> {
        if (clientId in this.clients) {
            delete this.clients[clientId];
        }
    }

    /**
     * If the given client exists in the database, update it with the passed values.  
     * 
     * @param client the fields to update.  This must include `clientId` for search purposes, but this field is not updated.
     * @throws {@link @crossauth/common!Crossauth} with `InvalidClientId` if the client id doesn't exist}
     */
    async updateClient(client : Partial<OAuthClient>) : Promise<void> {
        if (client.clientId && client.clientId in this.clients) {
            const oldClient = this.clients[client.clientId];
            this.clients[client.clientId] = {
                ...client, 
                clientName: client.clientName??oldClient.clientName, 
                clientId: oldClient.clientId, 
                redirectUri: client.redirectUri??oldClient.redirectUri,
                validFlow: client.validFlow??oldClient.validFlow,
                confidential: client.confidential??oldClient.confidential,
            }
        }
    }

}

/**
 * Implementation of {@link KeyStorage } where keys stored in memory.  Intended for testing.
 */
export class InMemoryOAuthAuthorizationStorage extends OAuthAuthorizationStorage {
    private byClientAndUser : { [clientId : string]: {[userId : string] : string[]} } = {};
    private byClient : { [clientId : string]: string[] } = {};

    /**
     * Constructor
     */
    constructor(_options : OAuthAuthorizationStorageOptions = {}) {
        super();
    }

    async getAuthorizations(clientId : string, userId : string|number|undefined) : Promise<string[]> {
        if (userId) {
            if (clientId in this.byClientAndUser) {
                const byClient = this.byClientAndUser[clientId];
                if (userId in byClient) return byClient[userId];
            }
        } else {
            if (clientId in this.byClient) return this.byClient[clientId];
        }
        return [];
    }

    /**
     * Saves a client in the client table.
     * 
     * @param client the client to save.
     */
    async updateAuthorizations(clientId : string, userId : string|number|undefined, scopes : string[]) : Promise<void> {
        if (userId) {
            if (!(clientId in this.byClientAndUser)) this.byClientAndUser[clientId] = {};
            const byClient = this.byClientAndUser[clientId];
            byClient[userId] = [...scopes];
        } else {
            this.byClient[clientId] = [...scopes];
        }
    }
}
