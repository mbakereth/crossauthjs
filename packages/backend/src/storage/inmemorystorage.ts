// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
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
    username_normalized? : string,
    email_normalized? : string,
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
     * @param options @see {@link InMemoryUserStorageOptions}
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

        user.username_normalized = UserStorage.normalize(user.username);
        if (user.username_normalized in this.usersByUsername) {
            throw new CrossauthError(ErrorCode.UserExists);
        }
        if ("email" in user && user.email) {
            user.email_normalized = UserStorage.normalize(user.email);
            if (user.email_normalized in this.getUserByEmail) {
                throw new CrossauthError(ErrorCode.UserExists);
            }

        }

        const userToStore = {id: user.username, ...user}
        this.usersByUsername[user.username_normalized] = userToStore;
        this.secretsByUsername[user.username_normalized] = secrets??{};
        if ("email" in user && user.email) this.usersByEmail[user.email_normalized] = userToStore;
        if ("email" in user && user.email) this.secretsByEmail[user.email_normalized] = secrets??{};

        return {id: user.username, ...user};
    }

    /**
     * Returns a {@link User }and {@link UserSecrets } instance matching the given username, or throws an Exception.
     * 
     * @param username the username to look up
     * @returns a {@link User } and {@link UserSecrets }instance
     * @throws {@link @crossauth/common!CrossauthError } with {@link @crossauth/common!ErrorCode } set to either `UserNotExist`.
     */
    async getUserByUsername(
        username : string, 
        options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}> {
        const username_normalized = UserStorage.normalize(username);
        if (username_normalized in this.usersByUsername) {

            const user = this.usersByUsername[username_normalized];
            if (!user) throw new CrossauthError(ErrorCode.UserNotExist);
            if (options?.skipActiveCheck!=true && user["state"]==UserState.passwordChangeNeeded) {
                CrossauthLogger.logger.debug(j({msg: "Password change required"}));
                throw new CrossauthError(ErrorCode.PasswordChangeNeeded);
            }
            if (options?.skipActiveCheck!=true && (user["state"]==UserState.passwordResetNeeded  || user["state"]==UserState.passwordAndFactor2ResetNeeded)) {
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
            const secrets = this.secretsByUsername[username_normalized];
            return {user: {...user}, secrets: {userid: user.id, ...secrets}};
        }

        CrossauthLogger.logger.debug(j({msg: "User does not exist"}));
        throw new CrossauthError(ErrorCode.UserNotExist);
    }

    /**
     * Returns a {@link User } and {@link UserSecrets } instance matching the given email address, or throws an Exception.
     * 
     * @param email the emaila ddress to look up
     * @returns a {@link User } and {@link UserSecrets } instance, ie including the password hash.
     * @throws {@link @crossauth/common!CrossauthError } with {@link @crossauth/common!ErrorCode } set to either `UserNotExist`.
     */
    async getUserByEmail(email : string, 
        options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}> {
        const email_normalized = UserStorage.normalize(email);
        if (email_normalized in this.usersByEmail) {

            const user = this.usersByEmail[email_normalized];
            if (!user) throw new CrossauthError(ErrorCode.UserNotExist);
            if (options?.skipEmailVerifiedCheck!=true && user['state'] == "awaitingemailverification") {
                CrossauthLogger.logger.debug(j({msg: "User email not verified"}));
                throw new CrossauthError(ErrorCode.EmailNotVerified);
            }
            if (options?.skipActiveCheck!=true && user['state'] != "active") {
                CrossauthLogger.logger.debug(j({msg: "User is deactivated"}));
                throw new CrossauthError(ErrorCode.UserNotActive);
            }
            const secrets = this.secretsByEmail[email_normalized];
            return {user: {...user}, secrets: {userid: user.id, ...secrets}};
        }

        CrossauthLogger.logger.debug(j({msg: "User does not exist"}));
        throw new CrossauthError(ErrorCode.UserNotExist);
    }

    /**
     * Same as {@link getUserByUsername } - userid is the username in this model,
     * @param id the user ID to match 
     * @returns a {@link @crossauth/common!User} and 
     *          {@link @crossauth/common!UserSecrets}instance, ie including 
     *          the password hash.
     * @throws {@link @crossauth/common!CrossauthError } with {@link @crossauth/common!ErrorCode } set to either `UserNotExist` or `Connection`.
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
            newUser.username_normalized = UserStorage.normalize(newUser.username);
        } else if ("id" in newUser && newUser.id) {
            newUser.username_normalized = UserStorage.normalize(String(newUser.id));
        }
        if ("email" in newUser && newUser.email) {
            newUser.email_normalized = UserStorage.normalize(newUser.email);

        }
        if (newUser.username_normalized && newUser.username_normalized in this.usersByUsername) {
            for (let field in newUser) {
                this.usersByUsername[newUser.username_normalized][field] = newUser[field];
            }
            if (secrets) {
                this.secretsByUsername[newUser.username_normalized] = {
                    ...this.secretsByUsername[newUser.username_normalized],
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
            const email_normalized = UserStorage.normalize(String(user.email));
            if (email_normalized in this.usersByEmail) {
                delete this.usersByEmail[email_normalized];
                delete this.secretsByEmail[email_normalized];
            }
        }
    }
    
    /**
     * Deletes the given user
     * @param id id of user to delete
     */
    async deleteUserById(id: string|number): Promise<void> {
        return await this.deleteUserByUsername(String(id));
    }
    
    async getUsers(skip? : number, take? : number) : Promise<User[]> {
        const keys = Object.keys(this.usersByUsername).sort();
        let users : User[] = [];
        if (!skip) skip = 0;
        let last = take? take : keys.length;
        if (last >= keys.length-skip) last = keys.length-skip;
        for (let i=skip; i<last; ++i) {
            users.push(this.usersByUsername[keys[i]]);
        }

        return users;
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
     * @throws a {@link @crossauth/common!CrossauthError } instance with {@link @crossauth/common!ErrorCode} of `InvalidKey`, `UserNotExist` or `Connection`
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
     * @param userid user ID to store with the session key.  See {@link InMemoryUserStorage} for how this may differ from `username`.
     * @param keyValue the value of session key to store.
     * @param dateCreated the date/time the key was created.
     * @param expires the date/time the key expires.
     * @param extraFields these will also be stored in the key table row
     */
    async saveKey(userid : string | number | undefined, 
                      keyValue : string, dateCreated : Date, 
                      expires : Date | undefined, 
                      data? : string,
                      extraFields? : {[key : string]: any}) : Promise<void> {
        const key : Key = {
            value : keyValue,
            userid : userid,
            created: dateCreated,
            expires: expires,
            data: data,
            ...extraFields
        };
        this.keys[keyValue] = key;
        if (userid) {
            if (!(userid in this.keysByUserId)) {
                this.keysByUserId[userid] = [key]
            } else {
                this.keysByUserId[userid].push(key);
            }
        } else {
            this.nonUserKeys.push(key);

        }
    }

    /**
     * 
     * @param keyValue the value of key to delete
     */
    async deleteKey(keyValue : string) : Promise<void> {
        if (keyValue in this.keys) {
            const key = this.keys[keyValue];
            if (key.userid) {
                delete this.keysByUserId[key.userid];
            } else {
                this.nonUserKeys = this.nonUserKeys.filter((v) => v.value != keyValue);
            }
            delete this.keys[keyValue];
        }
    }

    /**
     * Deletes all keys from storage for the given user ID
     * 
     * @param userid : user ID to delete keys for
     */
    async deleteAllForUser(userid : string | number | undefined | null, prefix: string, except : string|undefined = undefined) : Promise<void> {
        for (const key in this.keys) {
            if (this.keys[key].userid == userid && (!except || key != except) && key.startsWith(prefix)) {
                delete  this.keys[key];
            } 
        }
        if (userid) {
            if (userid in this.keysByUserId) delete this.keysByUserId[userid];
        } else {
            this.nonUserKeys = [];
        }
    }

    async getAllForUser(userid : string|number|undefined) : Promise<Key[]> {
        if (!userid) return this.nonUserKeys;
        if (userid in this.keysByUserId) return this.keysByUserId[userid];
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

        for (let userid in this.keysByUserId) {
            const thisKeys = this.keysByUserId[userid];
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
                    this.keysByUserId[userid] = this.keysByUserId[userid].splice(idx, 1);
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
        return await this.updateManyData(keyName, [{dataName, value}]);
    }

    /**
     * See {@link KeyStorage}.
     */
    async updateManyData(keyName : string, dataArray: {dataName: string, value: any|undefined}[]) : Promise<void> {
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
        for (let item of dataArray) {
            let ret = this.updateDataInternal(data, item.dataName, item.value);
            if (ret) key.data = JSON.stringify(data);
            else throw new CrossauthError(ErrorCode.BadRequest, `parents of ${item.dataName} not found in key data`)    
        }
    }
    

    /**
     * See {@link KeyStorage}.
     */
    async deleteData(keyName : string, dataName: string) : Promise<void> {
        const key = await this.getKey(keyName);
        let data : {[key:string] : any};
        if (!key.data || key.data == "") {
            return;
        } else {
            try {
                data = JSON.parse(key.data);
            } catch (e) {
                CrossauthLogger.logger.debug(j({err: e}));
                throw new CrossauthError(ErrorCode.DataFormat);
            }
        }
        let changed = this.deleteDataInternal(data, dataName);
        if (changed) key.data = JSON.stringify(data);
    }
}

/**
 * Implementation of {@link KeyStorage } where keys stored in memory.  Intended for testing.
 */
export class InMemoryOAuthClientStorage extends OAuthClientStorage {
    private clients : { [client_id : string]: OAuthClient } = {};
    private clientsByName : { [name : string]: OAuthClient[] } = {};

    /**
     * Constructor
     */
    constructor(_options : OAuthClientStorageOptions = {}) {
        super();
    }

    /**
     * Returns the matching client record or throws an exception.
     * @param client_id the client to look up in the key storage.
     * @returns the matching client record
     * @throws a {@link @crossauth/common!CrossauthError } instance with {@link @crossauth/common!ErrorCode} of `InvalidKey`, `UserNotExist` or `Connection`
     */
    async getClientById(client_id : string) : Promise<OAuthClient> {
        if (this.clients && client_id in this.clients) {
            return this.clients[client_id];
        }
        CrossauthLogger.logger.debug(j({msg: "Client does not exist in client storage"}));
        let err = new CrossauthError(ErrorCode.InvalidClientId); 
        CrossauthLogger.logger.debug(j({err: err}));
        throw err;
    }

    /**
     * Returns the matching client record or throws an exception.
     * @param name the client to look up in the key storage.
     * @returns the matching client record
     * @throws a {@link @crossauth/common!CrossauthError } instance with {@link @crossauth/common!ErrorCode} of `InvalidKey`, `UserNotExist` or `Connection`
     */
    async getClientByName(name : string, userid? : string|number|null) : Promise<OAuthClient[]> {
        if (this.clientsByName && name in this.clientsByName) {
            const clients = this.clientsByName[name];
            if (userid == undefined && !(userid === null)) return clients;
            const ret : OAuthClient[] = [];
            for (let client of clients) {
                if (client.userid === userid) ret.push(client);
            }
            return ret;
        }
        return [];
    }

    /**
     * Saves a client in the client table.
     * 
     * @param client the client to save.
     */
    async createClient(client : OAuthClient) : Promise<OAuthClient> {
        if (!("userid" in client )) client.userid = null;
        if (!(client.client_name in this.clientsByName)) {
            this.clientsByName[client.client_name] = [];
        }
        this.clientsByName[client.client_name].push(client);
        return this.clients[client.client_id] = client;
    }

    /**
     * 
     * @param client_id the client to delete
     */
    async deleteClient(client_id : string) : Promise<void> {
        if (client_id in this.clients) {
            const name = this.clients[client_id].client_name;
            if (name in this.clientsByName) {
                let ar = this.clientsByName[name];
                for (let i=0; i<ar.length; ++i) {
                    if (ar[i].client_id == client_id) {
                        ar.splice(i, 1);
                        break;
                    }
                }
            }
            delete this.clients[client_id];
        }
    }

    /**
     * If the given client exists in the database, update it with the passed values.  
     * 
     * @param client the fields to update.  This must include `client_id` for search purposes, but this field is not updated.
     * @throws {@link @crossauth/common!CrossauthError} with `InvalidClientId` if the client id doesn't exist}
     */
    async updateClient(client : Partial<OAuthClient>) : Promise<void> {
        if (client.client_id && client.client_id in this.clients) {
            const oldClient = this.clients[client.client_id];
            this.clients[client.client_id] = {
                ...oldClient,
                ...client, 
            }
        }
    }

    async getClients(skip? : number, take? : number, userid? : string|number|null) : Promise<OAuthClient[]> {
        const keys = Object.keys(this.clients).sort();
        let clients : OAuthClient[] = [];
        if (!skip) skip = 0;
        let last = take? take : keys.length;
        if (last >= keys.length-skip) last = keys.length-skip;
        for (let i=skip; i<last; ++i) {
            if (userid === null) {
                if (this.clients[keys[i]].userid == null) clients.push(this.clients[keys[i]]);
            } else if (userid != undefined && userid !== null) {
                if (this.clients[keys[i]].userid == userid) clients.push(this.clients[keys[i]]);

            } else {
                clients.push(this.clients[keys[i]]);
            }
        }

        return clients;
    }
}

/**
 * Implementation of {@link KeyStorage } where keys stored in memory.  Intended for testing.
 */
export class InMemoryOAuthAuthorizationStorage extends OAuthAuthorizationStorage {
    private byClientAndUser : { [client_id : string]: {[userid : string] : string[]} } = {};
    private byClient : { [client_id : string]: string[] } = {};

    /**
     * Constructor
     */
    constructor(_options : OAuthAuthorizationStorageOptions = {}) {
        super();
    }

    async getAuthorizations(client_id : string, userid : string|number|undefined) : Promise<string[]> {
        if (userid) {
            if (client_id in this.byClientAndUser) {
                const byClient = this.byClientAndUser[client_id];
                if (userid in byClient) return byClient[userid];
            }
        } else {
            if (client_id in this.byClient) return this.byClient[client_id];
        }
        return [];
    }

    /**
     * Saves a client in the client table.
     * 
     * @param client_id the client to save.
     * @param userid the user Id to associate with the client.  Undefined means
     *        not associated with a user
     * @param scopes the scopes that have been authorized for the client
     */
    async updateAuthorizations(client_id: string,
        userid: string | number | null,
        scopes: string[]) : Promise<void> {
        if (userid) {
            if (!(client_id in this.byClientAndUser)) this.byClientAndUser[client_id] = {};
            const byClient = this.byClientAndUser[client_id];
            byClient[userid] = [...scopes];
        } else {
            this.byClient[client_id] = [...scopes];
        }
    }
}
