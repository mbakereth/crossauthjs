import { UserStorage, KeyStorage, UserStorageGetOptions, UserStorageOptions } from '../storage';
import { User, UserSecrets, Key, UserInputFields, UserSecretsInputFields } from '../../interfaces';
import { CrossauthError, ErrorCode } from '../../error';
import { CrossauthLogger, j } from '../..';

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
     * @param enableEmailVerification if set to `true`, a user will only be returned as valid if the `state` field is not `awaitingemailverification`.  See explaination above.
    */
    constructor(options : InMemoryUserStorageOptions = {}) {
        super(options);
    }

    /**
     * Create a user
     * @param username 
     * @param password 
     * @param extraFields 
     */
    async createUser(user: UserInputFields, secrets? : UserSecretsInputFields)
        : Promise<User> {

            user.usernameNormalized = UserStorage.normalize(user.username);
            if ("email" in user && user.email) {
                user.emailNormalized = UserStorage.normalize(user.email);
            }

            const userToStore = {id: user.username, ...user}
            this.usersByUsername[user.usernameNormalized] = userToStore;
            this.secretsByUsername[user.usernameNormalized] = secrets||{};
            if ("email" in user && user.email) this.usersByEmail[user.emailNormalized] = userToStore;
            if ("email" in user && user.email) this.secretsByEmail[user.emailNormalized] = secrets||{};

        return {id: user.username, ...user};
    }

    /**
     * Returns a {@link User }and {@link UserSecrets } instance matching the given username, or throws an Exception.
     * 
     * @param username the username to look up
     * @returns a {@link User } and {@link UserSecrets }instance
     * @throws {@link index!CrossauthError } with {@link ErrorCode } set to either `UserNotExist`.
     */
    async getUserByUsername(
        username : string, 
        options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}> {
        const usernameNormalized = UserStorage.normalize(username);
        if (usernameNormalized in this.usersByUsername) {

            const user = this.usersByUsername[usernameNormalized];
            if (!user) throw new CrossauthError(ErrorCode.UserNotExist);
            if (options?.skipActiveCheck!=true && user["state"]=="passwordreset") {
                CrossauthLogger.logger.debug(j({msg: "Password reset reqzured"}));
                throw new CrossauthError(ErrorCode.PasswordResetNeeded);
            }
            if (options?.skipActiveCheck!=true && user["state"]=="awaitingtwofactorsetup") {
                CrossauthLogger.logger.debug(j({msg: "2FA setup is not complete"}));
                throw new CrossauthError(ErrorCode.TwoFactorIncomplete);
            }
            if (options?.skipEmailVerifiedCheck!=true && user['state'] == "awaitingemailverification") {
                CrossauthLogger.logger.debug(j({msg: "User email not verified"}));
                throw new CrossauthError(ErrorCode.EmailNotVerified);
            }
            if (options?.skipActiveCheck!=true && user['state'] == "disabled") {
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
     * @throws {@link index!CrossauthError } with {@link ErrorCode } set to either `UserNotExist`.
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
     * @throws {@link index!CrossauthError } with {@link ErrorCode } set to either `UserNotExist` or `Connection`.
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

    /**
     * Constructor with user storage object to use plus optional parameters.
     * 
     * @param userStorage an instance of {@link UserStorage } for fetching users.  If also in in memory, this may be an instance of {@link InMemoryUserStorage } but any can be used.
     */
    constructor() {
        super();
    }

    /**
     * Returns the matching key recortd, with additional, or throws an exception.
     * @param key the key to look up in the key storage.
     * @returns the matching Key record
     * @throws a {@link index!CrossauthError } instance with {@link ErrorCode} of `InvalidKey`, `UserNotExist` or `Connection`
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
     * @param id user ID to store with the session key.  See {@link InMemoryUserStorage} for how this may differ from `username`.
     * @param key the session key to store.
     * @param dateCreated the date/time the key was created.
     * @param expires the date/time the key expires.
     * @param extraFields these will also be stored in the key table row
     * @throws {@link index!CrossauthError } if the key could not be stored.
     */
    async saveKey(id : string, 
                      key : string, dateCreated : Date, 
                      expires : Date | undefined, 
                      data? : string,
                      extraFields? : {[key : string]: any}) : Promise<void> {
        this.keys[key] = {
            value : key,
            userId : id,
            created: dateCreated,
            expires: expires,
            data: data,
            ...extraFields
        };
        
    }

    /**
     * 
     * @param key the key to delete
     */
    async deleteKey(key : string) : Promise<void> {
        if (key in this.keys) {
            delete this.keys[key];
        }
    }

    /**
     * Deletes all keys from storage for the given user ID
     * 
     * @param userId : user ID to delete keys for
     */
    async deleteAllForUser(userId : string | number, prefix: string, except : string|undefined = undefined) : Promise<void> {
       for (const key in this.keys) {
            if (this.keys[key].userId == userId && (!except || key != except) && key.startsWith(prefix)) {
                delete  this.keys[key];
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
            let value : string = key.value||"";
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
