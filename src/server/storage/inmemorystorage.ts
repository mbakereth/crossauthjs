import { UserStorage, UserPasswordStorage, KeyStorage, UserStorageGetOptions } from '../storage';
import { UserWithPassword, Key } from '../../interfaces';
import { CrossauthError, ErrorCode } from '../../error';
import { CrossauthLogger } from '../..';
import type { User } from '../..';

/**
 * Optional parameters for {@link InMemoryUserStorage}.
 * 
 * See {@link InMemoryUserStorage.constructor} for definitions.
 */
export interface InMemoryUserStorageOptions {
    checkActive? : boolean,
    enableEmailVerification? : boolean,
}

/**
 * Implementation of {@link UserStorage} where username and password is stored in memory.  It is really only
 * intended for testing and is not thread safe.
 * 
 * There is no separate ID field - it is set to username.
 *  
 * You can optionally check if an `active` field is set to `true` when validating users,  Enabling this requires
 * the user table to also have an `active Boolean` field.
 *
 * You can optionally check if an `emailVerified` field is set to `true` when validating users,  Enabling this requires
 * the user table to also have an `emailVerified Boolean` field.
*/
export class InMemoryUserStorage extends UserPasswordStorage {
    usersByUsername : { [key : string]: UserWithPassword } = {};
    usersByEmail : { [key : string]: UserWithPassword } = {};
    private checkActive : boolean = false;
    private enableEmailVerification : boolean = false;

    /**
     * Creates a InMemoryUserStorage object, optionally overriding defaults.
     * @param checkActive if set to `true`, a user will only be returned as valid if the `active` field is `true`.  See explaination above.
     * @param enableEmailVerification if set to `true`, a user will only be returned as valid if the `emailVerified` field is `true`.  See explaination above.
    */
    constructor({checkActive,
        enableEmailVerification} : InMemoryUserStorageOptions = {}) {
        super();
        if (checkActive) {
            this.checkActive = checkActive;
        }
        if (enableEmailVerification) {
            this.enableEmailVerification = enableEmailVerification;
        }
    }

    /**
     * Create a user
     * @param username 
     * @param password 
     * @param extraFields 
     */
    async createUser(username : string, 
        passwordHash : string, 
        extraFields : {[key : string]: string|number|boolean|Date|undefined})
        : Promise<string|number> {

            let newUser : UserWithPassword = {
                username: username, 
                id: username, 
                passwordHash: passwordHash,
                normalizedUsername: UserStorage.normalize(username),
                ...extraFields,
            };
            if ("email" in newUser && newUser.email) {
                newUser.normalizedEmail = UserStorage.normalize(newUser.email);
            }
            this.usersByUsername[newUser.normalizedUsername] = newUser;
            if ("email" in newUser && newUser.email) this.usersByEmail[newUser.normalizedEmail] = newUser;
    
        return username;
    }

    /**
     * Returns a {@link UserWithPassword } instance matching the given username, or throws an Exception.
     * 
     * @param username the username to look up
     * @returns a {@link UserWithPassword } instance, ie including the password hash.
     * @throws {@link index!CrossauthError } with {@link ErrorCode } set to either `UserNotExist`.
     */
    async getUserByUsername(
        username : string, 
        _extraFields? : string[],
        options? : UserStorageGetOptions) : Promise<UserWithPassword> {
        const normalizedUsername = UserStorage.normalize(username);
        if (normalizedUsername in this.usersByUsername) {

            const user = this.usersByUsername[normalizedUsername];
            if ('active' in user && user['active'] == false && this.checkActive) {
                CrossauthLogger.logger.debug("User has active set to false");
                throw new CrossauthError(ErrorCode.UserNotActive);
            }
            if (options?.skipEmailVerifiedCheck!=true && 'emailVerified' in user && user['emailVerified'] == false && this.enableEmailVerification) {
                CrossauthLogger.logger.debug("User email not verified");
                throw new CrossauthError(ErrorCode.EmailNotVerified);
            }
            return {...user};
        }

        CrossauthLogger.logger.debug("User does not exist");
        throw new CrossauthError(ErrorCode.UserNotExist);
    }

    /**
     * Returns a {@link UserWithPassword } instance matching the given email address, or throws an Exception.
     * 
     * @param email the emaila ddress to look up
     * @returns a {@link UserWithPassword } instance, ie including the password hash.
     * @throws {@link index!CrossauthError } with {@link ErrorCode } set to either `UserNotExist`.
     */
    async getUserByEmail(email : string, 
        _extraFields? : string[],
        options? : UserStorageGetOptions) : Promise<UserWithPassword> {
        const normalizedEmail = UserStorage.normalize(email);
        if (normalizedEmail in this.usersByEmail) {

            const user = this.usersByUsername[normalizedEmail];
            if ('active' in user && user['active'] == false && this.checkActive) {
                CrossauthLogger.logger.debug("User has active set to false");
                throw new CrossauthError(ErrorCode.UserNotActive);
            }
            if (options?.skipEmailVerifiedCheck!=true && 'emailVerified' in user && user['emailVerified'] == false && this.enableEmailVerification) {
                CrossauthLogger.logger.debug("User email not verified");
                throw new CrossauthError(ErrorCode.EmailNotVerified);
            }
            return {...user};
        }

        CrossauthLogger.logger.debug("User does not exist");
        throw new CrossauthError(ErrorCode.UserNotExist);
    }

    /**
     * Same as {@link getUserByUsername } - userId is the username in this model,
     * @param id the user ID to match 
     * @returns a {@link UserWithPassword } instance, ie including the password hash.
     * @throws {@link index!CrossauthError } with {@link ErrorCode } set to either `UserNotExist` or `Connection`.
     */
    async getUserById(id : string, 
        extraFields? : string[],
        options? : UserStorageGetOptions) : Promise<UserWithPassword> {
        return /*await*/ this.getUserByUsername(id, extraFields, options);
    }

    /**
     * If the given session key exist in the database, update it with the passed values.  If it doesn't
     * exist, throw a CreossauthError with InvalidKey.
     * @param user the user to update.  The id to update is taken from this obkect, which must be present.  All other attributes are optional. 
     */
    async updateUser(user : Partial<User>) : Promise<void> {
        let newUser = {...user};
        if ("username" in newUser && newUser.username) {
            newUser.normalizedUsername = UserStorage.normalize(newUser.username);
        } else if ("id" in newUser && newUser.id) {
            newUser.normalizedUsername = UserStorage.normalize(String(newUser.id));
        }
        if ("email" in newUser && newUser.email) {
            newUser.normalizedEmail = UserStorage.normalize(newUser.email);

        }
        if (newUser.normalizedUsername && newUser.normalizedUsername in this.usersByUsername) {
            for (let field in newUser) {
                this.usersByUsername[newUser.normalizedUsername][field] = newUser[field];
            }
        }
    }

    async deleteUserByUsername(username: string): Promise<void> {
        const normalizedUser = UserStorage.normalize(String(username));
        if (normalizedUser in this.usersByUsername) {
            const user = this.usersByUsername.newUser[normalizedUser];
            delete this.usersByUsername[normalizedUser];
            const normalizedEmail = UserStorage.normalize(String(user.email));
            if (normalizedEmail in this.usersByEmail) {
                delete this.usersByEmail[normalizedEmail];
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
        CrossauthLogger.logger.debug("Key does not exist in key storage.  Stack trace follows");
        let err = new CrossauthError(ErrorCode.InvalidKey); 
        CrossauthLogger.logger.debug(err.stack);
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
    async deleteAllForUser(userId : string | number, except : string|undefined = undefined) : Promise<void> {
       for (const key in this.keys) {
            if (this.keys[key].userId == userId && (!except || key != except)) {
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
                this.keys[value] = key[field];
            }
        }
    }


}
