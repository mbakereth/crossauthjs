import { CrossauthError, ErrorCode } from '@crossauth/common';
import { setParameter, ParamType } from './utils';
import type { User, UserSecrets, Key, UserInputFields, UserSecretsInputFields, OAuthClient } from '@crossauth/common';

/**
 * Passed to get methods in {@link UserStorage}.
 */
export interface UserStorageGetOptions {

    /**
     * If true, a valid user will be returned even if state is set to `awaitingemailverification`
     */
    skipEmailVerifiedCheck? : boolean

    /**
     * If true, a valid user will be returned even if state is not set to `active`
     */
    skipActiveCheck? : boolean,

    /**
     * If true, usernames will be matched as lowercase and with diacritics removed.
     * Default true,
     * 
     * Note: this doesn't apply to the ID column
     */
    normalizeUsername? : boolean,

    /**
     * If true, email addresses (in the email column not in the username column) 
     * will be matched as lowercase and with diacritics removed.
     * Default true.
     */
    normalizeEmail? : boolean,
}

/**
 * Options passed to {@link UserStorage} constructor
 */
export interface UserStorageOptions {

    /**
     * Fields that users are allowed to edit.  Any fields passed to a create or
     * update call that are not in this list will be ignored.
     */
	userEditableFields? : string[],

    /**
     * Fields that admins are allowed to edit (in addition to `userEditableFields`)
     */
	adminEditableFields? : string[],
}

/**
 * Base class for place where user details are stored,
 * 
 * This class is subclasses for various types of user storage,  
 * eg {@link PrismaUserStorage } is for storing
 * username and password in a database table, managed by the Prisma ORM.
 * 
 * Username and email searches should be case insensitive, as should their 
 * unique constraints.  ID searches need not be case insensitive.
 */
export abstract class UserStorage {
    readonly userEditableFields : string[] = [];
    readonly adminEditableFields : string[] = [];
    readonly normalizeUsername = true;
    readonly normalizeEmail = true;
    
    /**
     * Constructor
     * @param options See {@link UserStorageOptions}
     */
    constructor(options : UserStorageOptions = {}) {
        setParameter("userEditableFields", ParamType.JsonArray, this, options, "USER_EDITABLE_FIELDS");
        setParameter("adminEditableFields", ParamType.JsonArray, this, options, "ADMIN_EDITABLE_FIELDS");
        setParameter("normalizeUsername", ParamType.JsonArray, this, options, "NORMALIZE_USERNAME");
        setParameter("normalizeEmail", ParamType.JsonArray, this, options, "NORMALIZE_EMAIL");
    }

    /**
     * Returns user matching the given username, or throws an exception.  
     * 
     * if `normalizeUsername` is true, the username should be matched normalized and 
     * lowercased (using normalize())
     * @param username the username to return the user of
     * @param options optionally turn off checks.  Used internally
     * @throws CrossauthException with ErrorCode either `UserNotExist` or `Connection`
     */
    abstract getUserByUsername(
        username : string, 
         options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}>;

    /**
     * Returns user matching the given user id, or throws an exception.
     * 
     * Not that implementations are free to define what the user ID is.  It can be a number of string,
     * or can simply be `username`.
     * 
     * @param id the user id to return the user of
     * @param options optionally turn off checks.  Used internally
     * @throws {@link @crossauth/common!CrossauthError} with 
     * {@link @crossauth/common!ErrorCode} either `UserNotExist` or `Connection`
     */
    abstract getUserById(
        id : string|number, 
         options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}>;

    /**
     * Returns user matching the given email address, or throws an exception.
     * 
     * If `normalizeEmail` is true, email should be matched normalized and lowercased (using normalize())
     * If the email field doesn't exist, username is assumed to be the email column
     * 
     * @param email the email address to return the user of
     * @param options optionally turn off checks.  Used internally
     * @throws {@link @crossauth/common!CrossauthError} with 
     * {@link @crossauth/common!ErrorCode} either `UserNotExist` or `Connection`
     */
    abstract getUserByEmail(
        email : string | number, 
        options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}>;

    /**
     * Creates a user with the given details and secrets.
     * 
     * @param _user will be put in the User table
     * @param _secrets will be put in the UserSecrets table
     * @returns the new user as a {@link @crossauth/common!User} object.
     */
    createUser(_user : UserInputFields, _secrets? : UserSecretsInputFields) 
        : Promise<User> {
        throw new CrossauthError(ErrorCode.Configuration);
    }

    /**
     * Updates an existing user with the given details and secrets.
     *
     * If the given user exists in the database, update it with the passed values. 
     * If it doesn't exist, throw a
     * {@link @crossauth/common!CrossauthError} with 
     * {@link @crossauth/common!ErrorCode} `InvalidKey`.
     * 
     * @param user  The `id` field must be set, but all others are optional.
     *              Any parameter not set (or undefined) will not be updated.
     *              If you want to set somethign to `null` in the database, pass
     *              the value as `null` not undefined.
     */
    abstract updateUser(user : Partial<User>, secrets? : Partial<UserSecrets>) : Promise<void>;

    /**
     * If the storage supports this, delete the named user from storage.
     * 
     * @param username username to delete
     */
    abstract deleteUserByUsername(username : string) : Promise<void>;

    /**
     * If the storage supports this, delete the user with the given ID from 
     * storage.
     * 
     * @param id id of user to delete
     */
    abstract deleteUserById(id : string|number) : Promise<void>;

    /**
     * Returns all users in the storage, in a a fixed order defined by 
     * the storage (eg alphabetical by username)
     * @param skip skip this number of records from the start of the set
     * @param take only return at most this number of records
     * 
     * @returns an array of {@link @crossauth/common!User} objects.
     */
    abstract getUsers(skip? : number, take? : number) : Promise<User[]>;

    /**
     * By default, usernames and emails are stored in lowercase, normalized format.  
     * This function returns that normalization.
     * 
     * @param str the string to normalize
     * @returns the normalized string, in lowercase with diacritics removed
     */
    static normalize(str : string) : string {
        return str.normalize("NFD").replace(/\p{Diacritic}/gu, "").toLowerCase();
    }
}

/**
 * Base class for storing session and API keys.
 *
 * This class is subclasses for various types of session key storage,  Eg
 * {@link PrismaKeyStorage } is for storing
 * session in a database table, managed by the Prisma ORM.
 */
export abstract class KeyStorage {

    /**
     * Returns the matching key in the session storage or throws an exception if it doesn't exist.
     * 
     * @param key the key to look up, as it will appear in this storage 
     *            (typically unsigned, hashed)
     * @returns The matching Key record.
     */
    abstract getKey(key : string) : Promise<Key>;

    /**
     * Saves a session key in the session storage (eg database).
     * 
     * @param userid the ID of the user.  This matches the primary key in the 
     *               {@link UserStorage } implementation.
     * @param value the key value to store.
     * @param dateCreated the date/time the key was created.
     * @param expires the date/time the key expires.
     * @param data an optional value, specific to the type of key, eg new 
     *             email for email change tokens
     * @param extraFields these will also be saved in the key record
     */
    abstract saveKey(userid : string | number | undefined, 
                         value : string, 
                         dateCreated : Date, 
                         expires : Date | undefined, 
                         data? : string,
                         extraFields? : {[key : string]: any}) : Promise<void>;


    /**
     * If the given session key exists in the database, update it with the 
     * passed values.  If it doesn't exist, throw a 
     * {@link @crossauth/common!CrossauthError} with 
     * {@link @crossauth/common!ErrorCode} `InvalidKey`.
     * @param key the fields defined in this will be updated.  `id` must
     *            be present and it will not be updated.
     */
    abstract updateKey(key : Partial<Key>) : Promise<void>;

    /**
     * Deletes a key from storage (eg the database).
     * 
     * @param value the key to delete
     */
    abstract deleteKey(value : string) : Promise<void>;

    /**
     * Deletes all keys from storage for the given user ID
     * 
     * @param userid : user ID to delete keys for
     * @param prefix only keys starting with this prefix will be
     *               deleted
     * @param except if defined, the key with this value will not be deleted
     */
    abstract deleteAllForUser(userid : string | number | undefined, 
        prefix : string, except? : string) : Promise<void>;

    /**
     * Deletes all matching the given specs
     * 
     * @param key : any key matching all defined values in this object will
     *              be deleted
     */
    abstract deleteMatching(key : Partial<Key>) : Promise<void>;

    /**
     * Return all keys matching the given user ID
     * @param userid user to return keys for
     * @returns an array of keys
     */
    abstract getAllForUser(userid : string|number|undefined) : Promise<Key[]>;

    /**
     * The `data` field in a key entry is a JSON string.  This class should
     * atomically update a field in it.
     * @param keyName the name of they to update, as it appears in the table.
     * @param dataName the field name to update
     * @param value the new value.
     */
    abstract updateData(keyName: string,
        dataName: string,
        value: any | undefined) : Promise<void>;

    /**
     * The `data` field in a key entry is a JSON string.  This class should
     * atomically update a field in it.
     * @param keyName the name of they to update, as it appears in the table.
     * @param dataName the field name to update
     */
    abstract deleteData(keyName: string,
        dataName: string) : Promise<void>;

    /**
     * Returns an object decoded from the data field as a JSON string
     * @param data the JSON string to decode
     * @returns the parse JSON object
     * @throws an exception is data is not a valid JSON string
     */
    static decodeData(data : string|undefined) : {[key:string]: any} {
        if (data == undefined || data == "") {
            return {};
        }
        return JSON.parse(data);
    }

    /**
     * Returns a JSON string encoded from the given object
     * @param data the object to encode
     * @returns a JSON string
     */
    static encodeData(data? : {[key:string]: any}) : string {
        if (!data) return "{}";
        return JSON.stringify(data);
    }
}

/**
 * Options for constructing an {@link OAuthClientStorage} object.
 */
export interface OAuthClientStorageOptions {
}

/**
 * Base class for storing OAuth clients.
 *
 * This class is subclassed for various types of client storage,  Eg {@link PrismaOAuthClientStorage } is for storing
 * clients in a database table, managed by the Prisma ORM.
 */
export abstract class OAuthClientStorage {

    /**
     * Constructor
     * @param _options see {@link OAuthClientStorageOptions}
     */
    constructor(_options : OAuthClientStorageOptions = {} ) {
    }
    

    /**
     * Returns the matching client by its auto-generated id in the storage or 
     * throws an exception if it doesn't exist.
     * 
     * @param client_id the client_id to look up
     * @returns The matching {@link @crossauth/common!OAuthClient} object.
     */
    abstract getClientById(client_id : string) : Promise<OAuthClient>;

    /**
     * Returns the matching client in the storage by friendly name or 
     * throws an exception if it doesn't exist.
     * 
     * @param name the client name to look up
     * @param userid if defined, only return clients belonging to this user.
     *               if `null`, return only clients with a null userid.  
     *               if undefined, return all clients with this name.
     * @returns An array of {@link @crossauth/common!OAuthClient} objects.
     * @throws {@link @crossauth/common!CrossauthError } with {@link @crossauth/common!ErrorCode } of `InvalidSessionId` if a match was not found in session storage.
     */
    abstract getClientByName(name : string, userid? : string|number|null) : Promise<OAuthClient[]>;

    /**
     * Returns all clients in alphabetical order of client name.
     * @param skip skip this number of records from the start in alphabetical
     *             order
     * @param take return at most this number of records
     * @param userid if defined, only return clients belonging to this user.
     *               if `null`, return only clients with a null userid.  
     *               if undefined, return all clients.
     * @returns An array of {@link @crossauth/common!OAuthClient} objects.
     */
    abstract getClients(skip? : number, take? : number, userid? : string|number|null) : Promise<OAuthClient[]>;

    /**
     * Creates and returns a new client with random ID and optionally secret.
     * 
     * Saves in the database.
     * 
     * @param client the client to save.
     * @returns the new client.
     * 
     */
    abstract createClient(client : OAuthClient) : Promise<OAuthClient>;

    /**
     * If the given session key exists in the database, update it with the 
     * passed values.  If it doesn't
     * exist, throw a {@link @crossauth/common!CrossauthError} with 
     * `InvalidClient`.
     * @param client all fields to update (client_id must be set but will not
     *        be updated) 
     */
    abstract updateClient(client : Partial<OAuthClient>) : Promise<void>;

    /**
     * Deletes a key from storage .
     * 
     * @param client_id the client to delete
     */
    abstract deleteClient(client_id : string) : Promise<void>;
}

/**
 * Options for creating an {@link OAuthAuthorizationStorage} object
 */
export interface OAuthAuthorizationStorageOptions {
}

/**
 * Base class for storing scopes that have been authorized by a user 
 * (or for client credentials, for a client).
 *
 * This class is subclassed for various types of storage,  Eg 
 * {@link PrismaOAuthAuthorizationStorage } is for storing
 * in a database table, managed by the Prisma ORM.
 */
export abstract class OAuthAuthorizationStorage {

    /**
     * Constructor
     * @param _options see {@link OAuthAuthorizationStorageOptions}
     */
    constructor(_options : OAuthAuthorizationStorageOptions = {} ) {
    }
    
    /**
     * Returns the matching all scopes authorized for the given client and optionally user.
     * 
     * @param client_id the client_id to look up
     * @param userid the userid to look up, undefined for a client authorization not user authorization
     * @returns The authorized scopes as an array.
     */
    abstract getAuthorizations(client_id: string,
        userid: string | number | undefined) : Promise<(string|null)[]>;

    /**
     * Saves a new set of authorizations for the given client and optionally 
     * user.
     * 
     * Deletes the old ones.
     * 
     * @param client_id the client_id to look up
     * @param userid the userid to look up, undefined for a client 
     *               authorization not user authorization
     * @param authorizations new set of authorized scopes, which may be empty
     * 
     */
    abstract updateAuthorizations(client_id: string,
        userid: string | number | null,
        authorizations: (string | null)[]) : Promise<void>;
}

