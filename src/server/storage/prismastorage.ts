import { PrismaClient, Prisma } from '@prisma/client';
import { UserStorage, UserPasswordStorage, KeyStorage, UserStorageGetOptions } from '../storage';
import { User, UserWithPassword, Key } from '../../interfaces';
import { CrossauthError, ErrorCode } from '../../error';
import { CrossauthLogger, j } from '../..';
import { setParameter, ParamType } from '../utils';

/**
 * Optional parameters for {@link PrismaUserStorage}.
 * 
 * See {@link PrismaUserStorage.constructor} for definitions.
 */
export interface PrismaUserStorageOptions {

    /** Name of user table (to Prisma, ie lowercase).  Default `user` */
    userTable? : string,

    /** Name of the id column in the user table.  Can be set to `username` if that is your primary key.
     * Default `id`.
     */
    idColumn? : string,

    /** If true, check if the `userVerified` field in the user table is true when fetching a user.
     * Must add this field to your table as a boolean. */
    enableEmailVerification? : boolean,


    /** If true, check if the `passwordReset` field in the user table is true when fetching a user.
     * Must add this field to your table as a boolean. Intended to enable forcing a user to reset their password */
    checkPasswordReset? : boolean,

    /** The prisma client instanfce.  Leave this out to have Crossauth create a default one */
    prismaClient? : PrismaClient,
}

/**
 * Implementation of {@link UserStorage} where username and password is stored in a database managed by
 * the Prisma ORM.
 * 
 * By default, the Prisma name (ie the lowercased version) is called `user`.  It must have at least these fields:
 *    * `username String \@unique`
 *    * `normalizedUsername String \@unique`
 *    * `password String`
 * It must also contain an ID column, which is either an `Int` or `String`, eg
 *    * `id Int \@id \@unique \@default(autoincrement())
 * Alternatively you can set it to `username` if you don't have a separate ID field.
 *
 * You can optionally check if an `emailVerified` field is set to `true` when validating users,  Enabling this requires
 * the user table to also have an `emailVerified Boolean` field.  If the username is not the email address,
 * it must contain these extra two fields:
 *     * `email String \@unique`
 *     * `normalizedEmail String \@unique`
 * 
 * You can optionally check if a `passwordReset` field is set to `true` when validating users.  Enabling this requires
 * the user table to also have a `passwordReset Boolean` field.  Use this if you want to require your user to change his/her password.
*/
export class PrismaUserStorage extends UserPasswordStorage {
    private userTable : string = "user";
    private idColumn : string = "id";
    readonly enableEmailVerification : boolean = false;
    readonly checkPasswordReset : boolean = false;
    private prismaClient : PrismaClient;

    /**
     * Creates a PrismaUserStorage object, optionally overriding defaults.
     * @param userTable the (Prisma, ie lowercase) name of the database table for storing users.  Defaults to `user`.
     * @param idColumn the column for the unique user ID.  May be a number of string.  Defaults to `id`.  May also be set to `username`.
     * @param enableEmailVerification if set to `true`, a user will only be returned as valid if the `emailVerified` field is `true`.  See explaination above.
     * @param checkPasswordReset if set to true, a user will only be returned as valid if the "passwordReset" field is not `true`.  See explaination above.
     * @param prismaClient an instance of the prisma client to use.  If omitted, one will be created with defaults (ie `new PrismaClient()`).
     */
    constructor(options : PrismaUserStorageOptions = {}) {
        super();
        setParameter("userTable", ParamType.String, this, options, "USER_TABLE");
        setParameter("idColumn", ParamType.String, this, options, "USER_ID_COLUMN");
        setParameter("enableEmailVerification", ParamType.Boolean, this, options, "ENABLE_EMAIL_VERIFICATION");
        setParameter("checkPasswordReset", ParamType.String, Boolean, options, "CHECK_PASSWORD_RESET");

        if (options && options.prismaClient) {
            this.prismaClient = options.prismaClient;
        } else {
            this.prismaClient = new PrismaClient();
        }
    }

    private async getUser(
        normalizedKey : string, 
        normalizedValue : string | number, 
        options? : UserStorageGetOptions) : Promise<UserWithPassword> {
        let error: CrossauthError|undefined = undefined;
        let prismaUser : any;
        try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            prismaUser = await this.prismaClient[this.userTable].findUniqueOrThrow({
                where: {
                    [normalizedKey]: normalizedValue
                }
            });

        }  catch (e) {
            error = new CrossauthError(ErrorCode.UserNotExist); 
        }
        if (!this.prismaClient) {
            error = new CrossauthError(ErrorCode.Connection); 

        }
        if (error) {
            CrossauthLogger.logger.error(j({err: error}));
            throw error;
        }
        if (options?.skipActiveCheck!=true && prismaUser["state"]=="awaitingtotpsetup") {
            CrossauthLogger.logger.debug(j({msg: "TOTP setup is not complete"}));
            throw new CrossauthError(ErrorCode.TotpIncomplete);
        }
        if (options?.skipActiveCheck!=true && prismaUser["state"]!="active") {
            CrossauthLogger.logger.debug(j({msg: "User is deactivated"}));
            throw new CrossauthError(ErrorCode.UserNotActive);
        }
        if (options?.skipEmailVerifiedCheck!=true && this.enableEmailVerification && !prismaUser["emailVerified"]) {
            CrossauthLogger.logger.debug(j({msg: "User has not verified email"}));
            throw new CrossauthError(ErrorCode.EmailNotVerified);
        }
        if (this.checkPasswordReset && !prismaUser["checkPasswordReset"]) {
            CrossauthLogger.logger.debug(j({msg: "User must reset password"}));
            throw new CrossauthError(ErrorCode.PasswordResetNeeded);
        }
        return {...prismaUser, id: prismaUser[this.idColumn]};
    }

    /**
     * Returns a {@link UserWithPassword } instance matching the given username, or throws an Exception.
     * @param username the username to look up
     * @returns a {@link UserWithPassword } instance, ie including the password hash.
     * @throws {@link index!CrossauthError } with {@link ErrorCode } set to either `UserNotExist` or `Connection`.
     */
    async getUserByUsername(
        username : string, 
        options? : UserStorageGetOptions) : Promise<UserWithPassword> {
        const normalizedValue = PrismaUserStorage.normalize(username);
        return this.getUser("normalizedUsername", normalizedValue, options);
    }

    /**
     * Returns a {@link UserWithPassword } instance matching the given email address, or throws an Exception.
     * 
     * If there is no email field in the user, the username is assumed to contain the email
     * 
     * @param email the email address to look up
     * @returns a {@link UserWithPassword } instance, ie including the password hash.
     * @throws {@link index!CrossauthError } with {@link ErrorCode } set to either `UserNotExist` or `Connection`.
     */
    async getUserByEmail(
        email : string, 
        options? : UserStorageGetOptions) : Promise<UserWithPassword> {
        const normalizedValue = PrismaUserStorage.normalize(email);
        return this.getUser("normalizedEmail", normalizedValue, options);
    }

    /**
     * Same as {@link getUserByUsername } but matching user ID,
     * @param id the user ID to match 
     * @returns a {@link UserWithPassword } instance, ie including the password hash.
     * @throws {@link index!CrossauthError } with {@link ErrorCode } set to either `UserNotExist` or `Connection`.
     */
    async getUserById(id : string | number, 
        options? : UserStorageGetOptions) : Promise<UserWithPassword> {
        return this.getUser(this.idColumn, id, options);
    }

    /**
     * If the given session key exist in the database, update it with the passed values.  If it doesn't
     * exist, throw a CreossauthError with InvalidKey.
     * @param user the user to update.  The id to update is taken from this obkect, which must be present.  All other attributes are optional. 
     */
    async updateUser(user : Partial<User>) : Promise<void> {
        if (!(this.idColumn in user)) throw new CrossauthError(ErrorCode.InvalidKey);
        try {
            let {id: _, ...data} = user;
            if ("email" in data && data.email) {
                data = {normalizedEmail: PrismaUserStorage.normalize(data.email), ...data};
            }
            if ("username" in data && data.username) {
                data = {normalizedUsername: PrismaUserStorage.normalize(data.username), ...data};
            }
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            await this.prismaClient[this.userTable].update({
                where: {
                    [this.idColumn]: user.id,
                },
                data: data
            });
        } catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            throw new CrossauthError(ErrorCode.Connection, "Error updating user");
        }
    }

    /**
     * Create a user
     * @param username 
     * @param password 
     * @param extraFields 
     */
    async createUser(username : string, 
               password : string, 
               extraFields : {[key : string]: string|number|boolean|Date|undefined})
               : Promise<string|number> {
        let error : CrossauthError|undefined = undefined;
        let id = 0;
        try {
            let data : {[key : string] : any} = {
                username : username,
                password : password,
                state: "active",
                ...extraFields,
            };
            if ("email" in data && data.email) {
                data = {normalizedEmail: PrismaUserStorage.normalize(data.email), ...data};
            }
            if ("username" in data && data.username) {
                data = {normalizedUsername: PrismaUserStorage.normalize(data.username), ...data};
            }

            // @ts-ignore  (because types only exist when do prismaClient.table...)
            let user = await this.prismaClient[this.userTable].create({
                data: data
            });
            id = user[this.idColumn];
        } catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            error = new CrossauthError(ErrorCode.Connection, "Error creating user");
            if (e instanceof Prisma.PrismaClientKnownRequestError || (e instanceof Object && "code" in e)) {
                if (e.code === 'P2002') {
                    error = new CrossauthError(ErrorCode.UserExists);
                }
            }
        }
        if (error) {
            throw error;
        }
        return id;
    }

   async  deleteUserByUsername(username : string) : Promise<void>  {
    let error : CrossauthError;
    try {
        // @ts-ignore  (because types only exist when do prismaClient.table...)
        return /*await*/ this.prismaClient[this.userTable].deleteMany({
        where: {
            username: username
        }
    });
    } catch (e) {
        CrossauthLogger.logger.error(j({err: e}));
        error = new CrossauthError(ErrorCode.Connection, "Error deleting key");
    } 
    if (error) throw error;

   }

}

/**
 * Optional parameters for {@link PrismaKeyStorage}.
 * 
 * See {@link PrismaKeyStorage.constructor} for definitions.
 */
export interface PrismaKeyStorageOptions {
    keyTable? : string,
    prismaClient? : PrismaClient,
}

/**
 * Implementation of {@link KeyStorage } where keys stored in a database managed by
 * the Prisma ORM.
 * 
 * By default, the Prisma name (ie the lowercased version) is called `session`.  It must have at least three fields:
 *    * `key String \@unique`
 *    * `user_id String or Int`
 *    * `created DateTime`
 *    * `expires DateTime`
 * `key` must have `\@unique`.  It may also contain an ID column, which is not used.  If in the schema,
 * it must be autoincrement.  THe `userId` may be a `String` or `Int`.  If a database table is used for
 * user storage (eg {@link PrismaUserStorage} this should be a foreign key to the user table), in which case there
 * should also be a `user` field (see Prisma documentation on foreign keys).
 */
export class PrismaKeyStorage extends KeyStorage {
    private keyTable : string = "key";
    private prismaClient : PrismaClient;

    /**
     * Constructor with user storage object to use plus optional parameters.
     * 
     * @param userStorage an instance of {@link UserStorage } for fetching users.  If also in Prisma, this may be an instance of {@link PrismaUserStorage } but any can be used.
     * @param keyTable the (Prisma, lowercased) name of the session table.  Defaults to `session`.
     * @param prismaClient an instance of the prisma client to use.  If omitted, one will be created with defaults (ie `new PrismaClient()`).
     * @param extraFields if given, these additional fields will be selected from the table into the returned Key.
     */
    constructor({keyTable, 
                 prismaClient} : PrismaKeyStorageOptions = {}) {
        super();
        if (keyTable) {
            this.keyTable = keyTable;
        }
        if (prismaClient == undefined) {
            this.prismaClient = new PrismaClient();
        } else {
            this.prismaClient = prismaClient;
        }
    }

    /**
     * Returns the matching Key record, or throws an exception if it doesn't exist
     * @param key the session key to look up in the session storage.
     * @returns the {@link User } object for the user with the given session key, with the password hash removed, as well as the expiry date/time of the key.
     * @throws a {@link index!CrossauthError } instance with {@link ErrorCode} of `InvalidSession`, `UserNotExist` or `Connection`
     */
    async getKey(key : string) : Promise<Key> {
        let returnKey : Key = {userId: 0, value: "", created: new Date(), expires: undefined};
        let error : CrossauthError|undefined = undefined;
        try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            let prismaKey =  await this.prismaClient[this.keyTable].findUniqueOrThrow({
                where: {
                    value: key
                }
            });
            returnKey = {
                ...prismaKey,
                userId: prismaKey.user_id,
            }
        } catch {
            error = new CrossauthError(ErrorCode.InvalidKey);
        }
        if (error) {
            throw error;
        }
        return returnKey;
    }
    
    /**
     * Saves a key in the session table.
     * 
     * @param userId user ID to store with the session key.  See {@link PrismaUserStorage} for how this may differ from `username`.
     * @param key the key to store.
     * @param created the date/time the key was created.
     * @param expires the date/time the key expires.
     * @param extraFields these will be stored in the key table row
     * @throws {@link index!CrossauthError } if the key could not be stored.
     */
    async saveKey(userId : string | number | undefined, 
                      value : string, created : Date, 
                      expires : Date | undefined,
                      data? : string,
                      extraFields : {[key : string]: any} = {}) : Promise<void> {
        let error : CrossauthError|undefined = undefined;
        try {
            let prismaData : {[key : string] : any} = {
                user_id : userId,
                value : value,
                created : created,
                expires : expires,
                data : data,
                ...extraFields,
            };

            // @ts-ignore  (because types only exist when do prismaClient.table...)
            await this.prismaClient[this.keyTable].create({
                data: prismaData
            })
        } catch (e) {
            if (e instanceof Prisma.PrismaClientKnownRequestError || (e instanceof Object && "code" in e)) {
                if (e.code == 'P2002') {
                    CrossauthLogger.logger.debug(j({msg: "Attempt to create key that already exists. Stack trace follows"}));
                    CrossauthLogger.logger.debug(j({err: e}));
                    error = new CrossauthError(ErrorCode.KeyExists);
                } else {
                    CrossauthLogger.logger.debug(j({err: e}));
                    error = new CrossauthError(ErrorCode.Connection, "Error saving key");
                }
            } else {
                CrossauthLogger.logger.debug(j({err: e}));
                error = new CrossauthError(ErrorCode.Connection, "Error saving key");
            }
        }
        if (error) {
            throw error;
        }
    }

    /**
     * 
     * @param key the key to delete
     * @throws {@link index!CrossauthError } if the key could not be deleted.
     */
    async deleteKey(value : string) : Promise<void> {
        let error : CrossauthError;
        try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            return /*await*/ this.prismaClient[this.keyTable].deleteMany({
            where: {
                value: value
            }
        });
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            error = new CrossauthError(ErrorCode.Connection, "Error deleting key");
        } 
        if (error) throw error;
    }

    /**
     * Deletes all keys from storage for the given user ID
     * 
     * @param userId : user ID to delete keys for
     */
    async deleteAllForUser(userId : string | number, prefix : string, except? : string) : Promise<void> {
        let error : CrossauthError;
        try {
            if (except) {
                // @ts-ignore - because referring to a table name in a variable doesn't have a type in Prisma
                return /*await*/ this.prismaClient[this.keyTable].deleteMany({
                    where: {
                        AND: [
                            { user_id: userId },
                            { value: {startsWith: prefix} },
                            { value: { not: except } },
                        ]
                    }
                });

            } else {
                // @ts-ignore - because referring to a table name in a variable doesn't have a type in Prisma
                return /*await*/ this.prismaClient[this.keyTable].deleteMany({
                    where: {
                        AND: [
                            { user_id: userId },
                            { value: {startsWith: prefix} } ,
                        ]
                    }
                });
            }
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            error = new CrossauthError(ErrorCode.Connection, "Error deleting key");
        } 
        if (error) throw error;
    }     

    /**
     * Deletes all keys from storage other than those with the given prefix
     * 
     * @param userId : user ID to delete keys for
     */
    async deleteWithPrefix(userId : string | number, prefix : string) : Promise<void> {
        let error : CrossauthError;
        try {
            // @ts-ignore - because referring to a table name in a variable doesn't have a type in Prisma
            return /*await*/ this.prismaClient[this.keyTable].deleteMany({
                where: {
                    AND: [
                        { user_id: userId },
                        { value: {startsWith: prefix} },
                    ]
                }
            });

        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            error = new CrossauthError(ErrorCode.Connection, "Error deleting key");
        } 
        if (error) throw error;
    }     

    /**
     * If the given session key exist in the database, update it with the passed values.  If it doesn't
     * exist, throw a CreossauthError with InvalidKey.
     * @param value 
     */
    async updateKey(key : Partial<Key>) : Promise<void> {
        let error : CrossauthError|undefined = undefined;
        if (!(key.value)) throw new CrossauthError(ErrorCode.InvalidKey);
        try {
            let data = {...key};
            delete data.value;
            /*let data : {[key : string] : any} = {
                user_id : key.userId,
                created : key.created,
                expires : key.expires,
            };
            if ("lastActive" in key) {
                data = {...data, lastActive: key.lastActive};
            }*/

            // @ts-ignore  (because types only exist when do prismaClient.table...)
            await this.prismaClient[this.keyTable].update({
                where: {
                    value: key.value,
                },
                data: data
            });
        } catch (e) {
            error = new CrossauthError(ErrorCode.Connection, String(e));
        }
        if (error) {
            CrossauthLogger.logger.debug(j({err: error}));
            throw error;
        }
    }
}
