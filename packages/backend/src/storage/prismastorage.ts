import { PrismaClient, Prisma } from '@prisma/client';
import { UserStorage, KeyStorage, type UserStorageGetOptions, type UserStorageOptions, OAuthClientStorage, type OAuthClientStorageOptions, OAuthAuthorizationStorage } from '../storage';
import { type User, type UserSecrets, type UserInputFields, type UserSecretsInputFields, type Key, type OAuthClient } from '@crossauth/common';
import { CrossauthError, ErrorCode, OAuthFlows } from'@crossauth/common';
import { CrossauthLogger, j, UserState } from '@crossauth/common';
import { setParameter, ParamType } from '../utils';

/**
 * Optional parameters for {@link PrismaUserStorage}.
 * 
 * See {@link PrismaUserStorage.constructor} for definitions.
 */
export interface PrismaUserStorageOptions extends UserStorageOptions {

    /** Name of user table (to Prisma, ie lowercase).  Default `user` */
    userTable? : string,

    /** Name of user secrets table (to Prisma, ie lowercase).  Default `user` */
    userSecretsTable? : string,

    /** Name of the id column in the user table.  Can be set to `username` if that is your primary key.
     * Default `id`.
     */
    idColumn? : string,

    /** The prisma client instanfce.  Leave this out to have Crossauth create a default one */
    prismaClient? : any; // PrismaClient,

    includes? : string[];

    /**
     * This works around a Fastify limitation.  If the id passed to 
     * getUserById() is a string but is numeric, first try forcing it to
     * a number before selecting.  If that fails, try it as the string,
     */
    forceIdToNumber? : boolean,
}

/**
 * Implementation of {@link UserStorage} where username and password is stored in a database managed by
 * the Prisma ORM.
 * 
 * By default, the Prisma name (ie the lowercased version) is called `user`.  It must have at least these fields:
 *    * `username String \@unique`
 *    * `usernameNormalized String \@unique`
 *    * `password String`
 * It must also contain an ID column, which is either an `Int` or `String`, eg
 *    * `id Int \@id \@unique \@default(autoincrement())
 * Alternatively you can set it to `username` if you don't have a separate ID field.
 *
 * You can optionally check if the `state` field is set to `awaitingemailverification` when validating users.
 *  If the username is not the email address,
 *  it must contain these extra two fields:
 *     * `email String \@unique`
 *     * `emailNormalized String \@unique`
 * 
 * You can optionally check if a `passwordReset` field is set to `true` when validating users.  Enabling this requires
 * the user table to also have a `passwordReset Boolean` field.  Use this if you want to require your user to change his/her password.
*/
export class PrismaUserStorage extends UserStorage {
    private userTable : string = "user";
    private userSecretsTable : string = "userSecrets";
    private idColumn : string = "id";
    private prismaClient : PrismaClient;
    private includes : string[] = ["secrets"];
    private includesObject : {[key:string]:boolean} = {};
    private forceIdToNumber : boolean = true;

    /**
     * Creates a PrismaUserStorage object, optionally overriding defaults.
     * @param options see {@link PrismaUserStorage}
     */
    constructor(options : PrismaUserStorageOptions = {}) {
        super(options);
        setParameter("userTable", ParamType.String, this, options, "USER_TABLE");
        setParameter("userSecretsTable", ParamType.String, this, options, "USER_SECRETS_TABLE");
        setParameter("idColumn", ParamType.String, this, options, "USER_ID_COLUMN");
        setParameter("includes", ParamType.String, this, options, "USER_INCLUDES");
        setParameter("forceIdToNumber", ParamType.String, this, options, "USER_FORCE_ID_TO_NUMBER");
	    this.includes.forEach((item) => {this.includesObject[item] = true});

        if (options && options.prismaClient) {
            this.prismaClient = options.prismaClient;
        } else {
            this.prismaClient = new PrismaClient();
        }
    }

    private async getUser(
        normalizedKey : string, 
        normalizedValue : string | number,
        options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}> {
        let error: CrossauthError|undefined = undefined;
        let prismaUser : any;
        try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            prismaUser = await this.prismaClient[this.userTable].findUniqueOrThrow({
                where: {
                    [normalizedKey]: normalizedValue
                },
                include: this.includesObject,
            });

        }  catch (e) {
            error = new CrossauthError(ErrorCode.UserNotExist); 
        }
        if (!this.prismaClient) {
            error = new CrossauthError(ErrorCode.Connection); 

        }
        if (error) throw error;
        
        if (options?.skipActiveCheck!=true && prismaUser["state"]==UserState.awaitingTwoFactorSetup) {
            CrossauthLogger.logger.debug(j({msg: "2FA setup is not complete"}));
            throw new CrossauthError(ErrorCode.TwoFactorIncomplete);
        }
        if (options?.skipActiveCheck!=true && prismaUser["state"]==UserState.disabled) {
            CrossauthLogger.logger.debug(j({msg: "User is deactivated"}));
            throw new CrossauthError(ErrorCode.UserNotActive);
        }
        if (options?.skipEmailVerifiedCheck!=true && prismaUser["state"]==UserState.awaitingEmailVerification) {
            CrossauthLogger.logger.debug(j({msg: "User has not verified email"}));
            throw new CrossauthError(ErrorCode.EmailNotVerified);
        }
        if (options?.skipActiveCheck!=true && prismaUser["state"] == UserState.passwordChangeNeeded) {
            CrossauthLogger.logger.debug(j({msg: "User must change password"}));
            throw new CrossauthError(ErrorCode.PasswordChangeNeeded);
        }
        if (options?.skipActiveCheck!=true && (prismaUser["state"] == UserState.passwordResetNeeded || prismaUser["state"] == UserState.passwordAndFactor2ResetNeeded)) {
            CrossauthLogger.logger.debug(j({msg: "User must reset password"}));
            throw new CrossauthError(ErrorCode.PasswordResetNeeded);
        }
        if (options?.skipActiveCheck!=true && prismaUser["state"]==UserState.factor2ResetNeeded) {
            CrossauthLogger.logger.debug(j({msg: "2FA reset required"}));
            throw new CrossauthError(ErrorCode.Factor2ResetNeeded);
        }
        const secrets = prismaUser.secrets || {};
        if (prismaUser.secrets) {
            delete secrets.user_id;
            delete prismaUser.secrets;
        }
        return {user: {...prismaUser, id: prismaUser[this.idColumn]}, secrets: {userId: prismaUser[this.idColumn], ...secrets}};
    }

    /**
     * Returns a {@link @crossauth/common!User} and {@link @crossauth/common!UserSecrets} instance matching the given username, or throws an Exception.
     * @param username the username to look up
     * @returns a {@link @crossauth/common!User} and {@link @crossauth/common!UserSecrets} instance, ie including the password hash.
     * @throws {@link @crossauth/common!CrossauthError } with {@link @crossauth/common!ErrorCode } set to either `UserNotExist` or `Connection`.
     */
    async getUserByUsername(
        username : string, 
        options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}> {
        const normalizedValue = PrismaUserStorage.normalize(username);
        return this.getUser("usernameNormalized", normalizedValue, options);
    }

    /**
     * Returns a {@link @crossauth/common!User} and {@link @crossauth/common!UserSecrets} instance matching the given email address, or throws an Exception.
     * 
     * If there is no email field in the user, the username is assumed to contain the email
     * 
     * @param email the email address to look up
     * @returns a {@link @crossauth/common!User} and {@link @crossauth/common!UserSecrets} instance, ie including the password hash.
     * @throws {@link @crossauth/common!CrossauthError } with {@link @crossauth/common!ErrorCode } set to either `UserNotExist` or `Connection`.
     */
    async getUserByEmail(
        email : string, 
        options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}> {
        const normalizedValue = PrismaUserStorage.normalize(email);
        return this.getUser("emailNormalized", normalizedValue, options);
    }

    /**
     * Same as {@link getUserByUsername } but matching user ID,
     * @param id the user ID to match 
     * @returns a {@link @crossauth/common!User} and {@link @crossauth/common!UserSecrets} instance, ie including the password hash.
     * @throws {@link @crossauth/common!CrossauthError } with {@link @crossauth/common!ErrorCode } set to either `UserNotExist` or `Connection`.
     */
    async getUserById(id : string | number, 
        options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}> {
        if (this.forceIdToNumber && typeof(id) == "string" && id.match(/^[+-]?[0-9]+$/)) {
            try {
                return await this.getUser(this.idColumn, Number(id), options);
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                if (ce.code == ErrorCode.UserNotExist) {
                    return await this.getUser(this.idColumn, id, options);
                } else {
                    CrossauthLogger.logger.debug(j({err: e}));
                    throw e;
                }
            }
        }
        return await this.getUser(this.idColumn, id, options);
    }

    /**
     * If the given session key exist in the database, update it with the passed values.  If it doesn't
     * exist, throw a CreossauthError with InvalidKey.
     * @param user the user to update.  The id to update is taken from this obkect, which must be present.  All other attributes are optional. 
     */
    async updateUser(user : Partial<User>, secrets?: Partial<UserSecrets>) : Promise<void> {
        if (!(this.idColumn in user)) throw new CrossauthError(ErrorCode.InvalidKey);
        if (secrets && !secrets.userId) secrets.userId = user[this.idColumn];
        try {
            let {id: dummyUserId, ...userData} = user;
            let {userId: dummySecretsId, ...secretsData} = secrets??{};
            if ("email" in userData && userData.email) {
                userData = {emailNormalized: PrismaUserStorage.normalize(userData.email), ...userData};
            }
            if ("username" in userData && userData.username) {
                userData = {usernameNormalized: PrismaUserStorage.normalize(userData.username), ...userData};
            }
            if (!secrets) {
                // @ts-ignore  (because types only exist when do prismaClient.table...)
                await this.prismaClient[this.userTable].update({
                    where: {
                        [this.idColumn]: user.id,
                    },
                    data: userData,
                });
            } else {
                await this.prismaClient.$transaction(async (tx: any) =>{

                    let existingSecrets : {[key:string]:any} = {}
                    try {
                        // @ts-ignore  (because types only exist when do prismaClient.table...)
                        await tx[this.userSecretsTable].findUniqueOrThrow({
                            where: {
                                user_id: user.id
                            },
                        });
                    } catch (e) {}
                    let {userId: dummySecretsId, ...existingSecretsData} = existingSecrets??{};
                    secretsData = {...existingSecretsData, ...secretsData}
                    // @ts-ignore
                    await tx[this.userTable].update({
                        where: {
                            [this.idColumn]: user.id,
                        },
                        data: {
                            ...userData,
                        },
                    });

                    // @ts-ignore
                    await tx[this.userSecretsTable].upsert({
                        where: {
                            user_id: user.id,
                        },
                        update: 
                            secretsData,
                        create:
                            {user_id: user.id,
                            ...secretsData
                            }
                    });
                });
            }
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            throw new CrossauthError(ErrorCode.Connection, "Error updating user");
        }
    }

    /**
     * Create a user
     * @param user 
     * @param secrets 
     */
    async createUser(user: UserInputFields, secrets? : UserSecretsInputFields)
               : Promise<User> {
        let error : CrossauthError|undefined = undefined;
        if (secrets && !secrets.password) throw new CrossauthError(ErrorCode.PasswordFormat, "Password required when creating user");
        let newUser;
        let usernameNormalized = "";
        let emailNormalized = "";
        try {
            if ("email" in user && user.email) {
                emailNormalized = PrismaUserStorage.normalize(user.email);
            }
            if ("username" in user && user.username) {
                usernameNormalized = PrismaUserStorage.normalize(user.username);
            }
            if (secrets) {

                // @ts-ignore  (because types only exist when do prismaClient.table...)
                newUser = await this.prismaClient[this.userTable].create({
                    data: {
                        ...user,
                        emailNormalized,
                        usernameNormalized,
                        secrets: { 
                            create: 
                                secrets
                        }
                    },
                    include: { secrets: true},
                });
            } else {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            newUser = await this.prismaClient[this.userTable].create({
                    data: {
                        ...user,
                        emailNormalized,
                        usernameNormalized,
                    }
            });
            }
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
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
        return newUser;
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
        CrossauthLogger.logger.debug(j({err: e}));
        error = new CrossauthError(ErrorCode.Connection, "Error deleting user");
    } 
    if (error) throw error;

   }

   async deleteUserById(id : string|number) : Promise<void>  {
        if (this.forceIdToNumber && typeof(id) == "string" && id.match(/^[+-]?[0-9]+$/)) {
            try {
                return await this.deleteUserById_internal(Number(id));
            } catch (e) {
                CrossauthLogger.logger.debug(j({msg: "Failed forcing id to number when deleting user"}));
            }
        }
        return await this.deleteUserById_internal(id);
    }

   private async deleteUserById_internal(id : string|number) : Promise<void>  {
    let error : CrossauthError;
    try {
        // @ts-ignore  (because types only exist when do prismaClient.table...)
        return /*await*/ this.prismaClient[this.userTable].delete({
        where: {
            id: id
        }
    });
    } catch (e) {
        CrossauthLogger.logger.debug(j({err: e}));
        error = new CrossauthError(ErrorCode.Connection, "Error deleting user");
    } 
    if (error) throw error;

   }

    async getUsers(skip? : number, take? : number) : Promise<User[]> {
        let opts : {[key:string]:number} = {};
        if (skip) opts.skip = skip;
        if (take) opts.take = take;

        try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            return await this.prismaClient[this.userTable].findMany({
                ...opts,
                orderBy: [
                    {
                        usernameNormalized: 'asc',
                    },
                ],
                include: this.includesObject,
            });
        }  catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            throw new CrossauthError(ErrorCode.Connection, "Couldn't select from user table")
        }
        
    }


}

///////////////////////////////////////////////////////////////////////////
// KeyStorage

/**
 * Optional parameters for {@link PrismaKeyStorage}.
 * 
 * See {@link PrismaKeyStorage.constructor} for definitions.
 */
export interface PrismaKeyStorageOptions {
    keyTable? : string,
    prismaClient? : PrismaClient,
    transactionTimeout? : number,
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
    private transactionTimeout = 5_000;

    /**
     * Constructor with user storage object to use plus optional parameters.
     * 
     * @param options See {@link PrismaKeyStorageOptions}
     */
    constructor(options : PrismaKeyStorageOptions = {}) {
        super();
        setParameter("transactionTimeout", ParamType.Number, this, options, "TRANSACTION_TIMEOUT");
        if (options.keyTable) {
            this.keyTable = options.keyTable;
        }
        if (options.prismaClient == undefined) {
            this.prismaClient = new PrismaClient();
        } else {
            this.prismaClient = options.prismaClient;
        }
    }

    async getKey(key : string) : Promise<Key> {
        return await this.getKeyWithTransaction(key, this.prismaClient);
    }

    /**
     * Returns the matching Key record, or throws an exception if it doesn't exist
     * @param key the session key to look up in the session storage.
     * @returns the {@link User } object for the user with the given session key, with the password hash removed, as well as the expiry date/time of the key.
     * @throws a {@link @crossauth/common!CrossauthError } instance with {@link @crossauth/common!ErrorCode} of `InvalidSession`, `UserNotExist` or `Connection`
     */
    private async getKeyWithTransaction(key : string, tx : any) : Promise<Key> {
        let returnKey : Key = {userId: 0, value: "", created: new Date(), expires: undefined};
        let error : CrossauthError|undefined = undefined;
        try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            let prismaKey =  await tx[this.keyTable].findUniqueOrThrow({
                where: {
                    value: key
                }
            });
            returnKey = {
                ...prismaKey,
                userId: prismaKey.user_id,
            }
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
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
     * @param value the value of the key to store.
     * @param created the date/time the key was created.
     * @param expires the date/time the key expires.
     * @param extraFields these will be stored in the key table row
     * @throws {@link @crossauth/common!CrossauthError } if the key could not be stored.
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
                expires : expires??null,
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
                    CrossauthLogger.logger.warn(j({msg: "Attempt to create key that already exists. Stack trace follows"}));
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
     * @param value the value of the key to delete
     * @throws {@link @crossauth/common!CrossauthError } if the key could not be deleted.
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
    async deleteAllForUser(userId : string | number | undefined, prefix : string, except? : string) : Promise<void> {
        let error : CrossauthError;
        try {
            if (except) {
                // @ts-ignore - because referring to a table name in a variable doesn't have a type in Prisma
                return /*await*/ this.prismaClient[this.keyTable].deleteMany({
                    where: {
                        AND: [
                            { user_id: userId??null },
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
                            { user_id: userId??null },
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

    async deleteMatching(key : Partial<Key>) : Promise<void> {
        try {
            let andClause = [];
            for (let entry in key) {
                if (entry == "userId") {
                    andClause.push({user_id: key[entry]});

                } else {
                    andClause.push({[entry]: key[entry]});
                }
            }
            // @ts-ignore - because referring to a table name in a variable doesn't have a type in Prisma
            return /*await*/ this.prismaClient[this.keyTable].deleteMany({
                where: {
                    AND: andClause,
                }
            });
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            throw new CrossauthError(ErrorCode.Connection, "Error deleting keys");
        }
}

    /**
     * Deletes all keys from storage other than those with the given prefix
     * 
     * @param userId : user ID to delete keys for
     */
    async deleteWithPrefix(userId : string | number | undefined, prefix : string) : Promise<void> {
        let error : CrossauthError;
        try {
            // @ts-ignore - because referring to a table name in a variable doesn't have a type in Prisma
            return /*await*/ this.prismaClient[this.keyTable].deleteMany({
                where: {
                    AND: [
                        { user_id: userId??null },
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

    async getAllForUser(userId : string|number|undefined) : Promise<Key[]> {
        let returnKeys : Key[] = [];
        let error : CrossauthError|undefined = undefined;
        try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            let prismaKeys =  await this.prismaClient[this.keyTable].findMany({
                where: {
                    user_id: userId??null
                }
            });
            returnKeys = prismaKeys.map((v : Partial<Key>) => { return {...v, userId: v.user_id} });
        } catch {
            error = new CrossauthError(ErrorCode.InvalidKey);
        }
        if (error) {
            throw error;
        }
        return returnKeys;

    }

    /**
     * If the given session key exist in the database, update it with the passed values.  If it doesn't
     * exist, throw a CreossauthError with InvalidKey.
     * @param key the new values of the key.   `value` must be set and will not be updated.
     *        any other fields set (not undefined) will be updated.
     */
    async updateKey(key : Partial<Key>) : Promise<void> {
        await this.updateKeyWithTransaction(key, this.prismaClient);
    }

    private async updateKeyWithTransaction(key : Partial<Key>, tx : any) : Promise<void> {
        let error : CrossauthError|undefined = undefined;
        if (!(key.value)) throw new CrossauthError(ErrorCode.InvalidKey);
        try {
            let data = {...key};
            delete data.value;

            // @ts-ignore  (because types only exist when do prismaClient.table...)
            await tx[this.keyTable].update({
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

    /**
     * See {@link KeyStorage}.
     */
    async updateData(keyName : string, dataName: string, value: any|undefined) : Promise<void> {
        try {

            await this.prismaClient.$transaction(async (tx: any) =>{
                const key = await this.getKeyWithTransaction(keyName, tx);
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
        
                await this.updateKeyWithTransaction({value: key.value, data: JSON.stringify(data)}, tx)
            }, {timeout: this.transactionTimeout});
        } catch (e) {
            if (e && typeof e == "object" && !("isCrossauthError" in e)) {
                CrossauthLogger.logger.debug(j({err: e}));
                throw new CrossauthError(ErrorCode.Connection, "Failed updating session data");
            }
            throw e;
        }

                  
    }
}

///////////////////////////////////////////////////////////////////////////
// OAuthClientStorage

/**
 * Optional parameters for {@link PrismaOAuthClientStorage}.
 */
export interface PrismaOAuthClientStorageOptions extends OAuthClientStorageOptions {

    /** Prisma name of the OAuth Client table.  Default oAuthClient */
    clientTable? : string,

    /** Prisma name of the OAuth valid flows table.  Default oClientValidFlow */
    validFlowTable? : string,

    /** Prisma name of the OAuth Redirect Uri table.  Default oAuthClientRedirectUri */
    redirectUriTable? : string,

    /** A Prisma client to use.  If not provided, one will be created */
    prismaClient? : any; // PrismaClient,

    /** In milliseconds.. Default 5000 */
    transactionTimeout? : number,

    /**
     * This is to work around a Prisma bug.  SQLite returns an error
     * when updating a client if inside a transaction.  
     * - `Update` `OAuthClient` table is updated, `OAuthClientAuthorization`
     *            and `OAuthValidFlow` are updared with a delete and insert.
     *            Doesn't work with SQLite.
     * - `DeleteAndInsert` updated to the `OAuthClient`, 
     *                     `OAuthClientAuthorization` and `OAuthValidFlow` are
     *                     all done as a delete then an insert.  Works for
     *                     SQLite but if you have cascading dependencies on
     *                     the `OAuthClient` table, dependent rows will be
     *                     deleted.
     * Our recommendation is to use `DeleteAndInsert` for SQLite and 
     * `Update` otherwise.
     * 
     * Default `DeleteAndInsert`
     */
    updateMode? : "Update" | "DeleteAndInsert",
}

/**
 * Implementation of {@link OAuthClientStorage } where clients stored in a database managed by
 * the Prisma ORM.
 */
export class PrismaOAuthClientStorage extends OAuthClientStorage {
    private clientTable : string = "oAuthClient";
    private redirectUriTable : string = "OAuthClientRedirectUri";
    private validFlowTable : string = "OAuthClientValidFlow";
    private prismaClient : any;// PrismaClient;
    private transactionTimeout = 5_000;
    private updateMode = "DeleteAndInsert";

    /**
     * Constructor with user storage object to use plus optional parameters.
     * 
     * @param options See {@link PrismaOAuthClientStorageOptions}
     */
    constructor(options : PrismaOAuthClientStorageOptions = {}) {
        super();
        setParameter("clientTable", ParamType.String, this, options, "OAUTH_CLIENT_TABLE");
        setParameter("redirectUriTable", ParamType.String, this, options, "OAUTH_REDIRECTURI_TABLE");
        setParameter("validFlowTable", ParamType.String, this, options, "OAUTH_VALID_FLOW_TABLE");
        setParameter("transactionTimeout", ParamType.Number, this, options, "TRANSACTION_TIMEOUT");
        setParameter("updateMode", ParamType.String, this, options, "OAUTHCLIENT_UPDATE_MODE");
        if (options.prismaClient == undefined) {
            this.prismaClient = new PrismaClient();
        } else {
            this.prismaClient = options.prismaClient;
        }
    }

    async getClientById(clientId : string) : Promise<OAuthClient> {
        return (await this.getClientWithTransaction("clientId", clientId, this.prismaClient, true, undefined))[0];
    }

    async getClientByName(name : string, userId? : string|number|null) : Promise<OAuthClient[]> {
        return await this.getClientWithTransaction("clientName", name, this.prismaClient, false, userId);
    }

    private async getClientWithTransaction(field : string, value : string, tx : any, unique : boolean, userId : string|number|null|undefined) : Promise<OAuthClient[]> {
        const userWhere = (userId == undefined && !(userId === null)) ? {} : {user_id: userId};
        try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            if (unique) {
                const client = await tx[this.clientTable].findUniqueOrThrow({
                    where: {
                        [field]: value,
                        ...userWhere,
                    },
                    include: {redirectUri: true, validFlow: true},
                });
                const redirectUriObjects = client.redirectUri;
                const validFlowObjects = client.validFlow;
                let userId = client.user_id;
                if (userId === null) userId = undefined;
                return [{
                    ...client, 
                    userId : userId,
                    clientSecret: client.clientSecret??undefined, 
                    redirectUri: redirectUriObjects.map((x:{[key:string]:any}) => x.uri), 
                    validFlow: validFlowObjects.map((x:{[key:string]:any}) => x.flow)
                }];
            } else {
                const clients = await tx[this.clientTable].findMany({
                    where: {
                        [field]: value,
                        ...userWhere,
                    },
                    include: {redirectUri: true, validFlow: true},
                });
                for (let client of clients) {
                    const redirectUriObjects = client.redirectUri;
                    const validFlowObjects = client.validFlow;
                    let userId = client.user_id;
                    if (userId == null) userId = undefined;    
                    client.userId = userId;
                    client.clientSecret = client.clientSecret??undefined;
                    client.redirectUri = redirectUriObjects.map((x:{[key:string]:any}) => x.uri);
                    client.validFlow = validFlowObjects.map((x:{[key:string]:any}) => x.flow)
                }
                return clients;
                }
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            CrossauthLogger.logger.error(j({msg: "Invalid OAuth client", [field]: value, cerr: e}))
            throw new CrossauthError(ErrorCode.InvalidClientId);
        }
    }

    /**
     * Saves a key in the session table.
     * 
     * @param client fields for the client to create
     * @throws {@link @crossauth/common!CrossauthError } if the client could not be stored.
     */
    async createClient(client : OAuthClient) : Promise<OAuthClient> {
        try {
            return this.prismaClient.$transaction(async (tx: any) => {
                return await this.createClientWithTransaction(client, tx);
            }, {timeout: this.transactionTimeout});
        } catch (e) {
            if (e && typeof e == "object" && !("isCrossauthError" in e)) {
                CrossauthLogger.logger.debug(j({err: e}));
                throw new CrossauthError(ErrorCode.Connection, "Failed creating client");
            }
            throw e;
        }
    }

    private async createClientWithTransaction(client : OAuthClient, tx : any) : Promise<OAuthClient> {
        const maxAttempts = 10;
        const {redirectUri, validFlow, userId, ...prismaClientData} = client;
        let newClient : OAuthClient|undefined;
        if (userId) prismaClientData.user_id = userId;
        // validate redirect uri
        if (redirectUri) {
            for (let i=0; i<redirectUri.length; ++i) {
                if (redirectUri[i].includes("#")) throw new CrossauthError(ErrorCode.InvalidRedirectUri, "Redirect Uri's may not contain page fragments");
                try {
                    new URL(redirectUri[i]);
                }
                catch (e) {
                    throw new CrossauthError(ErrorCode.InvalidRedirectUri, `Redriect uri ${redirectUri[i]} is not valid`);
                }
            }
        }

        // validate valid flows
        if (validFlow) {
            for (let i=0; i<validFlow.length; ++i) {
                if (!OAuthFlows.isValidFlow(validFlow[i])) throw new CrossauthError(ErrorCode.InvalidOAuthFlow, "Invalid flow " + validFlow[i]);
            }
        }
        
        
        // create client (without redirect uri and valid flows) - may take seveal attempts to get a unique clientId
        for (let attempt=0; attempt < maxAttempts; ++attempt) {
            try {
                // @ts-ignore  (because types only exist when do prismaClient.table...)
                newClient = await tx[this.clientTable].create({
                    data: prismaClientData,
                });
                break;
            } catch (e) {
                if (e instanceof Prisma.PrismaClientKnownRequestError || (e instanceof Object && "code" in e)) {
                    if (e.code == 'P2002') {
                        if (attempt < maxAttempts) {
                            CrossauthLogger.logger.debug(j({msg: `Attempt ${attempt} at creating a unique client ID failed`}));
                        } else {
                            CrossauthLogger.logger.debug(j({err: e}));
                            throw new CrossauthError(ErrorCode.InvalidClientId, "Attempt to create an OAuth client with a clientId that already exists. Maximum attempts failed");
                        }
                    } else {
                        CrossauthLogger.logger.debug(j({err: e}));
                        throw new CrossauthError(ErrorCode.Connection, "Error saving OAuth client");
                    }
                } else {
                    CrossauthLogger.logger.debug(j({err: e}));
                    throw new CrossauthError(ErrorCode.Connection, "Error saving OAuth client");
                }
            }
        }
        if (!newClient) {
            CrossauthLogger.logger.error(j({msg: "Attempt to create key that already exists. Stack trace follows"}));
            throw new CrossauthError(ErrorCode.KeyExists);    
        }

        // create redirect uris
        if (redirectUri) {
            try {
                for (let i=0; i<redirectUri.length; ++i) {
                    // @ts-ignore  (because types only exist when do prismaClient.table...)
                    await tx[this.redirectUriTable].create({
                        data: {
                            client_id: newClient.clientId,
                            uri: redirectUri[i],
                        }
                    });
                }
            } catch (e) {
                if (e instanceof Prisma.PrismaClientKnownRequestError || (e instanceof Object && "code" in e)) {
                    if (e.code == 'P2002') {
                        CrossauthLogger.logger.debug(j({err: e}));
                        throw new CrossauthError(ErrorCode.InvalidRedirectUri, "Attempt to create an OAuth client with a redirect uri that already belongs to another client");
                    } else {
                        CrossauthLogger.logger.debug(j({err: e}));
                        throw new CrossauthError(ErrorCode.Connection, "Error saving OAuth client");
                    }
                } else {
                    CrossauthLogger.logger.debug(j({err: e}));
                    throw new CrossauthError(ErrorCode.Connection, "Error saving OAuth client");
                }
            }
        }

        // create valid flows
        if (validFlow) {
            try {
                for (let i=0; i<validFlow.length; ++i) {
                    // @ts-ignore  (because types only exist when do prismaClient.table...)
                    await tx[this.validFlowTable].create({
                        data: {
                            client_id: newClient.clientId,
                            flow: validFlow[i],
                        }
                    });
                }
            } catch (e) {
                if (e instanceof Prisma.PrismaClientKnownRequestError || (e instanceof Object && "code" in e)) {
                    CrossauthLogger.logger.debug(j({err: e}));
                    throw new CrossauthError(ErrorCode.Connection, "Error saving OAuth client");
                } else {
                    CrossauthLogger.logger.debug(j({err: e}));
                    throw new CrossauthError(ErrorCode.Connection, "Error saving OAuth client");
                }
            }
        }

        return {...newClient, redirectUri: redirectUri, validFlow: validFlow};
    }

    /**
     * 
     * @param clientId the client to delete
     * @throws {@link @crossauth/common!CrossauthError } if the key could not be deleted.
     */
    async deleteClient(clientId : string) : Promise<void> {
        try {
            //return await this.updateClientWithTransaction(client, this.prismaClient);
                return this.prismaClient.$transaction(async (tx: any) => {
            return await this.deleteClientWithTransaction(clientId, tx);
        }, {timeout: this.transactionTimeout});
        } catch (e) {
            if (e && typeof e == "object" && !("isCrossauthError" in e)) {
                CrossauthLogger.logger.debug(j({err: e}));
                throw new CrossauthError(ErrorCode.Connection, "Failed deleting client");
            }
            throw e;
        }
    }


    private async deleteClientWithTransaction(clientId : string, tx : any) : Promise<void> {
            try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            await tx[this.clientTable].deleteMany({
            where: {
                clientId: clientId
            }
        });
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            throw new CrossauthError(ErrorCode.Connection, "Error deleting OAuth client");
        } 
    }

    /**
     * If the given session key exist in the database, update it with the passed values.  If it doesn't
     * exist, throw a CreossauthError with InvalidKey.
     * @param client the client to update.  It will be searched on its clientId, which cannot be updated.
     */
    async updateClient(client : Partial<OAuthClient>) : Promise<void> {
        try {
            //return await this.updateClientWithTransaction(client, this.prismaClient);
                return this.prismaClient.$transaction(async (tx:any) => {
            return this.updateMode == "Update" ? 
                 await this.updateClientWithTransaction_update(client, tx) :
                 await this.updateClientWithTransaction_deleteAndInsert(client, tx);
        }, {timeout: this.transactionTimeout});
        } catch (e) {
            if (e && typeof e == "object" && !("isCrossauthError" in e)) {
                CrossauthLogger.logger.debug(j({err: e}));
                throw new CrossauthError(ErrorCode.Connection, "Failed updating client");
            }
            throw e;
        }
    }

    // This gives a Rust error when used with a transaction on SQLlite

    private async updateClientWithTransaction_update(client : Partial<OAuthClient>, tx : any) : Promise<void> {
        if (!(client.clientId)) throw new CrossauthError(ErrorCode.InvalidClientId);
        const redirectUris = client.redirectUri;
        const validFlows = client.validFlow;

        // validate redirect uris
        if (redirectUris) {
            for (let i=0; i<redirectUris.length; ++i) {
                if (redirectUris[i].includes("#")) throw new CrossauthError(ErrorCode.InvalidRedirectUri, "Redirect Uri's may not contain page fragments");
                try {
                    new URL(redirectUris[i]);
                }
                catch (e) {
                    throw new CrossauthError(ErrorCode.InvalidRedirectUri, `Redriect uri ${redirectUris[i]} is not valid`);
                }
            }
        }
        

        // validate valid flows
        if (validFlows) {
            for (let i=0; i<validFlows.length; ++i) {
                if (!OAuthFlows.isValidFlow(validFlows[i])) throw new CrossauthError(ErrorCode.InvalidOAuthFlow, "Redirect Uri's may not contain page fragments");
            }
        }
    
        try {
            let data = {...client};
            delete data.clientId;
            delete data.redirectUri;
            delete data.validFlow;
            if ("userId" in data) {
                data.user_id = data.userId;
                delete data.userId;
            }

            if (Object.keys(data).length > 0) {
                // @ts-ignore  (because types only exist when do prismaClient.table...)
                await tx[this.clientTable].update({
                    where: {
                        clientId: client.clientId,
                    },
                    data: data
                });
            }
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            throw new CrossauthError(ErrorCode.Connection, "Error updating client");
        }

        if (redirectUris != undefined) {
            try {
                // @ts-ignore  (because types only exist when do prismaClient.table...)
                await this.prismaClient[this.redirectUriTable].deleteMany({
                        where: {
                        client_id: client.clientId
                    }
                });
                for (let i=0; i<redirectUris.length; ++i) { 
                    // @ts-ignore  (because types only exist when do prismaClient.table...)
                    await tx[this.redirectUriTable].create({
                        data: {
                            client_id: client.clientId,
                            uri: redirectUris[i],
                        }
                    });
                }
            } catch (e) {
                if (e instanceof Prisma.PrismaClientKnownRequestError || (e instanceof Object && "code" in e)) {
                    if (e.code == 'P2002') {
                        CrossauthLogger.logger.debug(j({err: e}));
                        throw new CrossauthError(ErrorCode.KeyExists, "Attempt to update an OAuth client with a redirect Uri that already belongs to another client");
                    } else {
                        CrossauthLogger.logger.debug(j({err: e}));
                        throw new CrossauthError(ErrorCode.Connection, "Error updating client");
                    }
                } else {
                    CrossauthLogger.logger.debug(j({err: e}));
                    throw new CrossauthError(ErrorCode.Connection, "Error updating client");
                }
            }    
        }

        if (validFlows != undefined) {
            try {
                // @ts-ignore  (because types only exist when do prismaClient.table...)
                await this.prismaClient[this.validFlowTable].deleteMany({
                    where: {
                        client_id: client.clientId
                    }
                });
                for (let i=0; i<validFlows.length; ++i) { 
                    // @ts-ignore  (because types only exist when do prismaClient.table...)
                    await tx[this.validFlowTable].create({
                        data: {
                            client_id: client.clientId,
                            flow: validFlows[i],
                        }
                    });
                }
            } catch (e) {
                if (e instanceof Prisma.PrismaClientKnownRequestError || (e instanceof Object && "code" in e)) {
                    CrossauthLogger.logger.debug(j({err: e}));
                    throw new CrossauthError(ErrorCode.Connection, "Error updating client");
                } else {
                    CrossauthLogger.logger.debug(j({err: e}));
                    throw new CrossauthError(ErrorCode.Connection, "Error updating client");
                }
            }    
        }

    }

    private async updateClientWithTransaction_deleteAndInsert(client : Partial<OAuthClient>, tx : any) : Promise<void> {
        if (!(client.clientId)) throw new CrossauthError(ErrorCode.InvalidClientId);
        const existingClient = (await this.getClientWithTransaction("clientId", client.clientId, this.prismaClient, true, undefined))[0];
        const newClient = {...existingClient, ...client};
        if ("userId" in newClient) {
            newClient.user_id = newClient.userId;
            delete newClient.userId;
        }
        await this.deleteClientWithTransaction(client.clientId, tx);
        await this.createClientWithTransaction(newClient, tx);
    }

    async getClients(skip? : number, take? : number, userId? : string|number|null) : Promise<OAuthClient[]> {
        let opts : {[key:string]:number} = {};
        if (skip) opts.skip = skip;
        if (take) opts.take = take;

        try {
            let clients : OAuthClient[] = [];
            if (userId || userId === null) {
                // @ts-ignore  (because types only exist when do prismaClient.table...)
                clients = await this.prismaClient[this.clientTable].findMany({
                    ...opts,
                    where: {
                        user_id: userId,
                    },
                    orderBy: [
                        {
                            clientName: 'asc',
                        },
                    ],
                });
            } else {
                // @ts-ignore  (because types only exist when do prismaClient.table...)
                clients = await this.prismaClient[this.clientTable].findMany({
                    ...opts,
                    orderBy: [
                        {
                            clientName: 'asc',
                        },
                    ],
                });
            } 

            clients.forEach((client) => {
                client.userId = client.user_id===null ? undefined : client.user_id; 
                return client});
            return clients;
        }  catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            throw new CrossauthError(ErrorCode.Connection, "Couldn't select from client table")
        }
        
    }
}

///////////////////////////////////////////////////////////////////////////
// OAuthAuthorizationStorage

/**
 * Optional parameters for {@link PrismaOAuthAuthorizationStorage}.
 */
export interface PrismaOAuthAuthorizationStorageOptions extends OAuthClientStorageOptions {

    /** Prisma name of the OAuth Authorization table.  Default oAuthAuthorization */
    authorizationTable? : string,

    /** A Prisma client to use.  If not provided, one will be created */
    prismaClient? : any; // PrismaClient,

    transactionTimeout? : number,
}

/**
 * Implementation of {@link OAuthAuthorizationStorage } where authorizations are stored in a database managed by
 * the Prisma ORM.
 */
export class PrismaOAuthAuthorizationStorage extends OAuthAuthorizationStorage {
    private authorizationTable : string = "oAuthAuthorization";
    private prismaClient : any;// PrismaClient;
    private transactionTimeout : number = 5_000;

    /**
     * Constructor with user storage object to use plus optional parameters.
     * 
     * @param options See {@link PrismaOAuthClientStorageOptions}
     */
    constructor(options : PrismaOAuthClientStorageOptions = {}) {
        super();
        setParameter("authorizationTable", ParamType.String, this, options, "OAUTH_CLIENT_TABLE");
        setParameter("transactionTimeout", ParamType.Number, this, options, "TRANSACTION_TIMEOUT");
        if (options.prismaClient == undefined) {
            this.prismaClient = new PrismaClient();
        } else {
            this.prismaClient = options.prismaClient;
        }
    }

    async getAuthorizations(clientId : string, userId : string|number|undefined) : Promise<string[]> {
        try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            let rows = await this.prismaClient[this.authorizationTable].findMany({
                where: {
                    client_id : clientId,
                    user_id: userId??null,
                },
                select: {
                    scope: true,
                },
        });
            return rows.map((row : {[key:string]:any}) => row.scope);
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            //CrossauthLogger.logger.error(j({msg: "Couldn't get authorizations", clientId: clientId, userId: userId, cerr: e}))
            throw new CrossauthError(ErrorCode.Connection);
        }
    }

    async updateAuthorizations(clientId : string, userId : string|number|undefined, scopes : string[]) : Promise<void> {
        return this.prismaClient.$transaction(async (tx:any) => {
            return await this.updateAuthorizationsWithTransaction(clientId, userId, scopes, tx);
        }, {timeout: this.transactionTimeout});
    }

    /**
     * Saves a key in the session table.
     * 
     * @param clientId the client to update
     * @param userId the user ID to associate with the client, or undefined
     *        for a client not associated with a user
     * @param scopes the scopes that are authorized (new plus existing)
     * @throws {@link @crossauth/common!CrossauthError } if the client could not be stored.
     */
    private async updateAuthorizationsWithTransaction(clientId : string, userId : string|number|undefined, scopes : string[], tx : any) : Promise<void> {

        try {
            // delete existing authorizations

            // @ts-ignore  (because types only exist when do prismaClient.table...)
            await tx[this.authorizationTable].deleteMany({
                where: {
                    client_id: clientId,
                    user_id : userId??null
                }
            });

            // add new authorizations
            const promises : Promise<void>[] = [];
            scopes.forEach((scope) => {
                promises.push(tx[this.authorizationTable].create({
                    data: {
                        client_id : clientId,
                        user_id : userId??null,
                        scope : scope,
                    },
                }));
            });
            await Promise.all(promises);
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            throw new CrossauthError(ErrorCode.Connection, "Error updating OAuth authorizations");
        } 
    }
}
