import { PrismaClient } from '@prisma/client';
import { UserStorage, UserPasswordStorage, SessionStorage } from '../storage';
import { User, UserWithPassword } from '../../interfaces';
import { CrossauthError, ErrorCode } from '../../error';

/**
 * Optional parameters for {@link PrismaUserStorage}.
 * 
 * See {@link PrismaUserStorage.constructor} for definitions.
 */
export interface PrismaUserStorageOptions {
    userTable? : string,
    idColumn? : string,
    extraFields? : string[],
    checkActive? : boolean,
    checkEmailVerified? : boolean,
    prismaClient? : PrismaClient,
}

/**
 * Implementation of {@link UserStorage} where username and password is stored in a database managed by
 * the Prisma ORM.
 * 
 * By default, the Prisma name (ie the lowercased version) is called `user`.  It must have at least two fields:
 *    * `username String \@unique`
 *    * `passwordHash String`
 * `username` must have `\@unique`.  It must also contain an ID column, which is either an `Int` or `String`, eg
 *    * `id Int \@id \@unique \@default(autoincrement())
 * Alternatively you can set it to `username` if you don't have a separate ID field.
 * 
 * You can optionally check if an `active` field is set to `true` when validating users,  Enabling this requires
 * the user table to also have an `active Boolean` field.
 *
 * You can optionally check if an `emailVerified` field is set to `true` when validating users,  Enabling this requires
 * the user table to also have an `emailVerified Boolean` field.
*/
export class PrismaUserStorage extends UserPasswordStorage {
    private userTable : string;
    private idColumn : string;
    private extraFields : string[];
    private checkActive : boolean = false;
    private checkEmailVerified : boolean = false;
    private prismaClient : PrismaClient;

    /**
     * Creates a PrismaUserStorage object, optionally overriding defaults.
     * @param userTable the (Prisma, ie lowercase) name of the database table for storing users.  Defaults to `user`.
     * @param idColumn the column for the unique user ID.  May be a number of string.  Defaults to `id`.  May also be set to `username`.
     * @param extraFields if set, these additional fields (an array of strings) will be fetched from the database and returned in {@link UserWithPassword } instances.
     * @param checkActive if set to `true`, a user will only be returned as valid if the `active` field is `true`.  See explaination above.
     * @param checkEmailVerified if set to `true`, a user will only be returned as valid if the `emailVerified` field is `true`.  See explaination above.
     * @param prismaClient an instance of the prisma client to use.  If omitted, one will be created with defaults (ie `new PrismaClient()`).
    */
    constructor({userTable,
                idColumn, 
                extraFields,
                checkActive,
                checkEmailVerified,
                prismaClient} : PrismaUserStorageOptions = {}) {
        super();
        if (userTable) {
            this.userTable = userTable;
        } else {
            this.userTable = "user";
        }
        if (idColumn) {
            this.idColumn = idColumn;
        } else {
            this.idColumn = "id";
        }
        if (extraFields) {
            this.extraFields = extraFields;
        } else {
            this.extraFields = [];
        }
        if (checkActive) {
            this.checkActive = checkActive;
        }
        if (checkEmailVerified) {
            this,checkEmailVerified = checkEmailVerified;
        }
        if (prismaClient) {
            this.prismaClient = prismaClient;
        } else {
            this.prismaClient = new PrismaClient();
        }
    }

    private async getUser(key : string, value : string | number) : Promise<UserWithPassword> {
        try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            let prismaUser = await this.prismaClient[this.userTable].findUniqueOrThrow({
                where: {
                    [key]: value
                }
            });
            if (this.checkActive && !prismaUser["active"]) {
                throw new CrossauthError(ErrorCode.UserNotActive);
            }
            if (this.checkEmailVerified && !prismaUser["emailVerified"]) {
                throw new CrossauthError(ErrorCode.EmailNotVerified);
            }
            let user : UserWithPassword = {
                id : prismaUser[this.idColumn],
                username : prismaUser.username,
                passwordHash : prismaUser.passwordHash
            }
            this.extraFields.forEach((key) => {
                user[key] = prismaUser[key];
            });
            return user;
        }  catch {
            throw new CrossauthError(ErrorCode.UserNotExist); 
        }

    }

    /**
     * Returns a {@link UserWithPassword } instance matching the given username, or throws an Exception.
     * @param username the username to look up
     * @returns a {@link UserWithPassword } instance, ie including the password hash.
     * @throws {@link index!CrossauthError } with {@link ErrorCode } set to either `UserNotExist` or `Connection`.
     */
    async getUserByUsername(username : string) : Promise<UserWithPassword> {
        return this.getUser("username", username);
    }

    /**
     * Same as {@link getUserByUsername } but matching user ID,
     * @param id the user ID to match 
     * @returns a {@link UserWithPassword } instance, ie including the password hash.
     * @throws {@link index!CrossauthError } with {@link ErrorCode } set to either `UserNotExist` or `Connection`.
     */
    async getUserById(id : string | number) : Promise<UserWithPassword> {
        return this.getUser(this.idColumn, id);
    }
}

/**
 * Optional parameters for {@link PrismaSessionStorage}.
 * 
 * See {@link PrismaSessionStorage.constructor} for definitions.
 */
export interface PrismaSessionStorageOptions {
    sessionTable? : string,
    prismaClient? : PrismaClient,
}

/**
 * Implementation of {@link SessionStorage } where session keys stored in a database managed by
 * the Prisma ORM.
 * 
 * By default, the Prisma name (ie the lowercased version) is called `session`.  It must have at least three fields:
 *    * `sessionKey String \@unique`
 *    * `user_id String or Int`
 *    * `dateCreated DateTime`
 *    * `expires DateTime`
 * `sessionKey` must have `\@unique`.  It may also contain an ID column, which is not used.  If in the schema,
 * it must be autoincrement.  THe `userId` may be a `String` or `Int`.  If a database table is used for
 * user storage (eg {@link PrismaUserStorage} this should be a foreign key to the user table), in which case there
 * should also be a `user` field (see Prisma documentation on foreign keys).
 */
export class PrismaSessionStorage extends SessionStorage {
    private sessionTable : string = "session";
    private userStorage : UserStorage
    private prismaClient : PrismaClient;

    /**
     * Constructor with user storage object to use plus optional parameters.
     * 
     * @param userStorage an instance of {@link UserStorage } for fetching users.  If also in Prisma, this may be an instance of {@link PrismaUserStorage } but any can be used.
     * @param sessionTable the (Prisma, lowercased) name of the session table.  Defaults to `session`.
     * @param prismaClient an instance of the prisma client to use.  If omitted, one will be created with defaults (ie `new PrismaClient()`).
     */
    constructor(userStorage : UserStorage,
                {sessionTable, 
                 prismaClient} : PrismaSessionStorageOptions = {}) {
        super();
        if (sessionTable) {
            this.sessionTable = sessionTable;
        }
        this.userStorage = userStorage;
        if (prismaClient == undefined) {
            this.prismaClient = new PrismaClient();
        } else {
            this.prismaClient = prismaClient;
        }
    }
    // throws UserNotExist, Connection
    /**
     * Returns the {@link User } and expiry date of the user matching the given session key, or throws an exception.
     * @param sessionKey the session key to look up in the session storage.
     * @returns the {@link User } object for the user with the given session key, with the password hash removed, as well as the expiry date/time of the key.
     * @throws a {@link index!CrossauthError } instance with {@link ErrorCode} of `InvalidSession`, `UserNotExist` or `Connection`
     */
    async getUserForSessionKey(sessionKey : string) : Promise<{user: User, expires : Date | undefined}> {
        let prismaSession;
        try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            prismaSession =  await this.prismaClient[this.sessionTable].findUniqueOrThrow({
                where: {
                    sessionKey: sessionKey
                }
            });
        } catch {
            throw new CrossauthError(ErrorCode.InvalidSessionId);
        }
        try {
            let user = await this.userStorage.getUserById(prismaSession.user_id);
            let expires = prismaSession.expires;
            return { user, expires };
        }  catch(e) {
            console.error(e);
            throw new CrossauthError(ErrorCode.UserNotExist); 
        }
    }

    /**
     * Saves a session key in the session table.
     * 
     * @param uniqueUserId user ID to store with the session key.  See {@link PrismaUserStorage} for how this may differ from `username`.
     * @param sessionKey the session key to store.
     * @param dateCreated the date/time the key was created.
     * @param expires the date/time the key expires.
     * @throws {@link index!CrossauthError } if the key could not be stored.
     */
    async saveSession(uniqueUserId : string | number, 
                      sessionKey : string, dateCreated : Date, 
                      expires : Date | undefined) : Promise<void> {
        try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            await this.prismaClient[this.sessionTable].create({
                data: {
                    user_id : uniqueUserId,
                    sessionKey : sessionKey,
                    created : dateCreated,
                    expires : expires
                }
            });
        } catch (e) {
            throw new CrossauthError(ErrorCode.Connection, String(e));
        }

    }

    /**
     * 
     * @param sessionKey the key to delete
     * @throws {@link index!CrossauthError } if the key could not be deleted.
     */
    async deleteSession(sessionKey : string) : Promise<void> {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            await this.prismaClient[this.sessionTable].delete({
            where: {
                sessionKey: sessionKey
            }
        });
    }

}
