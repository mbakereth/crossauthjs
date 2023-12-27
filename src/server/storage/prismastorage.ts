import { PrismaClient } from '@prisma/client';
import { UserStorage, UserPasswordStorage, SessionStorage } from '../storage';
import { User, UserWithPassword } from '../../interfaces';
import { CrossauthError, ErrorCode } from '../../error';

export interface PrismaUserStorageOptions {
    userTable? : string,
    idColumn? : string,
    extraFields? : string[],
    prismaClient? : PrismaClient,
}

export class PrismaUserStorage extends UserPasswordStorage {
    userTable : string;
    idColumn : string;
    extraFields : string[];
    prismaClient : PrismaClient;

    constructor({userTable,
                idColumn, 
                extraFields,
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
        if (prismaClient) {
            this.prismaClient = prismaClient;
        } else {
            this.prismaClient = new PrismaClient();
        }
    }
        // throws UserNotExist, Connection
        async getUser(key : string, value : string | number) : Promise<UserWithPassword> {
            try {
                let prismaUser =  this.prismaClient[this.userTable].findUniqueOrThrow({
                    where: {
                        [key]: value
                    }
                });
                let user : UserWithPassword = {
                    uniqueId : prismaUser[this.idColumn],
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
    
    // throws UserNotExist, Connection
    async getUserByUsername(username : string) : Promise<UserWithPassword> {
        return this.getUser("username", username);
    }

    // throws UserNotExist, Connection
    async getUserById(id : string | number) : Promise<UserWithPassword> {
        return this.getUser(this.idColumn, id);
    }
}

export interface PrismaSessionStorageOptions {
    sessionTable? : string,
    prismaClient? : PrismaClient,
}

export class PrismaSessionStorage extends SessionStorage {
    sessionTable : string = "session";
    userStorage : UserStorage
    prismaClient : PrismaClient;

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
    async getUserForSessionKey(sessionKey : string) : Promise<{user: User, expires : Date | undefined}> {
        try {
            let prismaSession =  this.prismaClient[this.sessionTable].findUniqueOrThrow({
                where: {
                    sessionKey: sessionKey
                }
            });
            let user = await this.userStorage.getUserByUsername(prismaSession.username);
            let expires = prismaSession.expires;
            return { user, expires };
        }  catch {
            throw new CrossauthError(ErrorCode.UserNotExist); 
        }
    }

    async saveSession(uniqueUserId : string | number, 
                      sessionKey : string, dateCreated : Date, 
                      expires : Date | undefined) : Promise<void> {
        try {
            await this.prismaClient[this.sessionTable].create({
                data: {
                    userId : uniqueUserId,
                    sessionKey : sessionKey,
                    created : dateCreated,
                    expires : expires
                }
            });
        } catch (e) {
            throw new CrossauthError(ErrorCode.Connection, String(e));
        }

    }

    async deleteSession(sessionKey : string) : Promise<void> {
        this.prismaClient[this.sessionTable].delete({
            where: {
                sessionKey: sessionKey
            }
        });
    }

}
