import type { 
    User, UserWithPassword, 
} from '../interfaces.ts';

export abstract class UserStorage {
    // throws UserNotExist, Connection
    abstract getUserByUsername(username : string) : Promise<User>;

    // throws UserNotExist, Connection
    abstract getUserById(id : string | number) : Promise<User>;
}

export abstract class UserPasswordStorage {
    // throws UserNotExist, Connection
    abstract getUserByUsername(username : string) : Promise<UserWithPassword>;

    // throws UserNotExist, Connection
    abstract getUserById(id : string | number) : Promise<UserWithPassword>;

}

export abstract class SessionStorage {
    // throws InvalidSessionId
    abstract getUserForSessionKey(sessionKey : string) : Promise<{user: User, expires : Date | undefined}>;

    abstract saveSession(uniqueUserId : string | number, 
                         sessionKey : string, 
                         dateCreated : Date, 
                         expires : Date | undefined) : Promise<void>;

    abstract deleteSession(sessionKey : string) : Promise<void>;
}

