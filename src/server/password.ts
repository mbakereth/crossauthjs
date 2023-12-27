import type { 
    User, 
} from '../interfaces.ts';
import { pbkdf2Sync }  from 'node:crypto';
import { ErrorCode, CrossauthError } from '../error';
import { UserStorage } from './storage'

export interface PasswordHash {
    hashedPassword : string,
    salt : string,
    iterations: number,
    keyLen : number,
    digest : string
}

export interface UsernamePasswordAuthenticatorOptions {
    iterations? : number,
    keyLen? : number,
    digest? : string,
    saltLength?: number;
}


export abstract class UsernamePasswordAuthenticator {

    // throws Connection, UserNotExist, PasswordNotMatch
    abstract authenticateUser(username : string, password : string) : Promise<User>;
}

export class HashedPasswordAuthenticator extends UsernamePasswordAuthenticator {

    private userStorage : UserStorage;
    private iterations = 100000;
    private keyLen = 64;
    private digest = 'sha512';
    private saltLength = 16;

    private saltChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" 
        + "abcdefghijklmnopqrstuvwxyz"
        + "0123456789"

    constructor(userStorage : UserStorage,
                {iterations,
                keyLen,
                digest,
                saltLength
        } : UsernamePasswordAuthenticatorOptions = {}) {
        super();
        this.userStorage = userStorage;
        if (iterations) {
            this.iterations = iterations;
        }
        if (keyLen) {
            this.keyLen = keyLen;
        }
        if (digest) {
            this.digest = digest;
        }
        if (saltLength) {
            this.saltLength = saltLength;
        }
    }

    async authenticateUser(username : string, password : string) : Promise<User> {
        let user = await this.userStorage.getUserByUsername(username);
        let storedPasswordHash = await this.decodePasswordHash(await user.passwordHash);

        let inputPasswordHash = pbkdf2Sync(
            password, 
            storedPasswordHash.salt, 
            storedPasswordHash.iterations, 
            storedPasswordHash.keyLen,
             storedPasswordHash.digest 
        ).toString('base64');
        if (storedPasswordHash.hashedPassword != inputPasswordHash)
            throw new CrossauthError(ErrorCode.PasswordNotMatch);
        if ("passwordHash" in user) {
            delete user.passwordHash;
        }
        return user;
    }

    // throws InvalidHash
    decodePasswordHash(hash : string) : PasswordHash {
        const parts = hash.split(':');
        if (parts.length != 5) {
            throw new CrossauthError(ErrorCode.InvalidHash);
        }
        try {
            return {
                hashedPassword : parts[4],
                salt : parts[3],
                iterations : Number(parts[2]),
                keyLen : Number(parts[1]),
                digest : parts[0]
            };
        } catch (e) {
            throw new CrossauthError(ErrorCode.InvalidHash);
        }
    }

    private encodePasswordHash(hashedPassword : string, 
                       salt : string, 
                       iterations : number, 
                       keyLen : number, 
                       digest : string) : string {
        return digest + ":" + String(keyLen) + ":" + String(iterations) + ":" + salt + ":" + hashedPassword;
    }

    createPasswordHash(password : string, encode = false, 
                       {salt, iterations, keyLen, digest} :
                       {salt? : string, 
                        iterations? : number, 
                        keyLen? : number, 
                        digest? : string} = {}) : string {
        
        if (salt == undefined) {
            const len = this.saltChars.length;
            salt = Array.from({length: this.saltLength}, 
                () => this.saltChars.charAt(Math.floor(Math.random() * len))).join();
    
        }
        if (iterations == undefined) {
            iterations = this.iterations;
        }
        if (keyLen == undefined) {
            keyLen = this.keyLen;
        }
        if (digest == undefined) {
            digest = this.digest;
        }
        let passwordHash = pbkdf2Sync(
            password, 
            salt, 
            iterations, 
            keyLen,
            digest 
        ).toString('base64');
        if (!encode) {
            return passwordHash;
        } else {
            return this.encodePasswordHash(passwordHash, salt, iterations, keyLen, digest);
        }
    }
}
