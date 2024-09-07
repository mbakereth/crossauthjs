// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { UserStorage, KeyStorage } from '../storage';
import { DbUserStorage, DbKeyStorage, DbOAuthClientStorage, DbOAuthAuthorizationStorage } from './dbstorage';
import type { DbUserStorageOptions, DbKeyStorageOptions, DbOAuthClientStorageOptions, DbOAuthAuthorizationStorageOptions } from './dbstorage';
import { SqlitePool, type SqlPoolOptions } from './sqliteconnection';

///////////////////////////////////////////////////////////////////////////
// UserStorage

/**
 * Optional parameters for {@link PostgresUserStorage}.
 * 
 * See {@link SqliteUserStorage.constructor} for definitions.
 */
export interface SqliteUserStorageOptions extends DbUserStorageOptions, SqlPoolOptions {
}

/**
 * Implementation of {@link UserStorage} where username and password is stored 
 * in two Sqlite tables: one for non secret fields, one for secret fields.
 * 
 * The `pg` package module is used to access the database.
 * 
 */
export class SqliteUserStorage extends DbUserStorage {

    /**
     * Creates a PostgresUserStorage object, optionally overriding defaults.
     * @param filename the Sqlite database file
     * @param options see {@link PostgresUserStorageOptions}.
     */
    constructor(filename : string, options : SqliteUserStorageOptions = {}) {
        super(new SqlitePool(filename, options), options);
    }    
}

///////////////////////////////////////////////////////////////////////////
// KeyStorage

/**
 * Optional parameters for {@link PostgresKeyStorage}.
 * 
 * See {@link SqliteKeyStorage.constructor} for definitions.
 */
export interface SqliteKeyStorageOptions extends DbKeyStorageOptions, SqlPoolOptions {
}

/**
 * Implementation of {@link KeyStorage } where keys stored in a 
 * Sqlite database.
 */
export class SqliteKeyStorage extends DbKeyStorage {

    /**
     * Creates a SqliteKeyStorage object, optionally overriding defaults.
     * @param filename the Sqlite database file
     * @param options see {@link SqliteKeyStorageOptions}.
     */
    constructor(filename : string, options : SqliteKeyStorageOptions = {}) {
        super(new SqlitePool(filename, options), options);
    }    
}

///////////////////////////////////////////////////////////////////////////
// OAuthClientStorage

/**
 * Optional parameters for {@link SqliteOAuthClientStorage}.
 * 
 * See {@link SqliteOAuthClientStorage.constructor} for definitions.
 */
export interface SqliteOAuthClientStorageOptions extends DbOAuthClientStorageOptions, SqlPoolOptions {
}

/**
 * Implementation of {@link OAuthClientStorage } where keys stored in a 
 * Sqlite database.
 */
export class SqliteOAuthClientStorage extends DbOAuthClientStorage {

    /**
     * Creates a PostgresOAuthStorage object, optionally overriding defaults.
     * @param filename the Sqlite database file
     * @param options see {@link SqliteOAuthClientStorageOptions}.
     */
    constructor(filename : string, options : SqliteOAuthClientStorageOptions = {}) {
        super(new SqlitePool(filename, options), options);
    }    
}

///////////////////////////////////////////////////////////////////////////
// SqliteOAuthAuthorizationStorage

/**
 * Optional parameters for {@link SqliteOAuthAuthorizationStorage}.
 * 
 * See {@link SqliteOAuthAuthorization.constructor} for definitions.
 */
export interface SqliteOAuthAuthorizationStorageOptions extends DbOAuthAuthorizationStorageOptions, SqlPoolOptions {
}

/**
 * Implementation of {@link OAuthAuthorization } where keys stored in a 
 * Sqlite database.
 */
export class SqliteOAuthAuthorizationStorage extends DbOAuthAuthorizationStorage {

    /**
     * Creates a PostgresOAuthStorage object, optionally overriding defaults.
     * @param filename the Sqlite database file
     * @param options see {@link SqliteOAuthAuthorizationStorageOptions}.
     */
    constructor(filename : string, options : SqliteOAuthAuthorizationStorageOptions = {}) {
        super(new SqlitePool(filename, options), options);
    }    
}
