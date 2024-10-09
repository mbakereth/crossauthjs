// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import pg from 'pg';
import { UserStorage, KeyStorage } from '../storage';
import { DbUserStorage, DbKeyStorage, DbOAuthClientStorage, DbOAuthAuthorizationStorage } from './dbstorage';
import type { DbUserStorageOptions, DbKeyStorageOptions, DbOAuthClientStorageOptions, DbOAuthAuthorizationStorageOptions } from './dbstorage';
import { PostgresPool } from './postgresconnection';

///////////////////////////////////////////////////////////////////////////
// UserStorage

/**
 * Optional parameters for {@link PostgresUserStorage}.
 * 
 * See {@link PostgresUserStorage.constructor} for definitions.
 */
export interface PostgresUserStorageOptions extends DbUserStorageOptions {
}

/**
 * Implementation of {@link UserStorage} where username and password is stored 
 * in two Postgres tables: one for non secret fields, one for secret fields.
 * 
 * The `pg` package module is used to access the database.
 * 
 */
export class PostgresUserStorage extends DbUserStorage {

    /**
     * Creates a PostgresUserStorage object, optionally overriding defaults.
     * @param pgPool the instance of the Posrgres client. 
     * @param options see {@link PostgresUserStorageOptions}.
     */
    constructor(pgPool : pg.Pool, options : PostgresUserStorageOptions = {}) {
        super(new PostgresPool(pgPool), options);
    }    
}

///////////////////////////////////////////////////////////////////////////
// KeyStorage

/**
 * Optional parameters for {@link PostgresKeyStorage}.
 * 
 * See {@link PostgresKeyStorage.constructor} for definitions.
 */
export interface PostgresKeyStorageOptions extends DbKeyStorageOptions {
}

/**
 * Implementation of {@link KeyStorage } where keys stored in a 
 * Postgres database.
 */
export class PostgresKeyStorage extends DbKeyStorage {

    /**
     * Creates a PostgresKeyStorage object, optionally overriding defaults.
     * @param pgPool the instance of the Posrgres client. 
     * @param options see {@link PostgresKeyStorageOptions}.
     */
    constructor(pgPool : pg.Pool, options : PostgresKeyStorageOptions = {}) {
        super(new PostgresPool(pgPool), options);
    }    
}

///////////////////////////////////////////////////////////////////////////
// OAuthClientStorage

/**
 * Optional parameters for {@link PostgresOAuthClientStorage}.
 * 
 * See {@link PostgresOAuthClientStorage.constructor} for definitions.
 */
export interface PostgresOAuthClientStorageOptions extends DbOAuthClientStorageOptions {
}

/**
 * Implementation of {@link OAuthClientStorage } where keys stored in a 
 * Postgres database.
 */
export class PostgresOAuthClientStorage extends DbOAuthClientStorage {

    /**
     * Creates a PostgresOAuthClientStorage object, optionally overriding defaults.
     * @param pgPool the instance of the Posrgres client. 
     * @param options see {@link PostgresOAuthClientStorageOptions}.
     */
    constructor(pgPool : pg.Pool, options : PostgresOAuthClientStorageOptions = {}) {
        super(new PostgresPool(pgPool), options);
    }    
}

///////////////////////////////////////////////////////////////////////////
// PostgresOAuthAuthorizationStorage

/**
 * Optional parameters for {@link PostgresOAuthAuthorizationStorage}.
 * 
 * See {@link PostgresOAuthClientStorage.constructor} for definitions.
 */
export interface PostgresOAuthAuthorizationStorageOptions extends DbOAuthAuthorizationStorageOptions {
}

/**
 * Implementation of {@link OAuthAuthorizationStorage } where keys stored in a 
 * Postgres database.
 */
export class PostgresOAuthAuthorizationStorage extends DbOAuthAuthorizationStorage {

    /**
     * Creates a PostgresOAuthClientStorage object, optionally overriding defaults.
     * @param pgPool the instance of the Posrgres client. 
     * @param options see {@link PostgresOAuthAuthorizationStorageOptions}.
     */
    constructor(pgPool : pg.Pool, options : PostgresOAuthAuthorizationStorageOptions = {}) {
        super(new PostgresPool(pgPool), options);
    }    
}
