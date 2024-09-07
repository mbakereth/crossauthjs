// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import pg from 'pg';
import { DbPool, DbConnection, DbParameter } from './dbconnection';
import { CrossauthLogger, j, CrossauthError, ErrorCode } from '@crossauth/common';

export class PostgresPool extends DbPool {
    private pgPool : pg.Pool;

    constructor(pgPool : pg.Pool) {
        super();
        this.pgPool = pgPool;
    }


    async connect() : Promise<DbConnection> {
        const client = await this.pgPool.connect();
        CrossauthLogger.logger.debug(j({msg: "DB connect"}));
        return new PostgresConnection(client);
    }

    parameters() : DbParameter {
        return new PostgresParameter();
    }

}

export class PostgresConnection extends DbConnection {
    private pgClient : pg.PoolClient;

    constructor(pgClient : pg.PoolClient) {
        super();
        this.pgClient = pgClient;
    }

    private crossauthErrorFromPostgresError(e : any) : CrossauthError {
        let code : string|undefined = undefined
        let detail : string|undefined = undefined
        if (e && typeof e == "object" && "code" in e && typeof e.code == "string") {
            code = e.code;
        }
        if (e && typeof e == "object" && "detail" in e && typeof e.detail == "string") {
            detail = e.detail;
        }
        if (code?.startsWith("23")) {
            const message = code + " : " + (detail ?? "Constraint violation during database insert/update");
            return new CrossauthError(ErrorCode.ConstraintViolation, message);
        }
        const message = code ? (code + " : " + (detail ?? "Constraint violation during database insert/update")) :
            "Couldn't execute database query";
        return new CrossauthError(ErrorCode.Connection, message);

    }
    
    async execute(query : string, values : any[] = []) : Promise<{[key:string]:any}[]> {

        try {
            CrossauthLogger.logger.debug(j({msg: "Executing query", query: query}));
            let ret = await this.pgClient.query({text: query, values: values});
            return ret.rows;
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            throw this.crossauthErrorFromPostgresError(e);
        }
    }

    release() : void {
        CrossauthLogger.logger.debug(j({msg: "DB release"}));
        this.pgClient.release();

    }

    async startTransaction() : Promise<void> {
        CrossauthLogger.logger.debug(j({msg: "DB start transaction"}));
        await this.pgClient.query('BEGIN')

    }

    async commit() : Promise<void> {
        CrossauthLogger.logger.debug(j({msg: "DB commit"}));
        await this.pgClient.query('COMMIT')

    }

    async rollback() : Promise<void> {
        CrossauthLogger.logger.debug(j({msg: "DB rollback"}));
        await this.pgClient.query('ROLLBACK')

    }
}


export class PostgresParameter extends DbParameter {
    private nextParam = 1;

    constructor() {
        super();
    }

    nextParameter() : string {
        return "$" + this.nextParam++;
    }
}
