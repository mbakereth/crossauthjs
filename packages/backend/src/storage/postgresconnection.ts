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

    async execute(query : string, values : any[] = []) : Promise<{[key:string]:any}[]> {
        let pgClient : pg.PoolClient | undefined = undefined;
        pgClient = this.pgClient;
        if (!pgClient) 
            throw new CrossauthError(ErrorCode.Configuration, "Couldn't create connection");
            if (this.pgClient) pgClient = this.pgClient;

        CrossauthLogger.logger.debug(j({msg: "Executing query", query: query}));
        let ret = await pgClient.query({text: query, values: values});
        return ret.rows;
    }

    release() : void {
        CrossauthLogger.logger.debug(j({msg: "DB release"}));
        if (this.pgClient) this.pgClient.release();

    }

    async startTransaction() : Promise<void> {
        CrossauthLogger.logger.debug(j({msg: "DB start transaction"}));
        await this.pgClient?.query('BEGIN')

    }

    async commit() : Promise<void> {
        CrossauthLogger.logger.debug(j({msg: "DB commit"}));
        await this.pgClient?.query('COMMIT')

    }

    async rollback() : Promise<void> {
        CrossauthLogger.logger.debug(j({msg: "DB rollback"}));
        await this.pgClient?.query('ROLLBACK')

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