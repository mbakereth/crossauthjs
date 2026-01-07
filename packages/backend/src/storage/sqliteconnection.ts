// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import sqlite3 from 'sqlite3';
import { DbPool, DbConnection, DbParameter } from './dbconnection';
import { CrossauthLogger, j, CrossauthError, ErrorCode } from '@crossauth/common';
import { setParameter, ParamType } from '../utils';

export interface SqlPoolOptions {
    /** Sqlite doesn't have a native date/time/timestamp format.
     * List any fields you have in your user or usersecrets models here
     * and they will be converted upon insert/update/select
     */
    dateFields? : string[];

}

export class SqlitePool extends DbPool {
    private database : sqlite3.Database;
    private dateFields : string[] = [];

    constructor(filename : string, options : SqlPoolOptions = {}) {
        super();
        this.database = new sqlite3.Database(filename);
        setParameter("dateFields", ParamType.JsonArray, this, options, "SQLITE_DATE_FIELDS");
    }


    async connect() : Promise<DbConnection> {
        return new SqliteConnection(this.database, this.dateFields);
    }

    parameters() : DbParameter {
        return new PostgresParameter();
    }

}

export class SqliteConnection extends DbConnection {
    private database : sqlite3.Database;
    dateFields? : string[];

    constructor(database : sqlite3.Database, dateFields : string[]) {
        super();
        this.database = database;
        this.dateFields = dateFields;
    }

    private crossauthErrorFromSqliteError(e : any) : CrossauthError {
        let code : string|undefined = undefined
        let detail : string|undefined = undefined
        if (e && typeof e == "object" && "code" in e && typeof e.code == "string") {
            code = e.code;
        }
        if (e && typeof e == "object" && "detail" in e && typeof e.detail == "string") {
            detail = e.detail;
        }
        if (code == 'SQLITE_CONSTRAINT') {
            const message = code + " : " + (detail ?? "Constraint violation during database insert/update");
            return new CrossauthError(ErrorCode.ConstraintViolation, message);
        }
        const message = code ? (code + " : " + (detail ?? "Constraint violation during database insert/update")) :
            "Couldn't execute database query";
        return new CrossauthError(ErrorCode.Connection, message);

    }

    async execute(query : string, values : any[] = []) : Promise<{[key:string]:any}[]> {
        try {
            let convertedValues = values.map((v : any) => {
                if (v instanceof Date) {
                    return v.getTime();
                } else {
                    return v;
                }
            });
            CrossauthLogger.logger.debug(j({msg: "Executing query", query: query}));
            let ret :{[key:string]: any}[] = await new Promise((resolve,reject)=>{
                this.database.all(query, convertedValues,
                    (err:any, rows:{[key:string]: any}[]|undefined)=>{
                        if(err) reject(err);
                        if (!rows) resolve([]);
                        else {
                            let convertedRows = rows.map((v: any) => {
                                if (typeof v == "object") {
                                    for (let k in v) {
                                        if (this.dateFields?.includes(k)) {
                                            v[k] = new Date(Number(v[k]));
                                        }
                                    }
                                }
                                return v;
                            });


                            resolve(convertedRows);
                        }
                })
            });
            return ret;
    
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            throw this.crossauthErrorFromSqliteError(e);
        }
    }

    release() : void {
        CrossauthLogger.logger.debug(j({msg: "DB release"}));

    }

    async startTransaction() : Promise<void> {
        CrossauthLogger.logger.debug(j({msg: "DB start transaction"}));
        await new Promise((resolve,reject)=>{
            this.database.run("BEGIN", [],
                (err:any, rows:{[key:string]: any}[]|undefined)=>{
                    if(err) reject(err);
                    resolve(rows);
            })
        });

    }

    async commit() : Promise<void> {
        CrossauthLogger.logger.debug(j({msg: "DB commit"}));
        await new Promise((resolve,reject)=>{
            this.database.run("COMMIT", [],
                (err:any, rows:{[key:string]: any}[]|undefined)=>{
                    if(err) reject(err);
                    resolve(rows);
            })
        });

    }

    async rollback() : Promise<void> {
        CrossauthLogger.logger.debug(j({msg: "DB rollback"}));
        await new Promise((resolve,reject)=>{
            this.database.run("ROLLBACK", [],
                (err:any, rows:{[key:string]: any}[]|undefined)=>{
                    if(err) reject(err);
                    resolve(rows);
            })
        });

    }
}


export class PostgresParameter extends DbParameter {

    constructor() {
        super();
    }

    nextParameter() : string {
        return "?";
    }
}
