// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
export abstract class DbPool {
    constructor() {}
    abstract connect() : Promise<DbConnection>;
    abstract parameters() : DbParameter;
}

export abstract class DbParameter {
    constructor() {}
    abstract nextParameter() : string;
}

export abstract class DbConnection {
    abstract execute(query : string, values : any[]) : Promise<{[key:string]:any}[]>;
    abstract startTransaction() : Promise<void>;
    abstract commit() : Promise<void>;
    abstract rollback() : Promise<void>;
    abstract release() : void;

}
