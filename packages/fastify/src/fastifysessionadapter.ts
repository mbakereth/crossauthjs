// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { type FastifyRequest } from 'fastify';
import type { User } from '@crossauth/common';

export abstract class FastifySessionAdapter {
    abstract csrfProtectionEnabled() : boolean;
    
    abstract getCsrfToken(request : FastifyRequest) : string|undefined;

    abstract getUser(request : FastifyRequest) : User|undefined;

    /**
     * Updates a field in the session data in the key storage record,
     * 
     * The `data` field is assumed to be JSON.  Just the field with the given
     * name is updated and the rest is unchanged.
     * @param request the Fastifdy request
     * @param name the field within `data` to update
     * @param value the value to set it to
     */
    abstract updateSessionData(request : FastifyRequest, name : string, value : any) : Promise<void> ;

    /**
     * Same as `updateData` but updates many within same transaction
     * 
     * The `data` field is assumed to be JSON.  Just the field with the given
     * name is updated and the rest is unchanged.
     * @param request the Fastifdy request
     * @param dataArray data to update
     */
    abstract updateManySessionData(request : FastifyRequest, dataArray: {dataName : string, value : any}[]) : Promise<void> ;

    /**
    * Deletes a field from the session data in the key storage record,
    * 
    * The `data` field is assumed to be JSON.  Just the field with the given
    * name is updated and the rest is unchanged.
    * @param request the Fastifdy request
    * @param name the field within `data` to update
    */
    abstract deleteSessionData(request : FastifyRequest, name : string) : Promise<void>;

    /**
     * Return data stored in the session with key `name` or undefined if not present
     * @param request the Fastify request
     * @param name name of the data to fetch
     * @return an object of the data, or undefined
     */
    abstract getSessionData(request : FastifyRequest, name : string)  : Promise<{[key:string]:any}|undefined>;

}
