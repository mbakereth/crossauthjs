import type { RequestEvent } from '@sveltejs/kit';
import type { User } from '@crossauth/common';

export abstract class SvelteKitSessionAdapter {
    abstract csrfProtectionEnabled() : boolean;
    
    abstract getCsrfToken(event : RequestEvent) : string|undefined;

    abstract getUser(event : RequestEvent) : User|undefined;

    /**
     * Updates a field in the session data in the key storage record,
     * 
     * The `data` field is assumed to be JSON.  Just the field with the given
     * name is updated and the rest is unchanged.
     * @param event the Sveltekit request event
     * @param name the field within `data` to update
     * @param value the value to set it to
     */
    abstract updateSessionData(event : RequestEvent, name : string, value : {[key:string]:any}) : Promise<void> ;


    /**
     * Same as `updateData` but updates many within same transaction
     * 
     * The `data` field is assumed to be JSON.  Just the field with the given
     * name is updated and the rest is unchanged.
     * @param request the Fastifdy request
     * @param dataArray data to update
     */
    abstract updateManySessionData(event : RequestEvent, dataArray: {dataName : string, value : {[key:string]:any}}[]) : Promise<void> ;

    /**
    * Deletes a field from the session data in the key storage record,
    * 
    * The `data` field is assumed to be JSON.  Just the field with the given
    * name is updated and the rest is unchanged.
     * @param event the Sveltekit request event
    * @param name the field within `data` to update
    */
    abstract deleteSessionData(event : RequestEvent, name : string) : Promise<void>;

    /**
     * Return data stored in the session with key `name` or undefined if not present
     * @param event the Sveltekit request event
     * @param name name of the data to fetch
     * @return an object of the data, or undefined
     */
    abstract getSessionData(event : RequestEvent, name : string)  : Promise<{[key:string]:any}|undefined>;

}