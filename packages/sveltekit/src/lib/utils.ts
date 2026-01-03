// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import type { RequestEvent } from '@sveltejs/kit';
import { CrossauthError, ErrorCode } from '@crossauth/common';

export class ObjectIterator implements IterableIterator<[string, string]> {
    values : string[] = [];
    keys: string[] = [];
    i = 0;
    
    constructor(values : {[key:string]:string} ) {
        for (let key in values) {
            this.keys.push(key);
            this.values.push(values[key]);
        }
    }

    public next(): IteratorResult<[string,string]> {
        if (this.i == this.values.length) { return {done: true, value: ["",""]}};
        const ret = [this.keys[this.i], this.values[this.i]];
        this.i++;
        return {done: false, value: [ret[0], ret[1]]};
    }

    [Symbol.iterator]() {
         return this;
    }
}

export class KeyIterator implements IterableIterator<string> {
    values : string[] = [];
    keys: string[] = [];
    i = 0;
    
    constructor(values : {[key:string]:string} ) {
        for (let key in values) {
                this.keys.push(key);
                this.values.push(values[key]);
        }
    }

    public next(): IteratorResult<string> {
        if (this.i == this.values.length) { return {done: true, value: ["",""]}};
        const ret = [this.keys[this.i], this.values[this.i]];
        this.i++;
        return {done: false, value: ret[0]};
    }

    [Symbol.iterator]() {
         return this;
    }
}

export class JsonOrFormData {
    private formData : FormData|undefined;
    private jsonData : {[key:string] : string}|undefined;
    private clone : boolean;
    constructor(clone = true) {
        this.clone = clone;
    }
    
    async loadData(event : RequestEvent) {
        if (!event.request?.body) {
            return;
        }
        const contentType = event.request.headers.get("content-type");
        if (contentType == "application/json") {
            this.jsonData = this.clone ? await event.request?.clone()?.json() :
                await event.request?.json();
        } else if (contentType == "application/x-www-form-urlencoded" || contentType?.startsWith("multipart/form-data")) {
            this.formData = this.clone ? await event.request.clone().formData() :
                await event.request.formData();
        }

    }

    get(param : string) : string|undefined {
        if (this.jsonData) return this.jsonData[param]; 
        if (this.formData) {
            const formValue = this.formData.get(param);
            if (formValue && typeof formValue == "string") return formValue;
        }
        return undefined;
    } 

    getAsString(param : string) : string|undefined {
        return this.get(param);
    }

    getAsBoolean(param : string) : boolean|undefined {
        const val = this.get(param);
        if (val == undefined) return undefined;
        const l = val.toLowerCase();
        return l == "t" || l == "true" || l == "1" || l == "y" || l == "yes" || l == "on";
    }

    getAsNumber(param : string) : number|undefined {
        const val = this.get(param);
        if (val == undefined) return undefined;
        try {
            return Number(val);
        } catch (e) {
            throw new CrossauthError(ErrorCode.FormEntry, "Value for " + param + " is not a number");
        }
    }

    has(param : string) : boolean {
        return ((this.jsonData && param in this.jsonData)
            || this.formData && this.formData.has(param)) ?? false;
    }

    keys() : IterableIterator<string> {
        if (this.jsonData) return new KeyIterator(this.jsonData);
        if (this.formData) return this.formData.keys();
        return new KeyIterator({});
    }

    toObject() : {[key:string]:string} {
        if (this.jsonData) return this.jsonData;
        if (this.formData) {
            let data : {[key:string]:string} = {};
            for (let pair of this.formData.entries()) {
                data[pair[0]] = pair[1]?.toString()??"";
            }
            return data;
        }
        return {};
    }
}
