import type { RequestEvent } from '@sveltejs/kit';

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
    constructor() {}
    
    async loadData(event : RequestEvent) {
        if (!event.request?.body) {
            return;
        }
        const contentType = event.request.headers.get("content-type")
        if (contentType == "application/json") {
            this.jsonData = await event.request?.clone()?.json();
        } else if (contentType == "application/x-www-form-urlencoded" || contentType == "multipart/form-data") {
            this.formData = await event.request.clone().formData();
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

