import { type Cookies, type RequestEvent } from '@sveltejs/kit';
import cookie, { type CookieParseOptions, type CookieSerializeOptions } from 'cookie';

class HeaderIterator implements IterableIterator<[string, string]> {
    values : string[] = [];
    keys: string[] = [];
    i = 0;

    constructor(values : {[key:string]:string[]} ) {
        for (let key in values) {
            for (let j=0; j<values[key].length; ++j) {
                this.keys.push(key);
                this.values.push(values[key][j]);
            }
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

class HeaderKeyIterator implements IterableIterator<string> {
    values : string[] = [];
    keys: string[] = [];
    i = 0;

    constructor(values : {[key:string]:string[]} ) {
        for (let key in values) {
            for (let j=0; j<values[key].length; ++j) {
                this.keys.push(key);
                this.values.push(values[key][j]);
            }
        }
    }
    public next(): IteratorResult<string> {
        if (this.i == this.values.length) { return {done: true, value: ""}};
        const ret = this.keys[this.i]
        this.i++;
        return {done: false, value: ret};
    }
    [Symbol.iterator]() {
        return this;
    }
}

class HeaderValueIterator implements IterableIterator<string> {
    values : string[] = [];
    keys: string[] = [];
    i = 0;

    constructor(values : {[key:string]:string[]} ) {
        for (let key in values) {
            for (let j=0; j<values[key].length; ++j) {
                this.keys.push(key);
                this.values.push(values[key][j]);
            }
        }
    }
    public next(): IteratorResult<string> {
        if (this.i == this.values.length) { return {done: true, value: ""}};
        const ret = this.values[this.i]
        this.i++;
        return {done: false, value: ret};
    }
    [Symbol.iterator]() {
        return this;
    }
}

class FormDataIterator implements IterableIterator<[string, string]> {
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

class FormDataKeyIterator implements IterableIterator<string> {
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
        if (this.i == this.values.length) { return {done: true, value: ""}};
        const ret = this.keys[this.i];
        this.i++;
        return {done: false, value: ret};
    }
    [Symbol.iterator]() {
        return this;
    }
}

class FormDataValueIterator implements IterableIterator<string> {
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
        if (this.i == this.values.length) { return {done: true, value: ""}};
        const ret = this.values[this.i];
        this.i++;
        return {done: false, value: ret};
    }
    [Symbol.iterator]() {
        return this;
    }
}

export class MockHeaders implements Headers {
    headers : {[key:string]:string[]} = {};

    constructor(values : {[key:string]:string[]}) {
        for (let key in values) {
            this.headers[key.toLowerCase()] = values[key];
        }
    }
    append(name: string, value: string): void {
        const lname = name.toLowerCase();
        if (!(lname in this.headers)) this.headers[lname] = []
        this.headers[lname].push(value);
    }
    delete(name: string): void {
        if (name.toLowerCase() in this.headers) delete this.headers[name.toLowerCase()];
    }
    get(name: string): string | null {
        return name.toLowerCase() in this.headers ? this.headers[name.toLowerCase()][0] : null;
    }
    getSetCookie(): string[] {
        if ("set-cookie" in this.headers) return this.headers["set-cookie"];
        return [];
    }
    has(name: string): boolean {
        return name in this.headers;
    }
    set(name: string, value: string): void {
        this.headers[name] = [value];
    }
    forEach(_callbackfn: (value: string, key: string, parent: Headers) => void, _thisArg?: any): void {
        throw new Error('Method not implemented.');
    }
    entries(): IterableIterator<[string, string]> {
        //throw new Error('Method not implemented.');
       return new HeaderIterator(this.headers);
       //return this.headers.entries;
    }
    keys(): IterableIterator<string> {
        return new HeaderKeyIterator(this.headers);
    }
    values(): IterableIterator<string> {
        return new HeaderValueIterator(this.headers);
    }
    [Symbol.iterator](): IterableIterator<[string, string]> {
        return this.entries();
    }
    
}

export class MockAbortSignal {
    aborted = false;
    onabort = () => {};
    addEventListener<K>(_type: K, _listener: (this:AbortSignal, ev : Event)=>void, _options?: boolean | AddEventListenerOptions) {}
    dispatchEvent(_event: Event): boolean {return true;}
    removeEventListener<K>(_type: K, _listener: (this:AbortSignal, ev : Event)=>void, _options?: boolean | EventListenerOptions) {}
    reason : string = "Unknown reason";
    throwIfAborted() {}

}

export class MockFormData implements FormData {
    data : {[key:string] : string};
    constructor(data : {[key:string] : string}) {
        this.data = data;
    }
    static fromBody(body : string) {
        let data : {[key:string] : string} = {};
        const components = body.trim().split("&");
        for (let i=0; i<components.length; ++i) {
            const parts = components[i].split("=", 2);
            data[parts[0]] = decodeURIComponent(parts[1].replace("+", "%20"));
        }
        return new MockFormData(data);
    }

    append(name: string, value: string | Blob, _filename? : string): void {
        if (value instanceof String) {
            this.data[name] = value.toString();
        } else {
            this.data[name] = value.toString();
        }
    }

    delete(name: string): void {
        if (name in this.data) delete this.data[name];
    }

    get(name: string): FormDataEntryValue | null {
        if (name in this.data) return this.data[name];
        return null;
    }
    getAll(name: string): FormDataEntryValue[] {
        // not supporting multiple
        if (name in this.data) return [this.data[name]];
        return [];
        
    }
    has(name: string): boolean {
        return name in this.data;
    }
    set(name: string, value: string | Blob): void {
        // ignoring filename
        this.data[name] = value.toString();
    }
    forEach(_callbackfn: (value: FormDataEntryValue, key: string, parent: FormData) => void, _thisArg?: any): void {
        throw new Error('Method not implemented.');
    }
    entries(): IterableIterator<[string, FormDataEntryValue]> {
        return new FormDataIterator(this.data);
    }
    keys(): IterableIterator<string> {
        return new FormDataKeyIterator(this.data);
    }
    values(): IterableIterator<FormDataEntryValue> {
        return new FormDataValueIterator(this.data);
    }
    [Symbol.iterator](): IterableIterator<[string, FormDataEntryValue]> {
        return this.entries();
    }

}
export class MockRequest implements Request {
    bodyString : string|null;

    constructor(url : string, {
        cache = "default", 
        credentials = "same-origin", 
        destination = "document", 
        headers = {}, 
        integrity = "", 
        keepalive = false, 
        method = "GET", 
        mode = "same-origin", 
        redirect = "error", 
        referrer = "", 
        referrerPolicy = "", 
        body = null
    } : {
        cache?: RequestCache,
        credentials?: RequestCredentials;
        destination?: RequestDestination;
        headers?: {[key:string]:string[]};
        integrity?: string;
        keepalive?: boolean,
        method?: string,
        mode?: RequestMode,
        redirect?: RequestRedirect,
        referrer?: string,
        referrerPolicy?: ReferrerPolicy;
        body?  : string|null,   
    } = {}) {
        this.cache = cache,
        this.credentials = credentials,
        this.destination = destination,
        this.headers = new MockHeaders(headers),
        this.integrity = integrity,
        this.keepalive = keepalive,
        this.method = method,
        this.mode = mode,
        this.redirect = redirect,
        this.referrer = referrer,
        this.referrerPolicy = referrerPolicy,
        this.url = url,
        this.signal = new MockAbortSignal(),
        this.body = body ? new Blob([body]).stream() : null,
        this.bodyUsed = body != null,
        this.bodyString = body;
    }
    cache: RequestCache;
    credentials: RequestCredentials;
    destination: RequestDestination;
    headers: MockHeaders;
    integrity: string;
    keepalive: boolean;
    method: string;
    mode: RequestMode;
    redirect: RequestRedirect;
    referrer: string;
    referrerPolicy: ReferrerPolicy;
    signal: AbortSignal;
    url: string;
    clone(): Request {
        return new MockRequest(this.url, {
            cache: this.cache, 
            credentials: this.credentials, 
            destination: this.destination, 
            headers: this.headers.headers, 
            integrity: this.integrity, 
            keepalive: this.keepalive, 
            method: this.method, 
            mode: this.mode, 
            redirect: this.redirect, 
            referrer: this.referrer, 
            referrerPolicy: this.referrerPolicy, 
            body: this.bodyString,
        })
    };
    body: ReadableStream<Uint8Array> | null;
    bodyUsed: boolean;
    arrayBuffer(): Promise<ArrayBuffer> {
        const str = this.bodyString??"";
        var buf = new ArrayBuffer(str.length*2); // 2 bytes for each char
        var bufView = new Uint16Array(buf);
        for (var i=0, strLen=str.length; i < strLen; i++) {
            bufView[i] = str.charCodeAt(i);
        }
        return new Promise((resolve, _reject) => {
            resolve(bufView);
        });
    }
    blob(): Promise<Blob> {
        return new Promise((resolve, _reject) => {
            resolve(new Blob([this.bodyString??""]))
        });
    }
    formData(): Promise<FormData> {
        return new Promise((resolve, _reject) => {
            resolve(MockFormData.fromBody(this.bodyString??""));
        });
    }
    json(): Promise<any> {
        return new Promise((resolve, reject) => {
            try {
                resolve(JSON.parse(this.bodyString??"{}"));
            } catch {
                reject("Not valid JSON " + this.bodyString);
            }
        });
    }
    text(): Promise<string> {
        return new Promise((resolve, _reject) => {
            resolve(this.bodyString??"");
        });
    }
    
}

export class MockCookies implements Cookies {
    cookies : {[key : string] : {value : string, opts?: CookieSerializeOptions}};

    constructor(cookies : {[key : string] : {value : string, opts?: CookieSerializeOptions}}) {
        this.cookies = cookies;
    }
    get(name: string, opts?: CookieParseOptions): string | undefined {
        if (opts?.decode) {
            if (name in this.cookies) return cookie.parse(this.cookies[name].value)[name];
            return undefined;
        }
        if (name in this.cookies) return this.cookies[name].value;
        return undefined;
    }
    getAll(opts?: CookieParseOptions): Array<{ name: string; value: string }> { 
        let ret = [];
        if (!opts?.decode) {
            for (let name in this.cookies) ret.push({name: name, value: this.cookies[name].value});
        } else {
            for (let name in this.cookies) ret.push({name: name, value: cookie.parse(this.cookies[name].value)[name]});
           
        }
        return ret;
    }

    set(
		name: string,
		value: string,
		opts: CookieSerializeOptions & { path: string }
	): void {
        this.cookies[name] = {value, opts};
    }

    delete(name: string, _opts: CookieSerializeOptions & { path: string }): void {
        if (name in this.cookies) delete this.cookies[name];
    }
    serialize(
		name: string,
		value: string,
		opts: CookieSerializeOptions & { path: string }
	): string {
        return cookie.serialize(name, value, opts);
    }
}

export class MockRequestEvent<
Params extends Partial<Record<string, string>> = {[key:string]:string},
RouteId extends string | null = string
> implements RequestEvent<Params, RouteId> {

    constructor(id : RouteId, request : MockRequest, params : Params, {
        isDataRequest = false,
        isSubRequest = false,
        cookies = {},
        baseUrl = "http://example.com"
    } : {
        isDataRequest? : boolean, 
        isSubRequest? : boolean,
        cookies? : {[key : string] : {value : string, opts?: CookieSerializeOptions}},
        baseUrl? : string} = {}) {
        this.cookies = new MockCookies(cookies);
        this.fetch = fetch;
        this.locals = {};
        this.params = params;
        this.request = request;
        try {
            this.url = new URL(request.url);
        } catch (e) {
            this.url = new URL(request.url, baseUrl);
        }
        this.isDataRequest = isDataRequest;
        this.isSubRequest = isSubRequest;
        this.route = {id: id};
    }

    cookies: Cookies;
    fetch: typeof fetch;
    getClientAddress(): string {
        throw new Error('Method not implemented.');
    }
    locals: App.Locals;
    params: Params;
    platform: Readonly<App.Platform> | undefined;
    request: MockRequest;
    route: { id: RouteId; };
    setHeaders(headers: Record<string, string>): void {
        let headers2 : {[key:string]:string[]} = {};
        for (let key in headers) {
            headers2[key] = [headers[key]];
        }
        this.request.headers = new MockHeaders(headers2);
    }
    url: URL;
    isDataRequest: boolean;
    isSubRequest: boolean;

    
}

export class MockResponse implements Response {
    constructor(ok : boolean, url : string, {
        headers = {},
        redirected = false,
        status = 200,
        statusText = "OK",
        type = "basic",
        body = null,
    } : {
        headers? : {[key:string]:string[]},
        redirected? : boolean,
        status? : number,
        statusText? : string,
        type? : ResponseType,
        body? : string|null,
    }) {
        this.headers = new MockHeaders(headers);
        this.ok = ok;
        this.redirected = redirected;
        this.status = status;
        this.statusText = statusText;
        this.type = type;
        this.url = url;
        this.bodyString = body;
        this.body = body ? new Blob([body]).stream() : null,
        this.bodyUsed = body != null;
    }
    bodyString : string|null;
    headers: MockHeaders;
    ok: boolean;
    redirected: boolean;
    status: number;
    statusText: string;
    type: ResponseType;
    url: string;
    clone(): Response {
        return new MockResponse(this.ok, this.url, {
            headers: this.headers.headers,
            redirected: this.redirected,
            status: this.status,
            statusText : this.statusText,
            type: this.type,
            body: this.bodyString,
        });
    }
    body: ReadableStream<Uint8Array> | null;
    bodyUsed: boolean;
    arrayBuffer(): Promise<ArrayBuffer> {
        throw new Error('Method not implemented.');
    }
    blob(): Promise<Blob> {
        throw new Error('Method not implemented.');
    }
    formData(): Promise<FormData> {
        throw new Error('Method not implemented.');
    }
    json(): Promise<any> {
        throw new Error('Method not implemented.');
    }
    text(): Promise<string> {
        throw new Error('Method not implemented.');
    }
    
}
