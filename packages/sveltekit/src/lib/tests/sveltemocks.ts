// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { type Cookies, type ResolveOptions } from '@sveltejs/kit';
import cookie, { type CookieParseOptions, type CookieSerializeOptions } from 'cookie';

export interface AppTypes {
    // These are all functions so that we can leverage function overloads to get the correct type.
    // Using the return types directly would error with a "not the same type" error.
    // https://www.typescriptlang.org/docs/handbook/declaration-merging.html#merging-interfaces
    RouteId(): string;
    RouteParams(): Record<string, Record<string, string>>;
    LayoutParams(): Record<string, Record<string, string>>;
    Pathname(): string;
    ResolvedPathname(): string;
    Asset(): string;
}


declare type RouteId1 = string
export type LayoutParams<T extends RouteId1> = T extends keyof ReturnType<AppTypes['LayoutParams']>
    ? ReturnType<AppTypes['LayoutParams']>[T]
    : Record<string, never>;

export type MaybePromise<T> = T | Promise<T>;

export class MockCookies implements Cookies {
    cookies : {[key : string] : {value : string, opts?: CookieSerializeOptions}};

    constructor(cookies : {[key : string] : {value : string, opts?: CookieSerializeOptions}}, req? : Request) {
        this.cookies = cookies;
        if (req ) {
            const reqCookiesString = req.headers.get("cookie");
            if (reqCookiesString) {
                const reqCookies = reqCookiesString.split(";");
                for (let reqCookie of reqCookies) {
                    const pair = reqCookie.trim().split("=", 2);
                    if (pair.length == 2) {
                        const name = decodeURIComponent(pair[0]);
                        const value = decodeURIComponent(pair[1]);
                        this.cookies[name] = {value: value};
                    }
                }
            }
        }
    }

    get(name: string, opts?: CookieParseOptions): string | undefined {
        // opts is ignored on the assumption 
        const decoder = opts?.decode??"decodeURIComponent";
        if (name in this.cookies) return eval(decoder+"('"+this.cookies[name].value+"')");
        return undefined;
    }
    getAll(opts?: CookieParseOptions): Array<{ name: string; value: string }> { 
        const decoder = opts?.decode??"decodeURIComponent";
        let ret = [];
        for (let name in this.cookies) ret.push({name: name, value: eval(decoder+"('"+this.cookies[name].value+"')")});
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
	Params extends LayoutParams<'/'> = LayoutParams<'/'>,
	RouteId extends RouteId1 | null = RouteId1 | null
> {

    constructor(id : RouteId, request : Request, params : Params, {
        isDataRequest = false,
        isSubRequest = false,
        cookies = {},
        baseUrl = "http://example.com"
    } : {
        isDataRequest? : boolean, 
        isSubRequest? : boolean,
        cookies? : {[key : string] : {value : string, opts?: CookieSerializeOptions}},
        baseUrl? : string} = {}) {
        this.cookies = new MockCookies(cookies, request);
        this.fetch = fetch;
        this.locals = {authType: undefined};
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
        this.tracing = {enabled: false, root: "", current: ""}
        this.isRemoteRequest = false;
    }

    cookies: Cookies;
    fetch: typeof fetch;
    getClientAddress(): string {
        throw new Error('Method not implemented.');
    }
    locals: App.Locals;
    params: Params;
    platform: Readonly<App.Platform> | undefined;
    request: Request;
    route: { id: RouteId; };
    headers? : {[key:string]:string}|undefined = undefined;
    setHeaders(headers: Record<string, string>): void {
        
        this.headers = headers;
    }
    url: URL;
    isDataRequest: boolean;
    isSubRequest: boolean;

    tracing: { enabled: boolean; root: any; current: any; }
    isRemoteRequest: boolean;
}

export interface MockResolveOptions extends ResolveOptions {
    body? : string,
    status? : number,
    statusText? : string,
}

type MockResolve = (event : MockRequestEvent<Record<string, string>, string | null>, _opts?: ResolveOptions|undefined) => MaybePromise<Response>;

export class MockResolver {
    body : string|undefined;
    status: number;
    statusText : string;

    constructor(body : string|undefined, status=200, statusText = "OK") {
        this.body = body;
        this.status = status;
        this.statusText = statusText;        
        this.mockResolve = (event : MockRequestEvent, _opts?: ResolveOptions)  => {
            let headers : [string,string][] = [];
            for (let header in event.headers) {
                headers.push([header, event.headers[header]]);
            }
            let cookies = event.cookies.getAll();
            if (cookies && cookies.length > 0) {
                for (let cookie of cookies) {
                    headers.push(["set-cookie", cookie.name + "=" + cookie.value]);
                }
            }
            return new Response(this.body, {
                headers: headers,
                status: this.status??200,
                statusText: this.statusText??"OK",
            });
    
        
        }
    }
    mockResolve : MockResolve;
}
