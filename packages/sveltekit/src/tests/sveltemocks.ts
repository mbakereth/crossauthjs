import { type Cookies, type RequestEvent, type MaybePromise, type ResolveOptions } from '@sveltejs/kit';
import cookie, { type CookieParseOptions, type CookieSerializeOptions } from 'cookie';

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
Params extends Partial<Record<string, string>> = {[key:string]:string},
RouteId extends string | null = string
> implements RequestEvent<Params, RouteId> {

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
    request: Request;
    route: { id: RouteId; };
    headers : {[key:string]:string}|undefined = undefined;
    setHeaders(headers: Record<string, string>): void {
        
        this.headers = headers;
    }
    url: URL;
    isDataRequest: boolean;
    isSubRequest: boolean;

    
}

export interface MockResolveOptions extends ResolveOptions {
    body? : string,
    status? : number,
    statusText? : string,
}

type MockResolve = (event : MockRequestEvent, _opts?: ResolveOptions) => MaybePromise<Response>;

export class MockResolver {
    body : string|undefined;
    status: number;
    statusText : string;

    constructor(body : string|undefined, status=200, statusText = "OK") {
        this.body = body;
        this.status = status;
        this.statusText = statusText;
        this.mockResolve = (event : MockRequestEvent, _opts?: ResolveOptions)  => {
            return new Response(this.body, {
                headers: event.headers,
                status: this.status??200,
                statusText: this.statusText??"OK",
            });
    
        
        }
    }
    mockResolve : MockResolve;
}

