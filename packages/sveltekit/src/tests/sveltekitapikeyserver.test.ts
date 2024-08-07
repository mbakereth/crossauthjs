import { MockRequestEvent } from './sveltemocks';
import { test, expect } from 'vitest';
import { makeServer } from './testshared';

test('SvelteApiKeyServer.hookWithGetNoKey', async () => {
    const { resolver, handle } = await makeServer();

    const getRequest = new Request("http://ex.com/test", {method: "GET"});
    let event = new MockRequestEvent("1", getRequest, {"param1": "value1"});

    await handle({event: event, resolve: resolver.mockResolve});
    expect(event.locals.user).toBeUndefined();
    expect(event.locals.apiKey).toBeUndefined();
});

test('SvelteApiKeyServer.validKeyAuthenticates', async () => {

    let { apiKeyManager, userStorage, resolver, handle} = await makeServer(false, true);
    expect(apiKeyManager).toBeDefined();
    if (apiKeyManager) {
        const { user } = await userStorage.getUserByUsername("bob");
        const {token} = await apiKeyManager.createKey("default", user.id);
        const getRequest = new Request("http://ex.com/test", {
            method: "GET",
            headers: {authorization: apiKeyManager.authScheme + " " + token }});
        let event = new MockRequestEvent("1", getRequest, {"param1": "value1"});
        await handle({event: event, resolve: resolver.mockResolve});
        expect(event.locals.user?.username).toBe("bob");
        expect(event.locals.apiKey).toBeDefined();    
    }
});

test('SvelteApiKeyServer.invalidKeyDoesntAuthenticate', async () => {

    let { apiKeyManager, userStorage, resolver, handle} = await makeServer(false, true);
    expect(apiKeyManager).toBeDefined();
    if (apiKeyManager) {
        const { user } = await userStorage.getUserByUsername("bob");
        const {token} = await apiKeyManager.createKey("default", user.id);
        const getRequest = new Request("http://ex.com/test", {
            method: "GET",
            headers: {authorization: apiKeyManager.authScheme + " " + token + "x"}});
        let event = new MockRequestEvent("1", getRequest, {"param1": "value1"});
        await handle({event: event, resolve: resolver.mockResolve});
        expect(event.locals.user).toBeUndefined();
        expect(event.locals.apiKey).toBeUndefined();    
    }
});
