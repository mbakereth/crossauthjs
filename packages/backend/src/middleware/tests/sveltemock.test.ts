import { MockRequest, MockRequestEvent, MockHeaders } from './sveltemocks';

test('SvelteMocks.MockHeaders', async () => {

    const headers = new MockHeaders({
        "Authorization": ["Bearer XYZ"],
    });
    expect(headers.get("authorization")).toBe("Bearer XYZ");
    let values = [...headers.values()];
    expect(values.length).toBe(1);
    expect(values[0]).toBe("Bearer XYZ");
    let keys = [...headers.keys()];
    expect(keys.length).toBe(1);
    expect(keys[0]).toBe("authorization");
    let entries = [...headers.entries()];
    expect(entries.length).toBe(1);
    expect(entries[0].length).toBe(2);
    expect(entries[0][0]).toBe("authorization");
    expect(entries[0][1]).toBe("Bearer XYZ");

    headers.append("Set-Cookie", "name1=value1");
    values = [...headers.values()];
    expect(values.length).toBe(2);

    headers.append("Set-Cookie", "name2=value2");
    values = [...headers.values()];
    expect(values.length).toBe(3);

    let cookies = headers.getSetCookie();
    expect(cookies.length).toBe(2);
});

test('SvelteMocks.RequestEvent', async () => {

    const request = new MockRequest("/test");
    const requestEvent = new MockRequestEvent("1", request, {"param1": "value1"});
    expect(requestEvent.route.id).toBe("1");
    expect(requestEvent.params["param1"]).toBe("value1");
});
