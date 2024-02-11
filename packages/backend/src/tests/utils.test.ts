import { test, expect } from 'vitest';
import { setParameter, ParamType } from '../utils';

interface InnerOptions {
    param10? : string,
    param11? : string,
    param12? : string,
}

interface Options {
    param1? : string,
    param2? : string,
    param3? : number,
    param4? : number,
    param5? : boolean,
    param6? : boolean,
    param7? : string,
    param8? : string,
    param9? : string,
    inner? : InnerOptions,
}

class MyClass {
    param1 : string = "ghi";
    param2 : string = "ghi";
    param3 : number = 789;
    param4 : number = 789;
    param5 : boolean = true;
    param6 : boolean = false;
    param7 : string[] = [];
    param8 : string[] = ["xyz"];
    param9 : string[] = ["xyz"];
    inner_param10 : string = "xyz";
    inner_param11 : string = "xyz";
    inner_param12 : string = "xyz";

}
test('utils.setParameter', async () => {
    process.env["CROSSAUTH_PARAM1"] = "abc"
    process.env["CROSSAUTH_PARAM2"] = "abc"
    process.env["CROSSAUTH_PARAM3"] = "123"
    process.env["CROSSAUTH_PARAM5"] = "1"
    process.env["CROSSAUTH_PARAM6"] = "0"
    process.env["CROSSAUTH_PARAM7"] = "abc,def, ghi";
    process.env["CROSSAUTH_PARAM8"] = "abc,def, ghi";
    process.env["CROSSAUTH_PARAM10"] = "abc";
    process.env["CROSSAUTH_PARAM11"] = "abc";

    let options : Options = {
        param1 : "efg",
        param3 : 456,
        param5 : true,
        param7 : "jkl,mno",
        inner: {
            param10: "efg",
        },
    }

    let instance = new MyClass();
    
    setParameter("param1", ParamType.String, instance, options, "PARAM1");
    setParameter("param2", ParamType.String, instance, options, "PARAM2");
    setParameter("param3", ParamType.Number, instance, options, "PARAM3");
    setParameter("param4", ParamType.Number, instance, options, "PARAM4");
    setParameter("param5", ParamType.Boolean, instance, options, "PARAM5");
    setParameter("param6", ParamType.Boolean, instance, options, "PARAM6");
    setParameter("param7", ParamType.StringArray, instance, options, "PARAM7");
    setParameter("param8", ParamType.StringArray, instance, options, "PARAM8");
    setParameter("param9", ParamType.StringArray, instance, options, "PARAM9");
    setParameter("inner.param10", ParamType.String, instance, options, "PARAM10");
    setParameter("inner.param11", ParamType.String, instance, options, "PARAM11");
    setParameter("inner.param12", ParamType.String, instance, options, "PARAM12");

    expect(instance.param1).toBe("efg");
    expect(instance.param2).toBe("abc");
    expect(instance.param3).toBe(456);
    expect(instance.param4).toBe(789);
    expect(instance.param5).toBe(true);
    expect(instance.param6).toBe(false);
    expect(instance.param7.length).toBe(2);
    expect(instance.param7[0]).toBe("jkl");
    expect(instance.param7[1]).toBe("mno");
    expect(instance.param8.length).toBe(3);
    expect(instance.param8[0]).toBe("abc");
    expect(instance.param8[1]).toBe("def");
    expect(instance.param8[2]).toBe("ghi");
    expect(instance.param9.length).toBe(1);
    expect(instance.param9[0]).toBe("xyz");
    expect(instance.inner_param10).toBe("efg");
    expect(instance.inner_param11).toBe("abc");
    expect(instance.inner_param12).toBe("xyz");

});
