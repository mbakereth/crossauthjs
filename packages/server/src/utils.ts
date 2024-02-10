import { CrossauthError, ErrorCode } from '@crossauth/common';

export enum ParamType {
    String = 0,
    Number,
    Boolean,
    StringArray,
}

function getOption(param : string, options: {[key:string]: any}) {
    let parts = param.split(".");
    let obj : {[key:string]: any} | any = options;
    for (let i in parts) {
        const part = parts[i];
        if (!(part in obj) || obj[part] == undefined) return undefined;
        obj = obj[part];
    }
    return obj;
}

function hasOption(param : string, options: {[key:string]: any}) : boolean {
    let parts = param.split(".");
    let obj : {[key:string]: any} | any = options;
    for (let i in parts) {
        const part = parts[i];
        if (!(part in obj) || obj[part] == undefined) return false;
        obj = obj[part];
    }
    return true;
}

function setFromOption(instance : any, param : string, type : ParamType, options : {[key:string]: any}) {
    const value = getOption(param, options);
    instance[param.replace(".", "_")] = type == ParamType.StringArray ? value.split(/ *, */) : value;
}

function setFromEnv(instance : any, param : string, type : ParamType, nameInEnvFile : string) {
    const key = param.replace(".", "_");
    switch (type) {
        case ParamType.StringArray:
            instance[key] = (process.env[nameInEnvFile]||"")?.split(/ *, */);
            break;
        case ParamType.String:
            instance[key] = process.env[nameInEnvFile];
            break;
        case ParamType.Number:
            instance[key] = Number(process.env[nameInEnvFile]);
            break;
        case ParamType.Boolean:
            instance[key] = ["1", "true"].includes(process.env[nameInEnvFile]?.toLowerCase()||"");
            break;
    }
}


export function setParameter(param : string,
                             type : ParamType,
                             instance : any, 
                             options : {[key:string]: any},
                             envName? : string, required : boolean=false) : void {
    const nameInEnvFile = "CROSSAUTH_"+envName;
    if (required && !hasOption(param, options) && !(nameInEnvFile && nameInEnvFile in process.env)) {
        throw new CrossauthError(ErrorCode.Configuration, param + " is required");
    }
        if (hasOption(param, options)) setFromOption(instance, param, type, options);
        else if (envName && nameInEnvFile in process.env && process.env[nameInEnvFile] != undefined) setFromEnv(instance, param, type, nameInEnvFile);     
}
