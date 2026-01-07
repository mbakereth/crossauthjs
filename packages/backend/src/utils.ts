// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { CrossauthError, ErrorCode } from '@crossauth/common';

/**
 * Type of parameter that can be parsed from an option value or 
 * environment variable
 */
export enum ParamType {
    String = 0,
    Number,
    Boolean,
    Json,
    JsonArray,
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

function setFromOption(instance : any, param : string, options : {[key:string]: any}) {
    const value = getOption(param, options);
    instance[param.replace(".", "_")] = value;
}

function setFromEnv(instance : any, param : string, type : ParamType, nameInEnvFile : string) {
    const key = param.replace(".", "_");
    switch (type) {
        case ParamType.String:
            instance[key] = process.env[nameInEnvFile]=="null" ? null : process.env[nameInEnvFile];
            break;
        case ParamType.Number:
            instance[key] = process.env[nameInEnvFile]=="null" ? null : Number(process.env[nameInEnvFile]);
            break;
        case ParamType.Boolean:
            instance[key] = ["1", "true"].includes(process.env[nameInEnvFile]?.toLowerCase()??"");
            break;
        case ParamType.Json:
            instance[key] = JSON.parse((process.env[nameInEnvFile]??"{}"));
            break;
        case ParamType.JsonArray:
            instance[key] = JSON.parse((process.env[nameInEnvFile]??"[]"));
            break;
        }
}

/**
 * Sets an instance variable in the passed object from the passed options
 * object and environment variable.
 * 
 * If the named parameter exists in the options object, that the instance
 * variable is set to that value.  Otherwise if the named environment
 * variable exists, it is set from that.  Otherwise, the instance variable
 * is not updarted.
 * 
 * @param param the name of the parameter in the options variable and the
 *        name of the variable in the instance
 * @param type The type of variable.  If the value is `StringArray` or `Json`,
 *         both the option and the environment variable value should be a
 *         string, which will be parsed.
 * @param instance options present in the `options` or environment variables
 *        will be set oin a corresponding instance variable in this
 *        class or object.
 * @param options object containing options as key/value pairs
 * @param envName name of environment variable
 * @param required if true, an exception will be thrown if the variable is 
 *        not present in `options` or the environment variable
 * @throws {@link @crossauth/common!CrossauthError} with 
 *         {@link @crossauth/common!ErrorCode} `Configuration` if `required`
 *         is set but the option was not present, or if there was a parsing
 *         error.
 */
export function setParameter(param : string,
                             type : ParamType,
                             instance : any, 
                             options : {[key:string]: any},
                             envName? : string, required : boolean=false) : void {
    const nameInEnvFile = "CROSSAUTH_"+envName;
    if (required && !hasOption(param, options) && !(nameInEnvFile && nameInEnvFile in process.env)) {
        throw new CrossauthError(ErrorCode.Configuration, param + " is required");
    }
        if (hasOption(param, options)) setFromOption(instance, param, options);
        else if (envName && nameInEnvFile in process.env && 
            process.env[nameInEnvFile] != undefined) {
            setFromEnv(instance, param, type, nameInEnvFile);     
        }
}
