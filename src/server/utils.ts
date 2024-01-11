import { CrossauthError, ErrorCode } from "..";

export enum ParamType {
    String = 0,
    Number,
    Boolean,
    StringArray,
}

export function setParameter(param : string,
                             type : ParamType,
                             instance : any, 
                             options : {[key:string]: any},
                             envName? : string, required : boolean=false) : void {
    const nameInEnvFile = "CROSSAUTH_"+envName;
    if (required && options[param] == undefined && !(nameInEnvFile && nameInEnvFile in process.env)) {
        throw new CrossauthError(ErrorCode.Configuration, param + " is required");
    }
    if (type == ParamType.StringArray) {
        if (options[param] != undefined) instance[param] = options[param].split(/ *, */);
        else if (envName && nameInEnvFile in process.env && process.env[nameInEnvFile] != undefined) instance[param] = (process.env[nameInEnvFile]||"")?.split(/ *, */);
        
    } else {
        if (options[param] != undefined) instance[param] = options[param];
        else if (envName && nameInEnvFile in process.env) {
            switch (type) {
                case ParamType.String:
                    instance[param] = process.env[nameInEnvFile];
                    break;
                case ParamType.Number:
                    instance[param] = Number(process.env[nameInEnvFile]);
                    break;
                    case ParamType.Boolean:
                        instance[param] = Boolean(Number(process.env[nameInEnvFile]));
                        break;
                    }
        }
    }
}

