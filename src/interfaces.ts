export interface SessionKey {
    value : string,
    dateCreated : Date,
    expires : Date | undefined
}

export interface User {
    uniqueId : string | number,
    username : string,
    [ key : string ] : any,
}

export interface UserWithPassword extends User {
    passwordHash : string
}

