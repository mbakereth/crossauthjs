import { InMemoryUserStorage } from '../inmemorystorage';
import { LocalPasswordAuthenticator } from '../../authenticators/passwordauth';

export async function getTestUserStorage(pepper? : string|undefined) : Promise<InMemoryUserStorage> {
    //let userStorage = new InMemoryUserStorage({userEditableFields: ["email", "dummyField"]});
    let userStorage = new InMemoryUserStorage({userEditableFields: ["email", "dummyField"]});
    let authenticator = new LocalPasswordAuthenticator(userStorage, {secret: pepper, pbkdf2Iterations: 1_000});
    await Promise.all([
        userStorage.createUser({
                username: "bob", 
                email: "bob@bob.com",
                state: "active",
                factor1: "localpassword"}, {
                password: await authenticator.createPasswordHash("bobPass123")
                } ),
        userStorage.createUser({
            username: "alice", 
            email: "alice@alice.com",
            state: "active",
            factor1: "localpassword"}, {
            password: await authenticator.createPasswordHash("alicePass123")
            } ),
        ]);
    return userStorage;
}
