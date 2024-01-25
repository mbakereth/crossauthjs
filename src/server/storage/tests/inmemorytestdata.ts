import { InMemoryUserStorage } from '../inmemorystorage';
import { HashedPasswordAuthenticator } from '../../password';

export async function getTestUserStorage(pepper? : string|undefined) : Promise<InMemoryUserStorage> {
    let userStorage = new InMemoryUserStorage();
    let authenticator = new HashedPasswordAuthenticator(userStorage, {secret: pepper});
    await Promise.all([
        userStorage.createUser({
                username: "bob", 
                email: "bob@bob.com",
                state: "active"}, {
                password: await authenticator.createPasswordHash("bobPass123")
                } ),
                userStorage.createUser({
                    username: "alice", 
                    email: "alice@alice.com",
                    state: "active"}, {
                    password: await authenticator.createPasswordHash("alicePass123")
                    } ),
        ]);
    return userStorage;
}
