import { InMemoryUserStorage } from '../inmemorystorage';
import { HashedPasswordAuthenticator } from '../../password';

export async function getTestUserStorage(pepper? : string|undefined) : Promise<InMemoryUserStorage> {
    let userStorage = new InMemoryUserStorage();
    let authenticator = new HashedPasswordAuthenticator(userStorage, {secret: pepper});
    await Promise.all([
        userStorage.createUser(
            "bob", 
            await authenticator.createPasswordHash("bobPass123"),
            {"dummyField": "abc", "email": "bob@bob.com"}),
        userStorage.createUser(
            "alice", 
            await authenticator.createPasswordHash("alicePass"),
            {"dummyField": "abc", "email": "alice@alice.com"})]);
    return userStorage;
}