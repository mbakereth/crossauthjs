import { InMemoryUserStorage } from '../inmemorystorage';
import { HashedPasswordAuthenticator } from '../../password';

export function getTestUserStorage(pepper? : string|undefined) : InMemoryUserStorage {
    let userStorage = new InMemoryUserStorage();
    let authenticator = new HashedPasswordAuthenticator(userStorage, {pepper: pepper});
    userStorage.createUser(
        "bob", 
        authenticator.createPasswordHash("bobPass123", true), 
        {"dummyField": "abc", "email": "bob@bob.com"});
    userStorage.createUser(
        "alice", 
        authenticator.createPasswordHash("alicePass123", true), 
        {"dummyField": "abc", "email": "alice@alice.com"});
    return userStorage;
}