import { InMemoryUserStorage } from '../inmemorystorage';
import { HashedPasswordAuthenticator } from '../../password';

export function getTestUserStorage(secret? : string|undefined) : InMemoryUserStorage {
    let userStorage = new InMemoryUserStorage();
    let authenticator = new HashedPasswordAuthenticator(userStorage, {secret: secret});
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