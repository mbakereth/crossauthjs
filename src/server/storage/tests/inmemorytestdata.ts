import { InMemoryUserStorage } from '../inmemorystorage';
import { HashedPasswordAuthenticator } from '../../password';

export function getTestUserStorage(pepper? : string|undefined) : InMemoryUserStorage {
    let userStorage = new InMemoryUserStorage();
    let authenticator = new HashedPasswordAuthenticator(userStorage, {pepper: pepper});
    userStorage.addUser({
        id: 'bob',
        username: 'bob',
        passwordHash: authenticator.createPasswordHash("bobPass123", true),
        dummyField: "abc",
    });
    userStorage.addUser({
        id: 'alice',
        username: 'alice',
        passwordHash: authenticator.createPasswordHash("bobPass123", true),
        dummyField: "def",
    });
    return userStorage;
}