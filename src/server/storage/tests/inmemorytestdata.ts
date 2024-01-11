import { InMemoryUserStorage } from '../inmemorystorage';
import { HashedPasswordAuthenticator } from '../../password';

export function getTestUserStorage(pepper? : string|undefined) : InMemoryUserStorage {
    let userStorage = new InMemoryUserStorage();
    let authenticator = new HashedPasswordAuthenticator(userStorage, {pepper: pepper});
    userStorage.addUser({
        id: 'bob',
        username: 'bob',
        passwordHash: authenticator.createPasswordHash("bobPass123", true),
        email: "bob@bob.com",
        dummyField: "abc",
    });
    userStorage.addUser({
        id: 'alice',
        username: 'alice',
        passwordHash: authenticator.createPasswordHash("bobPass123", true),
        email: "alice@alice.com",
        dummyField: "def",
    });
    return userStorage;
}