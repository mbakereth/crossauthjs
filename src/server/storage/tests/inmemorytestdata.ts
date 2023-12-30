import { InMemoryUserStorage } from '../inmemorystorage';
import { HashedPasswordAuthenticator } from '../../password';

export function getTestUserStorage() : InMemoryUserStorage {
    let userStorage = new InMemoryUserStorage();
    let authenticator = new HashedPasswordAuthenticator(userStorage);
    userStorage.addUser({
        uniqueId: 'bob',
        username: 'bob',
        passwordHash: authenticator.createPasswordHash("bobPass123", true),
    });
    userStorage.addUser({
        uniqueId: 'alice',
        username: 'alice',
        passwordHash: authenticator.createPasswordHash("bobPass123", true),
    });
    return userStorage;
}