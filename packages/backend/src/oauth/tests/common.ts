import { expect } from 'vitest';
import { OAuthAuthorizationServer, type OAuthAuthorizationServerOptions } from '../authserver';
import { InMemoryOAuthClientStorage, InMemoryKeyStorage } from '../../storage/inmemorystorage';
import { OAuthClientStorage } from '../../storage';
import { Hasher } from '../../hasher';
import { OAuthClient } from '@crossauth/common';
import fs from 'node:fs';

export async function createClient() : Promise<{clientStorage : OAuthClientStorage, client : OAuthClient}> {
    const clientStorage = new InMemoryOAuthClientStorage();
    const clientSecret = await Hasher.passwordHash("DEF", {
        encode: true,
        iterations: 1000,
        keyLen: 32,
    });
    const inputClient = {
        clientId : "ABC",
        clientSecret: clientSecret,
        clientName: "Test",
        redirectUri: ["/redirectUri"],
    };
    const client = await clientStorage.createClient(inputClient);
    return {clientStorage, client};

}

export async function getAuthorizationCode({challenge, aud, persistAccessToken} : {challenge?: boolean, aud?: string, persistAccessToken? : boolean} = {}) {
    const {clientStorage, client} = await createClient();
    const privateKey = fs.readFileSync("keys/rsa-private-key.pem", 'utf8');
    let options : OAuthAuthorizationServerOptions = {
        jwtPrivateKey : privateKey,
        jwtPublicKeyFile : "keys/rsa-public-key.pem",
        validateScopes : true,
        validScopes: "read, write",
        encryptionKey: "bK9CQHte6zhbirgEFwOGzc5dx6nIkf84_FIFnbc4jk8",
        issueRefreshToken: true,
    };
    if (aud) options.resourceServers = aud;
    if (persistAccessToken) {
        options.persistAccessToken = true;
        options.keyStorage = new InMemoryKeyStorage();
    }
    const authServer = new OAuthAuthorizationServer(clientStorage, options);
    const inputState = "ABCXYZ";
    let codeChallenge : string|undefined;
    const codeVerifier = "ABC123";
    if (challenge) codeChallenge = Hasher.hash(codeVerifier);
    const {code, error, errorDescription} 
        = await authServer.authorizeGetEndpoint({
            responseType: "code", 
            clientId: client.clientId, 
            redirectUri: client.redirectUri[0], 
            scope: "read write", 
            state: inputState,
            codeChallenge: codeChallenge});
    expect(error).toBeUndefined();
    expect(errorDescription).toBeUndefined();
    return {code, client, clientStorage, authServer, keyStorage: options.keyStorage};
}

