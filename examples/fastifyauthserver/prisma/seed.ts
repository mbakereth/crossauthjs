import { PrismaClient } from '../src/generated/client/index.js';
import { LocalPasswordAuthenticator } from '@crossauth/backend';
import { PrismaUserStorage, PrismaOAuthClientStorage, Hasher } from '@crossauth/backend';
import { CrossauthLogger, OAuthFlows } from '@crossauth/common';

const prisma = new PrismaClient();

let userStorage = new PrismaUserStorage({prismaClient : prisma});

async function main() {
    await prisma.user.deleteMany();
    await prisma.key.deleteMany();
    await prisma.oAuthClient.deleteMany();

    let authenticator = new LocalPasswordAuthenticator(userStorage);
    const user1 = await userStorage.createUser({
      username: "bob", 
      state: "active",
      factor1: "localpassword",
      email: "bob@bob.com",
  }, {
      password: await authenticator.createPasswordHash("bobPass123"), 
  });
  const user2 = await userStorage.createUser({
      username: "alice", 
      state: "active",
      factor1: "localpassword",
      email: "alice@alice.com",
  }, {
      password: await authenticator.createPasswordHash("alicePass123"), 
  });
  console.log({ user1, user2 })

  const clientStorage = new PrismaOAuthClientStorage({prismaClient : prisma});
  const clientSecret = await Hasher.passwordHash("DEF", {
      encode: true,
      iterations: 1000,
      keyLen: 32,
  });
  const inputClient = {
      clientId : "ABC",
      confidential: true,
      clientSecret: clientSecret,
      clientName: "Example Client",
      redirectUri: ["http://localhost:3001/authzcode"],
      validFlow: OAuthFlows.allFlows(),
  };
  const client = await clientStorage.createClient(inputClient);
  console.log(client);
}
main()
  .then(async () => {
    await prisma.$disconnect()
  })
  .catch(async (e) => {
    console.error(e)
    await prisma.$disconnect()
    process.exit(1)
  })

