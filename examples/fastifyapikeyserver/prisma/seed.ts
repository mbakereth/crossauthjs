import { PrismaClient } from '@prisma/client';
import { LocalPasswordAuthenticator } from '@crossauth/backend';
import { PrismaUserStorage, PrismaKeyStorage } from '@crossauth/backend';
import { ApiKeyManager } from '@crossauth/backend';
import { CrossauthLogger } from '@crossauth/common';

const prisma = new PrismaClient();
CrossauthLogger.logger.level = CrossauthLogger.Debug;

let userStorage = new PrismaUserStorage({prismaClient : prisma});

async function main() {
    await prisma.user.deleteMany();
    await prisma.apiKey.deleteMany();

    let authenticator = new LocalPasswordAuthenticator(userStorage);
    const user1 = await userStorage.createUser({
      username: "bob", 
      state: "active",
      factor1: "localpassword",
      email: "bob@bob.com",
  });
  console.log({ user1 })

  const keyStorage = new PrismaKeyStorage({prismaClient : prisma, keyTable: "apiKey"});
  const apiKeyManager = new ApiKeyManager(keyStorage);
  const {token} = await apiKeyManager.createKey("default", user1.id, {scope: ["one", "two"]});
  console.log("Key: " + token);

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

