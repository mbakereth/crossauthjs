import { PrismaClient } from '@prisma/client';
import { HashedPasswordAuthenticator } from 'crossauth/server';
import { PrismaUserStorage } from 'crossauth/server';
import { CrossauthLogger } from 'crossauth';

const prisma = new PrismaClient();

let userStorage = new PrismaUserStorage({prismaClient : prisma});
let hasher = new HashedPasswordAuthenticator(userStorage);

async function main() {
    await prisma.user.deleteMany();
    await prisma.key.deleteMany();

    let authenticator = new HashedPasswordAuthenticator(userStorage);
    const user1 = await userStorage.createUser({
      username: "bob", 
      state: "active",
      email: "bob@bob.com",
  }, {
      password: await authenticator.createPasswordHash("bobPass123"), 
  });
  const user2 = await userStorage.createUser({
      username: "alice", 
      state: "active",
      email: "alice@alice.com",
  }, {
      password: await authenticator.createPasswordHash("alicePass123"), 
  });
  console.log({ user1, user2 })
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

