import { PrismaClient } from '@prisma/client';
import { HashedPasswordAuthenticator } from 'crossauth/server';
import { PrismaUserStorage } from 'crossauth/server';

const prisma = new PrismaClient();

let userStorage = new PrismaUserStorage({prismaClient : prisma});
let hasher = new HashedPasswordAuthenticator(userStorage);

async function main() {
    await prisma.user.deleteMany();
    await prisma.key.deleteMany();

    const user1 = await userStorage.createUser(
        "bob",
        await hasher.createPasswordHash("bobPass123"),
        {"email": "bob@bob.com", "emailVerified": true}
    );
    const user2 = await userStorage.createUser(
      "alice",
      await hasher.createPasswordHash("alicePass123"),
      {"email": "alice@alice.com", "emailVerified": true}
  );
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

