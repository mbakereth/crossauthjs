import { PrismaClient } from '@prisma/client';
import { HashedPasswordAuthenticator } from 'crossauth/server';
import { PrismaUserStorage } from 'crossauth/server';

const prisma = new PrismaClient();

let userStorage = new PrismaUserStorage({prismaClient : prisma});
let hasher = new HashedPasswordAuthenticator(userStorage);

async function main() {
  await prisma.user.deleteMany();
  await prisma.key.deleteMany();

  const item1 = await prisma.user.create({
    data: {
      username : "bob",
      passwordHash: hasher.createPasswordHash("bobPass123", true),
      email: "bob@bob.com",
    },
  });
  const item2 = await prisma.user.create({
    data: {
      username : "alice",
      passwordHash: hasher.createPasswordHash("alicePass123", true),
      email: "alice@alice.com",
    },
  });
  console.log({ item1, item2 })
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

