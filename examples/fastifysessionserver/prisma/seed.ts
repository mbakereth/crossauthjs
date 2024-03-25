import { PrismaClient } from '@prisma/client'
import { LocalPasswordAuthenticator } from '@crossauth/backend';
import { PrismaUserStorage } from '@crossauth/backend';
import { CrossauthLogger } from '@crossauth/common';

const prisma = new PrismaClient();

let userStorage = new PrismaUserStorage({prismaClient : prisma});

async function main() {
    await prisma.user.deleteMany();
    await prisma.key.deleteMany();

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
      factor2: "email",
      email: "alice@alice.com",
  }, {
      password: await authenticator.createPasswordHash("alicePass123"), 
  });
  const admin = await userStorage.createUser({
    username: "admin", 
    state: "active",
    factor1: "localpassword",
    email: "admin@admin.com",
    admin: true,
}, {
    password: await authenticator.createPasswordHash("adminPass123"), 
});
console.log({ user1, user2, admin })
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

