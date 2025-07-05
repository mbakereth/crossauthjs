// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { PrismaClient } from '@prisma/client'
import { LocalPasswordAuthenticator } from '@crossauth/backend';
import { PrismaUserStorage, PrismaOAuthClientStorage, Crypto } from '@crossauth/backend';
import { CrossauthLogger } from '@crossauth/common';

const prisma = new PrismaClient();

let userStorage = new PrismaUserStorage({prismaClient : prisma});

async function main() {
    await prisma.user.deleteMany();
    await prisma.key.deleteMany();

    let authenticator = new LocalPasswordAuthenticator(userStorage);
    const user1 = await userStorage.createUser({
      username: "admin", 
      state: "active",
      factor1: "localpassword",
      email: "admin@admin.com",
  }, {
      password: await authenticator.createPasswordHash("adminPass123"), 
  });
  const user2 = await userStorage.createUser({
      username: "dave", 
      state: "active",
      factor1: "ldap",
      email: "dave@dave.com",
  }, {
      password: "*****", 
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
