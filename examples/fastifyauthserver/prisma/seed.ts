// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { PrismaClient } from '@prisma/client'
import { LocalPasswordAuthenticator } from '@crossauth/backend';
import {
  PrismaUserStorage,
  PrismaOAuthClientStorage,
  Crypto,
  UserStorage,
  TotpAuthenticator,
  EmailAuthenticator } from '@crossauth/backend';
import {
  CrossauthLogger,
  CrossauthError,
  ErrorCode,
  OAuthFlows,
  type UserInputFields } from '@crossauth/common';
import { authenticator as gAuthenticator } from 'otplib';

const prisma = new PrismaClient();

let userStorage = new PrismaUserStorage({prismaClient : prisma});

async function createTotpAccount(username: string,
  password: string,
  userStorage: UserStorage) {

  const userInputs : UserInputFields = {
      username: username,
      email: username + "@email.com",
      state: "active",
      factor1: "localpassword", 
      factor2: "totp", 
  };
  let lpAuthenticator = 
      new LocalPasswordAuthenticator(userStorage, {pbkdf2Iterations: 1_000});

  const totpAuth = new TotpAuthenticator("Unittest");
  totpAuth.factorName = "totp";
  const resp = await totpAuth.prepareConfiguration(userInputs);
  if (!resp?.sessionData) throw new CrossauthError(ErrorCode.UnknownError, 
      "TOTP created no session data")

  const user = await userStorage.createUser(userInputs, {
      password: await lpAuthenticator.createPasswordHash(password),
      totpsecret: resp.sessionData.totpsecret,
      } );

  return { user, totpsecret: resp.sessionData.totpsecret };
};

async function createEmailAccount(username: string,
  password: string,
  userStorage: UserStorage) {

  const userInputs : UserInputFields = {
      username: username,
      email: username + "@email.com",
      state: "active",
      factor1: "localpassword", 
      factor2: "email", 
  };
  let lpAuthenticator = 
      new LocalPasswordAuthenticator(userStorage, {pbkdf2Iterations: 1_000});

  const emailAuth = new EmailAuthenticator()
  emailAuth.factorName = "email";

  const user = await userStorage.createUser(userInputs, {
      password: await lpAuthenticator.createPasswordHash(password),
      } );

  return { user };
};

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
  /*const user2 = await userStorage.createUser({
      username: "alice", 
      state: "active",
      factor1: "localpassword",
      email: "alice@alice.com",
  }, {
      password: await authenticator.createPasswordHash("alicePass123"), 
  });*/
  const {user: user2, totpsecret} = await createTotpAccount("alice", "alicePass123", userStorage);
  const {user: user3} = await createEmailAccount("mary", "maryPass123", userStorage);
  console.log({ user1 })
  console.log({ user2 })
  console.log({ totpsecret })
  console.log({ user3 })

  const clientStorage = new PrismaOAuthClientStorage({prismaClient : prisma});
  const client_secret = await Crypto.passwordHash("DEF", {
      encode: true,
      iterations: 1000,
      keyLen: 32,
  });
  const inputClient = {
      client_id : "ABC",
      confidential: true,
      client_secret: client_secret,
      client_name: "Example Client",
      redirect_uri: ["http://localhost:3001/authzcode"],
      valid_flow: OAuthFlows.allFlows(),
  };
  const client = await clientStorage.createClient(inputClient);
  console.log(client);
  const inputClient2 = {
      client_id : "DEF",
      confidential: false,
      client_secret: null,
      client_name: "Example Public Client",
      redirect_uri: ["http://localhost:8080/authzcode.html"],
      valid_flow: OAuthFlows.allFlows(),
  };
  const client2 = await clientStorage.createClient(inputClient2);
  console.log(client2);
  const inputClient3 = {
      client_id : "GHI",
      confidential: true,
      client_secret: client_secret,
      client_name: "Python Client",
      redirect_uri: ["http://localhost:8000/authzcode"],
      valid_flow: OAuthFlows.allFlows(),
  };
  const client3 = await clientStorage.createClient(inputClient3);
  console.log(client3);
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
