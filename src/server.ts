export { UserStorage, UserPasswordStorage, KeyStorage as SessionStorage } from './server/storage'; 

export { 
    UsernamePasswordAuthenticator, 
    HashedPasswordAuthenticator } from './server/password';
export type { UsernamePasswordAuthenticatorOptions } from './server/password';

export { CookieSessionManager } from './server/cookieauth';
export type { CookieAuthOptions, CookieOptions, Cookie } from './server/cookieauth';

export { PrismaUserStorage, PrismaKeyStorage } from './server/storage/prismastorage';
export type { PrismaUserStorageOptions, PrismaKeyStorageOptions as PrismaSessionStorageOptions } from './server/storage/prismastorage';
export { InMemoryUserStorage, InMemoryKeyStorage as InMemorySessionStorage } from './server/storage/inmemorystorage';

export { FastifyCookieAuthServer } from './server/fastifyserver';
export type { FastifyCookieAuthServerOptions  } from './server/fastifyserver';

export { ExpressCookieAuthServer } from './server/expressserver';
export type { ExpressCookieAuthServerOptions } from './server/expressserver';

export { Hasher } from './server/hasher';
export type { HasherOptions, PasswordHash } from './server/hasher';

import type { User } from '..';

declare module 'fastify' {
    export interface FastifyRequest {
      user: User|undefined,
      csrfToken: string|undefined,
    }
    /*interface FastifyReply {
      myPluginProp: number
    }*/
  }

