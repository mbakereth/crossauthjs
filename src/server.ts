export { UserStorage, KeyStorage as SessionStorage } from './server/storage'; 

export { 
    UsernamePasswordAuthenticator, 
    HashedPasswordAuthenticator } from './server/password';
export type { UsernamePasswordAuthenticatorOptions } from './server/password';

export { Backend } from './server/backend';
export type { CookieOptions, Cookie } from './server/cookieauth';

export { PrismaUserStorage, PrismaKeyStorage } from './server/storage/prismastorage';
export type { PrismaUserStorageOptions, PrismaKeyStorageOptions as PrismaSessionStorageOptions } from './server/storage/prismastorage';
export { InMemoryUserStorage, InMemoryKeyStorage as InMemorySessionStorage } from './server/storage/inmemorystorage';

export { FastifyServer as FastifyCookieAuthServer } from './server/middleware/fastifyserver';
export type { FastifyServerOptions as FastifyCookieAuthServerOptions  } from './server/middleware/fastifyserver';

export { ExpressCookieAuthServer } from './server/middleware/expressserver';
export type { ExpressCookieAuthServerOptions } from './server/middleware/expressserver';

export { Hasher } from './server/hasher';
export type { PasswordHash } from './server/hasher';

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

