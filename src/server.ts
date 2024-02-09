// storage
export { UserStorage, KeyStorage as SessionStorage } from './server/storage'; 
export { PrismaUserStorage, PrismaKeyStorage } from './server/storage/prismastorage';
export type { PrismaUserStorageOptions, PrismaKeyStorageOptions } from './server/storage/prismastorage';
export { InMemoryUserStorage, InMemoryKeyStorage } from './server/storage/inmemorystorage';
export { LdapUserStorage } from './server/storage/ldapstorage';
export type  { LdapUserStorageOptions } from './server/storage/ldapstorage';

// authenticators
export { Authenticator } from './server/auth';
export type { AuthenticationOptions, AuthenticationParameters, AuthenticatorCapabilities } from './server/auth';
export {  LocalPasswordAuthenticator } from './server/authenticators/passwordauth';
export type {  LocalPasswordAuthenticatorOptions } from './server/authenticators/passwordauth';
export {  EmailAuthenticator } from './server/authenticators/emailauth';
export type {  EmailAuthenticatorOptions } from './server/authenticators/emailauth';
export {  LdapAuthenticator } from './server/authenticators/ldapauth';
export type {  LdapAuthenticatorOptions } from './server/authenticators/ldapauth';
export { TotpAuthenticator } from './server/authenticators/totpauth';

// session management
export { SessionManager as Backend } from './server/session';
export type { CookieOptions, Cookie } from './server/cookieauth';

// API key management
export { ApiKeyManager } from './server/apikey';
export type { ApiKeyManagerOptions } from './server/apikey';

// fastify
export { FastifyServer } from './server/middleware/fastifyserver';
export type { FastifyServerOptions as FastifyCookieAuthServerOptions  } from './server/middleware/fastifyserver';

// express
export { ExpressCookieAuthServer } from './server/middleware/expressserver';
export type { ExpressCookieAuthServerOptions } from './server/middleware/expressserver';

// hasher
export { Hasher } from './server/hasher';
export type { PasswordHash } from './server/hasher';

import type { User, ApiKey } from '..';

declare module 'fastify' {
    export interface FastifyRequest {
      user: User|undefined,
      csrfToken: string|undefined,
      apiKey: ApiKey,
    }
    /*interface FastifyReply {
      myPluginProp: number
    }*/
  }

