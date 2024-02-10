// storage
export { UserStorage, KeyStorage as SessionStorage } from './storage'; 
export { PrismaUserStorage, PrismaKeyStorage } from './storage/prismastorage';
export type { PrismaUserStorageOptions, PrismaKeyStorageOptions } from './storage/prismastorage';
export { InMemoryUserStorage, InMemoryKeyStorage } from './storage/inmemorystorage';
export { LdapUserStorage } from './storage/ldapstorage';
export type  { LdapUserStorageOptions } from './storage/ldapstorage';

// authenticators
export { Authenticator } from './auth';
export type { AuthenticationOptions, AuthenticationParameters, AuthenticatorCapabilities } from './auth';
export {  LocalPasswordAuthenticator } from './authenticators/passwordauth';
export type {  LocalPasswordAuthenticatorOptions } from './authenticators/passwordauth';
export {  EmailAuthenticator } from './authenticators/emailauth';
export type {  EmailAuthenticatorOptions } from './authenticators/emailauth';
export {  LdapAuthenticator } from './authenticators/ldapauth';
export type {  LdapAuthenticatorOptions } from './authenticators/ldapauth';
export { TotpAuthenticator } from './authenticators/totpauth';

// session management
export { SessionManager as Backend } from './session';
export type { CookieOptions, Cookie } from './cookieauth';

// API key management
export { ApiKeyManager } from './apikey';
export type { ApiKeyManagerOptions } from './apikey';

// fastify
export { FastifyServer } from './middleware/fastifyserver';
export type { FastifyServerOptions as FastifyCookieAuthServerOptions  } from './middleware/fastifyserver';

// hasher
export { Hasher } from './hasher';
export type { PasswordHash } from './hasher';

import type { User, ApiKey } from '@crossauth/common'

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

