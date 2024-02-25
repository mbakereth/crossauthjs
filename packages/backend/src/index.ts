// storage
export { UserStorage, KeyStorage } from './storage'; 
export { PrismaUserStorage, PrismaKeyStorage, PrismaOAuthClientStorage, PrismaOAuthAuthorizationStorage } from './storage/prismastorage';
export type { PrismaUserStorageOptions, PrismaKeyStorageOptions, PrismaOAuthAuthorizationStorageOptions } from './storage/prismastorage';
export { InMemoryUserStorage, InMemoryKeyStorage, InMemoryOAuthAuthorizationStorage } from './storage/inmemorystorage';
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
export { FastifyAuthorizationServer } from './middleware/fastifyoauthserver';
export type { FastifyAuthorizationServerOptions } from './middleware/fastifyoauthserver';
export { FastifyOAuthClient } from './middleware/fastifyoauthclient';
export type { FastifyOAuthClientOptions } from './middleware/fastifyoauthclient';
export { FastifyOAuthResourceServer } from './middleware/fastifyresserver';
export type  { FastifyOAuthResourceServerOptions } from './middleware/fastifyresserver';

// hasher
export { Hasher } from './hasher';
export type { PasswordHash } from './hasher';

// OAuth
export { OAuthAuthorizationServer } from './oauth/authserver';
export type { OAuthAuthorizationServerOptions } from './oauth/authserver';
export { OAuthResourceServer } from './oauth/resserver';
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

