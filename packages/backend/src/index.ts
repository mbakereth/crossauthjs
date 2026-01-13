// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
// utils
export { setParameter, ParamType } from './utils';

// storage
export { UserStorage, KeyStorage, OAuthClientStorage, OAuthAuthorizationStorage } from './storage'; 
export type { UserStorageOptions, UserStorageGetOptions, OAuthAuthorizationStorageOptions, OAuthClientStorageOptions } from './storage'; 
export { PrismaUserStorage, PrismaKeyStorage, PrismaOAuthClientStorage, PrismaOAuthAuthorizationStorage } from './storage/prismastorage';
export type { PrismaUserStorageOptions, PrismaKeyStorageOptions, PrismaOAuthAuthorizationStorageOptions, PrismaOAuthClientStorageOptions } from './storage/prismastorage';
export { InMemoryUserStorage, InMemoryKeyStorage, InMemoryOAuthClientStorage, InMemoryOAuthAuthorizationStorage } from './storage/inmemorystorage';
export type { InMemoryUserStorageOptions } from './storage/inmemorystorage';
export { LdapUserStorage } from './storage/ldapstorage';
export type  { LdapUser, LdapUserStorageOptions } from './storage/ldapstorage';
export { PostgresUserStorage, PostgresKeyStorage, PostgresOAuthClientStorage, PostgresOAuthAuthorizationStorage } from './storage/postgresstorage';
export type { PostgresUserStorageOptions, PostgresKeyStorageOptions, PostgresOAuthClientStorageOptions, PostgresOAuthAuthorizationStorageOptions } from './storage/postgresstorage';

// authenticators
export { Authenticator, PasswordAuthenticator } from './auth';
export type { AuthenticationOptions, AuthenticationParameters, AuthenticatorCapabilities } from './auth';
export {  LocalPasswordAuthenticator } from './authenticators/passwordauth';
export type {  LocalPasswordAuthenticatorOptions } from './authenticators/passwordauth';
export {  EmailAuthenticator } from './authenticators/emailauth';
export type {  EmailAuthenticatorOptions } from './authenticators/emailauth';
export {  SmsAuthenticator } from './authenticators/smsauth';
export type {  SmsAuthenticatorOptions } from './authenticators/smsauth';
export {  TwilioAuthenticator } from './authenticators/twilioauth';
export {  DummyFactor2Authenticator } from './authenticators/dummyfactor2';
export type {  DummyFactor2AuthenticatorOptions } from './authenticators/dummyfactor2';
export {  LdapAuthenticator } from './authenticators/ldapauth';
export type {  LdapAuthenticatorOptions } from './authenticators/ldapauth';
export { TotpAuthenticator } from './authenticators/totpauth';
export {  OidcAuthenticator } from './authenticators/oidcauthenticator';
export type {  OidcAuthenticatorOptions } from './authenticators/oidcauthenticator';

export { TokenEmailer } from './emailtokens';
export type { TokenEmailerOptions } from './emailtokens';

// session management
export { SessionManager } from './session';
export type { SessionManagerOptions } from './session';
export { SessionCookie, DoubleSubmitCsrfToken, toCookieSerializeOptions } from './cookieauth';
export type { CookieOptions, Cookie, DoubleSubmitCsrfTokenOptions, SessionCookieOptions } from './cookieauth';

// API key management
export { ApiKeyManager } from './apikey';
export type { ApiKeyManagerOptions } from './apikey';

// hasher
export { Crypto } from './crypto';
export type { PasswordHash, HashOptions } from './crypto';

// OAuth
export { OAuthAuthorizationServer } from './oauth/authserver';
export type { OAuthAuthorizationServerOptions } from './oauth/authserver';
export { OAuthClientBackend } from './oauth/client';
export type { OAuthClientOptions } from './oauth/client';
export { OAuthResourceServer } from './oauth/resserver';
export type{ OAuthResourceServerOptions } from './oauth/resserver';
export { OAuthTokenConsumer } from './oauth/tokenconsumer';
export type { OAuthTokenConsumerOptions } from './oauth/tokenconsumer';
export { OAuthClientManager } from './oauth/clientmanager';
export type { OAuthClientManagerOptions } from './oauth/clientmanager';
export type { TokenMergeFn, UpstreamClientOptions} from './oauth/authserver'
