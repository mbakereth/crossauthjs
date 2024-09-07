// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file

// fastify
export { FastifyServer } from './fastifyserver';
export type { FastifyServerOptions, FastifyErrorFn  } from './fastifyserver';
export { FastifyApiKeyServer } from './fastifyapikey';
export type { FastifyApiKeyServerOptions } from './fastifyapikey';
export { FastifySessionServer } from './fastifysession';
export type { LoginBodyType, LoginFactor2BodyType, SignupBodyType, } from './fastifysession';
export type { FastifySessionServerOptions, AuthenticatorDetails, CsrfBodyType } from './fastifysession';
export { FastifyAuthorizationServer } from './fastifyoauthserver';
export type { FastifyAuthorizationServerOptions, AuthorizeQueryType, MfaChallengeBodyType, UserAuthorizeBodyType } from './fastifyoauthserver';
export { FastifyOAuthClient } from './fastifyoauthclient';
export type { FastifyOAuthClientOptions, ClientAuthorizeQueryType, RedirectUriQueryType, PasswordQueryType, ClientCredentialsBodyType, RefreshTokenBodyType, PasswordBodyType, PasswordOtpType, PasswordOobType, DeviceCodeFlowResponse } from './fastifyoauthclient';
export { FastifyOAuthResourceServer } from './fastifyresserver';
export type  { FastifyOAuthResourceServerOptions } from './fastifyresserver';
export { FastifyAdminClientEndpoints } from './fastifyadminclientendpoints';
export type { SelectClientQueryType, CreateClientQueryType, CreateClientBodyType, UpdateClientQueryType, UpdateClientBodyType, DeleteClientParamType, UpdateClientParamType, DeleteClientQueryType,  } from './fastifyadminclientendpoints';
export { FastifyAdminEndpoints } from './fastifyadminendpoints';
export type { AdminChangePasswordBodyType, AdminCreateUserBodyType, AdminDeleteUserParamType, AdminUpdateUserBodyType } from './fastifyadminendpoints';
export { FastifyUserEndpoints } from './fastifyuserendpoints';
export type { UpdateUserBodyType, ChangeFactor2QueryType, ChangeFactor2BodyType, ChangePasswordQueryType, ChangePasswordBodyType, ConfigureFactor2QueryType, ConfigureFactor2BodyType, RequestPasswordResetQueryType, RequestPasswordResetBodyType, ResetPasswordBodyType, VerifyTokenParamType,  } from './fastifyuserendpoints';
export { FastifyUserClientEndpoints } from './fastifyuserclientendpoints';
import { User, ApiKey } from '@crossauth/common';
export { FastifySessionAdapter } from './fastifysessionadapter';

declare module 'fastify' {
    export interface FastifyRequest {
      user: User|undefined,
      csrfToken: string|undefined,
      sessionId : string|undefined,
      apiKey: ApiKey,
      authType : "cookie" | "oauth" | "oidc" | "apiKey" | undefined,
      scope: string[] | undefined,
      accessTokenPayload: {[key:string]:any}|undefined,
      idTokenPayload: {[key:string]:any}|undefined,
      authError: string|undefined,
      authErrorDescription: string|undefined,
    }
    /*interface FastifyReply {
      myPluginProp: number
    }*/
  }
