
// fastify
export { FastifyServer } from './fastifyserver';
export type { FastifyServerOptions, FastifyErrorFn  } from './fastifyserver';
export { FastifyAuthorizationServer } from './fastifyoauthserver';
export type { FastifyAuthorizationServerOptions } from './fastifyoauthserver';
export { FastifyOAuthClient } from './fastifyoauthclient';
export type { FastifyOAuthClientOptions } from './fastifyoauthclient';
export { FastifyOAuthResourceServer } from './fastifyresserver';
export type  { FastifyOAuthResourceServerOptions } from './fastifyresserver';
import { User, ApiKey } from '@crossauth/common';

declare module 'fastify' {
    export interface FastifyRequest {
      halfUser: User|undefined,
      user: User|undefined,
      csrfToken: string|undefined,
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

