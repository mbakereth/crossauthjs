
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
      user: User|undefined,
      csrfToken: string|undefined,
      apiKey: ApiKey,
      accessTokenPayload: {[key:string]:any}|undefined,
      authError: string|undefined,
      authErrorDescription: string|undefined,
    }
    /*interface FastifyReply {
      myPluginProp: number
    }*/
  }

