// Sveltekit
export { SvelteKitSessionServer } from './sveltekitsession';
export type { SvelteKitSessionServerOptions } from './sveltekitsession';
export type { LoginReturn, LogoutReturn } from './sveltekituserendpoints';
export { SvelteKitServer } from './sveltekitserver';
export type { SvelteKitServerOptions, Resolver } from './sveltekitserver';
import type { User, ApiKey } from '@crossauth/common'
export { JsonOrFormData } from './utils';

declare global {
    namespace App {
            // interface Error {}
            interface Locals {
                user?: User,
                csrfToken?: string,
                apiKey?: ApiKey,
                accessTokenPayload?: {[key:string]:any},
                authError?: string,
                authErrorDescription?: string,
                sessionId? : string,
            }
            // interface PageData {}
            // interface PageState {}
            // interface Platform {}
    }
}
