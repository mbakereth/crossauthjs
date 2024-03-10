// Sveltekit
export { SvelteKitSessionServer } from './sveltekitsession';
export type { SvelteKitSessionServerOptions } from './sveltekitsession';
export { SvelteKitServer } from './sveltekitserver';
export type { SvelteKitServerOptions } from './sveltekitserver';
import type { User, ApiKey } from '@crossauth/common'

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
            }
            // interface PageData {}
            // interface PageState {}
            // interface Platform {}
    }
}
