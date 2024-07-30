// Sveltekit
export { SvelteKitSessionServer } from './sveltekitsession';
export type { 
    SvelteKitSessionServerOptions,
    SveltekitEndpoint,
    InitiateFactor2Return,
    CompleteFactor2Return,
    CancelFactor2Return
} from './sveltekitsession';
export type {
    LoginReturn,
    LogoutReturn,
    SignupReturn,
    ConfigureFactor2Return,
    VerifyEmailReturn,
    RequestPasswordResetReturn,
    ResetPasswordReturn,
    RequestFactor2Return,
    ChangePasswordReturn,
    ChangeFactor2Return,
    DeleteUserReturn,
    UpdateUserReturn,
} from './sveltekituserendpoints';
export type {
    SearchUsersReturn,
} from './sveltekitadminendpoints';

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
                authType? : string,
                apiKey?: ApiKey,
                accessTokenPayload?: {[key:string]:any},
                authError?: string,
                authErrorDescription?: string,
                sessionId? : string,
                scope? : string,
            }
            // interface PageData {}
            // interface PageState {}
            // interface Platform {}
    }
}
