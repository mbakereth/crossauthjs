// Sveltekit
export { SvelteKitSessionServer } from './sveltekitsession';
export type { SvelteKitSessionServerOptions } from './sveltekitsession';
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
    AdminUpdateUserReturn,
    AdminCreateUserReturn,
    AdminDeleteUserReturn as ADminDeleteUserReturn,
} from './sveltekitadminendpoints';

export { SvelteKitServer } from './sveltekitserver';
export type { SvelteKitServerOptions, Resolver, SveltekitEndpoint } from './sveltekitserver';
import type { User, ApiKey } from '@crossauth/common'
export { JsonOrFormData } from './utils';

export {  } from './sveltekitoauthserver';
export { SvelteKitAuthorizationServer } from './sveltekitoauthserver';
export type {
    AuthorizeQueryType,
    ReturnBase,
    AuthorizePageData,
    AuthorizeFormData,
    DevicePageData,
    DeviceFormData,
    MfaChallengeBodyType,
    MfaChallengeReturn,
    SvelteKitAuthorizationServerOptions } from './sveltekitoauthserver';

export { SvelteKitOAuthClient } from './sveltekitoauthclient';
export type { 
    SvelteKitErrorFn,
    SvelteKitOAuthClientOptions,
    AuthorizationCodeFlowReturn,
    TokenReturn,
    RedirectUriReturn,

} from './sveltekitoauthclient';

export { SvelteKitOAuthResourceServer } from './sveltekitresserver';
export type { SvelteKitOAuthResourceServerOptions } from './sveltekitresserver';

export { SvelteKitSharedClientEndpoints, defaultClientSearchFn } from './sveltekitsharedclientendpoints';
export type { 
    SearchClientsPageData,
    UpdateClientPageData,
    UpdateClientFormData,
    CreateClientPageData,
    CreateClientFormData,
    DeleteClientPageData,
    DeleteClientFormData,
} from './sveltekitsharedclientendpoints';
export { SvelteKitUserClientEndpoints } from './sveltekituserclientendpoints';
export { SvelteKitAdminClientEndpoints } from './sveltekitadminclientendpoints';
export { SvelteKitSessionAdapter } from './sveltekitsessionadapter';

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
                scope? : string[],
            }
            // interface PageData {}
            // interface PageState {}
            // interface Platform {}
    }
}
