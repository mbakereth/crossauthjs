import { JsonWebKey } from 'crypto';

export type TokenEndpointAuthMethod = "client_secret_post" | "client_secret_basic" | "client_secret_jwt" | "private_key_jwt";
export type ResponseMode = "query" | "fragment";
export type GrantType = "authorization_code" | "implicit" | "client_credentials" | "password" | "refresh_token" | "http://auth0.com/oauth/grant-type/mfa-otp" | "http://auth0.com/oauth/grant-type/mfa-oob" | "urn:ietf:params:oauth:grant-type:device_code";
export type SubjectType = "pairwise" | "public";
export type ClaimType = "normal" | "aggregated" | "distributed";

/** This class encapsulate the data returned by the `oidc-configuration`
 * well-known endpoint.  For further details, see the OpenID Connect
 * specification.
 */
export interface OpenIdConfiguration {
    issuer : string,
    authorization_endpoint: string,
    token_endpoint: string,
    userinfo_endpoint? : string,
    jwks_uri : string,
    registration_endpoint? : string,
    scopes_supported? : string[],
    response_types_supported: string[],
    response_modes_supported: ResponseMode[],
    grant_types_supported : GrantType[],
    check_session_iframe? : string,
    end_session_endpoint? : string,
    acr_values_supported?: string[],
    subject_types_supported: SubjectType[],
    id_token_signing_alg_values_supported: string[],
    id_token_encryption_alg_values_supported? : string[],
    id_token_encryption_enc_values_supported? : string[],
    userinfo_signing_alg_values_supported? : string[],
    userinfo_encryption_alg_values_supported? : string[],
    userinfo_encryption_enc_values_supported? : string[],
    request_object_signing_alg_values_supported? : string[],
    request_object_encryption_alg_values_supported? : string[],
    request_object_encryption_enc_values_supported? : string[],
    token_endpoint_auth_methods_supported?: TokenEndpointAuthMethod[],
    token_endpoint_auth_signing_alg_values_supported? : string[],
    display_values_supported? : string[],
    claim_types_supported? : ClaimType[],
    claims_supported? : string[],
    service_documentation? : string,
    claims_locales_supported? : string[],
    ui_locales_supported? : string[],
    claims_parameter_supported? : boolean,
    request_parameter_supported? : boolean,
    request_uri_parameter_supported? : boolean,
    require_request_uri_registration? : boolean,
    op_policy_uri? : string,
    op_tos_uri? : string,
}

export interface Jwks {
    keys: JsonWebKey[],
}

/**
 * This is the detault configuration for 
 * {@link @crossauth/backend!OAuthAuthorizationServer}.wellknown
 */
export const DEFAULT_OIDCCONFIG : OpenIdConfiguration = {
    issuer: "",
    authorization_endpoint: "",
    token_endpoint: "",
    jwks_uri : "",
    response_types_supported: [],
    subject_types_supported : [],
    response_modes_supported: ["query", "fragment"],
    grant_types_supported : ["authorization_code", "implicit"],
    id_token_signing_alg_values_supported: [],
    claim_types_supported : ["normal"],
    claims_parameter_supported : false,
    request_parameter_supported : false,
    request_uri_parameter_supported : true,
    require_request_uri_registration : false,
};

