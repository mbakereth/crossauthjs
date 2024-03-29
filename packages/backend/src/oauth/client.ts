import { OAuthClientBase, OAuthFlows } from '@crossauth/common';
import { Hasher } from '../hasher';
import { setParameter, ParamType } from '../utils';
import { CrossauthError, ErrorCode  } from '@crossauth/common';
import {
    OAuthBackendTokenConsumer,
    type OAuthBackendTokenConsumerOptions } from './tokenconsumer';

export interface OAuthClientOptions extends OAuthBackendTokenConsumerOptions {
    stateLength? : number,
    verifierLength? : number,
    clientId? : string,
    clientSecret? : string,
    redirectUri? : string,
    codeChallengeMethod? : "plain" | "S256"
    validFlows? : string,
}

export class OAuthClientBackend extends OAuthClientBase {
    protected validFlows : string[] = [];

    constructor(authServerBaseUri : string, options : OAuthClientOptions) {
        const options1 = {
            clientId: "",
        }
        setParameter("clientId", ParamType.String, options1, options, "OAUTH_CLIENT_ID", true);
        super({ authServerBaseUri, 
            tokenConsumer: new OAuthBackendTokenConsumer(options1.clientId, { 
                authServerBaseUri, ...options }), ...options });

        setParameter("stateLength", ParamType.String, this, options, "OAUTH_STATE_LENGTH");
        setParameter("verifierLength", ParamType.String, this, options, "OAUTH_VERIFIER_LENGTH");
        setParameter("clientId", ParamType.String, this, options, "OAUTH_CLIENT_ID");
        setParameter("clientSecret", ParamType.String, this, options, "OAUTH_CLIENT_SECRET");
        setParameter("codeChallengeMethod", ParamType.String, this, options, "OAUTH_CODE_CHALLENGE_METHOD");
        setParameter("validFlows", ParamType.StringArray, this, options, "OAUTH_VALID_FLOWS");
        if (this.validFlows.length == 1 && this.validFlows[0] == OAuthFlows.All) {
            this.validFlows = OAuthFlows.allFlows();
        } else {
            if (!OAuthFlows.areAllValidFlows(this.validFlows)) {
                throw new CrossauthError(ErrorCode.Configuration, "Invalid flows specificied in " + this.validFlows.join(","));
            }
        }
    }

    protected randomValue(length : number) : string {
        return Hasher.randomValue(length);
    }
    protected sha256(plaintext :string) : string {
        return Hasher.sha256(plaintext);
    }
}
