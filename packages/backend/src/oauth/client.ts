import { OAuthClientBase, OAuthFlows } from '@crossauth/common';
import { Hasher } from '../hasher';
import { setParameter, ParamType } from '../utils';
import { CrossauthError, ErrorCode  } from '@crossauth/common';
import { jwtDecode } from "jwt-decode";

export interface OAuthClientOptions {
    authServerBaseUri : string,
    stateLength? : number,
    verifierLength? : number,
    clientId? : string,
    clientSecret? : string,
    redirectUri? : string,
    codeChallengeMethod? : "plain" | "S256"
    validFlows? : string,
}

export class OAuthClient extends OAuthClientBase {
    protected validFlows : string[] = [];

    constructor(options : OAuthClientOptions) {
        super(options);
        setParameter("authServerBaseUri", ParamType.String, this, options, "OAUTH_AUTH_SERVER_BASE_URI", true);
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

    tokenPayload(token : string) {
        return jwtDecode(token);

    }

}
