var client = new crossauth_frontend.OAuthClient({
    authServerBaseUrl: "http://localhost:3000",
    authServerMode: "cors",
    authServerCredentials: "include",
    resServerMode: "cors",
    resServerCredentials: "include",
    client_id : "DEF",
    redirect_uri: "http://localhost:8080/authzcode.html",
    accessTokenResponseType: "sessionStorage",
    idTokenResponseType: "sessionStorage",
    refreshTokenResponseType: "sessionStorage",
});
var logger = crossauth_frontend.CrossauthLogger.logger;
var j = crossauth_frontend.j;
logger.setLevel(crossauth_frontend.CrossauthLogger.Debug);
