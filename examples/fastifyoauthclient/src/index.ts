import dotenv from "dotenv-flow";
dotenv.config();
import { PrismaClient } from '@prisma/client';
import { KeyStorage, FastifyServer, FastifyOAuthClient, PrismaKeyStorage, PrismaUserStorage, PrismaOAuthClientStorage, PrismaOAuthAuthorizationStorage, LocalPasswordAuthenticator } from '@crossauth/backend';
import fastify, { FastifyRequest, FastifyReply } from 'fastify';
import fastifystatic from '@fastify/static';
import view from '@fastify/view';
import nunjucks from "nunjucks";
import path from 'path';
import { CrossauthError, CrossauthLogger, oauthErrorStatus, type OAuthTokenResponse } from '@crossauth/common';
//import * as Pino from 'pino'; // you can use loggers other than the default built-in one

const JSONHDR : [string,string] = ['Content-Type', 'application/json; charset=utf-8'];

CrossauthLogger.logger.level = CrossauthLogger.Debug;
//CrossauthLogger.setLogger(Pino.pino({level: "debug"}), true);  // replace default logger with Pino

const port = Number(process.env.PORT || 3001);
const __filename = new URL('', import.meta.url).pathname;
const __dirname = new URL('.', import.meta.url).pathname;

// point nunjucks at the directory containing .njk files
nunjucks.configure("views", {
    autoescape: true,
});

// create fastify instance, register nunjucks as the renderer and the static file plugin (for the CSS file)
const app = fastify({logger: false});
app.register(view, {
    engine: {
        nunjucks: nunjucks,
    },
    templates: [
        "node_modules/shared-components",
        "views",
    ],
    });
    app.register(fastifystatic, {
        root: path.join(__dirname, '../public'),
        prefix: '/public/', 
    })
      
// our user table and session key table will be served by Prisma (in a SQLite database)
const prisma = new PrismaClient({datasourceUrl: "file:"+process.cwd()+"/prisma/"+process.env.DATABASE_FILE});
let userStorage = new PrismaUserStorage({prismaClient : prisma, userEditableFields: "email"});
let keyStorage : KeyStorage = new PrismaKeyStorage(userStorage, {prismaClient : prisma});
let authStorage = new PrismaOAuthAuthorizationStorage({prismaClient : prisma});

let lpAuthenticator = new LocalPasswordAuthenticator(userStorage);

// in this example, we are saving the tokens as session data
async function receiveToken(request : FastifyRequest, reply : FastifyReply, oauthResponse : OAuthTokenResponse) : Promise<FastifyReply> {
    if (oauthResponse.error) {
        const status = oauthErrorStatus(oauthResponse.error);
        return reply.status(status).view("error.njk", {status: status, error: oauthResponse.error_description, errorCodeName: oauthResponse.error});
    }
    CrossauthLogger.logger.debug("Got access token " + JSON.stringify(fastifyClient.tokenPayload(oauthResponse.access_token)));
    try {
        await server.updateSessionData(request, "oauth", oauthResponse);
        return reply.status(200).view("authorized.njk", {});
    } catch (e) {
        const ce = e as CrossauthError;
        return reply.status(ce.httpStatus).view("error.njk", {status: ce.httpStatus, error: ce.message, errorCodeName: ce.codeName});
    }
}

// create the server, pointing it at the app we created and our nunjucks views directory
var server = new FastifyServer(userStorage, {
    session: {
        keyStorage: keyStorage,
        authenticators: {
            localpassword: lpAuthenticator,
        }}}, {
    app: app,
    views: path.join(__dirname, '../views'),
    allowedFactor2: "none",
    enableEmailVerification: false,
    siteUrl: `http://localhost:${port}`,
});
var fastifyClient = new FastifyOAuthClient(app, { 
    authServerBaseUri: "http://localhost:3000",  // auth server URL
    siteUrl: "http://localhost:3001", // my url
    validFlows: "all", // activate all OAuth flows
    receiveTokenFn: receiveToken,
});

app.get('/', async (request : FastifyRequest, reply : FastifyReply) =>  {
    if (!request.user) return reply.redirect(302, "/login?next=/");
    return reply.view('index.njk', {user: request.user});
}
);

// in this example, the API is called from the backend
app.get('/resource', async (request : FastifyRequest, reply : FastifyReply) =>  {
    if (!request.user) return reply.redirect(302, "/login?next=/");
    const oauthData = await server.getSessionData(request, "oauth");
    if (oauthData?.access_token) {
        const resp = await fetch("http://localhost:3000/resource", {
            headers: {
                "Authorization": "Bearer " + oauthData.access_token,
        }});
        return reply.header(...JSONHDR).status(resp.status).send(await resp.json());
    } else {
        return reply.header(...JSONHDR).status(401).send({ok: false});
    }
});

server.start(port);
