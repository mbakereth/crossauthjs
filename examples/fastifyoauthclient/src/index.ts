import { PrismaClient } from './generated/client/index.js';
import { KeyStorage, FastifyServer, FastifyOAuthClient, PrismaKeyStorage, PrismaUserStorage, PrismaOAuthAuthorizationStorage, LocalPasswordAuthenticator } from '@crossauth/backend';
import fastify, { FastifyRequest, FastifyReply } from 'fastify';
import fastifystatic from '@fastify/static';
import view from '@fastify/view';
import nunjucks from "nunjucks";
import path from 'path';
import { CrossauthError, CrossauthLogger, j, OAuthFlows, type OAuthTokenResponse } from '@crossauth/common';
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
const prisma = new PrismaClient();
let userStorage = new PrismaUserStorage({prismaClient : prisma, userEditableFields: "email"});
let keyStorage : KeyStorage = new PrismaKeyStorage(userStorage, {prismaClient : prisma});
let authStorage = new PrismaOAuthAuthorizationStorage({prismaClient : prisma});

let lpAuthenticator = new LocalPasswordAuthenticator(userStorage);

// create the server, pointing it at the app we created and our nunjucks views directory
const server = new FastifyServer(userStorage, {
    session: {
        keyStorage: keyStorage,
        authenticators: {
            localpassword: lpAuthenticator,
        }},
    oAuthClient: {
        authServerBaseUri: process.env["AUTHORIZATION_SERVER"],
    }}, {
    app: app,
    views: path.join(__dirname, '../views'),
    allowedFactor2: "none",
    enableEmailVerification: false,
    siteUrl: `http://localhost:${port}`,
    loginUrl: "login",
    validFlows: "all", // activate all OAuth flows
    loginProtectedFlows: OAuthFlows.AuthorizationCode + ", " + OAuthFlows.AuthorizationCodeWithPKCE,
    tokenResponseType: "saveInSessionAndLoad",
    bffGetEndpoints: "/resource"
});

app.get('/', async (request : FastifyRequest, reply : FastifyReply) =>  {
    return reply.view('index.njk', {user: request.user});
}
);

app.get('/authzcodeex', async (request : FastifyRequest, reply : FastifyReply) =>  {
    if (!request.user) return reply.redirect(302, "/login?next=/authzcodeex");
    return reply.view('authzcode.njk', {user: request.user});
}
);

app.get('/clientcredentialsex', async (request : FastifyRequest, reply : FastifyReply) =>  {
    return reply.view('clientcredentials.njk', {user: request.user, csrfToken: request.csrfToken});
}
);

app.get('/passwordex', async (request : FastifyRequest, reply : FastifyReply) =>  {
    return reply.view('passwordex.njk', {user: request.user, csrfToken: request.csrfToken});
}
);

server.start(port);
