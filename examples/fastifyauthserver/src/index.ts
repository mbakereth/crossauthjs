import { PrismaClient } from '@prisma/client'
import { PrismaKeyStorage, 
         PrismaUserStorage, 
         PrismaOAuthClientStorage, 
         PrismaOAuthAuthorizationStorage, 
         LocalPasswordAuthenticator, 
         TotpAuthenticator,
         EmailAuthenticator,
        } from '@crossauth/backend';
import { FastifyServer, FastifyOAuthResourceServer } from '@crossauth/fastify';
import fastify, { FastifyRequest, FastifyReply } from 'fastify';
import fastifystatic from '@fastify/static';
import view from '@fastify/view';
import nunjucks from "nunjucks";
import path from 'path';
import { CrossauthLogger } from '@crossauth/common';
import { totp } from 'otplib';
//import * as Pino from 'pino'; // you can use loggers other than the default built-in one

const JSONHDR : [string,string] = ['Content-Type', 'application/json; charset=utf-8'];

CrossauthLogger.logger.level = CrossauthLogger.Debug;
//CrossauthLogger.setLogger(Pino.pino({level: "debug"}), true);  // replace default logger with Pino

const port = Number(process.env.PORT || 3000);
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
let keyStorage = new PrismaKeyStorage(userStorage, {prismaClient : prisma});
let clientStorage = new PrismaOAuthClientStorage({prismaClient : prisma});
let authStorage = new PrismaOAuthAuthorizationStorage({prismaClient : prisma});

let lpAuthenticator = new LocalPasswordAuthenticator(userStorage);
let totpAuthenticator = new TotpAuthenticator("Fastify OAuth Server");
let emailAuthenticator = new EmailAuthenticator();

// create the server, pointing it at the app we created and our nunjucks views directory
let server = new FastifyServer(userStorage, {
    session: {
        keyStorage: keyStorage,
        authenticators: {
            localpassword: lpAuthenticator,
            totp: totpAuthenticator,
            email: emailAuthenticator,
        }},
    oAuthAuthServer : {
        clientStorage : clientStorage,
        keyStorage: keyStorage,
        options: {authenticators: {
            localpassword: lpAuthenticator,
            totp: totpAuthenticator,
            email: emailAuthenticator,
        }},
    },
    oAuthResServer: {
        protectedEndpoints: {"/resource": {scope: "read write"}}, 
    }}, {
        app: app,
        views: path.join(__dirname, '../views'),
        allowedFactor2: "totp, email, none",
        enableEmailVerification: false,
        validFlows: "all",
        validScopes: "read, write",
        siteUrl: `http://localhost:${port}`,
        authStorage: authStorage,
        userStorage: userStorage,
        resourceServerName: "https://resserver.com",
});

// SImple page to check login status and logout
app.get('/', async (request : FastifyRequest, reply : FastifyReply) =>  {
    if (!request.user) return reply.redirect(302, "/login?next=/");
    return reply.view('index.njk', {user: request.user});
}
);


// This is a resource server endpoint.  It doesn't have to be on the same
// server as the authorization server, in which initialize it with
// {authServerBaseUri: AUTH_SERVER_URI} instead
/*const resserver = new FastifyOAuthResourceServer(
    app, 
    server.authServer,
    {"/resource": {scope: "read write"}}, {
    resourceServerName: "https://resserver.com",
});*/
app.get('/resource', async (request : FastifyRequest, reply : FastifyReply) =>  {
    //const {authorized, error_description, tokenPayload} = await resserver.authorized(request);
    if (request.accessTokenPayload) {
        return reply.header(...JSONHDR).status(200).send({ok: true, timeCalled: new Date(), username: request.accessTokenPayload.sub});
    } else if (request.authErrorDescription) {
        return reply.header(...JSONHDR).status(500).send({ok: false, error: request.authErrorDescription});
    } else {
        return reply.header(...JSONHDR).status(401).send({ok: false});
    }
});

server.start(port);
