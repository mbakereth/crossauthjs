import { PrismaClient } from '@prisma/client'
import {
    PrismaKeyStorage,
    PrismaUserStorage,
    PrismaOAuthClientStorage,
    LocalPasswordAuthenticator,
    TotpAuthenticator,
    EmailAuthenticator,
    OAuthClientManager } from '@crossauth/backend';
import { FastifyServer } from '@crossauth/fastify'
import fastify, { FastifyRequest, FastifyReply } from 'fastify';
import fastifystatic from '@fastify/static';
import view from '@fastify/view';
import nunjucks from "nunjucks";
import path from 'path';
import { CrossauthLogger } from '@crossauth/common';
//import * as Pino from 'pino'; // you can use loggers other than the default built-in one


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
let lpAuthenticator = new LocalPasswordAuthenticator(userStorage);
let totpAuthenticator = new TotpAuthenticator("FastifyTest");
let emailAuthenticator = new EmailAuthenticator();

// create the server, pointing it at the app we created and our nunjucks views directory
let server = new FastifyServer(userStorage, {
    authenticators: {
        localpassword: lpAuthenticator,
        totp: totpAuthenticator,
        email: emailAuthenticator,
    },
    session: {
        keyStorage: keyStorage,
    }}, {
        app: app,
        views: path.join(__dirname, '../views'),
        allowedFactor2: "none, totp, email",
        enableEmailVerification: false,
        siteUrl: `http://localhost:${port}`,
        clientStorage: clientStorage,
        enableAdminEndpoints: true,
        enableOAuthClientManagement: true,
});

const clientManager = new OAuthClientManager({
    clientStorage: clientStorage
});
async function init(clientManager : OAuthClientManager) {
    /*await clientManager.updateClient("SHD1OQi5UIz-jEHELuqopg", {
        clientName : "Test 2",
        validFlow: [],
    });*/
}
init(clientManager)
  .then(async () => {
  })
  .catch(async (e) => {
    console.error(e)
    await prisma.$disconnect()
    process.exit(1)
  })

// create our home page
app.get('/', async (request : FastifyRequest, reply : FastifyReply) =>  {
    return reply.view('index.njk', {user: request.user, errorMessages: ["AAA", "BBB"]});
}
);

// create a login-protected page for user to edit account
app.get('/protected', async (request : FastifyRequest, reply : FastifyReply) =>  {
    if (!request.user) return reply.redirect(302, "/login?next=/protected");
    return reply.view('protected.njk', {user: request.user});
}
);

// create an admin entry page
app.get('/admin', async (request : FastifyRequest, reply : FastifyReply) =>  {
    return reply.redirect(302, "/admin/");
});

app.get('/admin/', async (request : FastifyRequest, reply : FastifyReply) =>  {
    if (!request.user) return reply.redirect(302, "/login?next=/admin/");
    if (!request.user.admin) return reply.status(401).send(new Error('Access denied'));
    return reply.view('admin/index.njk', {user: request.user});
});

server.start(port);
