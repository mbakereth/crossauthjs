import dotenv from "dotenv-flow";
dotenv.config();
import { PrismaClient } from '@prisma/client';
import { FastifyServer, PrismaKeyStorage, PrismaUserStorage, PrismaOAuthClientStorage, LocalPasswordAuthenticator } from '@crossauth/backend';
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

// create the server, pointing it at the app we created and our nunjucks views directory
let server = new FastifyServer(userStorage, {
    session: {
        keyStorage: keyStorage,
        authenticators: {
            localpassword: lpAuthenticator,
        }},
    oAuthAuthServer : {
        clientStorage : clientStorage,
        keyStorage: keyStorage,
    }}, {
        app: app,
        views: path.join(__dirname, '../views'),
        allowedFactor2: "none",
        enableEmailVerification: false,
});

server.start(port);
