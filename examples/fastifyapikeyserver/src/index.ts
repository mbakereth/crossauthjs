import dotenv from "dotenv";
dotenv.config();
import { PrismaClient } from '@prisma/client';
import { FastifyServer, PrismaKeyStorage, PrismaUserStorage, LocalPasswordAuthenticator, TotpAuthenticator, EmailAuthenticator } from '@crossauth/backend';
import fastify, { FastifyRequest, FastifyReply } from 'fastify';
import fastifystatic from '@fastify/static';
import view from '@fastify/view';
import nunjucks from "nunjucks";
import path from 'path';
import { CrossauthLogger } from '@crossauth/common';
//import * as Pino from 'pino'; // you can use loggers other than the default built-in one

CrossauthLogger.logger.level = CrossauthLogger.Debug;
//CrossauthLogger.setLogger(Pino.pino({level: "debug"}), true);  // replace default logger with Pino

const TOKEN = "eyJ2IjoiOENvX0ZZbkZBeW5Falk1QS0xRVYwZyIsInQiOjE3MDc0OTU5MDIxMDQsInMiOiJSUVZlR2laUEkzOGVMY2RRQ216VlRRIn0.OKZnaHoknATIVWPC53p2Oba0tP9zPKh_XkMMFv7F9Js";
const JSONHDR : [string,string] = ['Content-Type', 'application/json; charset=utf-8'];

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
let keyStorage = new PrismaKeyStorage(userStorage, {prismaClient : prisma, keyTable: "apiKey"});

// create the server, pointing it at the app we created and our nunjucks views directory
let server = new FastifyServer(userStorage, {
    apiKey: {
        keyStorage: keyStorage,
    }}, {
        app: app,
        views: path.join(__dirname, '../views'),
});

app.get('/', async (request : FastifyRequest, reply : FastifyReply) =>  {
    return reply.header(...JSONHDR).send({ok: true, user : request.user, apiKey: request.apiKey});
});

app.get('/protected', async (request : FastifyRequest, reply : FastifyReply) =>  {
    if (!request.apiKey) reply.status(403).header(...JSONHDR).send({ok: false});
    return reply.header(...JSONHDR).send({ok: true, user : request.user, apiKey: request.apiKey});
});

app.get('/protectedScopeOne', async (request : FastifyRequest, reply : FastifyReply) =>  {
    if (!(request.apiKey?.scope) || !request.apiKey?.scope.includes("one")) reply.status(403).header(...JSONHDR).send({ok: false});
    return reply.header(...JSONHDR).send({ok: true, user : request.user, apiKey: request.apiKey});
});

app.get('/protectedScopeThree', async (request : FastifyRequest, reply : FastifyReply) =>  {
    if (!(request.apiKey?.scope) || !request.apiKey?.scope.includes("three")) reply.status(403).header(...JSONHDR).send({ok: false});
    return reply.header(...JSONHDR).send({ok: true, user : request.user, apiKey: request.apiKey});
});

server.start(port);
