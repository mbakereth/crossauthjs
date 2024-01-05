import dotenv from "dotenv";
import { PrismaClient } from '@prisma/client';
import { CookieSessionManager, FastifyCookieAuthServer, PrismaKeyStorage, PrismaUserStorage } from 'crossauth/server';
import fastify, { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import fastifystatic from '@fastify/static';
import type { FastifyCookieOptions } from '@fastify/cookie'
import view from '@fastify/view';
import nunjucks from "nunjucks";
import path from 'path';
import { fileURLToPath } from 'url';
import { CrossauthLogger } from 'crossauth';
//import * as Pino from 'pino'; // you can use loggers other than the default built-in one

CrossauthLogger.logger.level = CrossauthLogger.Debug;
//CrossauthLogger.setLogger(Pino.pino({level: "debug"}));  // replace default logger with Pino

dotenv.config();

const port = Number(process.env.PORT || 3000);
const secret = process.env.SECRET;
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
let userStorage = new PrismaUserStorage({prismaClient : prisma});
let sessionStorage = new PrismaKeyStorage(userStorage, {prismaClient : prisma});
let sessionManager = new CookieSessionManager(userStorage, sessionStorage, secret);

// create the server, pointing it at the app we created and our nunjucks views directory
let server = new FastifyCookieAuthServer(sessionManager, {
    app: app,
    views: path.join(__dirname, '../views'),
    loginPage: "login.njk",
});

// create our home page
app.get('/', async (request : FastifyRequest, reply : FastifyReply) =>  {
    let user = await server.getUserFromCookie(request, reply);
    let username = user? user.username : undefined;
    return reply.view('index.njk', {username});
}
);

// create a sample login-protected page
app.get('/protected', async (request : FastifyRequest, reply : FastifyReply) =>  {
    let user = await server.getUserFromCookie(request, reply);
    if (!user) return reply.redirect(302, "/login?next=/protected");
    let username = user? user.username : undefined;
    return reply.view('protected.njk', {username});
}
);

server.start(port);
