import dotenv from "dotenv";
import { PrismaClient } from '@prisma/client';
import { CookieSessionManager, FastifyCookieAuthServer, PrismaKeyStorage, PrismaUserStorage } from 'crossauth/server';
import fastify, { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import type { FastifyCookieOptions } from '@fastify/cookie'
import view from '@fastify/view';
import nunjucks from "nunjucks";

dotenv.config();

const port = Number(process.env.PORT || 3000);

// point nunjucks at the directory containing .njk files
nunjucks.configure("views", {
    autoescape: true,
});

// create fastify instance and register nunjucks as the renderer
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

// our user table and session key table will be served by Prisma (in a SQLite database)
const prisma = new PrismaClient();
let userStorage = new PrismaUserStorage({prismaClient : prisma});
let sessionStorage = new PrismaKeyStorage(userStorage, {prismaClient : prisma});
let sessionManager = new CookieSessionManager(userStorage, sessionStorage);

// create the server, pointing it at the app we created and our nunjucks views directory
let server = new FastifyCookieAuthServer(sessionManager, {
    app: app,
    views: "./views",
});

// create our home page
app.get('/', async (request : FastifyRequest, reply : FastifyReply) =>  {
    let username = "nobody";
    try {
        if (request.cookies && "SESSIONID" in request.cookies) {
            const user = await sessionManager.userForSessionKey(request.cookies["SESSIONID"]);
            username = user.username;
        }
    } catch (e) {
        console.log(e);
    }
    try {
    return reply.view('index.njk', {username});
    } catch (e) {
        console.log(e);
    }
}
);


server.start(port);

