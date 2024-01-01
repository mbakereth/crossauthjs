import dotenv from "dotenv";
import { PrismaClient } from '@prisma/client';
import { CookieSessionManager, FastifyCookieAuthServer, PrismaSessionStorage, PrismaUserStorage } from 'crossauth/server';

dotenv.config();

const port = Number(process.env.PORT || 3000);
const prefix = process.env.PREFIX || "";

const prisma = new PrismaClient();
let userStorage = new PrismaUserStorage({prismaClient : prisma});
let sessionStorage = new PrismaSessionStorage(userStorage, {prismaClient : prisma});
let sessionManager = new CookieSessionManager(userStorage, sessionStorage);
let server = new FastifyCookieAuthServer(sessionManager);
server.start(port);

