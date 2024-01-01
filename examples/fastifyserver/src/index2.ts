import dotenv from "dotenv";
import { PrismaClient } from '@prisma/client';
import { CookieSessionManager, FastifyCookieAuthServer, PrismaSessionStorage, InMemoryUserStorage } from 'crossauth/server';

dotenv.config();

const port = Number(process.env.PORT || 3000);
const prefix = process.env.PREFIX || "";

const prisma = new InMemoryUserStorage();
let userStorage = new InMemoryUserStorage();
