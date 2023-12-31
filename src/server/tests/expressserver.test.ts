import { test, expect, beforeAll } from 'vitest';
import {  CookieSessionManager } from '../cookieauth';
import { ExpressCookieAuthServer } from '../expressserver';
import { InMemoryUserStorage, InMemorySessionStorage } from '../storage/inmemorystorage';
import { getTestUserStorage }  from '../storage/tests/inmemorytestdata';
import supertest from 'supertest'

export var userStorage : InMemoryUserStorage;

// for all these tests, the database will have two users: bob and alice
beforeAll(async () => {
    userStorage = getTestUserStorage();
});
  
test('ExpressCookieAuthServer.loginGetKeyLogout', async () => {
    const sessionStorage = new InMemorySessionStorage(userStorage);
    let manager = new CookieSessionManager(userStorage, sessionStorage);
    const server = new ExpressCookieAuthServer(manager);
    let cookieValueRegexp = new RegExp(".*=([a-z0-9-]+);.*", "g");

    // check login
    let sessionKey = "";
    await supertest(server.app)
        .post("/api/login")
        .send({username: "bob", password: "bobPass123"})
        .expect(200)
        .then((res) => {
            expect(res.body.user.username).toBe("bob");
            let cookiesString = res.headers["set-cookie"][0];
            expect(cookiesString).toContain("SESSIONID");
            //let cookie = cookiesString.matchAll(cookieValueRegexp);
            let matches = cookieValueRegexp.exec(cookiesString)
            let cookie = matches ? matches[1] : "";
            expect(cookie).not.toBeNull();
            sessionKey = cookie;
        });

    //const agent = supertest.agent(server.app); 
    // get  user for session
    await  supertest(server.app)
        .get("/api/userforsessionkey")
        .set('Cookie', [
            `SESSIONID=${sessionKey}`, 
          ])
        .expect(200)
        .then((res) => {
            expect(res.body.status).toBe("ok");
            expect(res.body.user.username).toBe("bob");
        });

        // check logout
        await supertest(server.app)
        .post("/api/logout")
        .expect(200)
        .then((res) => {
            expect(res.body.status).toBe("ok");
        });

    });
