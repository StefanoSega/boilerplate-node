// https://www.izertis.com/en/-/refresh-token-with-jwt-authentication-in-node-js

import express from "express";
import bodyParser from "body-parser";
import passport from "passport";
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";

import { Users } from "./model";
import { applyRoutes } from "./routes";
import dbContext from "./db";
import cache from "./cache";
import { config } from "~/config";
import { onExitingApp } from "./helpers/appHelpers";

const handleStart = async () => {
  await dbContext.connect();
  await cache.connect();
};

const handleExit = async () => {
  onExitingApp(async () => {
    await dbContext.disconnect();
    await cache.disconnect();
  });
};

async function execApp() {
  const app = express();
  const port = 3000;

  await handleStart();
  await handleExit();

  // apply Passport Strategy
  passport.use(
    new JwtStrategy(
      {
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        secretOrKey: config.auth.jwtSecret,
      },
      async ({ email, exp }, done) => {
        const isTokenExpired = new Date(exp * 1000) < new Date();
        if (isTokenExpired) {
          return done(null, false);
        }

        try {
          const user = await Users.findOne({ email });
          if (!user) {
            return done(null, false);
          }

          return done(null, {
            email: user.email,
            _id: user["_id"],
          });
        } catch (exc) {
          return done(exc, false);
        }
      }
    )
  );

  app.use(bodyParser.urlencoded({ extended: true }));
  app.use(bodyParser.json());

  app.get("/", (_req, res) => {
    res.send("Hello World!");
  });

  applyRoutes(app);

  app.listen(port, () => {
    return console.log(`Express is listening at http://localhost:${port}`);
  });
}

execApp();
