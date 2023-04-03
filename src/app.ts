// https://www.izertis.com/en/-/refresh-token-with-jwt-authentication-in-node-js

import express from "express";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import passport from "passport";
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";
import jwt from "jsonwebtoken";
import { check, validationResult } from "express-validator";
import omit from "lodash/omit";

import { Users } from "./model";

async function execApp() {
  const app = express();
  const port = 3000;

  // DB Connect
  await mongoose.connect("mongodb://localhost/test");
  [
    `exit`,
    `SIGINT`,
    `SIGUSR1`,
    `SIGUSR2`,
    `uncaughtException`,
    `SIGTERM`,
  ].forEach((eventType) => {
    process.on(eventType, () => {
      console.log("DISCONNECTING DB ...", eventType);
      mongoose.disconnect();
      process.exit(1);
    });
  });

  // apply Passport Strategy
  passport.use(
    new JwtStrategy(
      {
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        secretOrKey: "jwt-secret",
      },
      (payload, done) => {
        Users.findOne({ email: payload.email }, (err, user) => {
          if (err) {
            return done(err, false);
          }

          if (user) {
            return done(null, {
              email: user.email,
              _id: user["_id"],
            });
          }

          return done(null, false);
        });
      }
    )
  );

  app.use(bodyParser.urlencoded({ extended: true }));
  app.use(bodyParser.json());

  app.get("/", (_req, res) => {
    res.send("Hello World!");
  });

  app.post(
    "/login",
    [
      check("email")
        .exists()
        .withMessage("EMAIL_IS_EMPTY")
        .isEmail()
        .withMessage("EMAIL_IS_IN_WRONG_FORMAT"),
      check("password")
        .exists()
        .withMessage("PASSWORD_IS_EMPTY")
        .isLength({ min: 8 })
        .withMessage("PASSWORD_LENGTH_MUST_BE_MORE_THAN_8"),
    ],
    async (req, res) => {
      const errorsAfterValidation = validationResult(req);
      if (!errorsAfterValidation.isEmpty()) {
        return res.status(400).json({
          code: 400,
          errors: errorsAfterValidation.mapped(),
        });
      }

      try {
        const { email, password } = req.body;
        const user = await Users.findOne({ email });

        if (!user?.email) {
          return res.status(401).json({
            code: 401,
            errors: { email: "User or password not valid" },
          });
        }

        const isPasswordMatched = await user.isPasswordEqual(password);
        if (isPasswordMatched) {
          return res.status(403).json({
            code: 401,
            errors: { email: "User or password not valid" },
          });
        }

        // Sign token
        const userData = omit(user.toJSON(), "password");
        const token = jwt.sign({ email }, "jwt-secret", {
          expiresIn: 1000000,
        });
        res.status(200).json({
          ...userData,
          token,
        });
      } catch (exc) {
        return res.status(500).json({
          code: 500,
          errors: { email: exc },
        });
      }
    }
  );

  app.listen(port, () => {
    return console.log(`Express is listening at http://localhost:${port}`);
  });
}

execApp();
