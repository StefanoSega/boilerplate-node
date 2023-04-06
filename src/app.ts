// https://www.izertis.com/en/-/refresh-token-with-jwt-authentication-in-node-js

import express from "express";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import redis from "redis";
import passport from "passport";
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";
import jwt from "jsonwebtoken";
import { check, validationResult } from "express-validator";
import omit from "lodash/omit";
import bcrypt from "bcrypt";

import { Users } from "./model";

async function execApp() {
  const app = express();
  const port = 3000;

  // DB Connect
  await mongoose.connect("mongodb://localhost/test");

  // Cache connect
  const redisClient = redis.createClient();
  await redisClient.connect();

  // Close connections
  [
    `exit`,
    `SIGINT`,
    `SIGUSR1`,
    `SIGUSR2`,
    `uncaughtException`,
    `SIGTERM`,
  ].forEach((eventType) => {
    process.on(eventType, async () => {
      console.log("DISCONNECTING DB ...", eventType);

      await mongoose.disconnect();
      await redisClient.disconnect();

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
      ({ email, exp }, done) => {
        const isTokenExpired = new Date(exp * 1000) < new Date();
        if (isTokenExpired) {
          return done(null, false);
        }

        Users.findOne({ email }, (err, user) => {
          if (err) {
            return done(err, false);
          }

          if (!user) {
            return done(null, false);
          }

          return done(null, {
            email: user.email,
            _id: user["_id"],
          });
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
    "/auth/login",
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
        if (!isPasswordMatched) {
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
        const refreshTokenExp = 1000 * 60 * 60 * 24 * 30;
        const refreshToken = jwt.sign({ email }, "jwt-secret", {
          expiresIn: refreshTokenExp,
        });

        await redisClient.set(`user:${email}:refreshToken`, refreshToken, {
          PX: refreshTokenExp,
        });

        res.status(200).json({
          ...userData,
          token,
          refreshToken,
        });
      } catch (exc) {
        return res.status(500).json({
          code: 500,
          errors: { email: exc },
        });
      }
    }
  );

  app.post(
    "/auth/token/refresh",
    [check("refreshToken").exists().withMessage("REFRESHTOKEN_IS_EMPTY")],
    passport.authenticate("jwt"),
    async (req, res) => {
      const errorsAfterValidation = validationResult(req);
      if (!errorsAfterValidation.isEmpty()) {
        return res.status(400).json({
          code: 400,
          errors: errorsAfterValidation.mapped(),
        });
      }

      try {
        const { refreshToken } = req.body;
        const email = "zwonimir@live.it"; // todo: take from JWT

        const cachedRefreshToken = await redisClient.get(
          `user:${email}:refreshToken`
        );
        if (refreshToken !== cachedRefreshToken) {
          return res.status(400).json({
            code: 400,
            errors: "Invalid refresh token",
          });
        }

        // todo: how to invalidate previous token?
        const token = jwt.sign({ email }, "jwt-secret", {
          expiresIn: 1000000,
        });

        res.status(200).json({
          email,
          token,
          refreshToken,
        });
      } catch (exc) {
        return res.status(500).json({
          code: 500,
          errors: { email: exc },
        });
      }
    }
  );

  app.post(
    "/auth/register",
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
      check("name").exists().withMessage("EMAIL_IS_EMPTY"),
    ],
    async (req, res) => {
      const errorsAfterValidation = validationResult(req);
      if (!errorsAfterValidation.isEmpty()) {
        res.status(400).json({
          code: 400,
          errors: errorsAfterValidation.mapped(),
        });
      }

      try {
        const { email, password, name } = req.body;

        const user = await Users.findOne({ email });
        if (user) {
          return res.status(403).json({
            code: 409,
            errors: { email: "User with this email already exists" },
          });
        }

        const passwordEncrypted = await bcrypt.hash(password, 10);
        const newUser = await Users.create({
          email,
          password: passwordEncrypted,
          name,
        });

        // Sign token
        const userData = omit(newUser.toJSON(), "password");
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
          ...exc,
        });
      }
    }
  );

  app.listen(port, () => {
    return console.log(`Express is listening at http://localhost:${port}`);
  });
}

execApp();
