import express from "express";
import jwt from "jsonwebtoken";
import { check, validationResult } from "express-validator";
import omit from "lodash/omit";
import bcrypt from "bcrypt";
import passport from "passport";

import { Users } from "~/model";
import cache from "~/cache";
import { config } from "~/config";

const router = express.Router();

router.post(
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
      if (!isPasswordMatched) {
        return res.status(403).json({
          code: 401,
          errors: { email: "User or password not valid" },
        });
      }

      // Sign token
      const userData = omit(user.toJSON(), "password");
      const token = jwt.sign({ email }, config.auth.jwtSecret, {
        expiresIn: 1000000,
      });
      const refreshTokenExp = 1000 * 60 * 60 * 24 * 30;
      const refreshToken = jwt.sign({ email }, config.auth.jwtSecret, {
        expiresIn: refreshTokenExp,
      });

      await cache.set(
        `user:${email}:refreshToken`,
        refreshToken,
        refreshTokenExp
      );

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

router.post(
  "/token/refresh",
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

      const cachedRefreshToken = await cache.get(`user:${email}:refreshToken`);
      if (refreshToken !== cachedRefreshToken) {
        return res.status(400).json({
          code: 400,
          errors: "Invalid refresh token",
        });
      }

      // todo: how to invalidate previous token?
      const token = jwt.sign({ email }, config.auth.jwtSecret, {
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

router.post(
  "/register",
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
      const token = jwt.sign({ email }, config.auth.jwtSecret, {
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

export { router };
