import express from "express";
import passport from "passport";

import {
  emailValidator,
  existsValidator,
  passwordValidator,
} from "../validators";
import { getValidationErrors } from "~/routes/routesHelpers";
import { UsersRepository } from "~/db/repositories/usersRepository";
import { hashingHelpers } from "~/helpers/hashingHelpers";
import { authService } from "~/auth/authService";

export class AuthRoutes {
  private readonly usersRepository: UsersRepository;

  constructor(usersRepository: UsersRepository) {
    this.usersRepository = usersRepository;
  }

  attachToRouter(router: express.Router) {
    router.post(
      "/login",
      [emailValidator("email"), passwordValidator("password")],
      async (req, res) => {
        const errorsAfterValidation = getValidationErrors(req);
        if (errorsAfterValidation) {
          return res.status(400).json({
            code: 400,
            errors: errorsAfterValidation,
          });
        }

        try {
          const { email, password } = req.body;
          const user = await this.usersRepository.getByEmail(email);

          if (!user?.email) {
            return res.status(401).json({
              code: 401,
              errors: { email: "User or password not valid" },
            });
          }

          const isPasswordMatched = await hashingHelpers.isHashingEqual(
            password,
            user.password
          );
          if (!isPasswordMatched) {
            return res.status(403).json({
              code: 401,
              errors: { email: "User or password not valid" },
            });
          }

          const token = authService.generateAccessToken(user);
          const refreshToken = authService.generateRefreshToken(user);

          res.status(200).json({
            ...user,
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
      [existsValidator("refreshToken", "REFRESHTOKEN_IS_EMPTY")],
      passport.authenticate("jwt"),
      async (req, res) => {
        const errorsAfterValidation = getValidationErrors(req);
        if (errorsAfterValidation) {
          return res.status(400).json({
            code: 400,
            errors: errorsAfterValidation,
          });
        }

        try {
          const { refreshToken } = req.body;

          const refreshTokenPayload = await authService.getTokenPayload(
            refreshToken
          );
          const cachedRefreshToken = await authService.getRefreshToken(
            refreshTokenPayload
          );
          if (refreshToken !== cachedRefreshToken) {
            return res.status(400).json({
              code: 400,
              errors: "Invalid refresh token",
            });
          }

          const token = authService.generateAccessToken(refreshTokenPayload);
          const user = {
            email: refreshTokenPayload.email,
            name: refreshTokenPayload.name,
          };

          res.status(200).json({
            ...user,
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
        emailValidator("email"),
        passwordValidator("password"),
        existsValidator("name", "NAME_IS_EMPTY"),
      ],
      async (req, res) => {
        const errorsAfterValidation = getValidationErrors(req);
        if (errorsAfterValidation) {
          return res.status(400).json({
            code: 400,
            errors: errorsAfterValidation,
          });
        }

        try {
          const { email, password, name } = req.body;

          const user = await this.usersRepository.getByEmail(email);
          if (user) {
            return res.status(403).json({
              code: 409,
              errors: { email: "User with this email already exists" },
            });
          }

          const passwordEncrypted = await hashingHelpers.hash(password);
          const newUser = {
            email,
            password: passwordEncrypted,
            name,
          };
          await this.usersRepository.create(newUser);

          const token = authService.generateAccessToken(newUser);

          res.status(200).json({
            ...newUser,
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
  }
}
