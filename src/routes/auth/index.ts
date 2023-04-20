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
import { ResponseType, getJsonResponse } from "../responseHelpers";

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
          return getJsonResponse(
            res,
            ResponseType.BadRequest,
            errorsAfterValidation
          );
        }

        try {
          const { email, password } = req.body;
          const user = await this.usersRepository.getByEmail(email);

          if (!user?.email) {
            return getJsonResponse(res, ResponseType.Unauthorized, {
              email: "User or password not valid",
            });
          }

          const isPasswordMatched = await hashingHelpers.isHashingEqual(
            password,
            user.password
          );
          if (!isPasswordMatched) {
            return getJsonResponse(res, ResponseType.Unauthorized, {
              email: "User or password not valid",
            });
          }

          const token = await authService.generateAccessToken(user);
          const refreshToken = await authService.generateRefreshToken(user);

          return getJsonResponse(res, ResponseType.Success, {
            ...user,
            token,
            refreshToken,
          });
        } catch (exc) {
          return getJsonResponse(res, ResponseType.InternalServerError, {
            error: exc,
          });
        }
      }
    );

    router.post(
      "/token/refresh",
      [existsValidator("refreshToken", "REFRESHTOKEN_IS_EMPTY")],
      passport.authenticate("jwt", { session: false }),
      async (req, res) => {
        const errorsAfterValidation = getValidationErrors(req);
        if (errorsAfterValidation) {
          return getJsonResponse(
            res,
            ResponseType.BadRequest,
            errorsAfterValidation
          );
        }

        try {
          const { refreshToken } = req.body;

          const refreshTokenPayload = await authService.getTokenPayload(
            refreshToken
          );
          const cachedRefreshToken = await authService.getRefreshToken(
            refreshTokenPayload.email
          );
          if (refreshToken !== cachedRefreshToken) {
            return getJsonResponse(res, ResponseType.BadRequest, {
              error: "Invalid refresh token",
            });
          }

          const token = await authService.generateAccessToken(
            refreshTokenPayload
          );
          const user = {
            email: refreshTokenPayload.email,
            name: refreshTokenPayload.name,
          };

          return getJsonResponse(res, ResponseType.Success, {
            ...user,
            token,
            refreshToken,
          });
        } catch (exc) {
          return getJsonResponse(res, ResponseType.InternalServerError, {
            error: exc,
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
          return getJsonResponse(
            res,
            ResponseType.BadRequest,
            errorsAfterValidation
          );
        }

        try {
          const { email, password, name } = req.body;

          const user = await this.usersRepository.getByEmail(email);
          if (user) {
            return getJsonResponse(res, ResponseType.Conflict, {
              email: "User with this email already exists",
            });
          }

          const passwordEncrypted = await hashingHelpers.hash(password);
          const newUser = {
            email,
            password: passwordEncrypted,
            name,
          };
          await this.usersRepository.create(newUser);

          const token = await authService.generateAccessToken(newUser);

          return getJsonResponse(res, ResponseType.Success, {
            ...newUser,
            token,
          });
        } catch (exc) {
          return getJsonResponse(res, ResponseType.InternalServerError, {
            error: exc,
          });
        }
      }
    );
  }
}
