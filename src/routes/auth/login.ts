import express from "express";

import { emailValidator, passwordValidator } from "../validators";
import { getValidationErrors } from "../routesHelpers";
import { ResponseType, getJsonResponse } from "../responseHelpers";
import { UsersRepository } from "~/db/repositories/usersRepository";
import { hashingHelpers } from "~/helpers/hashingHelpers";
import { authService } from "~/auth/authService";

export const attachRouteAuthLogin = (
  router: express.Router,
  usersRepository: UsersRepository
) => {
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
        const user = await usersRepository.getByEmail(email);

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
};
