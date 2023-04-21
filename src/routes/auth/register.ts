import express from "express";

import {
  emailValidator,
  existsValidator,
  passwordValidator,
} from "../validators";
import { getValidationErrors } from "../routesHelpers";
import { ResponseType, getJsonResponse } from "../responseHelpers";
import { authService } from "~/auth/authService";
import { UsersRepository } from "~/db/repositories/usersRepository";
import { hashingHelpers } from "~/helpers/hashingHelpers";

export const attachRouteAuthRegister = (
  router: express.Router,
  usersRepository: UsersRepository
) => {
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

        const user = await usersRepository.getByEmail(email);
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
        await usersRepository.create(newUser);

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
};
