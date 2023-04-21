import express from "express";

import { existsValidator } from "../validators";
import { getValidationErrors, routeAuthProtected } from "../routesHelpers";
import { ResponseType, getJsonResponse } from "../responseHelpers";
import { authService } from "~/auth/authService";

export const attachRouteAuthTokenRefresh = (router: express.Router) => {
  router.post(
    "/token/refresh",
    [existsValidator("refreshToken", "REFRESHTOKEN_IS_EMPTY")],
    routeAuthProtected,
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
};
