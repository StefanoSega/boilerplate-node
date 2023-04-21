import { validationResult } from "express-validator";
import passport from "passport";

export const getValidationErrors = (req: any) => {
  const errorsAfterValidation = validationResult(req);

  if (errorsAfterValidation.isEmpty()) {
    return undefined;
  }

  return errorsAfterValidation.mapped();
};

export const routeAuthProtected = () =>
  passport.authenticate("jwt", { session: false });
