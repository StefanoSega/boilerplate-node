import { validationResult } from "express-validator";

export const getValidationErrors = (req: any) => {
  const errorsAfterValidation = validationResult(req);

  if (errorsAfterValidation.isEmpty()) {
    return undefined;
  }

  return errorsAfterValidation.mapped();
};
