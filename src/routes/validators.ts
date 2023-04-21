import { check } from "express-validator";

export const emailValidator = (fieldName: string) =>
  check(fieldName)
    .exists()
    .withMessage("EMAIL_IS_EMPTY")
    .isEmail()
    .withMessage("EMAIL_IS_IN_WRONG_FORMAT");

export const passwordValidator = (fieldName: string) =>
  check(fieldName)
    .exists()
    .withMessage("PASSWORD_IS_EMPTY")
    .isLength({ min: 8 })
    .withMessage("PASSWORD_LENGTH_MUST_BE_MORE_THAN_8");

export const existsValidator = (fieldName: string, message?: string) =>
  check(fieldName)
    .exists()
    .withMessage(message || "IS_EMPTY");
