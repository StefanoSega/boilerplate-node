import bcrypt from "bcrypt";

import { authConfig } from "~/config/auth";

const hash = async (value: string) =>
  await bcrypt.hash(value, authConfig.hashingSalt);

const isHashingEqual = async (value: string, hashedValue: string) =>
  await bcrypt.compare(value, hashedValue);

export const hashingHelpers = {
  hash,
  isHashingEqual,
};
