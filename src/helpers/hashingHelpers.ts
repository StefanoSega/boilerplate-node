import bcrypt from "bcrypt";

import { getConfig } from "~/config";

const hash = async (value: string) => {
  const config = getConfig().auth;

  return await bcrypt.hash(value, config.hashingSalt);
};

const isHashingEqual = async (value: string, hashedValue: string) =>
  await bcrypt.compare(value, hashedValue);

export const hashingHelpers = {
  hash,
  isHashingEqual,
};
