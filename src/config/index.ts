import { getAuthConfig } from "./auth";
import { getDbConfig } from "./db";

export const getConfig = () => ({
  auth: getAuthConfig(),
  db: getDbConfig(),
});
