import * as dotenv from "dotenv";

const loadEnvVars = () => {
  const isProduction = process.env.NODE_ENV === "production";
  const path = isProduction ? "./.env.production" : "./.env.development";

  dotenv.config({
    path,
  });
};

export const configHelpers = {
  loadEnvVars,
};
