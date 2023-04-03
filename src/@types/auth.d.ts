import OAuthServer from "express-oauth-server";

declare module "express-serve-static-core" {
  export interface Express {
    oauth?: OAuthServer;
  }
}

export {};
