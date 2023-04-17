import express, { Express } from "express";

import { AuthRoutes } from "./auth";
import { UsersRepository } from "~/db/repositories/usersRepository";

export const applyRoutes = (app: Express) => {
  const router = express.Router();
  const usersRepository = new UsersRepository();

  new AuthRoutes(usersRepository).attachToRouter(router);

  app.use("/auth", router);
};
