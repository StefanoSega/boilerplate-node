import { Express } from "express";

import { router as authRoutes } from "./auth";

export const applyRoutes = (app: Express) => {
  app.use("/auth", authRoutes);
};
