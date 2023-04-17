// https://www.izertis.com/en/-/refresh-token-with-jwt-authentication-in-node-js

import express from "express";
import bodyParser from "body-parser";

import { applyRoutes } from "./routes";
import dbContext from "./db";
import cache from "./cache";
import { onExitingApp } from "./helpers/appHelpers";
import { authService } from "./auth/authService";

const handleStart = async () => {
  await dbContext.connect();
  await cache.connect();
  authService.init();
};

const handleExit = async () => {
  onExitingApp(async () => {
    await dbContext.disconnect();
    await cache.disconnect();
  });
};

async function execApp() {
  const app = express();
  const port = 3000;

  await handleStart();
  await handleExit();

  app.use(bodyParser.urlencoded({ extended: true }));
  app.use(bodyParser.json());

  app.get("/", (_req, res) => {
    res.send("Hello World!");
  });

  applyRoutes(app);

  app.listen(port, () => {
    return console.log(`Express is listening at http://localhost:${port}`);
  });
}

execApp();
