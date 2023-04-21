// https://www.izertis.com/en/-/refresh-token-with-jwt-authentication-in-node-js

import express from "express";
import bodyParser from "body-parser";

import { applyRoutes } from "./routes";
import dbContext from "./db";
import cache from "./cache";
import { onExitingApp } from "./helpers/appHelpers";
import { authService } from "./auth/authService";
import {
  LoggerFormat,
  LoggerService,
  LoggerTransport,
} from "./logger/loggerService";
import { configHelpers } from "./config/configHelpers";
import { getConfig } from "./config";

const handleStart = async () => {
  configHelpers.loadEnvVars();
  await dbContext.connect();
  await cache.connect();
  authService.init(getConfig().auth);
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

  const loggerService = new LoggerService(app);

  await handleStart();
  await handleExit();

  app.use(bodyParser.urlencoded({ extended: true }));
  app.use(bodyParser.json());

  loggerService.initRequestLogger(
    [LoggerTransport.Console],
    [LoggerFormat.Colorize, LoggerFormat.Json]
  );

  app.get("/", (_req, res) => {
    res.send("Hello World!");
  });

  applyRoutes(app);

  loggerService.initErrorLogger(
    [LoggerTransport.Console],
    [LoggerFormat.Colorize, LoggerFormat.Json]
  );

  app.listen(port, () => {
    return console.log(`Express is listening at http://localhost:${port}`);
  });
}

execApp();
