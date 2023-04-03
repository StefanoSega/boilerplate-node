import express from "express";
import bodyParser from "body-parser";
import OAuthServer from "express-oauth-server";
import mongoose from "mongoose";

import oauthModel from "./model";

async function execApp() {
  const app = express() as any;
  const port = 3000;

  // DB Connect
  await mongoose.connect("mongodb://localhost/test");
  [
    `exit`,
    `SIGINT`,
    `SIGUSR1`,
    `SIGUSR2`,
    `uncaughtException`,
    `SIGTERM`,
  ].forEach((eventType) => {
    process.on(eventType, () => {
      console.log("DISCONNECTING DB ...", eventType);
      mongoose.disconnect();
      process.exit(1);
    });
  });

  app.oauth = new OAuthServer({
    model: oauthModel,
  });

  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(app.oauth.authorize());

  app.get("/", (_req, res) => {
    res.send("Hello World!");
  });

  app.listen(port, () => {
    return console.log(`Express is listening at http://localhost:${port}`);
  });
}

execApp();
