import mongoose from "mongoose";

import { DbConfig, DbContext } from "./dbTypes";

export class MongoDbContext implements DbContext {
  private mongooseClient: mongoose.Mongoose;
  private readonly dbConfig: DbConfig;

  constructor(dbConfig: DbConfig) {
    this.dbConfig = dbConfig;
  }

  async connect() {
    console.log("Connecting to MongoDb ...");

    const dbConn = `mongodb://${this.dbConfig.host}:${this.dbConfig.port}/${this.dbConfig.dbName}`;
    this.mongooseClient = await mongoose.connect(dbConn);
  }

  async disconnect() {
    const isConnected = [
      mongoose.ConnectionStates.connected,
      mongoose.ConnectionStates.connecting,
    ].includes(this.mongooseClient.connection.readyState);

    if (!isConnected) {
      console.log("Disconnecting from MongoDb ...");

      this.mongooseClient.disconnect();
    }
  }
}
