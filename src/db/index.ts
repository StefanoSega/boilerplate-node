import { MongoDbContext } from "./mongoDbContext";
import { dbConfig } from "~/config/db";

export default new MongoDbContext(dbConfig);
