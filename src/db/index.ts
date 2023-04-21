import { MongoDbContext } from "./mongoDbContext";
import { getConfig } from "~/config";

export default new MongoDbContext(getConfig().db);
