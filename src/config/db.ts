import { DbConfig } from "~/db/dbTypes";

export const getDbConfig: () => DbConfig = () => ({
  host: "localhost",
  port: 27017,
  dbName: "test",
});
