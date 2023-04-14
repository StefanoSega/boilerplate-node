export interface DbContext {
  connect: () => void;
  disconnect: () => void;
}

export interface DbConfig {
  host: string;
  port: number;
  dbName: string;
}
