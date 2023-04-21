import { Express } from "express";
import expressWinston from "express-winston";
import winston from "winston";

export enum LoggerTransport {
  Console,
}

const loggerTransportMap = {
  [LoggerTransport.Console]: () => new winston.transports.Console(),
};

export enum LoggerFormat {
  Colorize,
  Json,
}

const loggerFormatMap = {
  [LoggerFormat.Colorize]: () => winston.format.colorize(),
  [LoggerFormat.Json]: () => winston.format.json(),
};

export class LoggerService {
  private readonly app: Express;

  constructor(app: Express) {
    this.app = app;
  }

  initRequestLogger(
    transports: Array<LoggerTransport>,
    formats: Array<LoggerFormat>
  ) {
    this.app.use(
      expressWinston.logger({
        transports: transports.map((transport) =>
          loggerTransportMap[transport]()
        ),
        format: winston.format.combine(
          ...formats.map((format) => loggerFormatMap[format]())
        ),
      })
    );
  }

  initErrorLogger(
    transports: Array<LoggerTransport>,
    formats: Array<LoggerFormat>
  ) {
    this.app.use(
      expressWinston.errorLogger({
        transports: transports.map((transport) =>
          loggerTransportMap[transport]()
        ),
        format: winston.format.combine(
          ...formats.map((format) => loggerFormatMap[format]())
        ),
      })
    );
  }
}
