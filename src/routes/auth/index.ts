import express from "express";

import { UsersRepository } from "~/db/repositories/usersRepository";
import { attachRouteAuthLogin } from "./login";
import { attachRouteAuthTokenRefresh } from "./tokenRefresh";
import { attachRouteAuthRegister } from "./register";

export class AuthRoutes {
  private readonly usersRepository: UsersRepository;

  constructor(usersRepository: UsersRepository) {
    this.usersRepository = usersRepository;
  }

  attachToRouter(router: express.Router) {
    attachRouteAuthLogin(router, this.usersRepository);
    attachRouteAuthTokenRefresh(router);
    attachRouteAuthRegister(router, this.usersRepository);
  }
}
