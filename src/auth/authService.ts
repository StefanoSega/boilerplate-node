import jwt from "jsonwebtoken";
import omit from "lodash/omit";
import passport from "passport";
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";

import { authConfig } from "~/config/auth";
import { User } from "~/db/models/users";
import { UsersRepository } from "~/db/repositories/usersRepository";
import cacheService from "~/cache";

enum TokenType {
  AccessToken,
  RefreshToken,
}

const tokenTypeMap = {
  [TokenType.AccessToken]: "accessToken",
  [TokenType.RefreshToken]: "refreshToken",
};

const getTokenKey = (email: string, type: TokenType) =>
  `user:${email}:${tokenTypeMap[type]}`;

const getAccessToken = async (user: Partial<User>) =>
  await cacheService.get(getTokenKey(user.email, TokenType.RefreshToken));

class AuthService {
  private readonly usersRepository: UsersRepository;

  constructor() {
    this.usersRepository = new UsersRepository();
  }

  init() {
    // apply Passport Strategy
    passport.use(
      new JwtStrategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          secretOrKey: authConfig.jwtSecret,
        },
        async ({ email, exp }, done) => {
          const isTokenExpired = new Date(exp * 1000) < new Date();
          if (isTokenExpired) {
            return done(null, false);
          }

          const accessToken = await getAccessToken({ email });
          const accessTokenPayload = await this.getTokenPayload(accessToken);
          const isTokenCanceled = exp !== accessTokenPayload.exp;
          if (isTokenCanceled) {
            return done(null, false);
          }

          try {
            const user = await this.usersRepository.getByEmail(email);
            if (!user) {
              return done(null, false);
            }

            return done(null, user);
          } catch (exc) {
            return done(exc, false);
          }
        }
      )
    );
  }

  async generateAccessToken(user: Partial<User>) {
    const userData = omit(user, "password");

    const token = jwt.sign(userData, authConfig.jwtSecret, {
      expiresIn: authConfig.accessTokenExpiresIn,
    });

    await cacheService.set(
      getTokenKey(userData.email, TokenType.AccessToken),
      token,
      authConfig.accessTokenExpiresIn
    );

    return token;
  }

  async generateRefreshToken(user: Partial<User>) {
    const userData = omit(user, "password");

    const token = jwt.sign(userData, authConfig.jwtSecret, {
      expiresIn: authConfig.refreshTokenExpiresIn,
    });

    await cacheService.set(
      getTokenKey(userData.email, TokenType.RefreshToken),
      token,
      authConfig.refreshTokenExpiresIn
    );

    return token;
  }

  async getRefreshToken(user: Partial<User>) {
    return await cacheService.get(
      getTokenKey(user.email, TokenType.RefreshToken)
    );
  }

  async getTokenPayload(token: string) {
    const payload = await jwt.verify(token, authConfig.jwtSecret);

    return payload as User & {
      exp: number;
    };
  }
}

export const authService = new AuthService();
