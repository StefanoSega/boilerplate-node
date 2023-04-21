import jwt from "jsonwebtoken";
import omit from "lodash/omit";
import passport from "passport";
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";

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
  await cacheService.get(getTokenKey(user.email, TokenType.AccessToken));

class AuthService {
  private readonly usersRepository: UsersRepository;
  private config: Record<string, any>;

  constructor() {
    this.usersRepository = new UsersRepository();
  }

  init(config: Record<string, any>) {
    this.config = config;

    // apply Passport Strategy
    passport.use(
      new JwtStrategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          secretOrKey: this.config.jwtSecret,
        },
        async ({ email, exp, iat }, done) => {
          const isTokenExpired = new Date(exp * 1000) < new Date();
          if (isTokenExpired) {
            return done(null, false);
          }

          const accessToken = await getAccessToken({ email });
          const accessTokenPayload = await this.getTokenPayload(accessToken);
          const isTokenCanceled = iat !== accessTokenPayload.iat;
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
    const userData = omit(user, ["password", "exp", "jti", "iat"]);

    const token = jwt.sign(userData, this.config.jwtSecret, {
      expiresIn: this.config.accessTokenExpiresInMs,
    });

    await cacheService.set(
      getTokenKey(userData.email, TokenType.AccessToken),
      token,
      this.config.accessTokenExpiresInMs
    );

    return token;
  }

  async generateRefreshToken(user: Partial<User>) {
    const userData = omit(user, "password");

    const token = jwt.sign(userData, this.config.jwtSecret, {
      expiresIn: this.config.refreshTokenExpiresInMs,
    });

    await cacheService.set(
      getTokenKey(userData.email, TokenType.RefreshToken),
      token,
      this.config.refreshTokenExpiresInMs
    );

    return token;
  }

  async getRefreshToken(email: string) {
    return await cacheService.get(getTokenKey(email, TokenType.RefreshToken));
  }

  async getTokenPayload(token: string) {
    const payload = await jwt.verify(token, this.config.jwtSecret);

    return payload as User & {
      _id: string;
      exp: number;
      iat: number;
    };
  }
}

export const authService = new AuthService();
