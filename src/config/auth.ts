export const authConfig = {
  jwtSecret: "jwt-secret",
  accessTokenExpiresIn: 1000000,
  refreshTokenExpiresIn: 1000 * 60 * 60 * 24 * 30,
  hashingSalt: 10,
};
