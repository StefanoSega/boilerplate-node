export const authConfig = {
  jwtSecret: "jwt-secret",
  accessTokenExpiresInMs: 1000 * 60 * 60 * 24,
  refreshTokenExpiresInMs: 1000 * 60 * 60 * 24 * 30,
  hashingSalt: 10,
};
