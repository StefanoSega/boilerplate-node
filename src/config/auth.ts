export const getAuthConfig = () => ({
  jwtSecret: process.env.JWT_SECRET,
  accessTokenExpiresInMs: 1000 * 60 * 60 * 24,
  refreshTokenExpiresInMs: 1000 * 60 * 60 * 24 * 30,
  hashingSalt: 10,
});
