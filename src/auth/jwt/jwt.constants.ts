export const jwtConstants = {
  accessSecret: process.env.JWT_ACCESS_SECRET || "accessSecret123",
  refreshSecret: process.env.JWT_REFRESH_SECRET || "refreshSecret123",
  accessExpiresIn: 900,
  refreshExpiresIn: 60 * 60 * 24 * 7,
};