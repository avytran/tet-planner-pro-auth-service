import dotenv from "dotenv";

dotenv.config();

const { 
  JWT_PRIVATE_KEY,
  JWT_PUBLIC_KEY,
  ACCESS_TOKEN_EXPIRES_IN,
  REFRESH_TOKEN_EXPIRES_IN,
  JWT_RESET_PASSWORD_SECRET,
  RESET_PASSWORD_TOKEN_EXPIRES_IN,
  CLIENT_URL,
} = process.env;

export const jwtConstants = {
  privateKey: JWT_PRIVATE_KEY as string,
  publicKey: JWT_PUBLIC_KEY as string,
  accessTokenExpiresIn: ACCESS_TOKEN_EXPIRES_IN as `${number}${'s'|'m'|'h'|'d'|'y'}`,
  refreshTokenExpiresIn: REFRESH_TOKEN_EXPIRES_IN as `${number}${'s'|'m'|'h'|'d'|'y'}`,
  resetPasswordSecretKey: JWT_RESET_PASSWORD_SECRET as string,
  resetPasswordTokenExpiresIn: RESET_PASSWORD_TOKEN_EXPIRES_IN as `${number}${'s'|'m'|'h'|'d'|'y'}`,
  clientURL: CLIENT_URL as string,
};