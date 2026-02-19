import dotenv from "dotenv";

dotenv.config();

const { 
  JWT_PRIVATE_KEY,
  JWT_PUBLIC_KEY,
  ACCESS_TOKEN_EXPIRES_IN,
  REFRESH_TOKEN_EXPIRES_IN,
} = process.env;

export const jwtConstants = {
  privateKey: JWT_PRIVATE_KEY as string,
  publicKey: JWT_PUBLIC_KEY as string,
  accessTokenExpiresIn: ACCESS_TOKEN_EXPIRES_IN as `${number}${'s'|'m'|'h'|'d'|'y'}`,
  refreshTokenExpiresIn: REFRESH_TOKEN_EXPIRES_IN as `${number}${'s'|'m'|'h'|'d'|'y'}`,
};