import { Injectable, UnauthorizedException } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";
import { AuthErrorCode } from "../enums/authErrorCode.enum";

@Injectable()
export class JwtAuthGuard extends AuthGuard("jwt") {
  handleRequest(err: any, user: any, info: any) {
    if (err || !user) {
      // Missing token
      if (!info) {
        throw new UnauthorizedException({
          success: false,
          code: AuthErrorCode.TOKEN_MISSING,
          message: "Missing access token",
        });
      }

      // Token expired
      if (info?.name === "TokenExpiredError") {
        throw new UnauthorizedException({
          success: false,
          code: AuthErrorCode.TOKEN_EXPIRED,
          message: "Access token expired",
        });
      }

      // Invalid token
      if (info?.name === "JsonWebTokenError") {
        throw new UnauthorizedException({
          success: false,
          code: AuthErrorCode.TOKEN_INVALID,
          message: "Invalid access token",
        });
      }

      throw new UnauthorizedException({
        success: false,
        code: AuthErrorCode.UNAUTHORIZED,
        message: "Unauthorized",
      });
    }

    return user;
  }
}