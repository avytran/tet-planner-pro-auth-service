import { Module } from "@nestjs/common";
import { AuthController } from "./auth.controller";
import { AuthService } from "./auth.service";
import { userProviders } from "./auth.providers";
import { DatabaseModule } from "src/database/database.module";
import { JwtModule } from "@nestjs/jwt";
import { jwtConstants } from "./jwt/jwt.constants";
import { JwtStrategy } from "./jwt/jwt.strategy";
import { RefreshTokenStrategy } from "./jwt/refreshToken.strategy";


@Module({
    imports: [
        DatabaseModule,
        JwtModule.register({}),
    ],
    controllers: [AuthController],
    providers: [AuthService, JwtStrategy, RefreshTokenStrategy, ...userProviders],
})
export class AuthModule {}