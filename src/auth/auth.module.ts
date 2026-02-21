import { Module } from "@nestjs/common";
import { AuthController } from "./auth.controller";
import { AuthService } from "./auth.service";
import { userProviders } from "./auth.providers";
import { DatabaseModule } from "src/database/database.module";
import { JwtModule } from "@nestjs/jwt";
import { jwtConstants } from "./jwt/jwt.constants";
import { JwtStrategy } from "./jwt/jwt.strategy";
import { RefreshTokenStrategy } from "./jwt/refreshToken.strategy";
import { ConfigModule, ConfigService } from "@nestjs/config";
import { JwksModule } from "./jwks/jwks.module";
import { MailService } from "../mail/mail.service";

@Module({
    imports: [
        DatabaseModule,

        ConfigModule.forRoot(),

        JwtModule.registerAsync({
            imports: [ConfigModule],
            inject: [ConfigService],
            useFactory: () => ({
                privateKey: jwtConstants.privateKey.replace(/\\n/g, '\n'),
                publicKey: jwtConstants.publicKey.replace(/\\n/g, '\n'),
                signOptions: {
                    algorithm: 'RS256'
                },
            }),
        }),
        JwksModule,
    ],
    controllers: [AuthController],
    providers: [AuthService, JwtStrategy, RefreshTokenStrategy, ...userProviders, MailService],
})
export class AuthModule { }