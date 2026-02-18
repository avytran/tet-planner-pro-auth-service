import { Module } from "@nestjs/common";
import { AuthController } from "./auth.controller";
import { AuthService } from "./auth.service";
import { userProviders } from "./auth.providers";
import { DatabaseModule } from "src/database/database.module";

@Module({
    imports: [DatabaseModule],
    controllers: [AuthController],
    providers: [AuthService, ...userProviders],
})
export class AuthModule {}