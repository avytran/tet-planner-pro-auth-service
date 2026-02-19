import { Module } from "@nestjs/common";
import { JwksController } from "./jwks.controller";
import { JwksService } from "./jwks.service";
import { keyProvider } from "./key.providers";

@Module({
    controllers: [JwksController],
    providers: [JwksService, keyProvider],
    exports: [JwksService],
})
export class JwksModule {}