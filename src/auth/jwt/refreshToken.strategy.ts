import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { jwtConstants } from "./jwt.constants";
import { JwtPayload } from "../interfaces/jwtPayload.interface";

@Injectable()
export class RefreshTokenStrategy extends PassportStrategy(
    Strategy,
    "jwt-refresh",
) {
    constructor() {
        super({
            jwtFromRequest: ExtractJwt.fromBodyField("refresh_token"),
            secretOrKey: jwtConstants.refreshSecret,
        });
    }

    async validate(payload: JwtPayload) {
        return payload;
    }
}
