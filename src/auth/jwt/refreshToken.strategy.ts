import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { JwtPayload } from "../interfaces/jwtPayload.interface";
import { jwtConstants } from "./jwt.constants";

@Injectable()
export class RefreshTokenStrategy extends PassportStrategy(
    Strategy,
    "jwt-refresh",
) {
    constructor() {
        super({
            jwtFromRequest: ExtractJwt.fromBodyField("refresh_token"),
            secretOrKey: jwtConstants.publicKey.replace(/\\n/g, '\n'),
            algorithms: ['RS256'],
        });
    }

    async validate(payload: JwtPayload) {
        return payload;
    }
}
