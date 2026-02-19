import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { JwtPayload } from "../interfaces/jwtPayload.interface";
import { jwtConstants } from "./jwt.constants";
import dotenv from "dotenv";

dotenv.config();
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: jwtConstants.publicKey.replace(/\\n/g, '\n'),
      algorithms: ['RS256'],
    });
  }

  async validate(payload: JwtPayload) {
    return payload;
  }
}
