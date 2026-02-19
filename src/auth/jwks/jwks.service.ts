import { Inject, Injectable } from "@nestjs/common";
import * as crypto from "crypto";
import { PUBLIC_KEY } from "./key.providers";

@Injectable()
export class JwksService {
    constructor(@Inject(PUBLIC_KEY) private publicKey: string) {}

    getJwks() {
        const keyObject = crypto.createPublicKey(this.publicKey);
        const jwk = keyObject.export({ format: "jwk" }) as any;

        return {
            keys: [
                {
                    kty: jwk.kty,
                    n: jwk.n,
                    e: jwk.e,
                    alg: "RS256",
                    use: "sig",
                    kid: "main-key"
                }
            ]
        }
    }
}