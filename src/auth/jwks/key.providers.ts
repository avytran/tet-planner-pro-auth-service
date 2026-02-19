import { Provider } from "@nestjs/common";
import { jwtConstants } from "../jwt/jwt.constants";

export const PUBLIC_KEY = "PUBLIC_KEY";

export const keyProvider: Provider = {
  provide: PUBLIC_KEY,
  useFactory: () =>
    jwtConstants.publicKey.replace(/\\n/g, "\n"),
};
