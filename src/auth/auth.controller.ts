import { Body, Controller, Get, Post, UseGuards, Req } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { RegisterDto } from "./dto/register.dto";
import { User } from "./interfaces/user.interface";
import { JwtPayload } from "./interfaces/jwtPayload.interface";
import { JwtAuthGuard } from "./jwt/jwtAuth.guard";
import { RefreshTokenDto } from "./dto/refreshToken.dto";
import { DbResult } from "./interfaces/dbResult";

@Controller("v1/auth")
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    @Post("register")
    async register(@Body() dto: RegisterDto): Promise<DbResult<User>> {
        return this.authService.register(dto);
    }

    @Post("login")
    async login(@Body() body: { email: string; password: string }) {
        return this.authService.login(body.email, body.password);
    }

    @UseGuards(JwtAuthGuard)
    @Get("profile")
    async profile(@Req() req: any) {
        const user = req.user as JwtPayload;
        return this.authService.getProfile(user);
    }

    @Post("refresh-token")
    async refreshToken(@Body() dto: RefreshTokenDto) {
        return this.authService.refreshToken(dto.refreshToken);
    }
}