import { Body, Controller, Get, Post } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { RegisterDto } from "./dto/register.dto";
import { User } from "./types/user";

@Controller("v1/auth")
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post("register")
    async register(@Body() dto: RegisterDto): Promise<User> {
        return this.authService.register(dto);
    }
}