import { Model } from "mongoose";
import { Injectable, Inject } from "@nestjs/common";
import { IUser } from "./interfaces/user.interface";
import { RegisterDto } from "./dto/register.dto";
import { BadRequestException, UnauthorizedException } from "@nestjs/common";
import * as bcrypt from 'bcrypt';
import { User } from "./interfaces/user.interface";
import { JwtService } from "@nestjs/jwt";
import { jwtConstants } from "./jwt/jwt.constants";
import { JwtPayload } from "./interfaces/jwtPayload.interface";

@Injectable()
export class AuthService {
    constructor(@Inject("USER_MODEL") private readonly userModel: Model<IUser>,
        private jwtService: JwtService,
    ) { }

    async register(dto: RegisterDto): Promise<User> {
        const existingUser = await this.userModel.findOne({ email: dto.email });
        if (existingUser) {
            throw new BadRequestException('Email already exists');
        }

        const passwordHash = await bcrypt.hash(dto.password, 10);

        const user = await this.userModel.create({
            email: dto.email,
            password_hash: passwordHash,
            full_name: dto.fullName,
            total_budget: 0
        })

        return {
            id: user._id.toString(),
            email: user.email,
            fullName: user.full_name,
            totalBudget: user.total_budget,
            createdAt: user.created_at,
            updatedAt: user.updated_at
        };
    }

    async login(email: string, password: string) {
        const user = await this.userModel.findOne({ email });
        if (!user) throw new UnauthorizedException();

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) throw new UnauthorizedException();

        const payload: JwtPayload = {
            sub: user._id.toString(),
            email: user.email,
        };

        const { accessToken, refreshToken } = this.generateTokens(payload);

        return {
            status: "success",
            data: {
                accessToken,
                refreshToken,
                user: {
                    id: user.id,
                    name: user.full_name,
                    email: user.email,
                    createdAt: user.created_at,
                    updatedAt: user.updated_at
                }
            }
        }
    }

    async refreshToken(refreshToken: string) {
        try {
            const payload = this.jwtService.verify<JwtPayload>(refreshToken, {
                secret: jwtConstants.refreshSecret,
            });

            return this.generateTokens({
                sub: payload.sub,
                email: payload.email,
            });
        } catch (error) {
            throw new UnauthorizedException("Invalid refresh token");
        }
    }

    private generateTokens(user: JwtPayload) {
        const payload: JwtPayload = {
            sub: user.sub,
            email: user.email,
        };

        const accessToken = this.jwtService.sign(payload, {
            secret: jwtConstants.accessSecret,
            expiresIn: jwtConstants.accessExpiresIn,
        });

        const refreshToken = this.jwtService.sign(payload, {
            secret: jwtConstants.refreshSecret,
            expiresIn: jwtConstants.refreshExpiresIn,
        });

        return { accessToken, refreshToken };
    }

    async getProfile(user: JwtPayload) {
        const profile = await this.userModel.findById(user.sub);

        return {
            id: profile?.id,
            fullName: profile?.full_name,
            email: profile?.email,
            createdAt: profile?.created_at,
            updatedAt: profile?.updated_at
        };
    }
}