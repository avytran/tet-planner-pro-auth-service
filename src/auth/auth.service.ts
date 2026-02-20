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
import { ConfigService } from "@nestjs/config";
import { DbResult } from "./interfaces/dbResult";

@Injectable()
export class AuthService {
    constructor(@Inject("USER_MODEL") private readonly userModel: Model<IUser>,
        private jwtService: JwtService,
        private configService: ConfigService
    ) { }

    async register(dto: RegisterDto): Promise<DbResult<User>> {
        const existingUser = await this.userModel.findOne({ email: dto.email });
        if (existingUser) {
            throw new BadRequestException({
                status: 'error',
                message: 'Email already exists',
            });
        }

        const passwordHash = await bcrypt.hash(dto.password, 10);

        const user = await this.userModel.create({
            email: dto.email,
            password_hash: passwordHash,
            full_name: dto.fullName,
            total_budget: 0
        })

        return {
            status: "success",
            data: {
                id: user._id.toString(),
                email: user.email,
                fullName: user.full_name,
                totalBudget: user.total_budget,
                createdAt: user.created_at,
                updatedAt: user.updated_at
            }
        };
    }

    async login(email: string, password: string) {
        const user = await this.userModel.findOne({ email });
        if (!user) throw new UnauthorizedException({
            "status": "error",
            "message": "Unauthorized"
        });

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) throw new UnauthorizedException({
            "status": "error",
            "message": "Unauthorized"
        });

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
                    fullName: user.full_name,
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
                publicKey: this.configService
                    .get<string>("JWT_PUBLIC_KEY")
                    ?.replace(/\\n/g, "\n"),
                algorithms: ["RS256"],
            });

            const tokens = this.generateTokens({
                sub: payload.sub,
                email: payload.email,
            });

            return {
                status: "success",
                data: tokens
            }
        } catch (error) {
            throw new UnauthorizedException({
                "status": "error",
                "message": "Invalid refresh token"
            });
        }
    }

    private generateTokens(user: JwtPayload) {
        const payload: JwtPayload = {
            sub: user.sub,
            email: user.email,
        };

        const accessToken = this.jwtService.sign(payload, {
            expiresIn: jwtConstants.accessTokenExpiresIn,
            algorithm: "RS256",
        });

        const refreshToken = this.jwtService.sign(payload, {
            expiresIn: jwtConstants.refreshTokenExpiresIn,
            algorithm: "RS256",
        });


        return { accessToken, refreshToken };
    }

    async getProfile(user: JwtPayload) {
        const profile = await this.userModel.findById(user.sub);

        return {
            status: "success",
            data: {
                id: profile?.id,
                fullName: profile?.full_name,
                email: profile?.email,
                createdAt: profile?.created_at,
                updatedAt: profile?.updated_at
            }
        }
    }
}