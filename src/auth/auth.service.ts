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
import { ForgotPasswordDto } from "./dto/forgotPassword.dto";
import { ResetPasswordDto } from "./dto/resetPassword.dto";
import { MailService } from "src/mail/mail.service";
import { AuthErrorCode } from "./enums/authErrorCode.enum";

@Injectable()
export class AuthService {
    constructor(@Inject("USER_MODEL") private readonly userModel: Model<IUser>,
        private jwtService: JwtService,
        private configService: ConfigService,
        private mailService: MailService,
    ) { }

    async register(dto: RegisterDto): Promise<DbResult<User>> {
        const existingUser = await this.userModel.findOne({ email: dto.email });
        if (existingUser) {
            throw new BadRequestException({
                status: 'error',
                code: AuthErrorCode.EMAIL_EXISTS,
                message: 'Email already exists',
            });
        }

        const passwordHash = await bcrypt.hash(dto.password, 10);

        const user = await this.userModel.create({
            email: dto.email,
            password_hash: passwordHash,
            full_name: dto.fullName,
            total_budget: 0,
            password_updated_at: new Date(),
        })

        return {
            status: "success",
            data: {
                id: user._id.toString(),
                email: user.email,
                fullName: user.full_name,
                totalBudget: user.total_budget,
                passwordUpdatedAt: user.password_updated_at,
                createdAt: user.created_at,
                updatedAt: user.updated_at
            }
        };
    }

    async login(email: string, password: string) {
        const user = await this.userModel.findOne({ email });
        if (!user) throw new UnauthorizedException({
            status: "error",
            code: AuthErrorCode.INVALID_CREDENTIALS,
            message: "Unauthorized"
        });

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) throw new UnauthorizedException({
            status: "error",
            code: AuthErrorCode.INVALID_CREDENTIALS,
            message: "Unauthorized"
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
                    passwordUpdatedAt: user.password_updated_at,
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
            if (error.name === "TokenExpiredError") {
                throw new UnauthorizedException({
                    status: "error",
                    errorCode: AuthErrorCode.TOKEN_EXPIRED,
                    message: "Refresh token expired",
                });
            }

            throw new UnauthorizedException({
                status: "error",
                errorCode: AuthErrorCode.TOKEN_INVALID,
                message: "Invalid refresh token",
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
                passwordUpdatedAt: profile?.password_updated_at,
                createdAt: profile?.created_at,
                updatedAt: profile?.updated_at
            }
        }
    }

    async forgotPassword(dto: ForgotPasswordDto) {
        const user = await this.userModel.findOne({ email: dto.email });

        if (!user) {
            return {
                status: "success",
                data: {
                    message: "If email exists, reset link has been sent",
                },
            };
        }

        const token = await this.jwtService.signAsync(
            {
                sub: user._id,
                purpose: "reset_password",
                password_updated_at: user.password_updated_at,
            },
            {
                secret: jwtConstants.resetPasswordSecretKey,
                expiresIn: jwtConstants.resetPasswordTokenExpiresIn,
                algorithm: "HS256",
            }
        )

        const resetLink = `${jwtConstants.clientURL}/reset-password?token=${token}`;

        // console.log(resetLink);

        await this.mailService.sendResetPasswordEmail(user.email, resetLink);

        return {
            status: "success",
            data: {
                message: "If email exists, reset link has been sent",
            },
        };

    }

    async resetPassword(dto: ResetPasswordDto) {
        let payload: any;

        try {
            payload = await this.jwtService.verifyAsync(dto.token, {
                secret: jwtConstants.resetPasswordSecretKey,
                algorithms: ["HS256"],
            });
        } catch (error) {
            if (error.name === "TokenExpiredError") {
                throw new UnauthorizedException({
                    status: "error",
                    errorCode: AuthErrorCode.TOKEN_EXPIRED,
                    message: "Reset token expired",
                });
            }

            throw new UnauthorizedException({
                status: "error",
                errorCode: AuthErrorCode.TOKEN_INVALID,
                message: "Invalid reset token",
            });
        }

        if (payload.purpose !== "reset_password") {
            throw new UnauthorizedException({
                status: "error",
                errorCode: AuthErrorCode.TOKEN_INVALID,
                message: "Invalid token purpose",
            });
        }

        const user = await this.userModel.findById(payload.sub);
        if (!user) {
            throw new UnauthorizedException({
                status: "error",
                errorCode: AuthErrorCode.USER_NOT_FOUND,
                message: "User not found",
            });
        }

        if (
            !user.password_updated_at ||
            payload.password_updated_at !== user.password_updated_at.toISOString()
        ) {
            throw new UnauthorizedException({
                status: "error",
                errorCode: AuthErrorCode.RESET_TOKEN_USED,
                message: "Token already used or expired",
            });
        }

        const newHashedPassword = await bcrypt.hash(dto.newPassword, 10);

        const isMatch = await bcrypt.compare(newHashedPassword, user.password_hash);
        if (isMatch) {
            throw new BadRequestException({
                status: "error",
                errorCode: AuthErrorCode.SAME_PASSWORD,
                message: "New password must be different from old password",
            });
        }

        await this.userModel.findByIdAndUpdate(
            payload.sub,
            {
                $set: {
                    password_hash: newHashedPassword,
                    password_updated_at: new Date(),
                },
            }
        );

        return {
            status: "success",
            data: {
                message: "Password reset successfully"
            }
        };
    }
}