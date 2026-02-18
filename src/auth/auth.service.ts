import { Model } from "mongoose";
import { Injectable, Inject } from "@nestjs/common";
import { IUser } from "./interfaces/user.interface";
import { RegisterDto } from "./dto/register.dto";
import { BadRequestException } from "@nestjs/common";
import * as bcrypt from 'bcrypt';
import { User } from "./types/user";

@Injectable()
export class AuthService {
    constructor(@Inject("USER_MODEL") private readonly userModel: Model<IUser>) { }

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
}