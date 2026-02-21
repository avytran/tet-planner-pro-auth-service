import { Document } from 'mongoose';

export interface IUser extends Document {
    email: string;
    password_hash: string;
    full_name: string;
    total_budget: number;
    password_updated_at: Date;
    created_at: Date;
    updated_at: Date;
}

export interface User {
    id: string;
    email: string;
    fullName: string;
    totalBudget: number;
    passwordUpdatedAt: Date;
    createdAt: Date;
    updatedAt: Date;
}