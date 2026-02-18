import { Document } from 'mongoose';

export interface IUser extends Document {
    email: string;
    password_hash: string;
    full_name: string;
    total_budget: number;
    created_at: Date;
    updated_at: Date;
}