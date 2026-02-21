import * as mongoose from "mongoose";

export const UserSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
    },

    password_hash: {
        type: String,
        required: true,
    },

    full_name: {
        type: String,
        default: null,
    },

    total_budget: {
        type: Number,
        required: true,
        default: 0,
    },
    
    password_updated_at: {
        type: Date
    }
}, {
    timestamps: {
        createdAt: "created_at",
        updatedAt: "updated_at",
    },
});