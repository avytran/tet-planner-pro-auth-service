import * as mongoose from "mongoose";
import dotenv from "dotenv";

dotenv.config();

const {
  DB_USERNAME,
  DB_PASSWORD,
  DB_NAME
} = process.env;

export const databaseProviders = [
    {
        provide: "DATABASE_CONNECTION",
        useFactory:  (): Promise<typeof mongoose> => 
            mongoose.connect(`mongodb+srv://${DB_USERNAME}:${DB_PASSWORD}@tetplannerpro.3yuf5p8.mongodb.net/${DB_NAME}?appName=TetPlannerPro`),
    },
];