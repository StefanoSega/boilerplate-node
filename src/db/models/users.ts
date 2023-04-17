import mongoose from "mongoose";

export type User = {
  email: string;
  password: string;
  name: string;
};

export const UsersModel = mongoose.model<User>(
  "users",
  new mongoose.Schema({
    email: { type: String, required: true },
    password: { type: String, required: true },
    name: { type: String, required: true },
  })
);
