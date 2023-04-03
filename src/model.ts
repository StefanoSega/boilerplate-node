import mongoose from "mongoose";
import bcrypt from "bcrypt";

export const Users = mongoose.model(
  "users",
  new mongoose.Schema(
    {
      email: { type: String, required: true },
      password: { type: String, required: true },
      name: { type: String },
    },
    {
      methods: {
        isPasswordEqual: async function (password: string) {
          return await bcrypt.compare(password, this.password);
        },
      },
    }
  )
);
