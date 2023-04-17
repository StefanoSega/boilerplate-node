import bcrypt from "bcrypt";

import { Repository } from "./repository";
import { User, UsersModel } from "../models/users";
import { queryToJson } from "~/helpers/mongooseHelpers";

export class UsersRepository implements Repository<User> {
  async get() {
    return await queryToJson(UsersModel.find());
  }

  async getById(id: string): Promise<User> {
    return await queryToJson(UsersModel.findById(id));
  }

  async getByEmail(email: string): Promise<User> {
    return await queryToJson(UsersModel.findOne({ email }));
  }

  async create(item: User) {
    const passwordEncrypted = await bcrypt.hash(item.password, 10);
    UsersModel.create(item);
  }

  update(id: string, item: User) {
    UsersModel.updateOne({ _id: id }, item);
  }

  delete(id: string) {
    UsersModel.deleteOne({ _id: id });
  }
}
