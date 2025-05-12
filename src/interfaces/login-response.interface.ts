import { User } from "src/auth/entities/user.entity";

export interface LoginResponse {
    user: Omit<User, 'password'>,
    token: string,
}