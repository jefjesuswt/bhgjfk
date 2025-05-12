import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcryptjs from "bcryptjs";
import { JwtService } from '@nestjs/jwt';

import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { User } from './entities/user.entity';
import { LoginDto } from './dto/login.dto';
import { JwtPayload } from 'src/interfaces/jwt-payload.interface';
import { LoginResponse } from 'src/interfaces/login-response.interface';
import { RegisterDto } from './dto/register.dto';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) 
    private userModel: Model<User>,

    private jwtService: JwtService
  ) {}

  async create(createUserDto: CreateUserDto): Promise<Omit<User, 'password'>>{
    try {
      const {password, ...userData} = createUserDto;
      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData
      });

      await newUser.save();

      const {password:_, ...user} = newUser.toJSON();
      return user;

    } catch (error) {

      if (error.code === 11000) {
        throw new BadRequestException(`${createUserDto.email} already exists!`);
      }
      throw new InternalServerErrorException('Something bad happened!');
    }
  }

  async register(registerDto: RegisterDto): Promise<LoginResponse>{
    
    const user = await this.create(registerDto);

    if (!user._id) throw new BadRequestException('No user id found');  

    return {
      user,
      token: this.getJWToken({id: user._id})
    }
    
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    const {email, password} = loginDto;

    const user = await this.userModel.findOne({email: email});

    if (!user) throw new UnauthorizedException('Not valid credentials - email');
    if (!password) throw new BadRequestException('No password was given');
    if (!bcryptjs.compareSync(password, user.password)) throw new UnauthorizedException('Not valid credentials - password');

    const {password:_, ...rest} = user.toJSON();
    return {
      user: rest,
      token: this.getJWToken({id: user.id})
    }
  }



  
  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById(userId: string): Promise<Omit<User, 'password'>> {
    
    const user = await this.userModel.findById(userId);

    if (!user) throw new UnauthorizedException();

    const {password:_, ...userWithoutPassword} = user.toJSON();

    return userWithoutPassword;
    
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJWToken(jwtPayload: JwtPayload) {
    return this.jwtService.sign(jwtPayload);
  }
}
