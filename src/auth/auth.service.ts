import { ForbiddenException, Injectable } from '@nestjs/common';
import { AuthDto } from './dto';
import { PrismaService } from 'src/prisma/prisma.service';
import * as argon from 'argon2';
import { Prisma } from '@prisma/client';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config/dist';

@Injectable({})
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private config: ConfigService,
    private jwt: JwtService,
  ) {}
  async signup(AuthDto: AuthDto) {
    const hash = await argon.hash(AuthDto.password);
    try {
      const user = await this.prisma.user.create({
        data: {
          email: AuthDto.email,
          hash,
        },
      });
      return this.signToken(user.id, user.email);
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
      throw error;
    }
  }
  async signin(AuthDto: AuthDto) {
    const userExists = await this.prisma.user.findUnique({
      where: {
        email: AuthDto.email,
      },
    });
    if (!userExists) throw new ForbiddenException('Credential incorrect');
    const verifyPassword = argon.verify(userExists.hash, AuthDto.password);
    if (!verifyPassword) throw new ForbiddenException('Credential incorrect');
    return this.signToken(userExists.id, userExists.email);
  }
  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };
    const secret = this.config.get('JWT_SECRET');

    const token = await this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret: secret,
    });

    return {
      access_token: token,
    };
  }
}
