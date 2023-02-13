import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}
  @Post('signup')
  signup(@Body() AuthDto: AuthDto) {
    return this.authService.signup(AuthDto);
  }
  @Post('signin')
  signin(@Body() AuthDto: AuthDto) {
    return this.authService.signin(AuthDto);
  }
}
