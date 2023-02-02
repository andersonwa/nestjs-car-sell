import {
  BadRequestException,
  NotFoundException,
  Injectable,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { randomBytes, scrypt as _script } from 'crypto';
import { promisify } from 'util';

const script = promisify(_script);

@Injectable()
export class AuthService {
  constructor(private usersService: UsersService) {}

  async signup(emai: string, password: string) {
    const users = await this.usersService.find(emai);

    if (users.length) {
      throw new BadRequestException('E-mail in use');
    }

    const salt = randomBytes(8).toString('hex');
    const hash = (await script(password, salt, 32)) as Buffer;
    const result = salt + '.' + hash.toString('hex');

    const user = await this.usersService.create(emai, result);
    return user;
  }

  async signin(emai: string, password: string) {
    const [user] = await this.usersService.find(emai);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const [salt, storedHash] = user.password.split('.');
    const hash = (await script(password, salt, 32)) as Buffer;

    if (storedHash !== hash.toString('hex')) {
      throw new BadRequestException('Bad credentials');
    } else {
      return user;
    }
  }
}
