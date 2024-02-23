import { Controller, Get, Req } from '@nestjs/common';
import type { Request } from 'express';

import { CurrentUser } from './current-user';
import { Public } from './guard';
import { SessionService } from './session';

@Controller('/api/auth')
export class AuthSessionController {
  constructor(private readonly session: SessionService) {}

  @Public()
  @Get('/session')
  async currentSessionUser(@CurrentUser() user?: CurrentUser) {
    return {
      user,
    };
  }

  @Public()
  @Get('/sessions')
  async currentSessionUsers(@Req() req: Request) {
    const token = req.cookies[this.session.sessionCookieName];
    if (!token) {
      return {
        users: [],
      };
    }

    return {
      users: await this.session.users(token),
    };
  }

  @Public()
  @Get('/challenge')
  async challenge() {
    return this.session.createChallengeToken();
  }
}
