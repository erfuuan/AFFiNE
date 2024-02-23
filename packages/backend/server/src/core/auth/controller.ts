import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Header,
  Post,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { omit } from 'lodash-es';

import {
  Config,
  PaymentRequiredException,
  URLHelper,
} from '../../fundamentals';
import { UsersService } from '../users';
import { CurrentUser } from './current-user';
import { Public } from './guard';
import { AuthService } from './service';
import { parseAuthUserSeqNum, SessionService } from './session';
import { TokenService, TokenType } from './token';

interface SignInCredential {
  email: string;
  password?: string;
}

@Controller('/api/auth')
export class AuthController {
  constructor(
    private readonly config: Config,
    private readonly url: URLHelper,
    private readonly auth: AuthService,
    private readonly user: UsersService,
    private readonly session: SessionService,
    private readonly token: TokenService
  ) {}

  @Public()
  @Post('/sign-in')
  @Header('content-type', 'application/json')
  async signIn(
    @Req() req: Request,
    @Res() res: Response,
    @Body() credential: SignInCredential,
    @Query('redirect_uri') redirectUri = this.url.home
  ) {
    const canSignIn = await this.auth.canSignIn(credential.email);
    if (!canSignIn) {
      throw new PaymentRequiredException(
        `You don't have early access permission\nVisit https://community.affine.pro/c/insider-general/ for more information`
      );
    }

    if (credential.password) {
      const session = await this.session.signIn(
        credential.email,
        credential.password,
        req.cookies[this.session.sessionCookieName]
      );

      res.cookie(this.session.sessionCookieName, session.sessionId, {
        expires: session.expiresAt ?? void 0, // expiredAt is `string | null`
        ...this.session.cookieOptions,
      });

      const user = await this.user.findUserById(session.userId);

      res.send(omit(user, 'password'));
    } else {
      // send email magic link
      const user = await this.user.findUserByEmail(credential.email);
      const result = await this.sendSignInEmail(
        { email: credential.email, signUp: !user },
        redirectUri
      );

      if (result.rejected.length) {
        throw new Error('Failed to send sign-in email.');
      }

      res.send({
        email: credential.email,
      });
    }
  }

  async sendSignInEmail(
    { email, signUp }: { email: string; signUp: boolean },
    redirectUri: string
  ) {
    const token = await this.token.createToken(TokenType.SignIn, email);

    const magicLink = this.url.link('/api/auth/magic-link', {
      token,
      email,
      redirect_uri: redirectUri,
    });

    const result = await this.auth.sendSignInEmail(email, magicLink, signUp);

    return result;
  }

  @Get('/sign-out')
  async signOut(
    @Req() req: Request,
    @Res() res: Response,
    @Query('redirect_uri') redirectUri?: string
  ) {
    const session = await this.session.signOut(
      req.cookies[this.session.sessionCookieName],
      parseAuthUserSeqNum(req.headers[this.session.authUserSeqCookieName])
    );

    if (session) {
      res.cookie(this.session.sessionCookieName, session.id, {
        expires: session.expiresAt ?? void 0, // expiredAt is `string | null`
        ...this.session.cookieOptions,
      });
    } else {
      res.clearCookie(this.session.sessionCookieName);
    }

    if (redirectUri) {
      return this.url.safeRedirect(res, redirectUri);
    } else {
      return res.send(null);
    }
  }

  @Public()
  @Get('/challenge')
  async challenge() {
    return this.session.createChallengeToken();
  }

  @Public()
  @Get('/magic-link')
  async magicLinkSignIn(
    @Req() req: Request,
    @Res() res: Response,
    @Query('token') token?: string,
    @Query('email') email?: string,
    @Query('redirect_uri') redirectUri = this.url.home
  ) {
    if (!token || !email) {
      throw new BadRequestException('Invalid Sign-in mail Token');
    }

    email = decodeURIComponent(email);

    const valid = await this.token.verifyToken(TokenType.SignIn, token, {
      credential: email,
    });

    if (!valid) {
      throw new BadRequestException('Invalid Sign-in mail Token');
    }

    const user = await this.user.findOrCreateUser(email, {
      emailVerifiedAt: new Date(),
    });

    await this.session.setCookie(req, res, user);

    return this.url.safeRedirect(res, redirectUri);
  }

  @Get('/authorize')
  async authorize(
    @CurrentUser() user: CurrentUser,
    @Query('redirect_uri') redirect_uri?: string
  ) {
    const session = await this.session.createSession(
      user,
      undefined,
      this.config.auth.accessToken.ttl
    );

    this.url.link(redirect_uri ?? '/open-app/redirect', {
      token: session.sessionId,
    });
  }
}
