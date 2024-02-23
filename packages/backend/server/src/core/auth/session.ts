import { randomUUID } from 'node:crypto';

import {
  Injectable,
  NotAcceptableException,
  NotFoundException,
} from '@nestjs/common';
import { verify } from '@node-rs/argon2';
import { PrismaClient, Session, User } from '@prisma/client';
import { CookieOptions, Request, Response } from 'express';
import { assign, omit } from 'lodash-es';

import { Config, SessionCache } from '../../fundamentals';
import { UsersService } from '../users/service';
import type { CurrentUser } from './current-user';

export function parseAuthUserSeqNum(value: any) {
  switch (typeof value) {
    case 'number': {
      return value;
    }
    case 'string': {
      value = Number.parseInt(value);
      return Number.isNaN(value) ? 0 : value;
    }

    default: {
      return 0;
    }
  }
}

export function sessionUser(user: User): CurrentUser {
  return assign(omit(user, 'password', 'emailVerifiedAt', 'createdAt'), {
    hasPassword: user.password !== null,
    emailVerified: user.emailVerifiedAt !== null,
  });
}

@Injectable()
export class SessionService {
  readonly sessionCookieName = 'sid';
  readonly authUserSeqCookieName = 'authuser';

  readonly cookieOptions: CookieOptions = {
    sameSite: 'lax',
    httpOnly: true,
    path: '/',
    domain: this.config.host,
    secure: this.config.https,
  };

  constructor(
    private readonly db: PrismaClient,
    private readonly cache: SessionCache,
    private readonly config: Config,
    private readonly user: UsersService
  ) {}

  async signIn(email: string, password: string, existingSession?: string) {
    const user = await this.user.findUserByEmail(email);

    if (!user) {
      throw new NotFoundException('User Not Found');
    }

    if (!user.password) {
      throw new NotAcceptableException(
        'User Password is not set. Should login throw email link.'
      );
    }

    const passwordMatches = await verify(user.password, password);

    if (!passwordMatches) {
      throw new NotAcceptableException('Incorrect Password');
    }

    return this.createSession(user, existingSession);
  }

  async validate(token: string, seq = 0): Promise<CurrentUser | null> {
    const session = await this.db.session.findUnique({
      where: {
        id: token,
      },
      include: {
        userSessions: {
          skip: seq,
          take: 1,
          orderBy: {
            createdAt: 'asc',
          },
        },
      },
    });

    // no such session
    if (!session) {
      return null;
    }

    // session expired
    if (session.expiresAt && session.expiresAt <= new Date()) {
      await this.db.session.delete({ where: { id: session.id } });
      return null;
    }

    const userSession = session.userSessions.at(0);

    // no such user session
    if (!userSession) {
      return null;
    }

    // user session expired
    if (userSession.expiresAt && userSession.expiresAt <= new Date()) {
      await this.db.userSession.delete({ where: { id: userSession.id } });
      return null;
    }

    const user = await this.db.user.findUnique({
      where: { id: userSession.userId },
    });

    if (!user) {
      return null;
    }

    return sessionUser(user);
  }

  async users(token: string) {
    const session = await this.db.session.findUnique({
      where: {
        id: token,
      },
      include: {
        userSessions: true,
      },
    });

    if (!session) {
      return [];
    }

    if (session.expiresAt && session.expiresAt <= new Date()) {
      await this.db.session.delete({ where: { id: session.id } });
      return [];
    }

    await this.db.userSession.deleteMany({
      where: {
        id: {
          in: session.userSessions
            .filter(userSession => {
              return (
                userSession.expiresAt && userSession.expiresAt <= new Date()
              );
            })
            .map(({ id }) => id),
        },
      },
    });

    const users = await this.db.user.findMany({
      where: {
        id: {
          in: session.userSessions
            .filter(({ expiresAt }) => !expiresAt || expiresAt > new Date())
            .map(({ userId }) => userId),
        },
      },
    });

    return users.map(sessionUser);
  }

  async signOut(token: string, seq = 0) {
    const session = await this.db.session.findUnique({ where: { id: token } });

    if (session) {
      // session expired, delete the whole session
      if (session.expiresAt && session.expiresAt <= new Date()) {
        await this.db.session.delete({ where: { id: session.id } });

        return null;
      } else {
        const list = await this.db.userSession.findMany({
          select: {
            id: true,
          },
          where: { sessionId: session.id },
          orderBy: { createdAt: 'asc' },
        });

        // overflow the logged in user
        if (list.length <= seq) {
          return session;
        }

        await this.db.userSession.deleteMany({ where: { id: list[seq].id } });

        // no more user session active, delete the whole session
        if (list.length === 1) {
          await this.db.session.delete({ where: { id: session.id } });
          return null;
        }

        return session;
      }
    }

    return null;
  }

  async createSession(
    user: { id: string },
    existingSession?: string,
    ttl = this.config.auth.ttl
  ) {
    let session: Session | null = null;
    if (existingSession) {
      session = await this.db.session.findUnique({
        where: {
          id: existingSession,
        },
      });
    }

    if (!session) {
      session = await this.db.session.create({
        data: {
          id: randomUUID(),
        },
      });
    }

    let userSession = await this.db.userSession.findUnique({
      where: {
        sessionId_userId: {
          sessionId: session.id,
          userId: user.id,
        },
      },
    });

    if (!userSession) {
      const expiresAt = new Date(Date.now() + ttl * 1000);

      userSession = await this.db.userSession.create({
        data: {
          sessionId: session.id,
          userId: user.id,
          expiresAt,
        },
      });
    }

    return userSession;
  }

  getSessionUser(token: string, seq: number) {
    const session = this.db.userSession.findFirst({
      where: {
        sessionId: token,
        expiresAt: {
          gt: new Date(),
        },
      },
      include: {
        user: true,
      },
      orderBy: {
        createdAt: 'asc',
      },
      skip: seq,
    });

    return session.user;
  }

  async createChallengeToken() {
    const challenge = randomUUID();
    const resource = randomUUID();
    await this.cache.set(`CHALLENGE:${challenge}`, resource, {
      ttl: 5 * 60 * 1000,
    });

    return {
      challenge,
      resource,
    };
  }

  async setCookie(req: Request, res: Response, user: { id: string }) {
    const session = await this.createSession(
      user,
      req.cookies[this.sessionCookieName]
    );

    res.cookie(this.sessionCookieName, session.sessionId, {
      expires: session.expiresAt ?? void 0,
      ...this.cookieOptions,
    });
  }
}
