import { randomUUID } from 'node:crypto';

import { Injectable } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

export enum TokenType {
  SignIn,
  VerifyEmail,
  ChangeEmail,
  SetPassword,
  ChangePassword,
  Challenge,
}

@Injectable()
export class TokenService {
  constructor(private readonly db: PrismaClient) {}

  async createToken(
    type: TokenType,
    credential?: string,
    ttlInSec: number = 30 * 60
  ) {
    const plaintextToken = randomUUID();

    const { token } = await this.db.verificationToken.create({
      data: {
        type,
        token: plaintextToken,
        credential,
        expiresAt: new Date(Date.now() + ttlInSec * 1000),
      },
    });

    // TODO: encrypt the token
    return token;
  }

  async verifyToken(
    type: TokenType,
    token: string,
    {
      credential,
      keep,
    }: {
      credential?: string;
      keep?: boolean;
    } = {}
  ) {
    const record = await this.db.verificationToken.findUnique({
      where: {
        type_token: {
          token,
          type,
        },
      },
    });

    if (!record) {
      return null;
    }

    const expired = record.expiresAt <= new Date();
    const valid =
      !expired && (!record.credential || record.credential === credential);

    if ((expired || valid) && !keep) {
      await this.db.verificationToken.delete({
        where: {
          type_token: {
            token,
            type,
          },
        },
      });
    }

    return valid ? record : null;
  }
}
