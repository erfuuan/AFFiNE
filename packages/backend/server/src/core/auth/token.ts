import { randomUUID } from 'node:crypto';

import { Injectable } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

type Transaction = Parameters<Parameters<PrismaClient['$transaction']>[0]>[0];

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
    return await this.db.$transaction(async tx => {
      const record = await tx.verificationToken.findUnique({
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

      // always revoke expired token
      if (expired || (valid && !keep)) {
        await this.revokeToken(type, token, tx);
      }

      return valid ? record : null;
    });
  }

  async revokeToken(type: TokenType, token: string, tx?: Transaction) {
    const client = tx || this.db;
    await client.verificationToken.delete({
      where: {
        type_token: {
          token,
          type,
        },
      },
    });
  }
}
