import { Module } from '@nestjs/common';

import { FeatureModule } from '../features';
import { UsersModule } from '../users';
import { AuthController } from './controller';
import { AuthResolver } from './resolver';
import { AuthService } from './service';
import { SessionService } from './session';
import { AuthSessionController } from './session.controller';
import { TokenService } from './token';

@Module({
  imports: [FeatureModule, UsersModule],
  providers: [AuthService, AuthResolver, SessionService, TokenService],
  exports: [AuthService, SessionService],
  controllers: [AuthController, AuthSessionController],
})
export class AuthModule {}

export * from './guard';
export { ClientTokenType } from './resolver';
export { AuthService, SessionService };
export * from './current-user';
