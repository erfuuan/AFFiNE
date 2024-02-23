import { Global, Module } from '@nestjs/common';

import { URLHelper } from './url';

@Global()
@Module({
  providers: [URLHelper],
  exports: [URLHelper],
})
export class HelpersModule {}

export { URLHelper };
