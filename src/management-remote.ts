import type { Context } from '@deepseek-ai/cordis';
import { Remote, TypertRemoteService } from '@deepseek-ai/dsh-typert-protocol';
import type {} from '@deepseek-ai/dsh-typert-registry';
import type { PapService } from './plugin.js';
import type { PapManagementRequest } from './product-api.js';
import contribution from './remote.js';

/** Mounted only on the authenticated user management Gateway, never an Agent tool. */
export default class PapManagerRemote extends TypertRemoteService {
  static inject = ['pap', 'typert'];
  private readonly manager: ReturnType<PapService['acquireManagement']>;
  constructor(ctx: Context) {
    super(ctx, 'papManager');
    this.manager = ctx.pap.acquireManagement(ctx);
    ctx.effect(() => ctx.typert.register({ package: contribution.package, face: 'host', schemas: [],
      model: { services: [], events: [], objects: [] }, invocations: contribution.descriptors }));
  }
  @Remote status() { return this.manager.status(); }
  @Remote operations() { return this.manager.operations(); }
  /** Browser authorization URL is returned only through this user management endpoint. */
  @Remote manage(input: PapManagementRequest) { return this.manager.execute(input); }
}
