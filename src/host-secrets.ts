import { Service, type Context } from '@deepseek-ai/cordis';
import { KeyringSecretStore } from './keyring.js';
import type { PapHostServices } from './plugin.js';
export interface Config { keyringService: string; locksRoot: string }
export const name='@agentconnect/dsh-pap/host-secrets';
/** Optional concrete Linux Host secrets provider. A callback driver can provide papHost instead. */
export class PapHostService extends Service implements PapHostServices {
  readonly secrets: KeyringSecretStore;
  constructor(ctx: Context, config: Config) { super(ctx,'papHost'); this.secrets=new KeyringSecretStore(config.keyringService,config.locksRoot); }
}
export function apply(ctx: Context, config: Config): PapHostService { return new PapHostService(ctx,config); }
