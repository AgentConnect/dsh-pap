import { Service, type Context } from '@deepseek-ai/cordis';
import { KeyringSecretStore } from './keyring.js';
import { FileSecretStore } from './file-secrets.js';
import { requirePap } from './errors.js';
import type { HostSecretStore } from './host.js';
import type { PapHostServices } from './plugin.js';
export interface Config { secretStore?: 'keyring' | 'local-file'; secretsRoot?: string; keyringService?: string; locksRoot?: string }
export const name='@awiki/dsh-pap/host-secrets';
/** Optional Host secrets provider with an explicitly selected storage backend. */
export class PapHostService extends Service implements PapHostServices {
  readonly secrets: HostSecretStore;
  constructor(ctx: Context, config: Config) {
    super(ctx,'papHost');
    requirePap(config.secretStore === undefined || ['keyring', 'local-file'].includes(config.secretStore), 'not_configured');
    if (config.secretStore === 'local-file') {
      requirePap(typeof config.secretsRoot === 'string', 'not_configured');
      this.secrets = new FileSecretStore(config.secretsRoot);
    } else {
      requirePap(typeof config.keyringService === 'string' && typeof config.locksRoot === 'string', 'not_configured');
      this.secrets = new KeyringSecretStore(config.keyringService, config.locksRoot);
    }
  }
}
export function apply(ctx: Context, config: Config): PapHostService { return new PapHostService(ctx,config); }
