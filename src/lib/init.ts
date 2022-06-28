import { get as getEnvVar } from 'env-var';

import { Adapter } from './Adapter';
import { VaultPrivateKeyStore } from './vault/VaultPrivateKeyStore';
import { CloudKeystoreError } from './CloudKeystoreError';
import { CloudPrivateKeystore } from './CloudPrivateKeystore';

const ADAPTER_INITIALISERS = {
  [Adapter.VAULT]: initVaultKeystore,
};

export function initPrivateKeystoreFromEnv(adapter: Adapter): CloudPrivateKeystore {
  const init = ADAPTER_INITIALISERS[adapter];
  if (!init) {
    throw new CloudKeystoreError(`Invalid private keystore adapter (${adapter})`);
  }
  return init();
}

export function initVaultKeystore(): VaultPrivateKeyStore {
  const vaultUrl = getEnvVar('VAULT_URL').required().asString();
  const vaultToken = getEnvVar('VAULT_TOKEN').required().asString();
  const vaultKvPath = getEnvVar('VAULT_KV_PREFIX').required().asString();
  return new VaultPrivateKeyStore(vaultUrl, vaultToken, vaultKvPath);
}
