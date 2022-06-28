import { Datastore } from '@google-cloud/datastore';
import { KeyManagementServiceClient } from '@google-cloud/kms';
import { get as getEnvVar } from 'env-var';

import { Adapter } from './Adapter';
import { VaultPrivateKeyStore } from './vault/VaultPrivateKeyStore';
import { CloudKeystoreError } from './CloudKeystoreError';
import { CloudPrivateKeystore } from './CloudPrivateKeystore';
import { GCPPrivateKeyStore } from './gcp/GCPPrivateKeyStore';

const ADAPTER_INITIALISERS = {
  [Adapter.GCP]: initGCPKeystore,
  [Adapter.VAULT]: initVaultKeystore,
};

export function initPrivateKeystoreFromEnv(adapter: Adapter): CloudPrivateKeystore {
  const init = ADAPTER_INITIALISERS[adapter];
  if (!init) {
    throw new CloudKeystoreError(`Invalid private keystore adapter (${adapter})`);
  }
  return init();
}

export function initGCPKeystore(): GCPPrivateKeyStore {
  const datastore = new Datastore({
    namespace: getEnvVar('KS_DATASTORE_NS').required().asString(),
  });
  const kmsConfig = {
    location: getEnvVar('KS_GCP_LOCATION').required().asString(),
    keyRing: getEnvVar('KS_PRIV_KMS_KEYRING').required().asString(),
    identityKeyId: getEnvVar('KS_PRIV_KMS_ID_KEY').required().asString(),
    sessionEncryptionKeyId: getEnvVar('KS_PRIV_KMS_SESSION_ENC_KEY').required().asString(),
  };
  return new GCPPrivateKeyStore(new KeyManagementServiceClient(), datastore, kmsConfig);
}

export function initVaultKeystore(): VaultPrivateKeyStore {
  const vaultUrl = getEnvVar('VAULT_URL').required().asString();
  const vaultToken = getEnvVar('VAULT_TOKEN').required().asString();
  const vaultKvPath = getEnvVar('VAULT_KV_PREFIX').required().asString();
  return new VaultPrivateKeyStore(vaultUrl, vaultToken, vaultKvPath);
}
