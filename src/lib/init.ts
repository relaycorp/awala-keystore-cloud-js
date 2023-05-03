import { KeyManagementServiceClient } from '@google-cloud/kms';
import { get as getEnvVar } from 'env-var';
import { Connection } from 'mongoose';

import { Adapter } from './Adapter';
import { VaultPrivateKeyStore } from './vault/VaultPrivateKeyStore';
import { CloudKeystoreError } from './CloudKeystoreError';
import { CloudPrivateKeystore } from './CloudPrivateKeystore';
import { GCPPrivateKeyStore } from './gcp/GCPPrivateKeyStore';

const ADAPTER_INITIALISERS = {
  [Adapter.GCP]: initGCPKeystore,
  [Adapter.VAULT]: initVaultKeystore,
};

export function initPrivateKeystoreFromEnv(
  adapter: string | Adapter,
  dbConnection: Connection,
): CloudPrivateKeystore {
  const init = ADAPTER_INITIALISERS[adapter as unknown as Adapter];
  if (!init) {
    throw new CloudKeystoreError(`Invalid private keystore adapter (${adapter})`);
  }
  return init(dbConnection);
}

export function initGCPKeystore(dbConnection: Connection): GCPPrivateKeyStore {
  const kmsConfig = {
    location: getEnvVar('KS_GCP_LOCATION').required().asString(),
    keyRing: getEnvVar('KS_KMS_KEYRING').required().asString(),
    identityKeyId: getEnvVar('KS_KMS_ID_KEY').required().asString(),
    sessionEncryptionKeyId: getEnvVar('KS_KMS_SESSION_ENC_KEY').required().asString(),
  };
  return new GCPPrivateKeyStore(new KeyManagementServiceClient(), dbConnection, kmsConfig);
}

export function initVaultKeystore(_dbConnection: Connection): VaultPrivateKeyStore {
  const vaultUrl = getEnvVar('KS_VAULT_URL').required().asString();
  const vaultToken = getEnvVar('KS_VAULT_TOKEN').required().asString();
  const vaultKvPath = getEnvVar('KS_VAULT_KV_PREFIX').required().asString();
  return new VaultPrivateKeyStore(vaultUrl, vaultToken, vaultKvPath);
}
