import { Datastore } from '@google-cloud/datastore';
import { KeyManagementServiceClient } from '@google-cloud/kms';
import { EnvVarError } from 'env-var';

import { configureMockEnvVars } from '../testUtils/envVars';
import { initPrivateKeystoreFromEnv } from './init';
import { Adapter } from './Adapter';
import * as vaultKeystore from './vault/VaultPrivateKeyStore';
import { CloudKeystoreError } from './CloudKeystoreError';
import * as gcpKeystore from './gcp/GCPPrivateKeyStore';

jest.mock('./vault/VaultPrivateKeyStore');
jest.mock('./gcp/GCPPrivateKeyStore');

describe('initPrivateKeyStoreFromEnv', () => {
  test('Unknown adapter should be refused', () => {
    const invalidAdapter = 'potato';
    expect(() => initPrivateKeystoreFromEnv(invalidAdapter as any)).toThrowWithMessage(
      CloudKeystoreError,
      `Invalid private keystore adapter (${invalidAdapter})`,
    );
  });

  describe('Vault', () => {
    const BASE_ENV_VARS = {
      VAULT_KV_PREFIX: 'kv-prefix',
      VAULT_TOKEN: 'token',
      VAULT_URL: 'http://hi.lol',
    };
    const mockEnvVars = configureMockEnvVars(BASE_ENV_VARS);

    test.each(Object.getOwnPropertyNames(BASE_ENV_VARS))(
      'Environment variable %s should be present',
      (envVar) => {
        mockEnvVars({ ...BASE_ENV_VARS, [envVar]: undefined });

        expect(() => initPrivateKeystoreFromEnv(Adapter.VAULT)).toThrowWithMessage(
          EnvVarError,
          new RegExp(envVar),
        );
      },
    );

    test('Key store should be returned if env vars are present', () => {
      const keyStore = initPrivateKeystoreFromEnv(Adapter.VAULT);

      expect(keyStore).toBeInstanceOf(vaultKeystore.VaultPrivateKeyStore);
      expect(vaultKeystore.VaultPrivateKeyStore).toBeCalledWith(
        BASE_ENV_VARS.VAULT_URL,
        BASE_ENV_VARS.VAULT_TOKEN,
        BASE_ENV_VARS.VAULT_KV_PREFIX,
      );
    });
  });

  describe('GPC', () => {
    const BASE_ENV_VARS = {
      KS_GCP_LOCATION: 'westeros-3',
      KS_DATASTORE_NS: 'the-namespace',
      KS_PRIV_KMS_KEYRING: 'my-precious',
      KS_PRIV_KMS_ID_KEY: 'id',
      KS_PRIV_KMS_SESSION_ENC_KEY: 'session',
    };
    const mockEnvVars = configureMockEnvVars(BASE_ENV_VARS);

    test.each(Object.getOwnPropertyNames(BASE_ENV_VARS))(
      'Environment variable %s should be present',
      (envVar) => {
        mockEnvVars({ ...BASE_ENV_VARS, [envVar]: undefined });

        expect(() => initPrivateKeystoreFromEnv(Adapter.GCP)).toThrowWithMessage(
          EnvVarError,
          new RegExp(envVar),
        );
      },
    );

    test('Key store should be returned if env vars are present', async () => {
      const keyStore = initPrivateKeystoreFromEnv(Adapter.GCP);

      expect(keyStore).toBeInstanceOf(gcpKeystore.GCPPrivateKeyStore);
      expect(gcpKeystore.GCPPrivateKeyStore).toBeCalledWith(
        expect.any(KeyManagementServiceClient),
        expect.toSatisfy<Datastore>((d) => d.namespace === BASE_ENV_VARS.KS_DATASTORE_NS),
        expect.objectContaining<gcpKeystore.KMSConfig>({
          identityKeyId: BASE_ENV_VARS.KS_PRIV_KMS_ID_KEY,
          keyRing: BASE_ENV_VARS.KS_PRIV_KMS_KEYRING,
          location: BASE_ENV_VARS.KS_GCP_LOCATION,
          sessionEncryptionKeyId: BASE_ENV_VARS.KS_PRIV_KMS_SESSION_ENC_KEY,
        }),
      );
    });
  });
});
