import { EnvVarError } from 'env-var';

import { configureMockEnvVars } from '../testUtils/envVars';
import { initPrivateKeystoreFromEnv } from './init';
import { Adapter } from './Adapter';
import * as vaultKeyStore from './vault/VaultPrivateKeyStore';
import { CloudKeystoreError } from './CloudKeystoreError';

jest.mock('./vault/VaultPrivateKeyStore');

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

    test.each(['VAULT_URL', 'VAULT_TOKEN', 'VAULT_KV_PREFIX'])(
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

      expect(keyStore).toBeInstanceOf(vaultKeyStore.VaultPrivateKeyStore);
      expect(vaultKeyStore.VaultPrivateKeyStore).toBeCalledWith(
        BASE_ENV_VARS.VAULT_URL,
        BASE_ENV_VARS.VAULT_TOKEN,
        BASE_ENV_VARS.VAULT_KV_PREFIX,
      );
    });
  });
});
