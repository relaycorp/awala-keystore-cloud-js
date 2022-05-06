// tslint:disable:max-classes-per-file
import { Datastore, Query } from '@google-cloud/datastore';
import { KeyManagementServiceClient } from '@google-cloud/kms';
import {
  derSerializePublicKey,
  generateRSAKeyPair,
  getPrivateAddressFromIdentityKey,
} from '@relaycorp/relaynet-core';

import { mockSpy } from '../../testUtils/jest';
import { catchPromiseRejection } from '../../testUtils/promises';
import { bufferToArrayBuffer } from '../utils/buffer';
import { DatastoreIdentityKeyEntity } from './DatastoreIdentityKeyEntity';
import { GcpKmsError } from './GcpKmsError';
import { GcpKmsRsaPssPrivateKey } from './GcpKmsRsaPssPrivateKey';
import { GCPPrivateKeyStore, KMSConfig } from './GCPPrivateKeyStore';
import * as kmsUtils from './kmsUtils';

const GCP_PROJECT = 'the-project';
const KMS_CONFIG: KMSConfig = {
  identityKeyId: 'the-id-key',
  keyRing: 'the-ring',
  location: 'westeros-east1',
  sessionKeyId: 'the-session-key',
};

let kmsIdentityKeyPath: string;
beforeAll(async () => {
  const kmsClient = new KeyManagementServiceClient();
  kmsIdentityKeyPath = kmsClient.cryptoKeyPath(
    GCP_PROJECT,
    KMS_CONFIG.location,
    KMS_CONFIG.keyRing,
    KMS_CONFIG.identityKeyId,
  );
  await kmsClient.close();
});

describe('generateIdentityKeyPair', () => {
  let stubPublicKey: CryptoKey;
  let stubPublicKeySerialized: ArrayBuffer;
  let stubPrivateAddress: string;
  beforeAll(async () => {
    const keyPair = await generateRSAKeyPair();
    stubPublicKey = keyPair.publicKey;
    stubPublicKeySerialized = bufferToArrayBuffer(await derSerializePublicKey(stubPublicKey));
    stubPrivateAddress = await getPrivateAddressFromIdentityKey(stubPublicKey);
  });

  const mockRetrieveKMSPublicKey = mockSpy(
    jest.spyOn(kmsUtils, 'retrieveKMSPublicKey'),
    () => stubPublicKeySerialized,
  );

  describe('Key validation', () => {
    test('Key should use be a signing key with RSA-PSS algorithm', async () => {
      const kmsClient = makeKmsClient({ cryptoKeyAlgorithm: 'RSA_DECRYPT_OAEP_2048_SHA256' });
      const store = new GCPPrivateKeyStore(kmsClient, makeDatastoreClient(undefined), KMS_CONFIG);

      await expect(store.generateIdentityKeyPair()).rejects.toThrowWithMessage(
        GcpKmsError,
        `Key ${kmsIdentityKeyPath} is not an RSA-PSS key`,
      );
    });

    test('Key should use modulus 2048 if hashing algorithm is unspecified', async () => {
      const kmsClient = makeKmsClient({ cryptoKeyAlgorithm: 'RSA_SIGN_PSS_4096_SHA256' });
      const store = new GCPPrivateKeyStore(kmsClient, makeDatastoreClient(undefined), KMS_CONFIG);

      await expect(store.generateIdentityKeyPair()).rejects.toThrowWithMessage(
        GcpKmsError,
        `Key ${kmsIdentityKeyPath} does not use modulus 2048`,
      );
    });

    test('RSA modulus should match any explicitly set', async () => {
      const kmsClient = makeKmsClient({ cryptoKeyAlgorithm: 'RSA_SIGN_PSS_2048_SHA256' });
      const store = new GCPPrivateKeyStore(kmsClient, makeDatastoreClient(undefined), KMS_CONFIG);
      const modulus = 3072;

      await expect(store.generateIdentityKeyPair({ modulus })).rejects.toThrowWithMessage(
        GcpKmsError,
        `Key ${kmsIdentityKeyPath} does not use modulus ${modulus}`,
      );
    });

    test('Key should use SHA-256 if hashing algorithm is unspecified', async () => {
      const kmsClient = makeKmsClient({ cryptoKeyAlgorithm: 'RSA_SIGN_PSS_2048_SHA512' });
      const store = new GCPPrivateKeyStore(kmsClient, makeDatastoreClient(undefined), KMS_CONFIG);

      await expect(store.generateIdentityKeyPair()).rejects.toThrowWithMessage(
        GcpKmsError,
        `Key ${kmsIdentityKeyPath} does not use SHA-256`,
      );
    });

    test('Hashing algorithm should match any explicitly set', async () => {
      const kmsClient = makeKmsClient({ cryptoKeyAlgorithm: 'RSA_SIGN_PSS_2048_SHA256' });
      const store = new GCPPrivateKeyStore(kmsClient, makeDatastoreClient(undefined), KMS_CONFIG);
      const hashingAlgorithm = 'SHA-512';

      await expect(store.generateIdentityKeyPair({ hashingAlgorithm })).rejects.toThrowWithMessage(
        GcpKmsError,
        `Key ${kmsIdentityKeyPath} does not use ${hashingAlgorithm}`,
      );
    });
  });

  describe('Initial key version link check', () => {
    test('Query to determine initial key version assignment should be efficient', async () => {
      const datastoreClient = makeDatastoreClient();
      const store = new GCPPrivateKeyStore(makeKmsClient(), datastoreClient, KMS_CONFIG);

      await store.generateIdentityKeyPair();

      expect(datastoreClient.runQuery).toHaveBeenCalledWith(
        expect.objectContaining<Partial<Query>>({
          filters: [{ name: 'key', op: '=', val: KMS_CONFIG.identityKeyId }],
          kinds: ['identity_keys'],
          limitVal: 1,
        }),
      );
    });

    test('Link should be reported not to exist if Datastore index does not exist', async () => {
      const error = new (class extends Error {
        public readonly code = 9;
      })('Index does not exit');
      const kmsClient = makeKmsClient();
      const store = new GCPPrivateKeyStore(kmsClient, makeDatastoreClient(error), KMS_CONFIG);

      await store.generateIdentityKeyPair();

      // If no version was created, there was a link
      expect(kmsClient.createCryptoKeyVersion).not.toHaveBeenCalled();
    });

    test('Link should be reported not to exist if query returns no results', async () => {
      const kmsClient = makeKmsClient();
      const store = new GCPPrivateKeyStore(kmsClient, makeDatastoreClient(null), KMS_CONFIG);

      await store.generateIdentityKeyPair();

      // If no version was created, there was a link
      expect(kmsClient.createCryptoKeyVersion).not.toHaveBeenCalled();
    });

    test('Link should be reported to exist if query returns results', async () => {
      const kmsClient = makeKmsClient();
      const store = new GCPPrivateKeyStore(kmsClient, makeDatastoreClient(), KMS_CONFIG);

      await store.generateIdentityKeyPair();

      // If a new version was created, there was no link
      expect(kmsClient.createCryptoKeyVersion).toHaveBeenCalled();
    });

    test('Any error other than missing index should be propagated', async () => {
      const error = new Error('Something really bad happened');
      const store = new GCPPrivateKeyStore(makeKmsClient(), makeDatastoreClient(error), KMS_CONFIG);

      await expect(store.generateIdentityKeyPair()).rejects.toEqual(error);
    });
  });

  describe('Initial key version assignment', () => {
    test('No new key version should be created', async () => {
      const kmsClient = makeKmsClient();
      const store = new GCPPrivateKeyStore(kmsClient, makeDatastoreClient(null), KMS_CONFIG);

      await store.generateIdentityKeyPair();

      expect(kmsClient.createCryptoKeyVersion).not.toHaveBeenCalled();
    });

    test('Key name should be indexed in Datastore', async () => {
      const datastoreClient = makeDatastoreClient(null);
      const store = new GCPPrivateKeyStore(makeKmsClient(), datastoreClient, KMS_CONFIG);

      await store.generateIdentityKeyPair();

      expect(datastoreClient.save).toHaveBeenCalledWith(
        expect.objectContaining({
          excludeFromIndexes: expect.not.arrayContaining<keyof DatastoreIdentityKeyEntity>(['key']),
        }),
      );
    });
  });

  describe('Subsequent key version generation', () => {
    test('Version should be created under the pre-set key and ring', async () => {
      const kmsClient = makeKmsClient();
      const store = new GCPPrivateKeyStore(kmsClient, makeDatastoreClient(), KMS_CONFIG);

      await store.generateIdentityKeyPair();

      expect(kmsClient.createCryptoKeyVersion).toHaveBeenCalledWith(
        expect.objectContaining({ parent: kmsIdentityKeyPath }),
      );
    });

    test('Key name should not be indexed in Datastore', async () => {
      const datastoreClient = makeDatastoreClient();
      const store = new GCPPrivateKeyStore(makeKmsClient(), datastoreClient, KMS_CONFIG);

      await store.generateIdentityKeyPair();

      expect(datastoreClient.save).toHaveBeenCalledWith(
        expect.objectContaining({
          excludeFromIndexes: expect.arrayContaining<keyof DatastoreIdentityKeyEntity>(['key']),
        }),
      );
    });
  });

  describe('Datastore document', () => {
    test('Document should be saved to identity keys collection', async () => {
      const datastoreClient = makeDatastoreClient();
      const store = new GCPPrivateKeyStore(makeKmsClient(), datastoreClient, KMS_CONFIG);

      await store.generateIdentityKeyPair();

      expect(datastoreClient.save).toHaveBeenCalledWith(
        expect.objectContaining({
          key: expect.objectContaining({ kind: 'identity_keys' }),
        }),
      );
    });

    test('Document name should be private address derived from key', async () => {
      const datastoreClient = makeDatastoreClient();
      const store = new GCPPrivateKeyStore(makeKmsClient(), datastoreClient, KMS_CONFIG);

      await store.generateIdentityKeyPair();

      expect(datastoreClient.save).toHaveBeenCalledWith(
        expect.objectContaining({
          key: expect.objectContaining({ name: stubPrivateAddress }),
        }),
      );
    });

    test('KMS key id should be stored', async () => {
      const datastoreClient = makeDatastoreClient();
      const store = new GCPPrivateKeyStore(makeKmsClient(), datastoreClient, KMS_CONFIG);

      await store.generateIdentityKeyPair();

      expect(datastoreClient.save).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining<Partial<DatastoreIdentityKeyEntity>>({
            key: KMS_CONFIG.identityKeyId,
          }),
        }),
      );
    });

    test('KMS key version id should be stored but not indexed', async () => {
      const datastoreClient = makeDatastoreClient(undefined);
      const kmsKeyVersion = '42';
      const store = new GCPPrivateKeyStore(
        makeKmsClient({ versionId: kmsKeyVersion }),
        datastoreClient,
        KMS_CONFIG,
      );

      await store.generateIdentityKeyPair();

      expect(datastoreClient.save).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining<Partial<DatastoreIdentityKeyEntity>>({
            version: kmsKeyVersion,
          }),
          excludeFromIndexes: expect.arrayContaining<keyof DatastoreIdentityKeyEntity>(['version']),
        }),
      );
    });
  });

  describe('Output', () => {
    test('Public key should match private key', async () => {
      const kmsClient = makeKmsClient();
      const store = new GCPPrivateKeyStore(kmsClient, makeDatastoreClient(), KMS_CONFIG);

      const { privateKey, publicKey } = await store.generateIdentityKeyPair();

      expect(mockRetrieveKMSPublicKey).toHaveBeenCalledWith(
        (privateKey as GcpKmsRsaPssPrivateKey).kmsKeyVersionPath,
        kmsClient,
      );
      await expect(derSerializePublicKey(publicKey)).resolves.toEqual(
        Buffer.from(stubPublicKeySerialized),
      );
    });

    test('Private address should match public key', async () => {
      const store = new GCPPrivateKeyStore(makeKmsClient(), makeDatastoreClient(), KMS_CONFIG);

      const { privateAddress } = await store.generateIdentityKeyPair();

      expect(privateAddress).toEqual(stubPrivateAddress);
    });
  });

  function makeKmsClient({
    cryptoKeyAlgorithm = 'RSA_SIGN_PSS_2048_SHA256',
    versionId = '1',
  } = {}): KeyManagementServiceClient {
    const kmsClient = new KeyManagementServiceClient();

    jest.spyOn(kmsClient, 'getCryptoKey').mockImplementation(async (request) => {
      expect(request.name).toEqual(kmsIdentityKeyPath);
      return [{ versionTemplate: { algorithm: cryptoKeyAlgorithm } }];
    });

    const versionName = kmsClient.cryptoKeyVersionPath(
      GCP_PROJECT,
      KMS_CONFIG.location,
      KMS_CONFIG.keyRing,
      KMS_CONFIG.identityKeyId,
      versionId,
    );
    jest
      .spyOn(kmsClient, 'createCryptoKeyVersion')
      .mockImplementation(() => [{ name: versionName }, undefined, undefined]);

    jest.spyOn(kmsClient, 'getProjectId').mockImplementation(() => GCP_PROJECT);

    return kmsClient;
  }

  function makeDatastoreClient(
    existingIdKey: DatastoreIdentityKeyEntity | Error | null = {
      key: KMS_CONFIG.identityKeyId,
      version: '1',
    },
  ): Datastore {
    const datastore = new Datastore();

    jest.spyOn(datastore, 'runQuery').mockImplementation(() => {
      if (existingIdKey instanceof Error) {
        throw existingIdKey;
      }
      return [existingIdKey ? [existingIdKey] : []];
    });

    jest.spyOn(datastore, 'save').mockImplementation(() => undefined);
    return datastore;
  }
});

describe('retrieveIdentityKey', () => {
  test('Null should be returned if key is not found on Datastore', async () => {
    const store = new GCPPrivateKeyStore(makeKmsClient(), makeDatastoreClient(null), KMS_CONFIG);

    await expect(store.retrieveIdentityKey('non-existing')).resolves.toBeNull();
  });

  test('Datastore lookup error should be wrapped', async () => {
    const datastoreError = new Error('the planets were not aligned');
    const store = new GCPPrivateKeyStore(
      makeKmsClient(),
      makeDatastoreClient(datastoreError),
      KMS_CONFIG,
    );
    const privateAddress = '0deadbeef';

    const error = await catchPromiseRejection(
      store.retrieveIdentityKey(privateAddress),
      GcpKmsError,
    );

    expect(error.message).toStartWith(`Failed to look up KMS key version for ${privateAddress}`);
    expect(error.cause()).toEqual(datastoreError);
  });

  test('Key should be returned if found', async () => {
    const datastoreClient = makeDatastoreClient();
    const kmsClient = makeKmsClient();
    const store = new GCPPrivateKeyStore(kmsClient, datastoreClient, KMS_CONFIG);
    const privateAddress = '0deadbeef';

    const privateKey = await store.retrieveIdentityKey(privateAddress);

    const kmsKeyVersionPath = kmsClient.cryptoKeyVersionPath(
      GCP_PROJECT,
      KMS_CONFIG.location,
      KMS_CONFIG.keyRing,
      KMS_CONFIG.identityKeyId,
      '1',
    );
    expect(privateKey?.kmsKeyVersionPath).toEqual(kmsKeyVersionPath);
    expect(datastoreClient.get).toHaveBeenCalledWith(
      datastoreClient.key(['identity_keys', privateAddress]),
    );
  });

  test('Stored key name should override that of configuration', async () => {
    const kmsKey = `not-${KMS_CONFIG.identityKeyId}`;
    const kmsClient = makeKmsClient();
    const store = new GCPPrivateKeyStore(
      kmsClient,
      makeDatastoreClient({
        key: kmsKey,
        version: '1',
      }),
      KMS_CONFIG,
    );

    const privateKey = await store.retrieveIdentityKey('0deadbeef');

    expect(kmsClient.matchCryptoKeyFromCryptoKeyVersionName(privateKey!.kmsKeyVersionPath)).toEqual(
      kmsKey,
    );
  });

  function makeKmsClient(): KeyManagementServiceClient {
    const kmsClient = new KeyManagementServiceClient();
    jest.spyOn(kmsClient, 'getProjectId').mockImplementation(() => GCP_PROJECT);
    return kmsClient;
  }

  function makeDatastoreClient(
    existingIdKey: DatastoreIdentityKeyEntity | Error | null = {
      key: KMS_CONFIG.identityKeyId,
      version: '1',
    },
  ): Datastore {
    const datastore = new Datastore();
    jest.spyOn(datastore, 'get').mockImplementation(() => {
      if (existingIdKey instanceof Error) {
        throw existingIdKey;
      }
      return [existingIdKey ?? undefined];
    });

    return datastore;
  }
});

describe('saveIdentityKey', () => {
  test('Method should not be supported', async () => {
    const store = new (class extends GCPPrivateKeyStore {
      public async callSaveIdentityKey(): Promise<void> {
        await this.saveIdentityKey();
      }
    })(null as any, null as any, KMS_CONFIG);

    await expect(store.callSaveIdentityKey()).rejects.toThrowWithMessage(
      GcpKmsError,
      'Method is not supported',
    );
  });
});
