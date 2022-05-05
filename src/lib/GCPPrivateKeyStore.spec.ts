import { Datastore, Query } from '@google-cloud/datastore';
import { KeyManagementServiceClient } from '@google-cloud/kms';
import {
  derSerializePublicKey,
  generateRSAKeyPair,
  getPrivateAddressFromIdentityKey,
} from '@relaycorp/relaynet-core';

import { DatastoreIdentityKeyEntity } from './gcp/DatastoreIdentityKeyEntity';
import { GcpKmsError } from './gcp/GcpKmsError';
import { GcpKmsRsaPssProvider } from './gcp/GcpKmsRsaPssProvider';
import { GcpOptions } from './gcp/GcpOptions';
import { GCPKeyOptions, GCPPrivateKeyStore } from './GCPPrivateKeyStore';
import { bufferToArrayBuffer } from './utils/buffer';

const ID_KEY_OPTIONS: GCPKeyOptions = { kmsKey: 'the-id-key', kmsKeyRing: 'the-ring' };
const SESSION_KEY_OPTIONS: GCPKeyOptions = { ...ID_KEY_OPTIONS, kmsKey: 'the-session-key' };
const GCP_OPTIONS: GcpOptions = { location: 'westeros-east1', projectId: 'the-project' };

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

  let cryptoKeyPath: string;
  beforeAll(() => {
    const kmsClient = makeKmsClient();
    cryptoKeyPath = kmsClient.cryptoKeyPath(
      GCP_OPTIONS.projectId,
      GCP_OPTIONS.location,
      ID_KEY_OPTIONS.kmsKeyRing,
      ID_KEY_OPTIONS.kmsKey,
    );
  });

  describe('Key validation', () => {
    test('Key should use be a signing key with RSA-PSS algorithm', async () => {
      const kmsClient = makeKmsClient({ cryptoKeyAlgorithm: 'RSA_DECRYPT_OAEP_2048_SHA256' });
      const store = new GCPPrivateKeyStore(
        kmsClient,
        makeDatastoreClient(undefined),
        ID_KEY_OPTIONS,
        SESSION_KEY_OPTIONS,
        GCP_OPTIONS,
        makeRsaPssProvider(),
      );

      await expect(store.generateIdentityKeyPair()).rejects.toThrowWithMessage(
        GcpKmsError,
        `Key ${cryptoKeyPath} is not an RSA-PSS key`,
      );
    });

    test('Key should use modulus 2048 if hashing algorithm is unspecified', async () => {
      const kmsClient = makeKmsClient({ cryptoKeyAlgorithm: 'RSA_SIGN_PSS_4096_SHA256' });
      const store = new GCPPrivateKeyStore(
        kmsClient,
        makeDatastoreClient(undefined),
        ID_KEY_OPTIONS,
        SESSION_KEY_OPTIONS,
        GCP_OPTIONS,
        makeRsaPssProvider(),
      );

      await expect(store.generateIdentityKeyPair()).rejects.toThrowWithMessage(
        GcpKmsError,
        `Key ${cryptoKeyPath} does not use modulus 2048`,
      );
    });

    test('RSA modulus should match any explicitly set', async () => {
      const kmsClient = makeKmsClient({ cryptoKeyAlgorithm: 'RSA_SIGN_PSS_2048_SHA256' });
      const store = new GCPPrivateKeyStore(
        kmsClient,
        makeDatastoreClient(undefined),
        ID_KEY_OPTIONS,
        SESSION_KEY_OPTIONS,
        GCP_OPTIONS,
        makeRsaPssProvider(),
      );
      const modulus = 3072;

      await expect(store.generateIdentityKeyPair({ modulus })).rejects.toThrowWithMessage(
        GcpKmsError,
        `Key ${cryptoKeyPath} does not use modulus ${modulus}`,
      );
    });

    test('Key should use SHA-256 if hashing algorithm is unspecified', async () => {
      const kmsClient = makeKmsClient({ cryptoKeyAlgorithm: 'RSA_SIGN_PSS_2048_SHA512' });
      const store = new GCPPrivateKeyStore(
        kmsClient,
        makeDatastoreClient(undefined),
        ID_KEY_OPTIONS,
        SESSION_KEY_OPTIONS,
        GCP_OPTIONS,
        makeRsaPssProvider(),
      );

      await expect(store.generateIdentityKeyPair()).rejects.toThrowWithMessage(
        GcpKmsError,
        `Key ${cryptoKeyPath} does not use SHA-256`,
      );
    });

    test('Hashing algorithm should match any explicitly set', async () => {
      const kmsClient = makeKmsClient({ cryptoKeyAlgorithm: 'RSA_SIGN_PSS_2048_SHA256' });
      const store = new GCPPrivateKeyStore(
        kmsClient,
        makeDatastoreClient(undefined),
        ID_KEY_OPTIONS,
        SESSION_KEY_OPTIONS,
        GCP_OPTIONS,
        makeRsaPssProvider(),
      );
      const hashingAlgorithm = 'SHA-512';

      await expect(store.generateIdentityKeyPair({ hashingAlgorithm })).rejects.toThrowWithMessage(
        GcpKmsError,
        `Key ${cryptoKeyPath} does not use ${hashingAlgorithm}`,
      );
    });
  });

  test('Query to determine initial key version assignment should be efficient', async () => {
    const datastoreClient = makeDatastoreClient();
    const store = new GCPPrivateKeyStore(
      makeKmsClient(),
      datastoreClient,
      ID_KEY_OPTIONS,
      SESSION_KEY_OPTIONS,
      GCP_OPTIONS,
      makeRsaPssProvider(),
    );

    await store.generateIdentityKeyPair();

    expect(datastoreClient.runQuery).toHaveBeenCalledWith(
      expect.objectContaining<Partial<Query>>({
        filters: [{ name: 'key', op: '=', val: ID_KEY_OPTIONS.kmsKey }],
        kinds: ['identity_keys'],
        limitVal: 1,
        selectVal: ['version'],
      }),
    );
  });

  describe('Initial key version assignment', () => {
    test('No new key version should be created', async () => {
      const kmsClient = makeKmsClient();
      const store = new GCPPrivateKeyStore(
        kmsClient,
        makeDatastoreClient(null),
        ID_KEY_OPTIONS,
        SESSION_KEY_OPTIONS,
        GCP_OPTIONS,
        makeRsaPssProvider(),
      );

      await store.generateIdentityKeyPair();

      expect(kmsClient.createCryptoKeyVersion).not.toHaveBeenCalled();
    });

    test('Key name should be indexed in Datastore', async () => {
      const datastoreClient = makeDatastoreClient(null);
      const store = new GCPPrivateKeyStore(
        makeKmsClient(),
        datastoreClient,
        ID_KEY_OPTIONS,
        SESSION_KEY_OPTIONS,
        GCP_OPTIONS,
        makeRsaPssProvider(),
      );

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
      const store = new GCPPrivateKeyStore(
        kmsClient,
        makeDatastoreClient(),
        ID_KEY_OPTIONS,
        SESSION_KEY_OPTIONS,
        GCP_OPTIONS,
        makeRsaPssProvider(),
      );

      await store.generateIdentityKeyPair();

      expect(kmsClient.createCryptoKeyVersion).toHaveBeenCalledWith(
        expect.objectContaining({ parent: cryptoKeyPath }),
      );
    });

    test('Key name should not be indexed in Datastore', async () => {
      const datastoreClient = makeDatastoreClient();
      const store = new GCPPrivateKeyStore(
        makeKmsClient(),
        datastoreClient,
        ID_KEY_OPTIONS,
        SESSION_KEY_OPTIONS,
        GCP_OPTIONS,
        makeRsaPssProvider(),
      );

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
      const store = new GCPPrivateKeyStore(
        makeKmsClient(),
        datastoreClient,
        ID_KEY_OPTIONS,
        SESSION_KEY_OPTIONS,
        GCP_OPTIONS,
        makeRsaPssProvider(),
      );

      await store.generateIdentityKeyPair();

      expect(datastoreClient.save).toHaveBeenCalledWith(
        expect.objectContaining({
          key: expect.objectContaining({ kind: 'identity_keys' }),
        }),
      );
    });

    test('Document name should be private address derived from key', async () => {
      const datastoreClient = makeDatastoreClient();
      const store = new GCPPrivateKeyStore(
        makeKmsClient(),
        datastoreClient,
        ID_KEY_OPTIONS,
        SESSION_KEY_OPTIONS,
        GCP_OPTIONS,
        makeRsaPssProvider(),
      );

      await store.generateIdentityKeyPair();

      expect(datastoreClient.save).toHaveBeenCalledWith(
        expect.objectContaining({
          key: expect.objectContaining({ name: stubPrivateAddress }),
        }),
      );
    });

    test('KMS key id should be stored', async () => {
      const datastoreClient = makeDatastoreClient();
      const store = new GCPPrivateKeyStore(
        makeKmsClient(),
        datastoreClient,
        ID_KEY_OPTIONS,
        SESSION_KEY_OPTIONS,
        GCP_OPTIONS,
        makeRsaPssProvider(),
      );

      await store.generateIdentityKeyPair();

      expect(datastoreClient.save).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining<Partial<DatastoreIdentityKeyEntity>>({
            key: ID_KEY_OPTIONS.kmsKey,
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
        ID_KEY_OPTIONS,
        SESSION_KEY_OPTIONS,
        GCP_OPTIONS,
        makeRsaPssProvider(),
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
      const mockRsaPssProvider = makeRsaPssProvider();
      const store = new GCPPrivateKeyStore(
        makeKmsClient(),
        makeDatastoreClient(),
        ID_KEY_OPTIONS,
        SESSION_KEY_OPTIONS,
        GCP_OPTIONS,
        mockRsaPssProvider,
      );

      const { privateKey, publicKey } = await store.generateIdentityKeyPair();

      expect(mockRsaPssProvider.onExportKey).toHaveBeenCalledWith('spki', privateKey);
      await expect(derSerializePublicKey(publicKey)).resolves.toEqual(
        Buffer.from(stubPublicKeySerialized),
      );
    });

    test('Private address should match public key', async () => {
      const mockRsaPssProvider = makeRsaPssProvider();
      const store = new GCPPrivateKeyStore(
        makeKmsClient(),
        makeDatastoreClient(),
        ID_KEY_OPTIONS,
        SESSION_KEY_OPTIONS,
        GCP_OPTIONS,
        mockRsaPssProvider,
      );

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
      expect(request.name).toEqual(cryptoKeyPath);
      return [{ versionTemplate: { algorithm: cryptoKeyAlgorithm } }];
    });

    const versionName = kmsClient.cryptoKeyVersionPath(
      GCP_OPTIONS.projectId,
      GCP_OPTIONS.location,
      ID_KEY_OPTIONS.kmsKeyRing,
      ID_KEY_OPTIONS.kmsKey,
      versionId,
    );
    jest
      .spyOn(kmsClient, 'createCryptoKeyVersion')
      .mockImplementation(() => [{ name: versionName }, undefined, undefined]);

    return kmsClient;
  }

  function makeDatastoreClient(
    existingIdKey: DatastoreIdentityKeyEntity | null = {
      key: ID_KEY_OPTIONS.kmsKey,
      version: '1',
    },
  ): Datastore {
    const datastore = new Datastore();
    jest
      .spyOn(datastore, 'runQuery')
      .mockResolvedValue([existingIdKey ? [existingIdKey] : []] as never);
    jest.spyOn(datastore, 'save').mockImplementation(() => undefined);
    return datastore;
  }

  function makeRsaPssProvider(): GcpKmsRsaPssProvider {
    const provider = { onExportKey: jest.fn().mockResolvedValue(stubPublicKeySerialized) };
    return provider as any;
  }
});
