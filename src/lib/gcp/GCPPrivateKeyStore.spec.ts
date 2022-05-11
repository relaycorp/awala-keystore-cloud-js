// tslint:disable:max-classes-per-file

import { Datastore, Query } from '@google-cloud/datastore';
import { KeyManagementServiceClient } from '@google-cloud/kms';
import {
  derSerializePrivateKey,
  derSerializePublicKey,
  generateRSAKeyPair,
  getPrivateAddressFromIdentityKey,
  PrivateKeyStoreError,
  SessionKeyPair,
  UnknownKeyError,
} from '@relaycorp/relaynet-core';
import { calculate as calculateCRC32C } from 'fast-crc32c';

import { mockSpy } from '../../testUtils/jest';
import { catchPromiseRejection } from '../../testUtils/promises';
import { bufferToArrayBuffer } from '../utils/buffer';
import { IdentityKeyEntity, SessionKeyEntity } from './datastoreEntities';
import { DatastoreKinds } from './DatastoreKinds';
import { GCPKeystoreError } from './GCPKeystoreError';
import { GcpKmsRsaPssPrivateKey } from './GcpKmsRsaPssPrivateKey';
import { GCPPrivateKeyStore, KMSConfig } from './GCPPrivateKeyStore';
import * as kmsUtils from './kmsUtils';

const GCP_PROJECT = 'the-project';
const KMS_CONFIG: KMSConfig = {
  identityKeyId: 'the-id-key',
  keyRing: 'the-ring',
  location: 'westeros-east1',
  sessionEncryptionKeyId: 'the-session-key',
};

describe('Identity keys', () => {
  let kmsIdentityKeyPath: string;
  beforeAll(async () => {
    const kmsClient = new KeyManagementServiceClient();
    kmsIdentityKeyPath = kmsClient.cryptoKeyPath(
      GCP_PROJECT,
      KMS_CONFIG.location,
      KMS_CONFIG.keyRing,
      KMS_CONFIG.identityKeyId,
    );
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
          GCPKeystoreError,
          `Key ${kmsIdentityKeyPath} is not an RSA-PSS key`,
        );
      });

      test('Key should use modulus 2048 if hashing algorithm is unspecified', async () => {
        const kmsClient = makeKmsClient({ cryptoKeyAlgorithm: 'RSA_SIGN_PSS_4096_SHA256' });
        const store = new GCPPrivateKeyStore(kmsClient, makeDatastoreClient(undefined), KMS_CONFIG);

        await expect(store.generateIdentityKeyPair()).rejects.toThrowWithMessage(
          GCPKeystoreError,
          `Key ${kmsIdentityKeyPath} does not use modulus 2048`,
        );
      });

      test('RSA modulus should match any explicitly set', async () => {
        const kmsClient = makeKmsClient({ cryptoKeyAlgorithm: 'RSA_SIGN_PSS_2048_SHA256' });
        const store = new GCPPrivateKeyStore(kmsClient, makeDatastoreClient(undefined), KMS_CONFIG);
        const modulus = 3072;

        await expect(store.generateIdentityKeyPair({ modulus })).rejects.toThrowWithMessage(
          GCPKeystoreError,
          `Key ${kmsIdentityKeyPath} does not use modulus ${modulus}`,
        );
      });

      test('Key should use SHA-256 if hashing algorithm is unspecified', async () => {
        const kmsClient = makeKmsClient({ cryptoKeyAlgorithm: 'RSA_SIGN_PSS_2048_SHA512' });
        const store = new GCPPrivateKeyStore(kmsClient, makeDatastoreClient(undefined), KMS_CONFIG);

        await expect(store.generateIdentityKeyPair()).rejects.toThrowWithMessage(
          GCPKeystoreError,
          `Key ${kmsIdentityKeyPath} does not use SHA-256`,
        );
      });

      test('Hashing algorithm should match any explicitly set', async () => {
        const kmsClient = makeKmsClient({ cryptoKeyAlgorithm: 'RSA_SIGN_PSS_2048_SHA256' });
        const store = new GCPPrivateKeyStore(kmsClient, makeDatastoreClient(undefined), KMS_CONFIG);
        const hashingAlgorithm = 'SHA-512';

        await expect(
          store.generateIdentityKeyPair({ hashingAlgorithm }),
        ).rejects.toThrowWithMessage(
          GCPKeystoreError,
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
            kinds: [DatastoreKinds.IDENTITY_KEYS],
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
        const store = new GCPPrivateKeyStore(
          makeKmsClient(),
          makeDatastoreClient(error),
          KMS_CONFIG,
        );

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
            excludeFromIndexes: expect.not.arrayContaining<keyof IdentityKeyEntity>(['key']),
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
            excludeFromIndexes: expect.arrayContaining<keyof IdentityKeyEntity>(['key']),
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
            key: expect.objectContaining({ kind: DatastoreKinds.IDENTITY_KEYS }),
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
            data: expect.objectContaining<Partial<IdentityKeyEntity>>({
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
            data: expect.objectContaining<Partial<IdentityKeyEntity>>({
              version: kmsKeyVersion,
            }),
            excludeFromIndexes: expect.arrayContaining<keyof IdentityKeyEntity>(['version']),
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
      existingIdKey: IdentityKeyEntity | Error | null = {
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
      const store = new GCPPrivateKeyStore(
        makeKmsClientWithMockProject(),
        makeDatastoreClient(null),
        KMS_CONFIG,
      );

      await expect(store.retrieveIdentityKey('non-existing')).resolves.toBeNull();
    });

    test('Datastore lookup error should be wrapped', async () => {
      const datastoreError = new Error('the planets were not aligned');
      const store = new GCPPrivateKeyStore(
        makeKmsClientWithMockProject(),
        makeDatastoreClient(datastoreError),
        KMS_CONFIG,
      );
      const privateAddress = '0deadbeef';

      const error = await catchPromiseRejection(
        store.retrieveIdentityKey(privateAddress),
        GCPKeystoreError,
      );

      expect(error.message).toStartWith(`Failed to look up KMS key version for ${privateAddress}`);
      expect(error.cause()).toEqual(datastoreError);
    });

    test('Key should be returned if found', async () => {
      const datastoreClient = makeDatastoreClient();
      const kmsClient = makeKmsClientWithMockProject();
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
        datastoreClient.key([DatastoreKinds.IDENTITY_KEYS, privateAddress]),
      );
    });

    test('Stored key name should override that of configuration', async () => {
      const kmsKey = `not-${KMS_CONFIG.identityKeyId}`;
      const kmsClient = makeKmsClientWithMockProject();
      const store = new GCPPrivateKeyStore(
        kmsClient,
        makeDatastoreClient({
          key: kmsKey,
          version: '1',
        }),
        KMS_CONFIG,
      );

      const privateKey = await store.retrieveIdentityKey('0deadbeef');

      expect(
        kmsClient.matchCryptoKeyFromCryptoKeyVersionName(privateKey!.kmsKeyVersionPath),
      ).toEqual(kmsKey);
    });

    function makeDatastoreClient(
      existingIdKey: IdentityKeyEntity | Error | null = {
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
        GCPKeystoreError,
        'Method is not supported',
      );
    });
  });
});

describe('Session keys', () => {
  const peerPrivateAddress = '0deadbeef';

  let sessionKeyPair: SessionKeyPair;
  let kmsSessionKeyPath: string;
  beforeAll(async () => {
    sessionKeyPair = await SessionKeyPair.generate();

    const kmsClient = new KeyManagementServiceClient();
    kmsSessionKeyPath = kmsClient.cryptoKeyPath(
      GCP_PROJECT,
      KMS_CONFIG.location,
      KMS_CONFIG.keyRing,
      KMS_CONFIG.sessionEncryptionKeyId,
    );
  });

  describe('saveSessionKeySerialized', () => {
    test('Document should be saved to session keys collection', async () => {
      const datastoreClient = makeDatastoreClient();
      const store = new GCPPrivateKeyStore(makeKMSClient(), datastoreClient, KMS_CONFIG);

      await store.saveUnboundSessionKey(sessionKeyPair.privateKey, sessionKeyPair.sessionKey.keyId);

      expect(datastoreClient.insert).toHaveBeenCalledWith(
        expect.objectContaining({
          key: expect.objectContaining({ kind: DatastoreKinds.SESSION_KEYS }),
        }),
      );
    });

    test('Document name should be session key id', async () => {
      const datastoreClient = makeDatastoreClient();
      const store = new GCPPrivateKeyStore(makeKMSClient(), datastoreClient, KMS_CONFIG);

      await store.saveUnboundSessionKey(sessionKeyPair.privateKey, sessionKeyPair.sessionKey.keyId);

      expect(datastoreClient.insert).toHaveBeenCalledWith(
        expect.objectContaining({
          key: expect.objectContaining({ name: sessionKeyPair.sessionKey.keyId.toString('hex') }),
        }),
      );
    });

    test('Peer private address should be stored (but not indexed) if key is bound', async () => {
      const datastoreClient = makeDatastoreClient();
      const store = new GCPPrivateKeyStore(makeKMSClient(), datastoreClient, KMS_CONFIG);

      await store.saveBoundSessionKey(
        sessionKeyPair.privateKey,
        sessionKeyPair.sessionKey.keyId,
        peerPrivateAddress,
      );

      expect(datastoreClient.insert).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining<Partial<SessionKeyEntity>>({ peerPrivateAddress }),
          excludeFromIndexes: expect.arrayContaining<keyof SessionKeyEntity>([
            'peerPrivateAddress',
          ]),
        }),
      );
    });

    test('Peer private address should not be stored if key is unbound', async () => {
      const datastoreClient = makeDatastoreClient();
      const store = new GCPPrivateKeyStore(makeKMSClient(), datastoreClient, KMS_CONFIG);

      await store.saveUnboundSessionKey(sessionKeyPair.privateKey, sessionKeyPair.sessionKey.keyId);

      expect(datastoreClient.insert).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining<Partial<SessionKeyEntity>>({
            peerPrivateAddress: undefined,
          }),
        }),
      );
    });

    test('Private key should be stored encrypted', async () => {
      const privateKeyCiphertext = Buffer.from('encrypted real hard');
      const datastoreClient = makeDatastoreClient();
      const store = new GCPPrivateKeyStore(
        makeKMSClient({ ciphertext: privateKeyCiphertext }),
        datastoreClient,
        KMS_CONFIG,
      );

      await store.saveUnboundSessionKey(sessionKeyPair.privateKey, sessionKeyPair.sessionKey.keyId);

      expect(datastoreClient.insert).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining<Partial<SessionKeyEntity>>({ privateKeyCiphertext }),
        }),
      );
    });

    test('Private key field should not be indexed', async () => {
      const datastoreClient = makeDatastoreClient();
      const store = new GCPPrivateKeyStore(makeKMSClient(), datastoreClient, KMS_CONFIG);

      await store.saveUnboundSessionKey(sessionKeyPair.privateKey, sessionKeyPair.sessionKey.keyId);

      expect(datastoreClient.insert).toHaveBeenCalledWith(
        expect.objectContaining({
          excludeFromIndexes: expect.arrayContaining<keyof SessionKeyEntity>([
            'privateKeyCiphertext',
          ]),
        }),
      );
    });

    test('Creation date should be stored and indexed', async () => {
      const datastoreClient = makeDatastoreClient();
      const store = new GCPPrivateKeyStore(makeKMSClient(), datastoreClient, KMS_CONFIG);
      const beforeDate = new Date();

      await store.saveUnboundSessionKey(sessionKeyPair.privateKey, sessionKeyPair.sessionKey.keyId);

      const afterDate = new Date();
      expect(datastoreClient.insert).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining<Partial<SessionKeyEntity>>({
            creationDate: expect.toSatisfy((date) => beforeDate <= date && date <= afterDate),
          }),
          excludeFromIndexes: expect.not.arrayContaining<keyof SessionKeyEntity>(['creationDate']),
        }),
      );
    });

    describe('KMS encryption', () => {
      test('Specified KMS key should be used', async () => {
        const kmsClient = makeKMSClient();
        const store = new GCPPrivateKeyStore(kmsClient, makeDatastoreClient(), KMS_CONFIG);

        await store.saveUnboundSessionKey(
          sessionKeyPair.privateKey,
          sessionKeyPair.sessionKey.keyId,
        );

        expect(kmsClient.encrypt).toHaveBeenCalledWith(
          expect.objectContaining({ name: kmsSessionKeyPath }),
          expect.anything(),
        );
      });

      test('Plaintext should be session key serialized', async () => {
        const kmsClient = makeKMSClient();
        const store = new GCPPrivateKeyStore(kmsClient, makeDatastoreClient(), KMS_CONFIG);

        await store.saveUnboundSessionKey(
          sessionKeyPair.privateKey,
          sessionKeyPair.sessionKey.keyId,
        );

        expect(kmsClient.encrypt).toHaveBeenCalledWith(
          expect.objectContaining({
            plaintext: Buffer.from(await derSerializePrivateKey(sessionKeyPair.privateKey)),
          }),
          expect.anything(),
        );
      });

      test('Plaintext CRC32C checksum should be passed to KMS', async () => {
        const kmsClient = makeKMSClient();
        const store = new GCPPrivateKeyStore(kmsClient, makeDatastoreClient(), KMS_CONFIG);

        await store.saveUnboundSessionKey(
          sessionKeyPair.privateKey,
          sessionKeyPair.sessionKey.keyId,
        );

        const privateKeySerialized = await derSerializePrivateKey(sessionKeyPair.privateKey);
        expect(kmsClient.encrypt).toHaveBeenCalledWith(
          expect.objectContaining({
            plaintextCrc32c: { value: calculateCRC32C(privateKeySerialized) },
          }),
          expect.anything(),
        );
      });

      test('KMS should verify CRC32 checksum from client', async () => {
        const store = new GCPPrivateKeyStore(
          makeKMSClient({ verifiedPlaintextCrc32c: false }),
          makeDatastoreClient(),
          KMS_CONFIG,
        );

        const error = await catchPromiseRejection(
          store.saveUnboundSessionKey(sessionKeyPair.privateKey, sessionKeyPair.sessionKey.keyId),
          PrivateKeyStoreError,
        );

        expect(error.cause()?.message).toEqual('KMS failed to verify plaintext CRC32C checksum');
      });

      test('Client should verify CRC32 checksum from KMS', async () => {
        const ciphertext = Buffer.from('the private key');
        const store = new GCPPrivateKeyStore(
          makeKMSClient({
            ciphertext,
            ciphertextCrc32cValue: calculateCRC32C(ciphertext) + 1,
          }),
          makeDatastoreClient(),
          KMS_CONFIG,
        );

        const error = await catchPromiseRejection(
          store.saveUnboundSessionKey(sessionKeyPair.privateKey, sessionKeyPair.sessionKey.keyId),
          PrivateKeyStoreError,
        );

        expect(error.cause()?.message).toEqual(
          'Ciphertext CRC32C checksum does not match that from KMS',
        );
      });

      test('KMS should encrypt with the specified key', async () => {
        const kmsKeyName = 'this/is/not/even/well-formed';
        const store = new GCPPrivateKeyStore(
          makeKMSClient({ kmsKeyVersionName: kmsKeyName }),
          makeDatastoreClient(),
          KMS_CONFIG,
        );

        const error = await catchPromiseRejection(
          store.saveUnboundSessionKey(sessionKeyPair.privateKey, sessionKeyPair.sessionKey.keyId),
          PrivateKeyStoreError,
        );

        expect(error.cause()?.message).toEqual(`KMS used the wrong encryption key (${kmsKeyName})`);
      });

      test('KMS should encrypt with a similarly-named key', async () => {
        const kmsKeyName = `${kmsSessionKeyPath}-not/cryptoKeyVersions/1`;
        const store = new GCPPrivateKeyStore(
          makeKMSClient({ kmsKeyVersionName: kmsKeyName }),
          makeDatastoreClient(),
          KMS_CONFIG,
        );

        const error = await catchPromiseRejection(
          store.saveUnboundSessionKey(sessionKeyPair.privateKey, sessionKeyPair.sessionKey.keyId),
          PrivateKeyStoreError,
        );

        expect(error.cause()?.message).toEqual(`KMS used the wrong encryption key (${kmsKeyName})`);
      });

      test('Request should time out after 500ms', async () => {
        const kmsClient = makeKMSClient();
        const store = new GCPPrivateKeyStore(kmsClient, makeDatastoreClient(), KMS_CONFIG);

        await store.saveUnboundSessionKey(
          sessionKeyPair.privateKey,
          sessionKeyPair.sessionKey.keyId,
        );

        expect(kmsClient.encrypt).toHaveBeenCalledWith(
          expect.anything(),
          expect.objectContaining({ timeout: 500 }),
        );
      });

      test('API call error should be wrapped', async () => {
        const kmsError = new Error('Someone talked about Bruno');
        const store = new GCPPrivateKeyStore(
          makeKMSClient(kmsError),
          makeDatastoreClient(),
          KMS_CONFIG,
        );

        const error = await catchPromiseRejection(
          store.saveUnboundSessionKey(sessionKeyPair.privateKey, sessionKeyPair.sessionKey.keyId),
          PrivateKeyStoreError,
        );

        expect(error.message).toContain('Failed to encrypt session key with KMS');
        expect(error.cause()).toBeInstanceOf(GCPKeystoreError);
        expect((error.cause() as GCPKeystoreError).cause()).toEqual(kmsError);
      });
    });

    interface KMSEncryptResponse {
      readonly ciphertext: Buffer;
      readonly verifiedPlaintextCrc32c: boolean;
      readonly ciphertextCrc32cValue: number;
      readonly kmsKeyVersionName: string;
    }

    function makeKMSClient(
      responseOrError: Partial<KMSEncryptResponse> | Error = {},
    ): KeyManagementServiceClient {
      const kmsClient = makeKmsClientWithMockProject();
      jest.spyOn(kmsClient, 'encrypt').mockImplementation(async () => {
        if (responseOrError instanceof Error) {
          throw responseOrError;
        }
        const ciphertext = responseOrError.ciphertext ?? Buffer.from([]);
        const ciphertextCrc32c =
          responseOrError.ciphertextCrc32cValue ?? calculateCRC32C(ciphertext);
        const kmsKeyVersionName =
          responseOrError.kmsKeyVersionName ?? `${kmsSessionKeyPath}/cryptoKeyVersions/1`;
        return [
          {
            ciphertext,
            ciphertextCrc32c: { value: ciphertextCrc32c.toString() },
            name: kmsKeyVersionName,
            verifiedPlaintextCrc32c: responseOrError.verifiedPlaintextCrc32c ?? true,
          },
        ];
      });
      return kmsClient;
    }

    function makeDatastoreClient(): Datastore {
      const datastore = new Datastore();
      jest.spyOn(datastore, 'insert').mockImplementation(() => undefined);
      return datastore;
    }
  });

  describe('retrieveSessionKeyData', () => {
    test('Document should be retrieved from session keys collection', async () => {
      const datastoreClient = makeDatastoreClient();
      const store = new GCPPrivateKeyStore(makeKMSClient(), datastoreClient, KMS_CONFIG);

      await store.retrieveUnboundSessionKey(sessionKeyPair.sessionKey.keyId);

      expect(datastoreClient.get).toHaveBeenCalledWith(
        expect.objectContaining({ kind: DatastoreKinds.SESSION_KEYS }),
      );
    });

    test('Document name should be session key id', async () => {
      const datastoreClient = makeDatastoreClient();
      const store = new GCPPrivateKeyStore(makeKMSClient(), datastoreClient, KMS_CONFIG);

      await store.retrieveUnboundSessionKey(sessionKeyPair.sessionKey.keyId);

      expect(datastoreClient.get).toHaveBeenCalledWith(
        expect.objectContaining({ name: sessionKeyPair.sessionKey.keyId.toString('hex') }),
      );
    });

    test('Key should be regarded missing if it does not exist on Datastore', async () => {
      const datastoreClient = makeDatastoreClient(null);
      const store = new GCPPrivateKeyStore(makeKMSClient(), datastoreClient, KMS_CONFIG);

      await expect(
        store.retrieveUnboundSessionKey(sessionKeyPair.sessionKey.keyId),
      ).rejects.toBeInstanceOf(UnknownKeyError);
    });

    test('Unbound key should be returned regardless of peer', async () => {
      const store = new GCPPrivateKeyStore(makeKMSClient(), makeDatastoreClient(), KMS_CONFIG);

      const key = await store.retrieveSessionKey(
        sessionKeyPair.sessionKey.keyId,
        peerPrivateAddress,
      );

      await expect(derSerializePrivateKey(key)).resolves.toEqual(
        await derSerializePrivateKey(sessionKeyPair.privateKey),
      );
    });

    test('Bound key should not be returned if peer does not match', async () => {
      const store = new GCPPrivateKeyStore(
        makeKMSClient(),
        makeDatastoreClient({
          creationDate: new Date(),
          peerPrivateAddress,
          privateKeyCiphertext: Buffer.from('ciphertext'),
        }),
        KMS_CONFIG,
      );

      await expect(
        store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, `not${peerPrivateAddress}`),
      ).rejects.toBeInstanceOf(UnknownKeyError);
    });

    test('Bound key should be returned if peer matches', async () => {
      const store = new GCPPrivateKeyStore(
        makeKMSClient(),
        makeDatastoreClient({
          creationDate: new Date(),
          peerPrivateAddress,
          privateKeyCiphertext: Buffer.from('ciphertext'),
        }),
        KMS_CONFIG,
      );

      const key = await store.retrieveSessionKey(
        sessionKeyPair.sessionKey.keyId,
        peerPrivateAddress,
      );

      await expect(derSerializePrivateKey(key)).resolves.toEqual(
        await derSerializePrivateKey(sessionKeyPair.privateKey),
      );
    });

    describe('KMS decryption', () => {
      test('Specified KMS key should be used', async () => {
        const kmsClient = makeKMSClient();
        const store = new GCPPrivateKeyStore(kmsClient, makeDatastoreClient(), KMS_CONFIG);

        await store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, peerPrivateAddress);

        expect(kmsClient.decrypt).toHaveBeenCalledWith(
          expect.objectContaining({ name: kmsSessionKeyPath }),
          expect.anything(),
        );
      });

      test('Ciphertext should be taken from Datastore document', async () => {
        const privateKeyCiphertext = Buffer.from('the ciphertext');
        const kmsClient = makeKMSClient();
        const store = new GCPPrivateKeyStore(
          kmsClient,
          makeDatastoreClient({ creationDate: new Date(), privateKeyCiphertext }),
          KMS_CONFIG,
        );

        await store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, peerPrivateAddress);

        expect(kmsClient.decrypt).toHaveBeenCalledWith(
          expect.objectContaining({ ciphertext: privateKeyCiphertext }),
          expect.anything(),
        );
      });

      test('Ciphertext CRC32C checksum should be passed to KMS', async () => {
        const privateKeyCiphertext = Buffer.from('the ciphertext');
        const kmsClient = makeKMSClient();
        const store = new GCPPrivateKeyStore(
          kmsClient,
          makeDatastoreClient({ creationDate: new Date(), privateKeyCiphertext }),
          KMS_CONFIG,
        );

        await store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, peerPrivateAddress);

        expect(kmsClient.decrypt).toHaveBeenCalledWith(
          expect.objectContaining({
            ciphertextCrc32c: { value: calculateCRC32C(privateKeyCiphertext) },
          }),
          expect.anything(),
        );
      });

      test('Client should verify CRC32 checksum from KMS', async () => {
        const kmsClient = makeKMSClient({ plaintextCrc32cValue: 42 });
        const store = new GCPPrivateKeyStore(kmsClient, makeDatastoreClient(), KMS_CONFIG);

        const error = await catchPromiseRejection(
          store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, peerPrivateAddress),
          PrivateKeyStoreError,
        );

        expect(error.cause()?.message).toEqual(
          'Plaintext CRC32C checksum does not match that from KMS',
        );
      });

      test('Request should time out after 500ms', async () => {
        const kmsClient = makeKMSClient();
        const store = new GCPPrivateKeyStore(kmsClient, makeDatastoreClient(), KMS_CONFIG);

        await store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, peerPrivateAddress);

        expect(kmsClient.decrypt).toHaveBeenCalledWith(
          expect.anything(),
          expect.objectContaining({ timeout: 500 }),
        );
      });

      test('API call error should be wrapped', async () => {
        const kmsError = new Error('Someone talked about Bruno');
        const store = new GCPPrivateKeyStore(
          makeKMSClient(kmsError),
          makeDatastoreClient(),
          KMS_CONFIG,
        );

        const error = await catchPromiseRejection(
          store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, peerPrivateAddress),
          PrivateKeyStoreError,
        );

        expect(error.message).toContain('Failed to decrypt session key with KMS');
        expect(error.cause()).toBeInstanceOf(GCPKeystoreError);
        expect((error.cause() as GCPKeystoreError).cause()).toEqual(kmsError);
      });
    });

    interface KMSDecryptResponse {
      readonly plaintext: Buffer;
      readonly plaintextCrc32cValue: number;
    }

    function makeKMSClient(
      responseOrError: Partial<KMSDecryptResponse> | Error = {},
    ): KeyManagementServiceClient {
      const kmsClient = makeKmsClientWithMockProject();
      jest.spyOn(kmsClient, 'decrypt').mockImplementation(async () => {
        if (responseOrError instanceof Error) {
          throw responseOrError;
        }
        const plaintext =
          responseOrError.plaintext ?? (await derSerializePrivateKey(sessionKeyPair.privateKey));
        const plaintextCrc32c = responseOrError.plaintextCrc32cValue ?? calculateCRC32C(plaintext);
        return [{ plaintext, plaintextCrc32c: { value: plaintextCrc32c.toString() } }];
      });
      return kmsClient;
    }

    function makeDatastoreClient(
      keyDocumentOrError: SessionKeyEntity | Error | null = {
        creationDate: new Date(),
        privateKeyCiphertext: Buffer.from([]),
      },
    ): Datastore {
      const datastore = new Datastore();
      jest.spyOn(datastore, 'get').mockImplementation(() => {
        if (keyDocumentOrError instanceof Error) {
          throw keyDocumentOrError;
        }
        return [keyDocumentOrError ?? undefined];
      });
      return datastore;
    }
  });
});

function makeKmsClientWithMockProject(): KeyManagementServiceClient {
  const kmsClient = new KeyManagementServiceClient();
  jest.spyOn(kmsClient, 'getProjectId').mockImplementation(() => GCP_PROJECT);
  return kmsClient;
}
