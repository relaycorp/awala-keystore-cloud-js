// tslint:disable:max-classes-per-file

import { KeyManagementServiceClient } from '@google-cloud/kms';
import {
  derDeserializeRSAPublicKey,
  derSerializePrivateKey,
  derSerializePublicKey,
  getIdFromIdentityKey,
  KeyStoreError,
  SessionKeyPair,
  UnknownKeyError,
} from '@relaycorp/relaynet-core';
import { getModelForClass, ReturnModelType } from '@typegoose/typegoose';
import { calculate as calculateCRC32C } from 'fast-crc32c';

import { mockSpy } from '../../testUtils/jest';
import { catchPromiseRejection } from '../../testUtils/promises';
import { bufferToArrayBuffer } from '../utils/buffer';
import { GCPKeystoreError } from './GCPKeystoreError';
import { GcpKmsRsaPssPrivateKey } from './GcpKmsRsaPssPrivateKey';
import { GCPPrivateKeyStore, KMSConfig } from './GCPPrivateKeyStore';
import * as kmsUtils from './kmsUtils';
import { setUpTestDBConnection } from '../../testUtils/db';
import { GcpIdentityKey } from './models/GcpIdentityKey';
import { GcpSessionKey } from './models/GcpSessionKey';

const GCP_PROJECT = 'the-project';
const KMS_CONFIG: KMSConfig = {
  identityKeyId: 'the-id-key',
  keyRing: 'the-ring',
  location: 'westeros-east1',
  sessionEncryptionKeyId: 'the-session-key',
};

const getDBConnection = setUpTestDBConnection();

describe('Identity keys', () => {
  /**
   * Actual public key exported from KMS.
   *
   * Copied here to avoid interoperability issues -- namely around the serialisation of
   * `AlgorithmParams` (`NULL` vs absent).
   */
  const STUB_KMS_PUBLIC_KEY = Buffer.from(
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnL8hQlf3GLajYh5NA6k7bpHPYUxjiZJgOEiDs8y1iPa6p' +
      '/40p6OeFAakIgqNBZS4CfWnZQ8fPJxCN3ctRMOXQqyajkXHqcUO07shjlvJA9niPQfqpLF2izdSimqMdZkPDfOs4Q' +
      '254+ZLld/JpGn4CocYMaACXWrT+sY4CWw0EJh2kWKcEWF9Z5TL7wA+mJyHZN/cTndIM1kORb8ADzNfyBPMhGRp31N' +
      '4dLff0H28MQCr/0GPbAA+5dMReCPTMLollAI4JmaNtYEaw32sSsH35POtfVz91ui5AaxVONapfw4NfLrxdBvySBhZ' +
      'Zq76INzyG6uwx7TDqJwy0e+SLmF4mQIDAQAB',
    'base64',
  );

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

  describe('idKeyProvider', () => {
    test('Provider should reuse KMS client', () => {
      const kmsClient = new KeyManagementServiceClient();
      const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);

      expect(store.idKeyProvider.kmsClient).toBe(kmsClient);
    });
  });

  describe('generateIdentityKeyPair', () => {
    let stubPublicKey: CryptoKey;
    let stubPublicKeySerialized: ArrayBuffer;
    let stubId: string;
    beforeAll(async () => {
      stubPublicKey = await derDeserializeRSAPublicKey(STUB_KMS_PUBLIC_KEY);
      stubPublicKeySerialized = bufferToArrayBuffer(STUB_KMS_PUBLIC_KEY);
      stubId = await getIdFromIdentityKey(stubPublicKey);
    });

    const mockRetrieveKMSPublicKey = mockSpy(
      jest.spyOn(kmsUtils, 'retrieveKMSPublicKey'),
      () => stubPublicKeySerialized,
    );

    describe('Key validation', () => {
      test('Key should use be a signing key with RSA-PSS algorithm', async () => {
        const kmsClient = makeKmsClient({ cryptoKeyAlgorithm: 'RSA_DECRYPT_OAEP_2048_SHA256' });
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);

        await expect(store.generateIdentityKeyPair()).rejects.toThrowWithMessage(
          GCPKeystoreError,
          `Key ${kmsIdentityKeyPath} is not an RSA-PSS key`,
        );
      });

      test('Key should use modulus 2048 if hashing algorithm is unspecified', async () => {
        const kmsClient = makeKmsClient({ cryptoKeyAlgorithm: 'RSA_SIGN_PSS_4096_SHA256' });
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);

        await expect(store.generateIdentityKeyPair()).rejects.toThrowWithMessage(
          GCPKeystoreError,
          `Key ${kmsIdentityKeyPath} does not use modulus 2048`,
        );
      });

      test('RSA modulus should match any explicitly set', async () => {
        const kmsClient = makeKmsClient({ cryptoKeyAlgorithm: 'RSA_SIGN_PSS_2048_SHA256' });
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);
        const modulus = 3072;

        await expect(store.generateIdentityKeyPair({ modulus })).rejects.toThrowWithMessage(
          GCPKeystoreError,
          `Key ${kmsIdentityKeyPath} does not use modulus ${modulus}`,
        );
      });

      test('Key should use SHA-256 if hashing algorithm is unspecified', async () => {
        const kmsClient = makeKmsClient({ cryptoKeyAlgorithm: 'RSA_SIGN_PSS_2048_SHA512' });
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);

        await expect(store.generateIdentityKeyPair()).rejects.toThrowWithMessage(
          GCPKeystoreError,
          `Key ${kmsIdentityKeyPath} does not use SHA-256`,
        );
      });

      test('Hashing algorithm should match any explicitly set', async () => {
        const kmsClient = makeKmsClient({ cryptoKeyAlgorithm: 'RSA_SIGN_PSS_2048_SHA256' });
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);
        const hashingAlgorithm = 'SHA-512';

        await expect(
          store.generateIdentityKeyPair({ hashingAlgorithm }),
        ).rejects.toThrowWithMessage(
          GCPKeystoreError,
          `Key ${kmsIdentityKeyPath} does not use ${hashingAlgorithm}`,
        );
      });
    });

    describe('KMS key creation', () => {
      test('Version should be created under the pre-set key and ring', async () => {
        const kmsClient = makeKmsClient();
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);

        await store.generateIdentityKeyPair();

        expect(kmsClient.createCryptoKeyVersion).toHaveBeenCalledWith(
          expect.objectContaining({ parent: kmsIdentityKeyPath }),
          expect.anything(),
        );
      });

      test('Version creation call should time out after 3 seconds', async () => {
        const kmsClient = makeKmsClient();
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);

        await store.generateIdentityKeyPair();

        expect(kmsClient.createCryptoKeyVersion).toHaveBeenCalledWith(
          expect.anything(),
          expect.objectContaining({ timeout: 3_000 }),
        );
      });

      test('Version creation call should be retried', async () => {
        const kmsClient = makeKmsClient();
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);

        await store.generateIdentityKeyPair();

        expect(kmsClient.createCryptoKeyVersion).toHaveBeenCalledWith(
          expect.anything(),
          expect.objectContaining({ maxRetries: 10 }),
        );
      });

      test('Error to create key version should be wrapped', async () => {
        const callError = new Error('Cannot create key version');
        const kmsClient = makeKmsClient();
        jest.spyOn(kmsClient, 'createCryptoKeyVersion').mockImplementation(async () => {
          throw callError;
        });
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);

        const error = await catchPromiseRejection(
          store.generateIdentityKeyPair(),
          GCPKeystoreError,
        );

        expect(error.message).toStartWith('Failed to create key version');
        expect(error.cause()).toEqual(callError);
      });
    });

    describe('Mongoose document', () => {
      test('Private address should be stored', async () => {
        const store = new GCPPrivateKeyStore(makeKmsClient(), getDBConnection(), KMS_CONFIG);

        const { id } = await store.generateIdentityKeyPair();

        await expect(getDocument(id)).resolves.toBeTruthy();
      });

      test('Public key should be stored', async () => {
        const store = new GCPPrivateKeyStore(makeKmsClient(), getDBConnection(), KMS_CONFIG);

        const { id, publicKey } = await store.generateIdentityKeyPair();

        const document = await getDocument(id);
        expect(document!.publicKey.equals(await derSerializePublicKey(publicKey))).toBeTrue();
      });

      test('KMS key should be stored', async () => {
        const store = new GCPPrivateKeyStore(makeKmsClient(), getDBConnection(), KMS_CONFIG);

        const { id } = await store.generateIdentityKeyPair();

        const document = await getDocument(id);
        expect(document!.kmsKey).toEqual(KMS_CONFIG.identityKeyId);
      });

      test('KMS key id should be stored', async () => {
        const kmsKeyVersion = 42;
        const store = new GCPPrivateKeyStore(
          makeKmsClient({ versionId: kmsKeyVersion }),
          getDBConnection(),
          KMS_CONFIG,
        );

        const { id } = await store.generateIdentityKeyPair();

        const document = await getDocument(id);
        expect(document?.kmsKeyVersion).toEqual(kmsKeyVersion);
      });

      async function getDocument(nodeId: string): Promise<GcpIdentityKey | null> {
        return getGcpIdentityKeyModel().findOne({ nodeId }).exec();
      }
    });

    describe('Output', () => {
      test('Public key should match private key', async () => {
        const kmsClient = makeKmsClient();
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);

        const { privateKey, publicKey } = await store.generateIdentityKeyPair();

        expect(mockRetrieveKMSPublicKey).toHaveBeenCalledWith(
          (privateKey as GcpKmsRsaPssPrivateKey).kmsKeyVersionPath,
          kmsClient,
        );
        await expect(derSerializePublicKey(publicKey)).resolves.toEqual(
          Buffer.from(stubPublicKeySerialized),
        );
      });

      test('Private key algorithm should be populated correctly', async () => {
        const store = new GCPPrivateKeyStore(makeKmsClient(), getDBConnection(), KMS_CONFIG);

        const { privateKey } = await store.generateIdentityKeyPair();

        expect(privateKey.algorithm).toHaveProperty('hash', (stubPublicKey.algorithm as any).hash);
      });

      test('Private key should contain existing provider', async () => {
        const store = new GCPPrivateKeyStore(makeKmsClient(), getDBConnection(), KMS_CONFIG);

        const { privateKey } = await store.generateIdentityKeyPair();

        expect(privateKey).toBeInstanceOf(GcpKmsRsaPssPrivateKey);
        expect((privateKey as GcpKmsRsaPssPrivateKey).provider).toBe(store.idKeyProvider);
      });

      test('Private address should match public key', async () => {
        const store = new GCPPrivateKeyStore(makeKmsClient(), getDBConnection(), KMS_CONFIG);

        const { id } = await store.generateIdentityKeyPair();

        expect(id).toEqual(stubId);
      });
    });

    function makeKmsClient({
      cryptoKeyAlgorithm = 'RSA_SIGN_PSS_2048_SHA256',
      versionId = 1,
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
        versionId.toString(),
      );
      jest
        .spyOn(kmsClient, 'createCryptoKeyVersion')
        .mockImplementation(() => [{ name: versionName }, undefined, undefined]);

      jest.spyOn(kmsClient, 'getProjectId').mockImplementation(() => GCP_PROJECT);

      return kmsClient;
    }
  });

  describe('retrieveIdentityKey', () => {
    const ID = '0deadbeef';

    test('Null should be returned if key is not found', async () => {
      const store = new GCPPrivateKeyStore(
        makeKmsClientWithMockProject(),
        getDBConnection(),
        KMS_CONFIG,
      );

      await expect(store.retrieveIdentityKey('non-existing')).resolves.toBeNull();
    });

    test('Key should be returned if found', async () => {
      const kmsClient = makeKmsClientWithMockProject();
      const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);
      await saveKey();

      await expect(store.retrieveIdentityKey(ID)).resolves.toBeTruthy();
    });

    test('Key version path should be populated correctly', async () => {
      const kmsClient = makeKmsClientWithMockProject();
      const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);
      await saveKey();

      const privateKey = await store.retrieveIdentityKey(ID);

      const kmsKeyVersionPath = kmsClient.cryptoKeyVersionPath(
        GCP_PROJECT,
        KMS_CONFIG.location,
        KMS_CONFIG.keyRing,
        KMS_CONFIG.identityKeyId,
        '1',
      );
      expect(privateKey?.kmsKeyVersionPath).toEqual(kmsKeyVersionPath);
    });

    test('Public key should be populated', async () => {
      const store = new GCPPrivateKeyStore(
        makeKmsClientWithMockProject(),
        getDBConnection(),
        KMS_CONFIG,
      );
      await saveKey();

      const privateKey = await store.retrieveIdentityKey(ID);

      expect(privateKey).toBeInstanceOf(GcpKmsRsaPssPrivateKey);
      const publicKeySerialized = await derSerializePublicKey(
        (privateKey as GcpKmsRsaPssPrivateKey).publicKey,
      );
      expect(publicKeySerialized).toEqual(STUB_KMS_PUBLIC_KEY);
    });

    test('Key should contain existing provider', async () => {
      const store = new GCPPrivateKeyStore(
        makeKmsClientWithMockProject(),
        getDBConnection(),
        KMS_CONFIG,
      );
      await saveKey();

      const privateKey = await store.retrieveIdentityKey(ID);

      expect(privateKey).toBeInstanceOf(GcpKmsRsaPssPrivateKey);
      expect((privateKey as GcpKmsRsaPssPrivateKey).provider).toBe(store.idKeyProvider);
    });

    test('Stored key name should override that of configuration', async () => {
      const kmsKey = `not-${KMS_CONFIG.identityKeyId}`;
      const kmsClient = makeKmsClientWithMockProject();
      const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);
      await saveKey({ kmsKey });

      const privateKey = await store.retrieveIdentityKey(ID);

      expect(
        kmsClient.matchCryptoKeyFromCryptoKeyVersionName(privateKey!.kmsKeyVersionPath),
      ).toEqual(kmsKey);
    });

    async function saveKey({ kmsKey } = { kmsKey: KMS_CONFIG.identityKeyId }): Promise<void> {
      const model = getGcpIdentityKeyModel();
      await model.create({
        nodeId: ID,
        publicKey: STUB_KMS_PUBLIC_KEY,
        kmsKey,
        kmsKeyVersion: 1,
      });
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

  function getGcpIdentityKeyModel(): ReturnModelType<typeof GcpIdentityKey> {
    return getModelForClass(GcpIdentityKey, { existingConnection: getDBConnection() });
  }
});

describe('Session keys', () => {
  const nodeId = '0deadc0de';
  const peerId = '0deadbeef';

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

  let unboundKey: SaveKeyProps;
  beforeAll(async () => {
    unboundKey = {
      nodeId,
      keyId: sessionKeyPair.sessionKey.keyId,
      privateKey: sessionKeyPair.privateKey,
    };
  });

  describe('saveSessionKeySerialized', () => {
    test('Document should be saved', async () => {
      const store = new GCPPrivateKeyStore(makeKMSClient(), getDBConnection(), KMS_CONFIG);

      await store.saveSessionKey(
        sessionKeyPair.privateKey,
        sessionKeyPair.sessionKey.keyId,
        nodeId,
      );

      await expect(getDocument(sessionKeyPair.sessionKey.keyId)).resolves.toBeTruthy();
    });

    test('Node id should be stored', async () => {
      const store = new GCPPrivateKeyStore(makeKMSClient(), getDBConnection(), KMS_CONFIG);

      await store.saveSessionKey(
        sessionKeyPair.privateKey,
        sessionKeyPair.sessionKey.keyId,
        nodeId,
        peerId,
      );

      const document = await getDocument(sessionKeyPair.sessionKey.keyId);
      expect(document?.nodeId).toEqual(nodeId);
    });

    test('Peer id should be stored', async () => {
      const store = new GCPPrivateKeyStore(makeKMSClient(), getDBConnection(), KMS_CONFIG);

      await store.saveSessionKey(
        sessionKeyPair.privateKey,
        sessionKeyPair.sessionKey.keyId,
        nodeId,
        peerId,
      );

      const document = await getDocument(sessionKeyPair.sessionKey.keyId);
      expect(document?.peerId).toEqual(peerId);
    });

    test('Peer id should not be stored if key is unbound', async () => {
      const store = new GCPPrivateKeyStore(makeKMSClient(), getDBConnection(), KMS_CONFIG);

      await store.saveSessionKey(
        sessionKeyPair.privateKey,
        sessionKeyPair.sessionKey.keyId,
        nodeId,
      );

      const document = await getDocument(sessionKeyPair.sessionKey.keyId);
      expect(document?.peerId).toBeUndefined();
    });

    test('Private key should be stored encrypted', async () => {
      const privateKeyCiphertext = Buffer.from('military-grade encryption');
      const store = new GCPPrivateKeyStore(
        makeKMSClient({ ciphertext: privateKeyCiphertext }),
        getDBConnection(),
        KMS_CONFIG,
      );

      await store.saveSessionKey(
        sessionKeyPair.privateKey,
        sessionKeyPair.sessionKey.keyId,
        nodeId,
      );

      const document = await getDocument(sessionKeyPair.sessionKey.keyId);
      expect(document!.privateKeyCiphertext.equals(privateKeyCiphertext)).toBeTrue();
    });

    test('Creation date should be stored', async () => {
      const store = new GCPPrivateKeyStore(makeKMSClient(), getDBConnection(), KMS_CONFIG);
      const beforeDate = new Date();

      await store.saveSessionKey(
        sessionKeyPair.privateKey,
        sessionKeyPair.sessionKey.keyId,
        nodeId,
      );

      const afterDate = new Date();
      const document = await getDocument(sessionKeyPair.sessionKey.keyId);
      expect(document?.creationDate).toBeBeforeOrEqualTo(afterDate);
      expect(document?.creationDate).toBeAfterOrEqualTo(beforeDate);
    });

    describe('KMS encryption', () => {
      test('Specified KMS key should be used', async () => {
        const kmsClient = makeKMSClient();
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);

        await store.saveSessionKey(
          sessionKeyPair.privateKey,
          sessionKeyPair.sessionKey.keyId,
          nodeId,
        );

        expect(kmsClient.encrypt).toHaveBeenCalledWith(
          expect.objectContaining({ name: kmsSessionKeyPath }),
          expect.anything(),
        );
      });

      test('Plaintext should be session key serialized', async () => {
        const kmsClient = makeKMSClient();
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);

        await store.saveSessionKey(
          sessionKeyPair.privateKey,
          sessionKeyPair.sessionKey.keyId,
          nodeId,
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
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);

        await store.saveSessionKey(
          sessionKeyPair.privateKey,
          sessionKeyPair.sessionKey.keyId,
          nodeId,
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
          getDBConnection(),
          KMS_CONFIG,
        );

        const error = await catchPromiseRejection(
          store.saveSessionKey(sessionKeyPair.privateKey, sessionKeyPair.sessionKey.keyId, nodeId),
          KeyStoreError,
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
          getDBConnection(),
          KMS_CONFIG,
        );

        const error = await catchPromiseRejection(
          store.saveSessionKey(sessionKeyPair.privateKey, sessionKeyPair.sessionKey.keyId, nodeId),
          KeyStoreError,
        );

        expect(error.cause()?.message).toEqual(
          'Ciphertext CRC32C checksum does not match that from KMS',
        );
      });

      test('KMS should encrypt with the specified key', async () => {
        const kmsKeyName = `${kmsSessionKeyPath}-not/cryptoKeyVersions/1`;
        const store = new GCPPrivateKeyStore(
          makeKMSClient({ kmsKeyVersionName: kmsKeyName }),
          getDBConnection(),
          KMS_CONFIG,
        );

        const error = await catchPromiseRejection(
          store.saveSessionKey(sessionKeyPair.privateKey, sessionKeyPair.sessionKey.keyId, nodeId),
          KeyStoreError,
        );

        expect(error.cause()?.message).toEqual(`KMS used the wrong encryption key (${kmsKeyName})`);
      });

      test('AAD should be node id if key is unbound', async () => {
        const kmsClient = makeKMSClient();
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);

        await store.saveSessionKey(
          sessionKeyPair.privateKey,
          sessionKeyPair.sessionKey.keyId,
          nodeId,
        );

        const additionalAuthenticatedData = Buffer.from(nodeId);
        expect(kmsClient.encrypt).toHaveBeenCalledWith(
          expect.objectContaining({
            additionalAuthenticatedData,
            additionalAuthenticatedDataCrc32c: {
              value: calculateCRC32C(additionalAuthenticatedData),
            },
          }),
          expect.anything(),
        );
      });

      test('ADD should be node and peer id if key is bound', async () => {
        const kmsClient = makeKMSClient();
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);

        await store.saveSessionKey(
          sessionKeyPair.privateKey,
          sessionKeyPair.sessionKey.keyId,
          nodeId,
          peerId,
        );

        const additionalAuthenticatedData = Buffer.from(`${nodeId},${peerId}`);
        expect(kmsClient.encrypt).toHaveBeenCalledWith(
          expect.objectContaining({
            additionalAuthenticatedData,
            additionalAuthenticatedDataCrc32c: {
              value: calculateCRC32C(additionalAuthenticatedData),
            },
          }),
          expect.anything(),
        );
      });

      test('Request should time out after 3 seconds', async () => {
        const kmsClient = makeKMSClient();
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);

        await store.saveSessionKey(
          sessionKeyPair.privateKey,
          sessionKeyPair.sessionKey.keyId,
          nodeId,
        );

        expect(kmsClient.encrypt).toHaveBeenCalledWith(
          expect.anything(),
          expect.objectContaining({ timeout: 3_000 }),
        );
      });

      test('Request should be retried', async () => {
        const kmsClient = makeKMSClient();
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);

        await store.saveSessionKey(
          sessionKeyPair.privateKey,
          sessionKeyPair.sessionKey.keyId,
          nodeId,
        );

        expect(kmsClient.encrypt).toHaveBeenCalledWith(
          expect.anything(),
          expect.objectContaining({ maxRetries: 10 }),
        );
      });

      test('API call error should be wrapped', async () => {
        const kmsError = new Error('Someone talked about Bruno');
        const store = new GCPPrivateKeyStore(
          makeKMSClient(kmsError),
          getDBConnection(),
          KMS_CONFIG,
        );

        const error = await catchPromiseRejection(
          store.saveSessionKey(sessionKeyPair.privateKey, sessionKeyPair.sessionKey.keyId, nodeId),
          KeyStoreError,
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
      jest.spyOn(kmsClient, 'encrypt').mockImplementation(async ({ plaintext }: any) => {
        if (responseOrError instanceof Error) {
          throw responseOrError;
        }
        const ciphertext = responseOrError.ciphertext ?? mockEncrypt(plaintext);
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

    async function getDocument(id: Buffer): Promise<GcpSessionKey | null> {
      return getGcpSessionKeyModel()
        .findOne({ keyId: id.toString('hex') })
        .exec();
    }
  });

  describe('retrieveSessionKeyData', () => {
    test('Key should be regarded missing if it does not exist on the DB', async () => {
      const store = new GCPPrivateKeyStore(
        mockKmsDecryptionClient(),
        getDBConnection(),
        KMS_CONFIG,
      );

      await expect(
        store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, nodeId, 'peer id'),
      ).rejects.toBeInstanceOf(UnknownKeyError);
    });

    test('Unbound key should be returned regardless of peer', async () => {
      const store = new GCPPrivateKeyStore(
        mockKmsDecryptionClient(),
        getDBConnection(),
        KMS_CONFIG,
      );
      await saveKey(unboundKey);

      const key = await store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, nodeId, peerId);

      await expect(derSerializePrivateKey(key)).resolves.toEqual(
        await derSerializePrivateKey(sessionKeyPair.privateKey),
      );
    });

    test('Bound key should not be returned if owner does not match', async () => {
      const store = new GCPPrivateKeyStore(
        mockKmsDecryptionClient(),
        getDBConnection(),
        KMS_CONFIG,
      );
      await saveKey({ ...unboundKey, nodeId: `not-${nodeId}` });

      await expect(
        store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, nodeId, peerId),
      ).rejects.toBeInstanceOf(UnknownKeyError);
    });

    test('Bound key should not be returned if peer does not match', async () => {
      const store = new GCPPrivateKeyStore(
        mockKmsDecryptionClient(),
        getDBConnection(),
        KMS_CONFIG,
      );
      await saveKey({ ...unboundKey, peerId: `not-${peerId}` });

      await expect(
        store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, nodeId, peerId),
      ).rejects.toBeInstanceOf(UnknownKeyError);
    });

    test('Bound key should be returned if peer matches', async () => {
      const store = new GCPPrivateKeyStore(
        mockKmsDecryptionClient(),
        getDBConnection(),
        KMS_CONFIG,
      );
      await saveKey({ ...unboundKey, peerId });

      const key = await store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, nodeId, peerId);

      await expect(derSerializePrivateKey(key)).resolves.toEqual(
        await derSerializePrivateKey(sessionKeyPair.privateKey),
      );
    });

    describe('KMS decryption', () => {
      test('Specified KMS key should be used', async () => {
        const kmsClient = mockKmsDecryptionClient();
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);
        await saveKey(unboundKey);

        await store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, nodeId, peerId);

        expect(kmsClient.decrypt).toHaveBeenCalledWith(
          expect.objectContaining({ name: kmsSessionKeyPath }),
          expect.anything(),
        );
      });

      test('Ciphertext should be taken from DB', async () => {
        const kmsClient = mockKmsDecryptionClient();
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);
        await saveKey(unboundKey);

        await store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, nodeId, peerId);

        const ciphertext = mockEncrypt(await derSerializePrivateKey(sessionKeyPair.privateKey));
        expect(kmsClient.decrypt).toHaveBeenCalledWith(
          expect.objectContaining({ ciphertext: expect.toSatisfy((c) => c.equals(ciphertext)) }),
          expect.anything(),
        );
      });

      test('Ciphertext CRC32C checksum should be passed to KMS', async () => {
        const kmsClient = mockKmsDecryptionClient();
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);
        await saveKey(unboundKey);

        await store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, nodeId, peerId);

        const ciphertext = mockEncrypt(await derSerializePrivateKey(sessionKeyPair.privateKey));
        expect(kmsClient.decrypt).toHaveBeenCalledWith(
          expect.objectContaining({
            ciphertextCrc32c: { value: calculateCRC32C(ciphertext) },
          }),
          expect.anything(),
        );
      });

      test('Client should verify CRC32 checksum from KMS', async () => {
        const kmsClient = mockKmsDecryptionClient(42);
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);
        await saveKey(unboundKey);

        const error = await catchPromiseRejection(
          store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, nodeId, peerId),
          KeyStoreError,
        );

        expect(error.cause()?.message).toEqual(
          'Plaintext CRC32C checksum does not match that from KMS',
        );
      });

      test('AAD should be node id if key is unbound', async () => {
        const kmsClient = mockKmsDecryptionClient();
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);
        await saveKey(unboundKey);

        await store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, nodeId, peerId);

        const additionalAuthenticatedData = Buffer.from(nodeId);
        expect(kmsClient.decrypt).toHaveBeenCalledWith(
          expect.objectContaining({
            additionalAuthenticatedData,
            additionalAuthenticatedDataCrc32c: {
              value: calculateCRC32C(additionalAuthenticatedData),
            },
          }),
          expect.anything(),
        );
      });

      test('ADD should be node and peer id if key is bound', async () => {
        const kmsClient = mockKmsDecryptionClient();
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);
        await saveKey({ ...unboundKey, peerId });

        await store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, nodeId, peerId);

        const additionalAuthenticatedData = Buffer.from(`${nodeId},${peerId}`);
        expect(kmsClient.decrypt).toHaveBeenCalledWith(
          expect.objectContaining({
            additionalAuthenticatedData,
            additionalAuthenticatedDataCrc32c: {
              value: calculateCRC32C(additionalAuthenticatedData),
            },
          }),
          expect.anything(),
        );
      });

      test('Request should time out after 3 seconds', async () => {
        const kmsClient = mockKmsDecryptionClient();
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);
        await saveKey(unboundKey);

        await store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, nodeId, peerId);

        expect(kmsClient.decrypt).toHaveBeenCalledWith(
          expect.anything(),
          expect.objectContaining({ timeout: 3_000 }),
        );
      });

      test('Request should be retried', async () => {
        const kmsClient = mockKmsDecryptionClient();
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);
        await saveKey(unboundKey);

        await store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, nodeId, peerId);

        expect(kmsClient.decrypt).toHaveBeenCalledWith(
          expect.anything(),
          expect.objectContaining({ maxRetries: 10 }),
        );
      });

      test('API call error should be wrapped', async () => {
        const kmsError = new Error('Someone talked about Bruno');
        const store = new GCPPrivateKeyStore(
          mockKmsDecryptionClient(kmsError),
          getDBConnection(),
          KMS_CONFIG,
        );
        await saveKey(unboundKey);

        const error = await catchPromiseRejection(
          store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, nodeId, peerId),
          KeyStoreError,
        );

        expect(error.message).toContain('Failed to decrypt session key with KMS');
        expect(error.cause()).toBeInstanceOf(GCPKeystoreError);
        expect((error.cause() as GCPKeystoreError).cause()).toEqual(kmsError);
      });
    });
  });

  describe('retrieveLatestUnboundSessionKeySerialised', () => {
    test('should return null if node has no unbound keys', async () => {
      const store = new GCPPrivateKeyStore(
        mockKmsDecryptionClient(),
        getDBConnection(),
        KMS_CONFIG,
      );

      await expect(store.retrieveUnboundSessionPublicKey(nodeId)).resolves.toBeNull();
    });

    test('should ignore keys from other nodes', async () => {
      const store = new GCPPrivateKeyStore(
        mockKmsDecryptionClient(),
        getDBConnection(),
        KMS_CONFIG,
      );
      await saveKey({ ...unboundKey, nodeId: `not-${nodeId}` });

      await expect(store.retrieveUnboundSessionPublicKey(nodeId)).resolves.toBeNull();
    });

    test('should ignore bound keys', async () => {
      const store = new GCPPrivateKeyStore(
        mockKmsDecryptionClient(),
        getDBConnection(),
        KMS_CONFIG,
      );
      await saveKey({ ...unboundKey, peerId });

      await expect(store.retrieveUnboundSessionPublicKey(nodeId)).resolves.toBeNull();
    });

    test('should return latest key', async () => {
      await saveKey(unboundKey);
      const latestKey = await SessionKeyPair.generate();
      await saveKey({
        nodeId,
        keyId: latestKey.sessionKey.keyId,
        privateKey: latestKey.privateKey,
      });
      const store = new GCPPrivateKeyStore(
        mockKmsDecryptionClient(),
        getDBConnection(),
        KMS_CONFIG,
      );

      const key = await store.retrieveUnboundSessionPublicKey(nodeId);

      expect(key?.keyId).toMatchObject(latestKey.sessionKey.keyId);
      await expect(derSerializePublicKey(key!.publicKey)).resolves.toStrictEqual(
        await derSerializePublicKey(latestKey.sessionKey.publicKey),
      );
    });

    describe('KMS decryption', () => {
      test('Specified KMS key should be used', async () => {
        const kmsClient = mockKmsDecryptionClient();
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);
        await saveKey(unboundKey);

        await store.retrieveUnboundSessionPublicKey(nodeId);

        expect(kmsClient.decrypt).toHaveBeenCalledWith(
          expect.objectContaining({ name: kmsSessionKeyPath }),
          expect.anything(),
        );
      });

      test('Ciphertext should be taken from DB', async () => {
        const kmsClient = mockKmsDecryptionClient();
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);
        await saveKey(unboundKey);

        await store.retrieveUnboundSessionPublicKey(nodeId);

        const expectedCiphertext = mockEncrypt(await derSerializePrivateKey(unboundKey.privateKey));
        expect(kmsClient.decrypt).toHaveBeenCalledWith(
          expect.objectContaining({
            ciphertext: expect.toSatisfy((c) => c.equals(expectedCiphertext)),
          }),
          expect.anything(),
        );
      });

      test('Ciphertext CRC32C checksum should be passed to KMS', async () => {
        const kmsClient = mockKmsDecryptionClient();
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);
        await saveKey(unboundKey);

        await store.retrieveUnboundSessionPublicKey(nodeId);

        const ciphertext = mockEncrypt(await derSerializePrivateKey(unboundKey.privateKey));
        expect(kmsClient.decrypt).toHaveBeenCalledWith(
          expect.objectContaining({
            ciphertextCrc32c: { value: calculateCRC32C(ciphertext) },
          }),
          expect.anything(),
        );
      });

      test('Client should verify CRC32 checksum from KMS', async () => {
        const kmsClient = mockKmsDecryptionClient(42);
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);
        await saveKey(unboundKey);

        await expect(store.retrieveUnboundSessionPublicKey(nodeId)).rejects.toThrowWithMessage(
          GCPKeystoreError,
          'Plaintext CRC32C checksum does not match that from KMS',
        );
      });

      test('AAD should be node id', async () => {
        const kmsClient = mockKmsDecryptionClient();
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);
        await saveKey(unboundKey);

        await store.retrieveUnboundSessionPublicKey(nodeId);

        const additionalAuthenticatedData = Buffer.from(nodeId);
        expect(kmsClient.decrypt).toHaveBeenCalledWith(
          expect.objectContaining({
            additionalAuthenticatedData,
            additionalAuthenticatedDataCrc32c: {
              value: calculateCRC32C(additionalAuthenticatedData),
            },
          }),
          expect.anything(),
        );
      });

      test('Request should time out after 3 seconds', async () => {
        const kmsClient = mockKmsDecryptionClient();
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);
        await saveKey(unboundKey);

        await store.retrieveUnboundSessionPublicKey(nodeId);

        expect(kmsClient.decrypt).toHaveBeenCalledWith(
          expect.anything(),
          expect.objectContaining({ timeout: 3_000 }),
        );
      });

      test('Request should be retried', async () => {
        const kmsClient = mockKmsDecryptionClient();
        const store = new GCPPrivateKeyStore(kmsClient, getDBConnection(), KMS_CONFIG);
        await saveKey(unboundKey);

        await store.retrieveUnboundSessionPublicKey(nodeId);

        expect(kmsClient.decrypt).toHaveBeenCalledWith(
          expect.anything(),
          expect.objectContaining({ maxRetries: 10 }),
        );
      });

      test('API call error should be wrapped', async () => {
        const kmsError = new Error('Someone talked about Bruno');
        const store = new GCPPrivateKeyStore(
          mockKmsDecryptionClient(kmsError),
          getDBConnection(),
          KMS_CONFIG,
        );
        await saveKey(unboundKey);

        await expect(store.retrieveUnboundSessionPublicKey(nodeId)).rejects.toThrowWithMessage(
          GCPKeystoreError,
          /^Failed to decrypt session key with KMS/,
        );
      });
    });
  });

  interface SaveKeyProps {
    readonly nodeId: string;
    readonly peerId?: string;
    readonly keyId: Buffer;
    readonly privateKey: CryptoKey;
    readonly creationDate?: Date;
  }

  async function saveKey(key: SaveKeyProps): Promise<void> {
    const model = getGcpSessionKeyModel();
    await model.create({
      creationDate: key.creationDate,
      nodeId: key.nodeId,
      peerId: key.peerId,
      keyId: key.keyId.toString('hex'),
      privateKeyCiphertext: mockEncrypt(await derSerializePrivateKey(key.privateKey)),
    });
  }

  function getGcpSessionKeyModel(): ReturnModelType<typeof GcpSessionKey> {
    return getModelForClass(GcpSessionKey, { existingConnection: getDBConnection() });
  }

  function mockEncrypt(plaintext: Buffer): Buffer {
    return Buffer.from(plaintext.toString('base64'));
  }

  function mockDecrypt(ciphertext: Buffer): Buffer {
    return Buffer.from(ciphertext.toString('ascii'), 'base64');
  }

  function mockKmsDecryptionClient(
    plaintextCrc32cOrError?: number | Error,
  ): KeyManagementServiceClient {
    const kmsClient = makeKmsClientWithMockProject();
    jest.spyOn(kmsClient, 'decrypt').mockImplementation(async ({ ciphertext }: any) => {
      if (plaintextCrc32cOrError instanceof Error) {
        throw plaintextCrc32cOrError;
      }
      const plaintext = mockDecrypt(ciphertext);
      const plaintextCrc32c = plaintextCrc32cOrError ?? calculateCRC32C(plaintext);
      return [{ plaintext, plaintextCrc32c: { value: plaintextCrc32c.toString() } }];
    });
    return kmsClient;
  }
});

describe('close', () => {
  test('KMS client should be closed', async () => {
    const kmsClient = makeKMSClient();
    const store = new GCPPrivateKeyStore(kmsClient, null as any, KMS_CONFIG);

    await store.close();

    expect(kmsClient.close).toBeCalled();
  });

  function makeKMSClient(): KeyManagementServiceClient {
    const kmsClient = new KeyManagementServiceClient();
    jest.spyOn(kmsClient, 'close').mockImplementation(async () => undefined);
    return kmsClient;
  }
});

function makeKmsClientWithMockProject(): KeyManagementServiceClient {
  const kmsClient = new KeyManagementServiceClient();
  jest.spyOn(kmsClient, 'getProjectId').mockImplementation(() => GCP_PROJECT);
  return kmsClient;
}
