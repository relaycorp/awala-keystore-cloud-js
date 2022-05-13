import { Datastore } from '@google-cloud/datastore';
import { KeyManagementServiceClient } from '@google-cloud/kms';
import {
  derDeserializeRSAPublicKey,
  getPrivateAddressFromIdentityKey,
  IdentityKeyPair,
  PrivateKeyStore,
  RSAKeyGenOptions,
  SessionPrivateKeyData,
} from '@relaycorp/relaynet-core';
import { calculate as calculateCRC32C } from 'fast-crc32c';

import { IdentityKeyEntity, SessionKeyEntity } from './datastoreEntities';
import { DatastoreKinds } from './DatastoreKinds';
import { GCPKeystoreError } from './GCPKeystoreError';
import { GcpKmsRsaPssPrivateKey } from './GcpKmsRsaPssPrivateKey';
import { wrapGCPCallError } from './gcpUtils';
import { retrieveKMSPublicKey } from './kmsUtils';

export interface KMSConfig {
  readonly location: string;
  readonly keyRing: string;
  readonly identityKeyId: string;
  readonly sessionEncryptionKeyId: string;
}

const SESSION_KEY_INDEX_EXCLUSIONS: ReadonlyArray<keyof SessionKeyEntity> = [
  'peerPrivateAddress',
  'privateAddress',
  'privateKeyCiphertext',
];

export class GCPPrivateKeyStore extends PrivateKeyStore {
  constructor(
    protected kmsClient: KeyManagementServiceClient,
    protected datastoreClient: Datastore,
    protected kmsConfig: KMSConfig,
  ) {
    super();
  }

  public override async generateIdentityKeyPair(
    options: Partial<RSAKeyGenOptions> = {},
  ): Promise<IdentityKeyPair> {
    const kmsKeyName = this.kmsClient.cryptoKeyPath(
      await this.getGCPProjectId(),
      this.kmsConfig.location,
      this.kmsConfig.keyRing,
      this.kmsConfig.identityKeyId,
    );
    await this.validateExistingSigningKey(kmsKeyName, options);

    const kmsKeyVersionPath = await this.createSigningKMSKeyVersion(kmsKeyName);

    const privateKey = new GcpKmsRsaPssPrivateKey(kmsKeyVersionPath);
    const publicKeySerialized = await retrieveKMSPublicKey(
      privateKey.kmsKeyVersionPath,
      this.kmsClient,
    );
    const publicKey = await derDeserializeRSAPublicKey(publicKeySerialized);
    const privateAddress = await getPrivateAddressFromIdentityKey(publicKey);

    await this.linkKMSKeyVersion(kmsKeyVersionPath, privateAddress);

    return { privateAddress, privateKey, publicKey };
  }

  public async retrieveIdentityKey(privateAddress: string): Promise<GcpKmsRsaPssPrivateKey | null> {
    const datastoreKey = this.datastoreClient.key([DatastoreKinds.IDENTITY_KEYS, privateAddress]);
    let keyDocument: IdentityKeyEntity | undefined;
    try {
      const [entity] = await this.datastoreClient.get(datastoreKey);
      keyDocument = entity;
    } catch (err) {
      throw new GCPKeystoreError(
        err as Error,
        `Failed to look up KMS key version for ${privateAddress}`,
      );
    }
    if (!keyDocument) {
      return null;
    }
    const kmsKeyPath = this.kmsClient.cryptoKeyVersionPath(
      await this.getGCPProjectId(),
      this.kmsConfig.location,
      this.kmsConfig.keyRing,
      keyDocument.key, // Ignore the KMS key in the constructor
      keyDocument.version,
    );
    return new GcpKmsRsaPssPrivateKey(kmsKeyPath);
  }

  protected async saveIdentityKey(): Promise<void> {
    throw new GCPKeystoreError('Method is not supported');
  }

  protected async saveSessionKeySerialized(
    keyId: string,
    keySerialized: Buffer,
    privateAddress: string,
    peerPrivateAddress?: string,
  ): Promise<void> {
    const datastoreKey = this.datastoreClient.key([DatastoreKinds.SESSION_KEYS, keyId]);
    const data: SessionKeyEntity = {
      creationDate: new Date(),
      peerPrivateAddress,
      privateAddress,
      privateKeyCiphertext: await this.encryptSessionPrivateKey(keySerialized),
    };
    await wrapGCPCallError(
      this.datastoreClient.save(
        { data, excludeFromIndexes: SESSION_KEY_INDEX_EXCLUSIONS, key: datastoreKey },
        { timeout: 500 },
      ),
      'Failed to store session key in Datastore',
    );
  }

  protected async retrieveSessionKeyData(keyId: string): Promise<SessionPrivateKeyData | null> {
    const datastoreKey = this.datastoreClient.key([DatastoreKinds.SESSION_KEYS, keyId]);
    const [entity] = await wrapGCPCallError(
      this.datastoreClient.get(datastoreKey, { gaxOptions: { timeout: 500 } }),
      'Failed to retrieve key',
    );
    if (!entity) {
      return null;
    }
    const keyData: SessionKeyEntity = entity;
    const keySerialized = await this.decryptSessionPrivateKey(keyData.privateKeyCiphertext);
    return {
      keySerialized,
      peerPrivateAddress: keyData.peerPrivateAddress,
      privateAddress: keyData.privateAddress,
    };
  }

  //region Identity key utilities

  private async validateExistingSigningKey(
    kmsKeyName: string,
    options: Partial<RSAKeyGenOptions>,
  ): Promise<void> {
    const [kmsKey] = await this.kmsClient.getCryptoKey({ name: kmsKeyName });
    const keyAlgorithm = kmsKey.versionTemplate!.algorithm as string;
    if (!keyAlgorithm.startsWith('RSA_SIGN_PSS_')) {
      throw new GCPKeystoreError(`Key ${kmsKeyName} is not an RSA-PSS key`);
    }

    const requiredRSAModulus = options.modulus ?? 2048;
    if (!keyAlgorithm.includes(`_${requiredRSAModulus}_`)) {
      throw new GCPKeystoreError(`Key ${kmsKeyName} does not use modulus ${requiredRSAModulus}`);
    }

    const requiredHashingAlgorithm = options.hashingAlgorithm ?? 'SHA-256';
    if (!keyAlgorithm.endsWith(requiredHashingAlgorithm.replace('-', ''))) {
      throw new GCPKeystoreError(`Key ${kmsKeyName} does not use ${requiredHashingAlgorithm}`);
    }
  }

  private async createSigningKMSKeyVersion(kmsKeyName: string): Promise<string> {
    // Version 1 of the KMS key was already linked, so create a new version.
    const [kmsVersionResponse] = await wrapGCPCallError(
      this.kmsClient.createCryptoKeyVersion({ parent: kmsKeyName }, { timeout: 500 }),
      'Failed to create key version',
    );
    return kmsVersionResponse.name!;
  }

  private async linkKMSKeyVersion(
    kmsKeyVersionPath: string,
    privateAddress: string,
  ): Promise<void> {
    const datastoreKey = this.datastoreClient.key([DatastoreKinds.IDENTITY_KEYS, privateAddress]);
    const identityKeyEntity: IdentityKeyEntity = {
      key: this.kmsConfig.identityKeyId,
      version: this.kmsClient.matchCryptoKeyVersionFromCryptoKeyVersionName(
        kmsKeyVersionPath,
      ) as string,
    };
    await wrapGCPCallError(
      this.datastoreClient.save(
        {
          data: identityKeyEntity,
          excludeFromIndexes: ['version', 'key'],
          key: datastoreKey,
        },
        { timeout: 500 },
      ),
      'Failed to register identity key on Datastore',
    );
  }

  //endregion
  //region Session key handling utilities

  private async encryptSessionPrivateKey(keySerialized: Buffer): Promise<Buffer> {
    const kmsKeyName = await this.getKMSKeyForSessionKey();
    const plaintextCRC32C = calculateCRC32C(keySerialized);
    const [encryptResponse] = await wrapGCPCallError(
      this.kmsClient.encrypt(
        { name: kmsKeyName, plaintext: keySerialized, plaintextCrc32c: { value: plaintextCRC32C } },
        { timeout: 500 },
      ),
      'Failed to encrypt session key with KMS',
    );
    if (!encryptResponse.name!.startsWith(kmsKeyName + '/')) {
      throw new GCPKeystoreError(`KMS used the wrong encryption key (${encryptResponse.name})`);
    }
    if (!encryptResponse.verifiedPlaintextCrc32c) {
      throw new GCPKeystoreError('KMS failed to verify plaintext CRC32C checksum');
    }
    const ciphertext = encryptResponse.ciphertext as Buffer;
    if (calculateCRC32C(ciphertext) !== Number(encryptResponse.ciphertextCrc32c!.value)) {
      throw new GCPKeystoreError('Ciphertext CRC32C checksum does not match that from KMS');
    }
    return ciphertext;
  }

  private async decryptSessionPrivateKey(privateKeyCiphertext: Buffer): Promise<Buffer> {
    const kmsKeyName = await this.getKMSKeyForSessionKey();
    const ciphertextCRC32C = calculateCRC32C(privateKeyCiphertext);
    const [decryptionResponse] = await wrapGCPCallError(
      this.kmsClient.decrypt(
        {
          ciphertext: privateKeyCiphertext,
          ciphertextCrc32c: { value: ciphertextCRC32C },
          name: kmsKeyName,
        },
        { timeout: 500 },
      ),
      'Failed to decrypt session key with KMS',
    );
    const plaintext = decryptionResponse.plaintext as Buffer;
    if (calculateCRC32C(plaintext) !== Number(decryptionResponse.plaintextCrc32c!.value)) {
      throw new GCPKeystoreError('Plaintext CRC32C checksum does not match that from KMS');
    }
    return plaintext;
  }

  private async getKMSKeyForSessionKey(): Promise<string> {
    return this.kmsClient.cryptoKeyPath(
      await this.getGCPProjectId(),
      this.kmsConfig.location,
      this.kmsConfig.keyRing,
      this.kmsConfig.sessionEncryptionKeyId,
    );
  }

  //endregion

  private async getGCPProjectId(): Promise<string> {
    // GCP client library already caches the project id.
    return this.kmsClient.getProjectId();
  }
}
