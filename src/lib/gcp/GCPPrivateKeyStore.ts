import { KeyManagementServiceClient } from '@google-cloud/kms';
import {
  derDeserializeRSAPublicKey,
  derSerializePublicKey,
  getIdFromIdentityKey,
  IdentityKeyPair,
  RSAKeyGenOptions,
  SessionPrivateKeyData,
} from '@relaycorp/relaynet-core';
import { getModelForClass, ReturnModelType } from '@typegoose/typegoose';
import { calculate as calculateCRC32C } from 'fast-crc32c';
import { Connection } from 'mongoose';

import { GCPKeystoreError } from './GCPKeystoreError';
import { GcpKmsRsaPssPrivateKey } from './GcpKmsRsaPssPrivateKey';
import { wrapGCPCallError } from './gcpUtils';
import { KMS_REQUEST_OPTIONS, retrieveKMSPublicKey } from './kmsUtils';
import { CloudPrivateKeystore } from '../CloudPrivateKeystore';
import { GcpKmsRsaPssProvider } from './GcpKmsRsaPssProvider';
import { GcpIdentityKey } from './models/GcpIdentityKey';
import { GcpSessionKey } from './models/GcpSessionKey';

export interface KMSConfig {
  readonly location: string;
  readonly keyRing: string;
  readonly identityKeyId: string;
  readonly sessionEncryptionKeyId: string;
}

interface ADDRequestParams {
  readonly additionalAuthenticatedData: Buffer;
  readonly additionalAuthenticatedDataCrc32c: { readonly value: number };
}

export class GCPPrivateKeyStore extends CloudPrivateKeystore {
  public readonly idKeyProvider: GcpKmsRsaPssProvider;

  protected readonly idKeyModel: ReturnModelType<typeof GcpIdentityKey>;
  protected readonly sessionKeyModel: ReturnModelType<typeof GcpSessionKey>;

  constructor(
    protected kmsClient: KeyManagementServiceClient,
    dbConnection: Connection,
    protected kmsConfig: KMSConfig,
  ) {
    super();

    this.idKeyProvider = new GcpKmsRsaPssProvider(kmsClient);

    this.idKeyModel = getModelForClass(GcpIdentityKey, { existingConnection: dbConnection });
    this.sessionKeyModel = getModelForClass(GcpSessionKey, { existingConnection: dbConnection });
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

    const publicKeySerialized = await retrieveKMSPublicKey(kmsKeyVersionPath, this.kmsClient);
    const publicKey = await derDeserializeRSAPublicKey(publicKeySerialized);
    const privateKey = new GcpKmsRsaPssPrivateKey(kmsKeyVersionPath, publicKey, this.idKeyProvider);
    const id = await getIdFromIdentityKey(publicKey);

    await this.linkKMSKeyVersion(kmsKeyVersionPath, id, publicKey);

    return { id, privateKey, publicKey };
  }

  public async retrieveIdentityKey(nodeId: string): Promise<GcpKmsRsaPssPrivateKey | null> {
    const keyData = await this.idKeyModel.findOne({ nodeId }).exec();
    if (!keyData) {
      return null;
    }
    const kmsKeyPath = this.kmsClient.cryptoKeyVersionPath(
      await this.getGCPProjectId(),
      this.kmsConfig.location,
      this.kmsConfig.keyRing,
      keyData.kmsKey, // Ignore the KMS key in the constructor
      keyData.kmsKeyVersion.toString(),
    );
    const publicKey = await derDeserializeRSAPublicKey(keyData.publicKey);
    return new GcpKmsRsaPssPrivateKey(kmsKeyPath, publicKey, this.idKeyProvider);
  }

  public async close(): Promise<void> {
    await this.kmsClient.close();
  }

  public async saveIdentityKey(): Promise<void> {
    throw new GCPKeystoreError('Method is not supported');
  }

  protected async saveSessionKeySerialized(
    keyId: string,
    keySerialized: Buffer,
    nodeId: string,
    peerId?: string,
  ): Promise<void> {
    const privateKeyCiphertext = await this.encryptSessionPrivateKey(keySerialized, nodeId, peerId);
    await this.sessionKeyModel.create({
      keyId,
      nodeId,
      peerId,
      privateKeyCiphertext,
    });
  }

  protected async retrieveSessionKeyData(keyId: string): Promise<SessionPrivateKeyData | null> {
    const document = await this.sessionKeyModel.findOne({ keyId }).exec();
    if (!document) {
      return null;
    }
    const nodeId = document.nodeId;
    const peerId = document.peerId;
    const keySerialized = await this.decryptSessionPrivateKey(
      document.privateKeyCiphertext,
      nodeId,
      peerId,
    );
    return { keySerialized, peerId, nodeId };
  }

  protected override async retrieveLatestUnboundSessionKeySerialised(
    nodeId: string,
  ): Promise<Buffer | null> {
    const document = await this.sessionKeyModel
      .findOne(
        { nodeId, peerId: undefined },
        { privateKeyCiphertext: 1 },
        { sort: { creationDate: -1 } },
      )
      .exec();
    if (!document) {
      return null;
    }
    return this.decryptSessionPrivateKey(document.privateKeyCiphertext, nodeId);
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
      this.kmsClient.createCryptoKeyVersion({ parent: kmsKeyName }, KMS_REQUEST_OPTIONS),
      'Failed to create key version',
    );
    return kmsVersionResponse.name!;
  }

  private async linkKMSKeyVersion(
    kmsKeyVersionPath: string,
    nodeId: string,
    publicKey: CryptoKey,
  ): Promise<void> {
    const kmsKeyVersion =
      this.kmsClient.matchCryptoKeyVersionFromCryptoKeyVersionName(kmsKeyVersionPath);
    await this.idKeyModel.create({
      nodeId,
      publicKey: await derSerializePublicKey(publicKey),
      kmsKey: this.kmsConfig.identityKeyId,
      kmsKeyVersion,
    });
  }

  //endregion
  //region Session key handling utilities

  private async encryptSessionPrivateKey(
    keySerialized: Buffer,
    nodeId: string,
    peerId?: string,
  ): Promise<Buffer> {
    const kmsKeyName = await this.getKMSKeyForSessionKey();
    const aadParams = getAADForEncryption(nodeId, peerId);
    const [encryptResponse] = await wrapGCPCallError(
      this.kmsClient.encrypt(
        {
          ...aadParams,
          name: kmsKeyName,
          plaintext: keySerialized,
          plaintextCrc32c: { value: calculateCRC32C(keySerialized) },
        },
        KMS_REQUEST_OPTIONS,
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

  private async decryptSessionPrivateKey(
    privateKeyCiphertext: Buffer,
    nodeId: string,
    peerId?: string,
  ): Promise<Buffer> {
    const kmsKeyName = await this.getKMSKeyForSessionKey();
    const ciphertextCRC32C = calculateCRC32C(privateKeyCiphertext);
    const aadParams = getAADForEncryption(nodeId, peerId);
    const [decryptionResponse] = await wrapGCPCallError(
      this.kmsClient.decrypt(
        {
          ...aadParams,
          ciphertext: privateKeyCiphertext,
          ciphertextCrc32c: { value: ciphertextCRC32C },
          name: kmsKeyName,
        },
        KMS_REQUEST_OPTIONS,
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

function getAADForEncryption(nodeId: string, peerId?: string): ADDRequestParams {
  const additionalAuthenticatedData = Buffer.from(peerId ? `${nodeId},${peerId}` : nodeId);
  const additionalAuthenticatedDataCrc32c = {
    value: calculateCRC32C(additionalAuthenticatedData),
  };
  return { additionalAuthenticatedData, additionalAuthenticatedDataCrc32c };
}
