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

    const isInitialKeyVersionLinked = await this.isInitialKeyVersionLinked();
    const kmsKeyVersionPath = await this.getOrCreateSigningKMSKeyVersion(
      kmsKeyName,
      isInitialKeyVersionLinked,
    );

    const privateKey = new GcpKmsRsaPssPrivateKey(kmsKeyVersionPath);
    const publicKeySerialized = await retrieveKMSPublicKey(
      privateKey.kmsKeyVersionPath,
      this.kmsClient,
    );
    const publicKey = await derDeserializeRSAPublicKey(publicKeySerialized);
    const privateAddress = await getPrivateAddressFromIdentityKey(publicKey);

    await this.linkKMSKeyVersion(kmsKeyVersionPath, privateAddress, isInitialKeyVersionLinked);

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
    peerPrivateAddress?: string,
  ): Promise<void> {
    const datastoreKey = this.datastoreClient.key([DatastoreKinds.SESSION_KEYS, keyId]);
    const data: SessionKeyEntity = {
      creationDate: new Date(),
      peerPrivateAddress,
      privateKeyCiphertext: await this.encryptSessionPrivateKey(keySerialized),
    };
    await this.datastoreClient.insert({
      data,
      excludeFromIndexes: SESSION_KEY_INDEX_EXCLUSIONS,
      key: datastoreKey,
    });
  }

  protected async retrieveSessionKeyData(keyId: string): Promise<SessionPrivateKeyData | null> {
    const datastoreKey = this.datastoreClient.key([DatastoreKinds.SESSION_KEYS, keyId]);
    const [entity] = await this.datastoreClient.get(datastoreKey);
    if (!entity) {
      return null;
    }
    const keyData: SessionKeyEntity = entity;
    const keySerialized = await this.decryptSessionPrivateKey(keyData.privateKeyCiphertext);
    return { keySerialized, peerPrivateAddress: keyData.peerPrivateAddress };
  }

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

  private async getOrCreateSigningKMSKeyVersion(
    kmsKeyName: string,
    isInitialKeyVersionLinked: boolean,
  ): Promise<string> {
    if (isInitialKeyVersionLinked) {
      // Version 1 of the KMS key was already linked, so create a new version.
      const [kmsVersionResponse] = await this.kmsClient.createCryptoKeyVersion({
        parent: kmsKeyName,
      });
      return kmsVersionResponse.name!;
    }

    // Version 1 of the KMS key is not linked so let's assign it by registering it on Datastore
    return this.kmsClient.cryptoKeyVersionPath(
      await this.getGCPProjectId(),
      this.kmsConfig.location,
      this.kmsConfig.keyRing,
      this.kmsConfig.identityKeyId,
      '1', // TODO: GET LATEST VERSION INSTEAD
    );
  }

  //region Identity key linking

  private async isInitialKeyVersionLinked(): Promise<boolean> {
    const query = this.datastoreClient
      .createQuery(DatastoreKinds.IDENTITY_KEYS)
      .filter('key', '=', this.kmsConfig.identityKeyId)
      .limit(1);
    try {
      const [entities] = await this.datastoreClient.runQuery(query);
      return !!entities.length;
    } catch (err) {
      if ((err as any).code === 9) {
        // The index doesn't exist (most likely because the collection doesn't exist)
        return false;
      }

      throw err;
    }
  }

  private async linkKMSKeyVersion(
    kmsKeyVersionPath: string,
    privateAddress: string,
    isInitialKeyVersionLinked: boolean,
  ): Promise<void> {
    const datastoreKey = this.datastoreClient.key([DatastoreKinds.IDENTITY_KEYS, privateAddress]);
    const identityKeyEntity: IdentityKeyEntity = {
      key: this.kmsConfig.identityKeyId,
      version: this.kmsClient.matchCryptoKeyVersionFromCryptoKeyVersionName(
        kmsKeyVersionPath,
      ) as string,
    };
    await this.datastoreClient.save({
      data: identityKeyEntity,
      excludeFromIndexes: ['version', ...(isInitialKeyVersionLinked ? ['key'] : [])],
      key: datastoreKey,
    });
  }

  //endregion
  //region Session key handling utilities

  private async encryptSessionPrivateKey(keySerialized: Buffer): Promise<Buffer> {
    const kmsKeyName = await this.getKMSKeyForSessionKey();
    const [encryptResponse] = await this.kmsClient.encrypt(
      { name: kmsKeyName, plaintext: keySerialized },
      { timeout: 500 },
    );
    return encryptResponse.ciphertext as Buffer;
  }

  private async decryptSessionPrivateKey(privateKeyCiphertext: Buffer): Promise<Buffer> {
    const kmsKeyName = await this.getKMSKeyForSessionKey();
    const [decryptionResponse] = await wrapGCPCallError(
      this.kmsClient.decrypt(
        { name: kmsKeyName, ciphertext: privateKeyCiphertext },
        { timeout: 500 },
      ),
      'Failed to decrypt with KMS',
    );
    return decryptionResponse.plaintext as Buffer;
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
